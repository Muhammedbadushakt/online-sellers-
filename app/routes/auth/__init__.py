from flask import Blueprint, request, jsonify, make_response
from flask_jwt_extended import (
    create_refresh_token, create_access_token,
    jwt_required, get_jwt_identity, verify_jwt_in_request,
)
import hmac, hashlib, re, secrets, json, logging
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from functools import wraps

import requests as http_requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from email_validator import validate_email, EmailNotValidError
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
from .extensions import db, limiter
from .models import (
    Seller, User, Store, StoreType, ResetOtp
)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")
subscription_bp = Blueprint("subscription", __name__, url_prefix="/subscription")

TURNSTILE_SECRET_KEY = Config.TURNSTILE_SECRET_KEY
ACCESS_EXPIRES = timedelta(hours=1)
REFRESH_EXPIRES = timedelta(days=30)
OTP_EXPIRES = timedelta(minutes=10)
OTP_RESEND_COOLDOWN = timedelta(seconds=60)
TRIAL_AMOUNT = Decimal("2.00")  # Rs 2 trial (Go plan)

logger = logging.getLogger("auth")


# ==========================================
# HELPERS
# ==========================================

def verify_captcha(token):
    if not TURNSTILE_SECRET_KEY or not token:
        return False
    try:
        response = http_requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={"secret": TURNSTILE_SECRET_KEY, "response": token},
            timeout=5,
        )
        return response.json().get("success", False)
    except Exception:
        return False


def log_event(event, level="info", **fields):
    message = json.dumps({"event": event, **fields})
    if level == "warning":
        logger.warning(message)
    else:
        logger.info(message)


def _now():
    return datetime.now(timezone.utc)


def _aware(dt):
    """DB drivers (e.g. SQLite) may return naive datetimes."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def generate_otp(length=6):
    return "".join(secrets.choice("0123456789") for _ in range(length))


def hash_otp(otp):
    """Keyed hash, truncated to fit the String(10) otp columns."""
    key = str(Config.SECRET_KEY).encode()
    return hmac.new(key, otp.encode(), hashlib.sha256).hexdigest()[:10]


def otp_matches(stored_hash, otp):
    return bool(stored_hash) and hmac.compare_digest(stored_hash, hash_otp(otp))


def normalize_phone(raw):
    """Returns +<country><number> or None. 10-digit numbers default to +91."""
    if not raw:
        return None
    cleaned = re.sub(r"[\s\-()]", "", str(raw))
    if re.fullmatch(r"[6-9]\d{9}", cleaned):
        return "+91" + cleaned
    if re.fullmatch(r"\+[1-9]\d{9,14}", cleaned):
        return cleaned
    return None


def normalize_email(raw):
    try:
        return validate_email((raw or "").strip(), check_deliverability=False).normalized.lower()
    except EmailNotValidError:
        return None


def validate_password(pw):
    if not pw or len(pw) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
        return "Password must contain letters and numbers"
    return None


def send_sms_otp(phone, otp):
    """Plug in your SMS provider here (MSG91, Twilio, Fast2SMS...)."""
    if getattr(Config, "DEBUG", False):
        logger.info("DEV SMS OTP for %s: %s", phone, otp)
    # TODO: call provider
    return True


def send_email_otp(email, otp):
    """Plug in your email provider here."""
    if getattr(Config, "DEBUG", False):
        logger.info("DEV EMAIL OTP for %s: %s", email, otp)
    # TODO: call provider
    return True


def issue_tokens(seller):
    identity = str(seller.id)
    access = create_access_token(identity=identity, expires_delta=ACCESS_EXPIRES)
    refresh = create_refresh_token(identity=identity, expires_delta=REFRESH_EXPIRES)
    return access, refresh


def token_response(seller, body, status=200):
    access, refresh = issue_tokens(seller)
    resp = make_response(jsonify({**body, "access_token": access}), status)
    resp.set_cookie(
        "refresh_token", refresh,
        max_age=int(REFRESH_EXPIRES.total_seconds()),
        httponly=True,
        secure=not getattr(Config, "DEBUG", False),
        samesite="Lax",
        path="/auth",
    )
    return resp


def set_phone_otp(user):
    otp = generate_otp()
    user.otp = hash_otp(otp)
    user.otp_expires_at = _now() + OTP_EXPIRES
    return otp


# ==========================================
# STORE SETUP GATE
# Use @require_store_setup on add-product / create-order routes.
# Address, owner name and contact are optional at signup but required here.
# ==========================================

def store_setup_missing(store):
    missing = []
    if not (store.address or "").strip():
        missing.append("address")
    if not (store.owner_name or "").strip():
        missing.append("owner_name")
    if not (store.contact_number or "").strip():
        missing.append("contact_number")
    return missing


def require_store_setup(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        seller_id = int(get_jwt_identity())
        store = Store.query.filter_by(seller_id=seller_id).first()
        if not store:
            return jsonify(error="Store not found"), 404
        missing = store_setup_missing(store)
        if missing:
            return jsonify(
                error="Complete your store setup to continue",
                setup_required=True,
                missing_fields=missing,
            ), 428
        return fn(*args, **kwargs)
    return wrapper


# ==========================================
# REGISTER
# GET  -> store types for the dropdown
# POST -> creates seller + user + store, sends phone OTP
# ==========================================

@auth_bp.route("/register", methods=["POST", "GET"])
@limiter.limit("5 per hour")
def register():
    if request.method == "GET":
        types = StoreType.query.order_by(StoreType.name).all()
        return jsonify(store_types=[
            {"id": t.id, "name": t.name, "description": t.description} for t in types
        ])

    data = request.get_json(silent=True) or {}

    if not verify_captcha(data.get("captcha_token")):
        log_event("register_captcha_failed", level="warning", ip=request.remote_addr)
        return jsonify(error="Captcha verification failed"), 400

    name = (data.get("name") or "").strip()
    email = normalize_email(data.get("email"))
    phone = normalize_phone(data.get("number"))
    password = data.get("password")
    store_name = (data.get("store_name") or "").strip()
    store_type_id = data.get("store_type_id")

    # Optional at signup; asked again when adding products / orders
    address = (data.get("store_address") or "").strip() or None
    owner_name = (data.get("owner_name") or "").strip() or None
    contact_number = normalize_phone(data.get("contact_number")) if data.get("contact_number") else None

    errors = {}
    if not name:
        errors["name"] = "Name is required"
    if not email:
        errors["email"] = "Valid email is required"
    if not phone:
        errors["number"] = "Valid phone number is required"
    pw_error = validate_password(password)
    if pw_error:
        errors["password"] = pw_error
    if not store_name:
        errors["store_name"] = "Store name is required"
    if not store_type_id or not db.session.get(StoreType, store_type_id):
        errors["store_type_id"] = "Select a valid store type"
    if data.get("contact_number") and not contact_number:
        errors["contact_number"] = "Invalid contact number"
    if errors:
        return jsonify(errors=errors), 400

    if Seller.query.filter((Seller.email == email) | (Seller.number == phone)).first():
        return jsonify(error="An account with this email or phone already exists"), 409

    try:
        seller = Seller(name=name, email=email, number=phone)
        db.session.add(seller)
        db.session.flush()

        user = User(seller_id=seller.id, password=generate_password_hash(password))
        otp = set_phone_otp(user)
        db.session.add(user)

        db.session.add(Store(
            seller_id=seller.id,
            name=store_name,
            type_id=store_type_id,
            address=address,
            owner_name=owner_name,
            contact_number=contact_number,
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.exception("register failed")
        return jsonify(error="Could not create account"), 500

    send_sms_otp(phone, otp)
    log_event("register_success", seller_id=seller.id)
    return jsonify(
        message="Account created. Enter the OTP sent to your phone.",
        number=phone,
        otp_expires_in=int(OTP_EXPIRES.total_seconds()),
    ), 201


# ==========================================
# PHONE OTP VERIFICATION
# ==========================================

@auth_bp.route("/verify-phone", methods=["POST"])
@limiter.limit("10 per 10 minutes")
def verify_phone():
    data = request.get_json(silent=True) or {}
    phone = normalize_phone(data.get("number"))
    otp = str(data.get("otp") or "").strip()

    if not phone or not re.fullmatch(r"\d{6}", otp):
        return jsonify(error="Phone number and 6-digit OTP required"), 400

    seller = Seller.query.filter_by(number=phone).first()
    user = seller.user if seller else None

    if (not user or not user.otp or not user.otp_expires_at
            or _aware(user.otp_expires_at) < _now()
            or not otp_matches(user.otp, otp)):
        log_event("phone_verify_failed", level="warning", ip=request.remote_addr)
        return jsonify(error="Invalid or expired OTP"), 400

    seller.phone_verified = True
    user.otp = None
    user.otp_expires_at = None
    db.session.commit()

    log_event("phone_verified", seller_id=seller.id)
    return token_response(seller, {
        "message": "Phone verified",
        "next": "subscription_plans",
    })


@auth_bp.route("/resend-phone-otp", methods=["POST"])
@limiter.limit("5 per hour")
def resend_phone_otp():
    data = request.get_json(silent=True) or {}
    phone = normalize_phone(data.get("number"))
    generic = jsonify(message="If the number is registered, a new OTP has been sent")

    if not phone:
        return jsonify(error="Valid phone number required"), 400

    seller = Seller.query.filter_by(number=phone).first()
    if not seller or not seller.user or seller.phone_verified:
        return generic  # don't reveal account state

    user = seller.user
    if user.otp_expires_at:
        issued_at = _aware(user.otp_expires_at) - OTP_EXPIRES
        if _now() < issued_at + OTP_RESEND_COOLDOWN:
            return jsonify(error="Please wait before requesting another OTP"), 429

    otp = set_phone_otp(user)
    db.session.commit()
    send_sms_otp(phone, otp)
    return generic


# ==========================================
# LOGIN / REFRESH / LOGOUT
# ==========================================

@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10 per 15 minutes")
def login():
    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or "").strip()  # email or phone
    password = data.get("password") or ""

    email = normalize_email(identifier) if "@" in identifier else None
    phone = None if email else normalize_phone(identifier)

    seller = None
    if email:
        seller = Seller.query.filter_by(email=email).first()
    elif phone:
        seller = Seller.query.filter_by(number=phone).first()

    user = seller.user if seller else None
    if not user or not check_password_hash(user.password, password):
        log_event("login_failed", level="warning", ip=request.remote_addr)
        return jsonify(error="Invalid credentials"), 401

    if not seller.phone_verified:
        otp = set_phone_otp(user)
        db.session.commit()
        send_sms_otp(seller.number, otp)
        return jsonify(
            error="Phone not verified. A new OTP has been sent.",
            needs_phone_verification=True,
            number=seller.number,
        ), 403

    log_event("login_success", seller_id=seller.id)
    return token_response(seller, {"message": "Logged in"})


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True, locations=["cookies", "headers"])
def refresh():
    seller = db.session.get(Seller, int(get_jwt_identity()))
    if not seller:
        return jsonify(error="Account not found"), 401
    access = create_access_token(identity=str(seller.id), expires_delta=ACCESS_EXPIRES)
    return jsonify(access_token=access)


@auth_bp.route("/logout", methods=["POST"])
def logout():
    resp = make_response(jsonify(message="Logged out"))
    resp.delete_cookie("refresh_token", path="/auth")
    return resp


# ==========================================
# GOOGLE SIGN-IN
# Frontend uses Google Identity Services and sends the `credential` (ID token).
#   POST /auth/google          -> existing account: logs in
#                                 new account: 202 + signup_token (prefilled name/email)
#   POST /auth/google/complete -> new account: phone + store details, then phone OTP
# ==========================================

GOOGLE_SIGNUP_MAX_AGE = 15 * 60
_signup_serializer = URLSafeTimedSerializer(str(Config.SECRET_KEY), salt="google-signup")


def verify_google_token(credential):
    """Returns the verified Google claims dict, or None."""
    client_id = getattr(Config, "GOOGLE_CLIENT_ID", None)
    if not client_id or not credential:
        return None
    try:
        info = id_token.verify_oauth2_token(
            credential, google_requests.Request(), client_id
        )
    except Exception:
        return None
    if info.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
        return None
    if not info.get("email_verified"):
        return None
    return info


@auth_bp.route("/google", methods=["POST"])
@limiter.limit("20 per 15 minutes")
def google_login():
    data = request.get_json(silent=True) or {}
    info = verify_google_token(data.get("credential"))
    if not info:
        log_event("google_login_failed", level="warning", ip=request.remote_addr)
        return jsonify(error="Google sign-in failed"), 401

    email = normalize_email(info.get("email"))
    if not email:
        return jsonify(error="Google sign-in failed"), 401

    seller = Seller.query.filter_by(email=email).first()

    if seller:
        if not seller.phone_verified:
            user = seller.user
            otp = set_phone_otp(user)
            db.session.commit()
            send_sms_otp(seller.number, otp)
            return jsonify(
                error="Phone not verified. A new OTP has been sent.",
                needs_phone_verification=True,
                number=seller.number,
            ), 403
        log_event("google_login_success", seller_id=seller.id)
        return token_response(seller, {"message": "Logged in"})

    # No account yet: hand back a short-lived signed token so the next step
    # doesn't need to re-verify Google.
    signup_token = _signup_serializer.dumps(
        {"email": email, "name": info.get("name") or ""}
    )
    return jsonify(
        needs_registration=True,
        signup_token=signup_token,
        name=info.get("name") or "",
        email=email,
        message="Add your phone number and store details to finish signing up",
    ), 202


@auth_bp.route("/google/complete", methods=["POST"])
@limiter.limit("10 per hour")
def google_complete():
    data = request.get_json(silent=True) or {}

    try:
        claims = _signup_serializer.loads(
            data.get("signup_token") or "", max_age=GOOGLE_SIGNUP_MAX_AGE
        )
    except (BadSignature, SignatureExpired):
        return jsonify(error="Sign-up session expired. Please sign in with Google again."), 400

    email = claims["email"]
    name = (data.get("name") or claims.get("name") or "").strip()
    phone = normalize_phone(data.get("number"))
    store_name = (data.get("store_name") or "").strip()
    store_type_id = data.get("store_type_id")

    address = (data.get("store_address") or "").strip() or None
    owner_name = (data.get("owner_name") or "").strip() or None
    contact_number = normalize_phone(data.get("contact_number")) if data.get("contact_number") else None

    errors = {}
    if not name:
        errors["name"] = "Name is required"
    if not phone:
        errors["number"] = "Valid phone number is required"
    if not store_name:
        errors["store_name"] = "Store name is required"
    if not store_type_id or not db.session.get(StoreType, store_type_id):
        errors["store_type_id"] = "Select a valid store type"
    if data.get("contact_number") and not contact_number:
        errors["contact_number"] = "Invalid contact number"
    if errors:
        return jsonify(errors=errors), 400

    if Seller.query.filter((Seller.email == email) | (Seller.number == phone)).first():
        return jsonify(error="An account with this email or phone already exists"), 409

    try:
        seller = Seller(name=name, email=email, number=phone)
        db.session.add(seller)
        db.session.flush()

        # users.password is NOT NULL: store an unguessable random password.
        # The seller can set a real one later via forgot-password.
        user = User(
            seller_id=seller.id,
            password=generate_password_hash(secrets.token_urlsafe(32)),
        )
        otp = set_phone_otp(user)
        db.session.add(user)

        db.session.add(Store(
            seller_id=seller.id,
            name=store_name,
            type_id=store_type_id,
            address=address,
            owner_name=owner_name,
            contact_number=contact_number,
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.exception("google signup failed")
        return jsonify(error="Could not create account"), 500

    send_sms_otp(phone, otp)
    log_event("google_register_success", seller_id=seller.id)
    return jsonify(
        message="Account created. Enter the OTP sent to your phone.",
        number=phone,
        otp_expires_in=int(OTP_EXPIRES.total_seconds()),
    ), 201


# ==========================================
# FORGOT / RESET PASSWORD (email OTP via ResetOtp)
# ==========================================

@auth_bp.route("/forgot-password", methods=["POST"])
@limiter.limit("5 per hour")
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = normalize_email(data.get("email"))
    generic = jsonify(message="If the email is registered, an OTP has been sent")

    if not email:
        return jsonify(error="Valid email required"), 400

    seller = Seller.query.filter_by(email=email).first()
    if not seller:
        return generic

    ResetOtp.query.filter_by(seller_email=email, is_used=False).update({"is_used": True})
    otp = generate_otp()
    db.session.add(ResetOtp(
        seller_email=email,
        otp=hash_otp(otp),
        expires_at=_now() + OTP_EXPIRES,
    ))
    db.session.commit()
    send_email_otp(email, otp)
    return generic


@auth_bp.route("/reset-password", methods=["POST"])
@limiter.limit("10 per 10 minutes")
def reset_password():
    data = request.get_json(silent=True) or {}
    email = normalize_email(data.get("email"))
    otp = str(data.get("otp") or "").strip()
    new_password = data.get("new_password")

    pw_error = validate_password(new_password)
    if not email or not re.fullmatch(r"\d{6}", otp) or pw_error:
        return jsonify(error=pw_error or "Email and 6-digit OTP required"), 400

    record = (ResetOtp.query
              .filter_by(seller_email=email, is_used=False)
              .order_by(ResetOtp.created_at.desc())
              .first())

    if (not record or _aware(record.expires_at) < _now()
            or not otp_matches(record.otp, otp)):
        return jsonify(error="Invalid or expired OTP"), 400

    seller = Seller.query.filter_by(email=email).first()
    if not seller or not seller.user:
        return jsonify(error="Invalid or expired OTP"), 400

    seller.user.password = generate_password_hash(new_password)
    record.is_used = True
    db.session.commit()
    log_event("password_reset", seller_id=seller.id)
    return jsonify(message="Password updated. Please log in.")


# ==========================================
# STORE SETUP (called when they add products / orders and get a 428)
# ==========================================

@auth_bp.route("/store-setup", methods=["GET", "POST"])
@jwt_required()
def store_setup():
    seller_id = int(get_jwt_identity())
    store = Store.query.filter_by(seller_id=seller_id).first()
    if not store:
        return jsonify(error="Store not found"), 404

    if request.method == "GET":
        return jsonify(
            missing_fields=store_setup_missing(store),
            address=store.address,
            owner_name=store.owner_name,
            contact_number=store.contact_number,
        )

    data = request.get_json(silent=True) or {}
    address = (data.get("address") or "").strip()
    owner_name = (data.get("owner_name") or "").strip()
    contact = normalize_phone(data.get("contact_number"))

    errors = {}
    if not address:
        errors["address"] = "Address is required"
    if not owner_name:
        errors["owner_name"] = "Owner name is required"
    if not contact:
        errors["contact_number"] = "Valid contact number is required"
    if errors:
        return jsonify(errors=errors), 400

    store.address, store.owner_name, store.contact_number = address, owner_name, contact
    db.session.commit()
    return jsonify(message="Store setup complete")

