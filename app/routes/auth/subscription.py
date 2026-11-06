from flask import Blueprint, request, jsonify, make_response
from flask_jwt_extended import (
    jwt_required, get_jwt_identity,
)
from models import  SubscriptionPlan, Subscription , Seller
from extensions import db ,limiter
from email_validator import validate_email, EmailNotValidError
from decimal import Decimal
from datetime import datetime, timedelta, timezone
import re 
subscription_bp = Blueprint("subscription", __name__, url_prefix="/subscription")

TRIAL_AMOUNT = Decimal("2.00")


def _now():
    return datetime.now(timezone.utc)

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
@subscription_bp.route("/plans", methods=["GET"])
def list_plans():
    plans = SubscriptionPlan.query.filter_by(is_active=True).order_by(SubscriptionPlan.price).all()
    return jsonify(plans=[{
        "id": p.id,
        "name": p.name,
        "price": str(p.price),
        "duration_days": p.duration_days,
        "trial_available": p.trial_available,
        "trial_amount": str(TRIAL_AMOUNT) if p.trial_available else None,
    } for p in plans])
@subscription_bp.route("/payment-setup", methods=["POST"])
@jwt_required()
@limiter.limit("10 per hour")
def payment_setup():
    """Step 1 of checkout: collect contact details and create a pending subscription.
    Payment gateway call comes in the next step."""
    seller = db.session.get(Seller, int(get_jwt_identity()))
    if not seller:
        return jsonify(error="Account not found"), 404
    if not seller.phone_verified:
        return jsonify(error="Verify your phone number first"), 403
 
    data = request.get_json(silent=True) or {}
    plan = db.session.get(SubscriptionPlan, data.get("plan_id"))
    email = normalize_email(data.get("email"))
    phone = normalize_phone(data.get("phone"))
 
    errors = {}
    if not plan or not plan.is_active:
        errors["plan_id"] = "Select a valid plan"
    if not email:
        errors["email"] = "Valid email is required"
    if not phone:
        errors["phone"] = "Valid phone number is required"
    if errors:
        return jsonify(errors=errors), 400
 
    now = _now()
    active = Subscription.query.filter(
        Subscription.seller_id == seller.id,
        Subscription.status == "active",
        Subscription.end_date > now,
    ).first()
    if active:
        return jsonify(error="You already have an active subscription"), 409
 
    had_trial = Subscription.query.filter_by(seller_id=seller.id, is_trial=True).first() is not None
    use_trial = bool(plan.trial_available and not had_trial)
 
    # Reuse an existing pending record instead of piling up duplicates
    sub = Subscription.query.filter_by(
        seller_id=seller.id, status="pending_payment"
    ).first()
    if not sub:
        sub = Subscription(seller_id=seller.id, plan_id=plan.id, start_date=now)
        db.session.add(sub)
 
    sub.plan_id = plan.id
    sub.status = "pending_payment"
    sub.is_trial = use_trial
    sub.billing_email = email
    sub.billing_phone = phone
    db.session.commit()
 
    return jsonify(
        message="Payment setup saved",
        subscription_id=sub.id,
        plan=plan.name,
        is_trial=use_trial,
        amount_due=str(TRIAL_AMOUNT if use_trial else plan.price),
        next="payment",
    ), 201
 
