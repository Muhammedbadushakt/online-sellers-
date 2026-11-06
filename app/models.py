from .extensions import db
from datetime import datetime, timezone


# ==========================================
# 1. SELLER TABLE
# ==========================================

class Seller(db.Model):
    __tablename__ = "sellers"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    number = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    # Relationships
    user = db.relationship(
        "User",
        back_populates="seller",
        uselist=False,
        cascade="all, delete-orphan"
    )

    stores = db.relationship(
        "Store",
        back_populates="seller",
        cascade="all, delete-orphan"
    )

    subscriptions = db.relationship(
        "Subscription",
        back_populates="seller"
    )


# ==========================================
# 2. USER TABLE (AUTHENTICATION)
# ==========================================

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    seller_id = db.Column(
        db.Integer,
        db.ForeignKey("sellers.id"),
        unique=True,
        nullable=False
    )

    password = db.Column(db.String(255), nullable=False)

    otp = db.Column(db.String(10), nullable=True)

    otp_expires_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True
    )

    # Relationship
    seller = db.relationship("Seller", back_populates="user")


# ==========================================
# 3. STORE TYPE TABLE
# ==========================================

class StoreType(db.Model):
    __tablename__ = "store_types"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100), unique=True, nullable=False)

    description = db.Column(db.Text, nullable=True)

    # Relationship
    stores = db.relationship(
        "Store",
        back_populates="store_type"
    )


# ==========================================
# 4. STORE TABLE
# ==========================================

class Store(db.Model):
    __tablename__ = "stores"

    id = db.Column(db.Integer, primary_key=True)

    seller_id = db.Column(
        db.Integer,
        db.ForeignKey("sellers.id"),
        nullable=False
    )

    name = db.Column(db.String(150), nullable=False)

    type_id = db.Column(
        db.Integer,
        db.ForeignKey("store_types.id"),
        nullable=False
    )

    address = db.Column(db.Text, nullable=True)

    # Relationships
    seller = db.relationship("Seller", back_populates="stores")

    store_type = db.relationship(
        "StoreType",
        back_populates="stores"
    )


# ==========================================
# 5. RESET OTP TABLE
# ==========================================

class ResetOtp(db.Model):
    __tablename__ = "reset_otps"

    id = db.Column(db.Integer, primary_key=True)

    seller_email = db.Column(
        db.String(120),
        db.ForeignKey("sellers.email"),
        nullable=False
    )

    otp = db.Column(db.String(10), nullable=False)

    is_used = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    expires_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False
    )


# ==========================================
# 6. SUBSCRIPTION PLAN TABLE
# ==========================================

class SubscriptionPlan(db.Model):
    __tablename__ = "subscription_plan"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(
        db.String(200),
        nullable=False
    )

    price = db.Column(
        db.Numeric(10, 2),
        nullable=False,
        default=0
    )

    # Duration in days (example: 30, 90, 365)
    duration_days = db.Column(
        db.Integer,
        nullable=False
    )

    trial_available = db.Column(
        db.Boolean,
        default=True,
        nullable=False
    )

    is_active = db.Column(
        db.Boolean,
        default=True,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    subscriptions = db.relationship(
        "Subscription",
        back_populates="plan"
    )

    plan_features = db.relationship(
        "PlanFeature",
        back_populates="plan",
        cascade="all, delete-orphan"
    )


# ==========================================
# 7. SUBSCRIPTION TABLE
# ==========================================

class Subscription(db.Model):
    __tablename__ = "subscription"

    id = db.Column(db.Integer, primary_key=True)

    seller_id = db.Column(
        db.Integer,
        db.ForeignKey("sellers.id"),
        nullable=False
    )

    plan_id = db.Column(
        db.Integer,
        db.ForeignKey("subscription_plan.id"),
        nullable=False
    )

    status = db.Column(
        db.String(30),
        default="active",
        nullable=False
    )

    start_date = db.Column(
        db.DateTime(timezone=True),
        nullable=False
    )

    end_date = db.Column(
        db.DateTime(timezone=True),
        nullable=True
    )

    is_trial = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    seller = db.relationship(
        "Seller",
        back_populates="subscriptions"
    )

    plan = db.relationship(
        "SubscriptionPlan",
        back_populates="subscriptions"
    )

    payments = db.relationship(
        "Payment",
        back_populates="subscription"
    )


# ==========================================
# 8. FEATURE TABLE
# ==========================================

#class Feature(db.Model):
    __tablename__ = "feature"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    description = db.Column(db.Text, nullable=True)

    # Relationship
    plan_features = db.relationship(
        "PlanFeature",
        back_populates="feature",
        cascade="all, delete-orphan"
    )


# ==========================================
# 9. PLAN FEATURE TABLE
# ==========================================

#class PlanFeature(db.Model):
    __tablename__ = "plan_feature"

    id = db.Column(db.Integer, primary_key=True)

    plan_id = db.Column(
        db.Integer,
        db.ForeignKey("subscription_plan.id"),
        nullable=False
    )

    feature_id = db.Column(
        db.Integer,
        db.ForeignKey("feature.id"),
        nullable=False
    )

    # Relationships
    plan = db.relationship(
        "SubscriptionPlan",
        back_populates="plan_features"
    )

    feature = db.relationship(
        "Feature",
        back_populates="plan_features"
    )

    # Prevent duplicate features in the same plan
    __table_args__ = (
        db.UniqueConstraint(
            "plan_id",
            "feature_id",
            name="unique_plan_feature"
        ),
    )


# ==========================================
# 10. PAYMENT TABLE
# ==========================================

class Payment(db.Model):
    __tablename__ = "payment"

    id = db.Column(db.Integer, primary_key=True)

    subscription_id = db.Column(
        db.Integer,
        db.ForeignKey("subscription.id"),
        nullable=False
    )

    amount = db.Column(
        db.Numeric(10, 2),
        nullable=False
    )

    payment_method = db.Column(
        db.String(50),
        nullable=False
    )

    transaction_id = db.Column(
        db.String(150),
        unique=True,
        nullable=True
    )

    payment_status = db.Column(
        db.String(30),
        default="pending",
        nullable=False
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationship
    subscription = db.relationship(
        "Subscription",
        back_populates="payments"
    )
