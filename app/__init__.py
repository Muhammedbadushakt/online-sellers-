"""Seller platform application package."""
from flask import Flask
from flask_migrate import Migrate
from .extensions import db,jwt,bcrypt,mail,limiter
from .config import Config 
from .models import * 
migrate = Migrate()
def create_app():
    app = Flask(__name__)
    db.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)

    return app