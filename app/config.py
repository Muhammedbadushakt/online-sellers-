from dotenv import load_dotenv

load_dotenv()
import os
class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TURNSTILE_SECRET_KEY =os.getenv("TURNSTILE_SECRET_KEY")