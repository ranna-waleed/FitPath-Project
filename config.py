import os
import urllib
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

class Config:
    """Base config class, can be inherited by other environments."""
    SECRET_KEY = "temporary_secret_key"

    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Avoid overhead for tracking modifications
    SQLALCHEMY_ECHO = False  # Optional: Enables SQL query logging if True

class DevelopmentConfig(Config):
    """Development environment configuration"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "mssql+pyodbc:///?odbc_connect=" + urllib.parse.quote_plus(
        f"DRIVER={{ODBC Driver 17 for SQL Server}};"
        f"SERVER={os.environ.get('DEV_DB_SERVER', 'localhost')};"
        f"DATABASE={os.environ.get('DEV_DB_NAME', 'FitPath_DB')};"
        f"Trusted_Connection=yes;"
    )

class ProductionConfig(Config):
    """Production environment configuration"""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "mssql+pyodbc:///?odbc_connect=" + urllib.parse.quote_plus(
        f"DRIVER={{ODBC Driver 17 for SQL Server}};"
        f"SERVER={os.environ.get('PROD_DB_SERVER', 'prod-server')};"
        f"DATABASE={os.environ.get('PROD_DB_NAME', 'PROD_DB')};"
        f"Trusted_Connection=yes;"
    )

class TestingConfig(Config):
    """Testing environment configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"  # Use SQLite in-memory database for testing
