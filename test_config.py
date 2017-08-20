import os

basedir = os.path.abspath(os.path.dirname(__file__))
DEBUG = True
PORT = 5000
HOST = "127.0.0.1"
SECRET_KEY = os.urandom(15)
SQLALCHEMY_ECHO = False
SQLALCHEMY_TRACK_MODIFICATIONS = True
SQLALCHEMY_DATABASE_URI = "postgresql://{DB_USER}:{DB_PASS}@{DB_ADDR}/{DB_NAME}".format(
    DB_USER="postgres", DB_PASS="postgresgodking832", DB_ADDR="127.0.0.1", DB_NAME="test_bucket")
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')
PAGINATION_PAGE_SIZE = 5
PAGINATION_PAGE_ARGUMENT_NAME = 'page'
# Disable CSRF protection in the testing configuration
WTF_CSRF_ENABLED = False
SERVER_NAME = "127.0.0.1:5000"
JWT_TOKEN_LOCATION = ['headers', 'cookies']
