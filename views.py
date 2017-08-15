from flask import Blueprint, request, jsonify, make_response
from flask_restful import Api, Resource
from models import db, User, UserSchema
from sqlalchemy.exc import SQLAlchemyError
import status
from helpers import PaginationHelper
from flask_httpauth import HTTPTokenAuth
from flask import g
from models import User, UserSchema

auth = HTTPTokenAuth(scheme='Token')

@auth.verify_password
def verify_user_password(name, password):
    user = User.query.filter_by(name=name).first()
    if not user or not user.verify_password(password):
        return False
    g.user = user
    return True

class AuthenticationResource(Resource):
    """
    Restrict resources to authenticated users.
    """
    method_decorators = [auth.login_required]

api_bp = Blueprint('api', __name__)
user_schema = UserSchema()
api = Api(api_bp)

class UserResource(Resource):
