from flask import Blueprint, request, jsonify, make_response
from flask_restful import Api, Resource
from models import db, User, UserSchema, BucketList, BucketListSchema
from sqlalchemy.exc import SQLAlchemyError
import status
from helpers import PaginationHelper
from flask_jwt import JWT, jwt_required, current_identity
from werkzeug.security import safe_str_cmp
from flask import g
from models import User, UserSchema

def authenticate(username, password):
    if not (username and password):
        return False
    user = User.query.filter_by(username=username).first()
    if user is None:
        return False
    if user.verify_password(password):
        return user

def identity(payload):
    user_id = payload['identity']
    return {'user_id': user_id}

api_bp = Blueprint('api', __name__)
user_schema = UserSchema()
bucketlist_schema = BucketListSchema()
api = Api(api_bp)

class UserResource(Resource):
    def get(self, id):
        user = User.query.get_or_404(id)
        result = user_schema.dump(user).data
        return result

class UserListResource(Resource):
    @jwt_required()
    def get(self):
        """
        Retrieves a paginated result set of users.
        """
        pagination_helper = PaginationHelper(
            request,
            query=User.query,
            resource_for_url='api.userlistresource',
            key_name='results',
            schema=user_schema
        )
        result = pagination_helper.paginate_query()
        return result

    def post(self):
        """
        Verify and register a new user.
        """
        request_dict = request.get_json()
        if not request_dict:
            response = {'user': 'No input data provided'}
            return response, status.HTTP_400_BAD_REQUEST
        try:
            confirm_password = request_dict['confirm_password']
            if confirm_password != request_dict['password']:
                response = {'error': 'Passwords do not match'}
                return response, status.HTTP_400_BAD_REQUEST
        except KeyError as e:
            response = {'error': 'Please confirm your password before registering'}
            return response, status.HTTP_400_BAD_REQUEST
        errors = user_schema.validate(request_dict)
        if errors:
            return errors, status.HTTP_400_BAD_REQUEST
        username = request_dict['username']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user is not None:
            response = {'error': 'A user with the same name already exists'}
            return response, status.HTTP_400_BAD_REQUEST
        try:
            user = User(username=username)
            error_message, password_ok = \
            user.check_password_strength_and_hash_if_ok(request_dict['password'])
            if password_ok:
                user.add(user)
                query = User.query.get(user.id)
                result = user_schema.dump(query).data
                return result, status.HTTP_201_CREATED
            else:
                return {'error': error_message}, status.HTTP_400_BAD_REQUEST
        except SQLAlchemyError as e:
            db.session.rollback()
            resp = {'error': str(e)}
            return resp, status.HTTP_400_BAD_REQUEST

class BucketListResource(Resource):
    def get(self, id):
        bucketlist = BucketList.query.get_or_404(id)
        result = bucketlist_schema.dump(bucketlist).data
        return result

    def patch(self, id):
        bucketlist = BucketList.query.get_or_404(id)
        bucketlist_dict = request.get_json(force=True)
        if 'bkt_name' in bucketlist_dict:
            bucketlist_bucketlist = bucketlist_dict['bkt_name']
            if BucketList.is_unique(id=id, bkt_name=bucketlist_bucketlist):
                bucketlist.bkt_name = bucketlist_bucketlist
            else:
                response = {'error': 'A bucketlist with the same name already exists'}
                return response, status.HTTP_400_BAD_REQUEST
        dumped_bucketlist, dump_errors = bucketlist_schema.dump(bucketlist)
        if dump_errors:
            return dump_errors, status.HTTP_400_BAD_REQUEST
        validate_errors = bucketlist_schema.validate(dumped_bucketlist)
        if validate_errors:
            return validate_errors, status.HTTP_400_BAD_REQUEST

        try:
            bucketlist.update()
            return self.get(id)
        except SQLAlchemyError as e:
            db.session.rollback()
            resp = jsonify({"error": str(e)})
            return resp, status.HTTP_400_BAD_REQUEST

    def delete(self, id):
        bucketlist = BucketList.query.get_or_404(id)
        try:
            delete = bucketlist.delete(bucketlist)
            response = make_response()
            return response, status.HTTP_204_NO_CONTENT
        except SQLAlchemyError as e:
            db.session.rollback()
            resp = jsonify({"error": str(e)})
            return resp, status.HTTP_401_UNAUTHORIZED

class BucketListListResource(Resource):
    def get(self):
        pagination_helper = PaginationHelper(
            request,
            query=BucketList.query,
            resource_for_url='api.bucketlistlistresource',
            key_name='results',
            schema=bucketlist_schema
        )
        result = pagination_helper.paginate_query()
        return result

    def post(self):
        request_dict = request.get_json()
        if not request_dict:
            response = {'error': 'No input data provided'}
            return response, status.HTTP_400_BAD_REQUEST
        errors = bucketlist_schema.validate(request_dict)
        if errors:
            return errors, status.HTTP_400_BAD_REQUEST
        bucketlist_name = request_dict['bkt_name']
        if not BucketList.is_unique(id=0, bkt_name=bucketlist_name):
            response = {'error': 'A bucketlist with the same name already exists'}
            return response, status.HTTP_400_BAD_REQUEST
        try:
            username = request_dict['username']
            user = User.query.filter_by(username=username)
            
            bucketlist = BucketList(
                bkt_name=bucketlist_name,
                user=user)
            bucketlist.add(bucketlist)
            query = BucketList.query.get(bucketlist.id)
            result = bucketlist_schema.dump(query).data
            return result, status.HTTP_201_CREATED
        except SQLAlchemyError as e:
            db.session.rollback()
            resp = jsonify({"error": str(e)})
            return resp, status.HTTP_400_BAD_REQUEST

api.add_resource(UserListResource, '/register/')
api.add_resource(UserResource, '/users/<int:id>')
api.add_resource(BucketListListResource, '/bucketlists/')
api.add_resource(BucketListResource, '/bucketlists/<int:id>')
