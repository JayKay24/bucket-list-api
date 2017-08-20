import json
from datetime import timedelta
from flask import Blueprint, request, jsonify, make_response
from flask_restful import Api, Resource
from models import db, User, UserSchema, Bucketlist, BucketListSchema, Bucketlistitem, BucketListItemSchema
from sqlalchemy.exc import SQLAlchemyError
import status
from helpers import PaginationHelper
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask import g
from models import User, UserSchema

def authenticate(username, password):
    if not (username and password):
        return False
    user = User.query.filter_by(username=username).first()
    if user is None:
        return False
    return True

def identity(payload):
    user_id = payload['identity']
    return {'user_id': user_id}

api_bp = Blueprint('api', __name__)
user_schema = UserSchema()
bucketlist_schema = BucketListSchema()
bucketlist_item_schema = BucketListItemSchema()
api = Api(api_bp)

class UserResource(Resource):
    def get(self, id):
        user = User.query.get_or_404(id)
        result = user_schema.dump(user).data
        return result

class UserListResource(Resource):
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
    @jwt_required
    def get(self, id):
        bucketlist = Bucketlist.query.get_or_404(id)
        result = bucketlist_schema.dump(bucketlist).data
        return result

    @jwt_required
    def patch(self, id):
        bucketlist = Bucketlist.query.get_or_404(id)
        bucketlist_dict = request.get_json(force=True)
        if 'bkt_name' in bucketlist_dict:
            bucketlist_bucketlist = bucketlist_dict['bkt_name']
            if Bucketlist.is_unique(id=id, bkt_name=bucketlist_bucketlist):
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

    @jwt_required
    def delete(self, id):
        bucketlist = Bucketlist.query.get_or_404(id)
        try:
            bucketlist.delete(bucketlist)
            response = {"error": "The bucketlist has been successfully deleted"}
            return response, status.HTTP_204_NO_CONTENT
        except SQLAlchemyError as e:
            db.session.rollback()
            resp = jsonify({"error": str(e)})
            return resp, status.HTTP_401_UNAUTHORIZED

class BucketListListResource(Resource):
    @jwt_required
    def get(self):
        pagination_helper = PaginationHelper(
            request,
            query=Bucketlist.query,
            resource_for_url='api.bucketlistlistresource',
            key_name='results',
            schema=bucketlist_schema
        )
        result = pagination_helper.paginate_query()
        return result

    @jwt_required
    def post(self):
        request_dict = request.get_json()
        if not request_dict:
            response = {'error': 'No input data provided'}
            return response, status.HTTP_400_BAD_REQUEST
        errors = bucketlist_schema.validate(request_dict)
        if errors:
            return errors, status.HTTP_400_BAD_REQUEST
        bucketlist_name = request_dict['bkt_name']
        if not Bucketlist.is_unique(id=0, bkt_name=bucketlist_name):
            response = {'error': 'A bucketlist with the same name already exists'}
            return response, status.HTTP_400_BAD_REQUEST
        try:
            try:
                username = request_dict['username']
            except KeyError as e:
                response = {"error": "Please provide a user for the bucketlist"}
                return response, status.HTTP_400_BAD_REQUEST
            if not username:
                response = {"error": "Please provide a user for the bucketlist"}
                return response, status.HTTP_400_BAD_REQUEST
            user = User.query.filter_by(username=username).first()
            if user is None:
                response = {"error": "No user with that name exists"}
                return response, status.HTTP_400_BAD_REQUEST
            
            bucketlist = Bucketlist(
                bkt_name=bucketlist_name,
                user=user)
            bucketlist.add(bucketlist)
            query = Bucketlist.query.get(bucketlist.id)
            result = bucketlist_schema.dump(query).data
            return result, status.HTTP_201_CREATED
        except SQLAlchemyError as e:
            db.session.rollback()
            resp = jsonify({"error": str(e)})
            return resp, status.HTTP_400_BAD_REQUEST

class BucketListItemResource(Resource):
    @jwt_required
    def get(self, id):
        bucket_list_item = Bucketlistitem.query.get_or_404(id)
        result = bucketlist_item_schema.dump(bucket_list_item).data
        return result

    @jwt_required
    def patch(self, id):
        print("start")
        bucketlist_item = Bucketlistitem.query.get_or_404(id)
        bucketlist_item_dict = request.get_json(force=True)
        # bucketlist_item_dict = request.get_json()
        print(bucketlist_item_dict)
        if 'bkt_item_name' in bucketlist_item_dict:
            bucketitem_bucketitem = bucketlist_item_dict['bkt_item_name']
            if Bucketlistitem.is_unique(id=id, bkt_item_name=bucketitem_bucketitem):
                bucketlist_item.bkt_item_name = bucketitem_bucketitem
            else:
                response = {"error": "A bucketlist item with the same name already exists"}
                return response, status.HTTP_400_BAD_REQUEST
        if 'bkt_name' in bucketlist_item_dict:
            bucketlist = Bucketlist.query.filter_by(bkt_name=bucketlist_item_dict['bkt_name']).first()
            if bucketlist is None:
                response = {'error': 'No bucketlist by that name exists'}
                return response, status.HTTP_400_BAD_REQUEST
            else:
                bucketlist_item.bucketlist = bucketlist
        print("middle")
        print(bucketlist_item.bkt_item_name)
        dumped_bucketlist_item, dump_errors = bucketlist_item_schema.dump(bucketlist_item)
        if dump_errors:
            return dump_errors, status.HTTP_400_BAD_REQUEST

        dumped_bucketlist_item['bkt_name'] = Bucketlistitem.query.get(id).bucketlist.bkt_name
        print('_'*100)
        print(dumped_bucketlist_item)
        print('_'*100)
        validate_errors = bucketlist_schema.validate(dumped_bucketlist_item)
        if validate_errors:
            return validate_errors, status.HTTP_400_BAD_REQUEST
        print("end")
        try:
            bucketlist_item.update()
            return self.get(id)
        except SQLAlchemyError as e:
            db.session.rollback()
            resp = jsonify({"error": str(e)})
            return resp, status.HTTP_400_BAD_REQUEST

    @jwt_required
    def delete(self, id):
        bucketlist_item = Bucketlistitem.query.get_or_404(id)
        try:
            bucketlist_item.delete(bucketlist_item)
            response = {"message": "The bucketlist item has been safely deleted"}
            return response, status.HTTP_204_NO_CONTENT
        except SQLAlchemyError as e:
            db.session.rollback()
            resp = jsonify({"error": str(e)})
            return resp, status.HTTP_400_BAD_REQUEST

class BucketListItemListResource(Resource):
    @jwt_required
    def get(self):
        pagination_helper = PaginationHelper(
            request,
            query=Bucketlistitem.query,
            resource_for_url='api.bucketlistitemlistresource',
            key_name='result',
            schema=bucketlist_item_schema
        )
        result = pagination_helper.paginate_query()
        return result

    @jwt_required
    def post(self):
        request_dict = request.get_json()
        if not request_dict:
            response = {'error': 'No input data provided'}
            return response, status.HTTP_400_BAD_REQUEST
        errors = bucketlist_item_schema.validate(request_dict)
        if errors:
            return errors, status.HTTP_400_BAD_REQUEST
        bucketlist_item_name = request_dict['bkt_item_name']
        if not Bucketlistitem.is_unique(id=0, bkt_item_name=bucketlist_item_name):
            response = {'error': 'A bucketlist item with the same name already exists'}
            return response, status.HTTP_400_BAD_REQUEST
        try:
            bkt_name = request_dict['bkt_name']
            bucketlist = Bucketlist.query.filter_by(bkt_name=bkt_name).first()
            if bucketlist is None:
                response = {"error": "No bucketlist with that name exists"}
                return response, status.HTTP_400_BAD_REQUEST

            bucketlist_item = Bucketlistitem(
                bkt_item_name=bucketlist_item_name,
                bucketlist=bucketlist)
            bucketlist_item.add(bucketlist_item)
            query = Bucketlistitem.query.get(bucketlist_item.id)
            result = bucketlist_item_schema.dump(bucketlist_item).data
            return result, status.HTTP_200_OK
        except SQLAlchemyError as e:
            db.session.rollback()
            resp = jsonify({"error": str(e)})
            return resp, status.HTTP_400_BAD_REQUEST

api.add_resource(UserListResource, '/auth/register/')
api.add_resource(UserResource, '/auth/users/<int:id>')
api.add_resource(BucketListListResource, '/bucketlists/')
api.add_resource(BucketListResource, '/bucketlists/<int:id>')
api.add_resource(BucketListItemListResource, '/bucketlistitems/')
api.add_resource(BucketListItemResource, '/bucketlistitems/<int:id>')
