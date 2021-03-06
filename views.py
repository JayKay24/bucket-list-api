"""
This module contains all the views that used to build the bucketlist
api including endpoints.
"""
import status
from datetime import timedelta
from flasgger import swag_from
from flask import Blueprint, request, jsonify
from flask_restful import Api, Resource
from models import (db, User, UserSchema, Bucketlist,
                    BucketListSchema, Bucketlistitem, BucketListItemSchema)
from sqlalchemy.exc import SQLAlchemyError
from helpers import PaginationHelper
from flask_jwt_extended import (jwt_required, get_jwt_identity,
                                get_jwt_claims)
from models import User, UserSchema


def authenticate(username, password):
    if not (username and password):
        return False
    user = User.query.filter_by(username=username).first()
    if user is None:
        return False
    return True


api_bp = Blueprint('api', __name__)
user_schema = UserSchema()
bucketlist_schema = BucketListSchema()
bucketlist_item_schema = BucketListItemSchema()
api = Api(api_bp)


class UserResource(Resource):
    @swag_from('route_docs/userresource_specs.yml', methods=['GET'])
    def get(self, id):
        user = User.query.get_or_404(id)
        result = user_schema.dump(user).data
        return result


class UserListResource(Resource):
    @swag_from('route_docs/userlistresource_specs.yml', methods=['GET'])
    @jwt_required
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
        return result, status.HTTP_200_OK

    def post(self):
        """
        Verify and register a new user.
        """
        request_dict = request.get_json()
        if not request_dict:
            response = {'user': 'No input data provided'}
            return response, status.HTTP_400_BAD_REQUEST
        try:
            if request_dict['password'] and request_dict['confirm_password']:
                if request_dict['password'] != request_dict['confirm_password']:
                    response = {'error': 'Passwords do not match'}
                    return response, status.HTTP_400_BAD_REQUEST
        except KeyError:
            response = {
                'error': 'Please confirm your password before registering'}
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
                user.check_password_strength_and_hash_if_ok(
                    request_dict['password'])
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
    @swag_from('route_docs/bucketlistresource_specs.yml', methods=['GET'])
    def get(self, id):
        """
        Retrieve a bucketlist with the specified id.
        """
        claims = get_jwt_claims()
        user = User.query.filter_by(username=claims['username']).first()
        bucketlist = Bucketlist.query.filter(
            (Bucketlist.user_id == user.id) & (Bucketlist.id == id)).first()
        if bucketlist is None:
            response = {"error": "No bucketlist matches that id"}
            return response, status.HTTP_404_NOT_FOUND
        result = bucketlist_schema.dump(bucketlist).data
        return result, status.HTTP_200_OK

    @jwt_required
    def patch(self, id):
        """
        Modify a bucketlist with the specified id.
        """
        claims = get_jwt_claims()
        user = User.query.filter_by(username=claims['username']).first()
        bucketlist = Bucketlist.query.filter(
            (Bucketlist.id == id) & (Bucketlist.user_id == user.id)).first()
        if bucketlist is None:
            response = {"error": "No bucketlist by that name exists"}
            return response, status.HTTP_404_NOT_FOUND
        bucketlist_dict = request.get_json(force=True)
        if 'bkt_name' in bucketlist_dict:
            bucketlist_name = bucketlist_dict['bkt_name']
            if bucketlist_name != bucketlist.bkt_name:
                bucketlist.bkt_name = bucketlist_name
            else:
                response = {
                    'error': 'A bucketlist with the same name already exists'}
                return response, status.HTTP_409_CONFLICT
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
        """
        Delete a bucketlist with the specified id.
        """
        claims = get_jwt_claims()
        user = User.query.filter_by(username=claims['username']).first()
        bucketlist = Bucketlist.query.filter(
            (Bucketlist.id == id) & (Bucketlist.user_id == user.id)).first()
        if bucketlist is None:
            response = {"error": "No bucketlist matches that id"}
            return response, status.HTTP_404_NOT_FOUND
        try:
            bucketlist.delete(bucketlist)
            response = {
                "message": "The bucketlist has been successfully deleted"}
            return response, status.HTTP_200_OK
        except SQLAlchemyError as e:
            db.session.rollback()
            resp = jsonify({"error": str(e)})
            return resp, status.HTTP_401_UNAUTHORIZED


class BucketListListResource(Resource):
    @jwt_required
    def get(self):
        """
        Retrieve a paginated set of bucketlists.
        """
        claims = get_jwt_claims()
        user = User.query.filter_by(username=claims['username']).first()
        pagination_helper = PaginationHelper(
            request,
            query=Bucketlist.query.filter_by(user_id=user.id),
            resource_for_url='api.bucketlistlistresource',
            key_name='results',
            schema=bucketlist_schema
        )
        result = pagination_helper.paginate_query()
        return result

    @jwt_required
    def post(self):
        """
        Create a new bucketlist.
        """
        claims = get_jwt_claims()
        request_dict = request.get_json()
        if not request_dict:
            response = {'error': 'No input data provided'}
            return response, status.HTTP_400_BAD_REQUEST
        # errors = bucketlist_schema.validate(request_dict)
        # if errors:
        #     return errors, status.HTTP_400_BAD_REQUEST
        bucketlist_name = request_dict['bkt_name']
        # if not Bucketlist.is_unique(id=0, bkt_name=bucketlist_name):
        #     response = {
        #         'error': 'A bucketlist with the same name already exists'}
        #     return response, status.HTTP_400_BAD_REQUEST
        try:
            # claims = get_jwt_claims()
            # print(claims)
            user = User.query.filter_by(username=claims['username']).first()
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
    def get(self, bkt_id, id):
        """
        Retrieve a bucketlist item with the specified id.
        """
        claims = get_jwt_claims()
        user = User.query.filter_by(username=claims['username']).first()
        bucketlist = Bucketlist.query.filter(
            Bucketlist.user_id == user.id).first()
        if bucketlist is None:
            response = {"error": "No bucketlist by that name exists"}
            return response, status.HTTP_404_NOT_FOUND
        bucket_list_item = Bucketlistitem.query.filter(
            (Bucketlistitem.id == id) & (Bucketlistitem.bkt_id == bkt_id)).first()
        if bucket_list_item is None:
            response = {"error": "No bucketlist item by that name exists"}
            return response, status.HTTP_400_BAD_REQUEST
        result = bucketlist_item_schema.dump(bucket_list_item).data
        return result, status.HTTP_200_OK

    @jwt_required
    def patch(self, bkt_id, id):
        """
        Modify a bucketlist item with the specified id.
        """
        claims = get_jwt_claims()
        user = User.query.filter_by(username=claims['username']).first()
        bucketlist = Bucketlist.query.filter(
            Bucketlist.user_id == user.id).first()
        if bucketlist is None:
            response = {"error": "No bucketlist by that name exists"}
            return response, status.HTTP_404_NOT_FOUND
        bucketlist_item = Bucketlistitem.query.filter(
            (Bucketlistitem.id == id) & (Bucketlistitem.bkt_id == bkt_id)).first()
        if bucketlist_item is None:
            response = {"error": "No bucketlist item by that name exists"}
            return response, status.HTTP_404_NOT_FOUND
        bucketlist_item_dict = request.get_json(force=True)
        if 'bkt_item_name' in bucketlist_item_dict:
            if bucketlist_item_dict['bkt_item_name'] == bucketlist_item.bkt_item_name:
                response = {
                    "error": "A bucketlist item with the same name already exists"}
                return response, status.HTTP_409_CONFLICT
            bucketlist_item.bkt_item_name = bucketlist_item_dict['bkt_item_name']
        dumped_bucketlist_item, dump_errors = bucketlist_item_schema.dump(
            bucketlist_item)
        if dump_errors:
            return dump_errors, status.HTTP_400_BAD_REQUEST
        # validate_errors = bucketlist_schema.validate(dumped_bucketlist_item)
        # if validate_errors:
        #     return validate_errors, status.HTTP_400_BAD_REQUEST
        try:
            bucketlist_item.update()
            return self.get(bkt_id, id)
        except SQLAlchemyError as e:
            db.session.rollback()
            resp = jsonify({"error": str(e)})
            return resp, status.HTTP_400_BAD_REQUEST

    @jwt_required
    def delete(self, bkt_id, id):
        """
        Delete a bucketlist item with the specified id.
        """
        claims = get_jwt_claims()
        user = User.query.filter_by(username=claims['username']).first()
        bucketlist = Bucketlist.query.filter(
            Bucketlist.user_id == user.id).first()
        if bucketlist is None:
            response = {"error": "No bucketlist by that name exists"}
            return response, status.HTTP_404_NOT_FOUND
        bucketlist_item = Bucketlistitem.query.filter(
            (Bucketlistitem.id == id) & (Bucketlistitem.bkt_id == bkt_id)).first()
        if bucketlist_item is None:
            response = {"error": "No bucketlist item by that id exists"}
            return response, status.HTTP_404_NOT_FOUND
        # bucketlist_item = Bucketlistitem.query.get_or_404(id)
        try:
            bucketlist_item.delete(bucketlist_item)
            response = {
                "message": "The bucketlist item has been safely deleted"}
            return response, status.HTTP_200_OK
        except SQLAlchemyError as e:
            db.session.rollback()
            resp = jsonify({"error": str(e)})
            return resp, status.HTTP_400_BAD_REQUEST


class BucketListItemListResource(Resource):
    @jwt_required
    @swag_from('route_docs/bucketlistlistresource_specs.yml')
    def get(self, id):
        """
        Retrieve a paginated set of bucketlist items.
        """
        claims = get_jwt_claims()
        user = User.query.filter_by(username=claims['username']).first()
        bucketlist = Bucketlist.query.filter(
            Bucketlist.user_id == user.id).first()
        if bucketlist is None:
            response = {"error": "No bucketlist by that id exists"}
            return response, status.HTTP_404_NOT_FOUND
        pagination_helper = PaginationHelper(
            request,
            query=Bucketlistitem.query.filter_by(bkt_id=id),
            resource_for_url='api.bucketlistitemlistresource',
            key_name='result',
            schema=bucketlist_item_schema
        )
        result = pagination_helper.paginate_query()
        return result

    @jwt_required
    def post(self, id):
        """
        Create a new bucketlist item.
        """
        claims = get_jwt_claims()
        user = User.query.filter_by(username=claims['username']).first()
        request_dict = request.get_json()
        if not request_dict:
            response = {'error': 'No input data provided'}
            return response, status.HTTP_400_BAD_REQUEST
        bucketlist = Bucketlist.query.filter(
            (Bucketlist.user_id == user.id) & (Bucketlist.id == id)).first()
        if bucketlist is None:
            response = {"error": "No bucketlist by that name exists"}
            return response, status.HTTP_404_NOT_FOUND
        bucketlist_items = Bucketlistitem.query.filter(
            (Bucketlistitem.bkt_id == id) & (Bucketlistitem.bkt_id == bucketlist.id)).all()
        for bkt_item in bucketlist_items:
            if bkt_item.bkt_item_name == request_dict['bkt_item_name']:
                response = {
                    "error": "A bucketlist item with the same name already exists"}
                return response, status.HTTP_409_CONFLICT
        try:
            bucketlist_item = Bucketlistitem(
                bkt_item_name=request_dict['bkt_item_name'],
                bucketlist=bucketlist)
            bucketlist_item.add(bucketlist_item)
            query = Bucketlistitem.query.get(bucketlist_item.id)
            result = bucketlist_item_schema.dump(query).data
            return result, status.HTTP_201_CREATED
        except SQLAlchemyError as e:
            db.session.rollback()
            resp = jsonify({"error": str(e)})
            return resp, status.HTTP_400_BAD_REQUEST


api.add_resource(UserListResource, '/auth/register/')
api.add_resource(UserResource, '/auth/users/<int:id>')
api.add_resource(BucketListListResource, '/bucketlists/')
api.add_resource(BucketListResource, '/bucketlists/<int:id>')
api.add_resource(BucketListItemListResource,
                 '/bucketlists/<int:id>/bucketlistitems/')
api.add_resource(BucketListItemResource,
                 '/bucketlists/<int:bkt_id>/bucketlistitems/<int:id>')
