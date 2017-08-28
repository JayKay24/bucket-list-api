import unittest
import status
from datetime import timedelta
from flask_jwt_extended import (create_access_token, JWTManager,
                                jwt_required, get_jwt_claims)
# from flask_jwt_extended import (jwt_required, get_jwt_identity,
#                                 get_jwt_claims)
from app import create_app
from flask import current_app, json, url_for
from models import db, User
from views import authenticate

APP = create_app('test_config')
JWT = JWTManager(APP)


@JWT.user_claims_loader
def add_claims_to_access_token(username):
    data = {'username': username}
    return data


class ViewsTests(unittest.TestCase):
    def setUp(self):
        self.app = APP
        self.test_client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.test_user_name = 'Kryptonian'
        self.test_user_password = 'Kryptonian832!'
        db.create_all()
        self.create_user(self.test_user_name, self.test_user_password)
        self.login_response = self.login_user(
            self.test_user_name, self.test_user_password)
        self.token = json.loads(self.login_response.data)['access_token']
        self.authorization = {'Accept': 'application/json',
                              'Content-Type': 'application/json', 'Authorization': 'Bearer ' + str(self.token)}

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def get_accept_content_type_headers(self):
        return {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    # def get_authentication_headers(self):
    #     authentication_headers = self.get_accept_content_type_headers()
    #     response_data = json.loads(response.get_data(as_text=True))
    #     authentication_headers['Authorization'] = 'Bearer ' + str(self.token)
    #     # response_data['access_token']
    #     return authentication_headers
    #     # authenticated = authenticate(username, password)
    #     # if authenticated:
    #     #     expiration_time = timedelta(hours=2)
    #     #     token = create_access_token(
    #     #         identity=username, expires_delta=expiration_time)
    #     #     authentication_headers['Authorization'] = 'Bearer ' + str(token)

    def create_user(self, username, password):
        url = url_for('api.userlistresource', _external=True)
        data = {'username': username, 'password': password,
                'confirm_password': password}
        response = self.test_client.post(
            url,
            headers=self.get_accept_content_type_headers(),
            data=json.dumps(data))
        return response

    def create_bucketlist(self, bkt_name):
        url = url_for('api.bucketlistlistresource', _external=True)
        data = {'bkt_name': bkt_name}
        response = self.test_client.post(
            url,
            headers=self.authorization,
            data=json.dumps(data))
        return response

    def create_bucketlist_item(self, bkt_id, bkt_item_name):
        url = url_for('api.bucketlistitemlistresource',
                      id=bkt_id, _external=True)
        data = {'bkt_item_name': bkt_item_name}
        response = self.test_client.post(
            url,
            headers=self.authorization,
            data=json.dumps(data))
        return response

    def delete_bucketlist(self, bkt_id):
        url = url_for('api.bucketlistresource',
                      id=bkt_id, _external=True)
        response = self.test_client.delete(
            url,
            headers=self.authorization)
        return response

    def delete_bucketlist_item(self, bkt_id, bkt_item_id):
        url = url_for('api.bucketlistitemresource',
                      id=bkt_item_id, bkt_id=bkt_id, _external=True)
        response = self.test_client.delete(
            url,
            headers=self.authorization)
        return response

    def login_user(self, username, password):
        url = '/api/v1/auth/login/'
        data = {'username': username, 'password': password}
        response = self.test_client.post(
            url,
            headers=self.get_accept_content_type_headers(),
            data=json.dumps(data))
        return response

    def test_user_registration(self):
        """
        Ensure we can register a user with the application.
        """
        response = self.create_user("James", "James832!")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_get_users_without_authentication(self):
        """
        Ensure a user cannot access a resource that requires authentication
        without an authorization header.
        """
        response = self.test_client.get(
            url_for('api.userlistresource', _external=True),
            headers=self.get_accept_content_type_headers())
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_users_with_authentication(self):
        """
        Ensure an authenticated user can get a list of users.
        """
        response = self.test_client.get(
            url_for('api.userlistresource', _external=True),
            headers=self.authorization)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_create_bucketlist(self):
        """
        An authenticated user should be able to create a bucketlist.
        """
        response = self.create_bucketlist("Extreme heights")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_bucketlist_item(self):
        """
        An authenticated user should be able to create a bucketlist item.
        """
        response = self.create_bucketlist("Extreme heights")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        response = self.create_bucketlist_item(1, "Mount Everest")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_update_a_bucketlist(self):
        """
        An authenticated user should be able to update a bucketlist.
        """
        new_bucketlist_name_1 = "Extreme heights"
        post_response_1 = self.create_bucketlist(new_bucketlist_name_1)
        self.assertEqual(post_response_1.status_code, status.HTTP_201_CREATED)
        post_response_data_1 = json.loads(
            post_response_1.get_data(as_text=True))
        new_bucketlist_url = post_response_data_1['url']
        new_bucketlist_name_2 = "Low level"
        data = {"bkt_name": new_bucketlist_name_2}
        patch_response = self.test_client.patch(
            new_bucketlist_url,
            headers=self.authorization,
            data=json.dumps(data))
        self.assertEqual(patch_response.status_code, status.HTTP_200_OK)

    def test_update_a_bucketlist_item(self):
        """
        An authenticated user should be able to create a bucketlist item.
        """
        bucketlist_name = "Extreme heights"
        response = self.create_bucketlist(bucketlist_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_bucket_item_name_1 = "Low Level"
        post_response_1 = self.create_bucketlist_item(
            1, new_bucket_item_name_1)
        self.assertEqual(post_response_1.status_code, status.HTTP_201_CREATED)
        post_response_data_1 = json.loads(
            post_response_1.get_data(as_text=True))
        new_bucketl_item_url = post_response_data_1['url']
        new_bucket_item_name_2 = "Lower level heights"
        data = {"bkt_item_name": new_bucket_item_name_2}
        patch_response = self.test_client.patch(
            new_bucketl_item_url,
            headers=self.authorization,
            data=json.dumps(data))
        self.assertEqual(patch_response.status_code, status.HTTP_200_OK)

    def test_delete_a_bucketlist(self):
        """
        An authenticated user should be able to delete a bucketlist.
        """
        bucketlist_name = "Extreme heights"
        response = self.create_bucketlist(bucketlist_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        response = self.delete_bucketlist(1)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
