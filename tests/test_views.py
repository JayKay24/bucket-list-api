import unittest
import status
from datetime import timedelta
from flask_jwt_extended import create_access_token, JWTManager
from app import create_app
from flask import current_app, json, url_for
from models import db, User
from views import authenticate

class ViewsTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('test_config')
        self.jwt = JWTManager(self.app)
        self.test_client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.test_user_name = 'Kryptonian'
        self.test_user_password = 'Kryptonian832!'
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def get_accept_content_type_headers(self):
        return {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': ''
        }

    def get_authentication_headers(self, username, password):
        authentication_headers = self.get_accept_content_type_headers()
        authenticated = authenticate(username, password)
        if authenticated:
            expiration_time = timedelta(hours=2)
            token = create_access_token(identity=username, 
                expiration_time=expiration_time)
            authentication_headers['Authorization'] ='Bearer ' + token
        return authentication_headers

    def create_user(self, username, password):
        url = url_for('api.userlistresource', _external=True)
        data = {'username': username, 'password': password, 
            'confirm_password': password}
        response = self.test_client.post(
            url,
            headers=self.get_accept_content_type_headers(),
            data=json.dumps(data))
        return response

    def create_bucketlist(self, bkt_name, username):
        url = url_for('api.bucketlistlistresource', _external=True)
        data = {'username': username, 'bkt_name': bkt_name}
        response = self.test_client.post(
            url,
            headers=self.get_authentication_headers(self.test_user_name,
                self.test_user_password),
            data=json.dumps(data))
        return response

    def test_user_registration(self):
        """
        Ensure we can register a user with the application.
        """
        response = self.create_user(self.test_user_name, self.test_user_password)
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

    def test_create_bucketlist(self):
        response = self.create_user(self.test_user_name, self.test_user_password)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        response = self.create_bucketlist("Extreme heights", self.test_user_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)





