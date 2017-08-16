import unittest
import status
from app import create_app
from flask import current_app, json, url_for
from models import db, User

class InitialTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('test_config')
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
            'Content-Type': 'application/json'
        }

    def test_get_users_without_authentication(self):
        """
        Ensure a user cannot access a resource that requires authentication
        without an authorization header.
        """
        response = self.test_client.get(
            url_for('api.userlistresource', _external=True),
            headers=self.get_accept_content_type_headers(),
        )
        self.assertTrue(response.status_code, status.HTTP_401_UNAUTHORIZED)



