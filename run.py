import json
from datetime import timedelta
from flask import request, jsonify
from app import create_app
from flask_jwt_extended import JWTManager, create_access_token
from views import authenticate
from models import User
import views
import status

app = create_app('config')
jwt = JWTManager(app)

# The logged in user credentials are needed to
# access the current user's information.


@jwt.user_claims_loader
def add_claims_to_access_token(username):
    data = {'username': username}
    return data


if __name__ == '__main__':
    app.run(host=app.config['HOST'],
            port=app.config['PORT'],
            debug=app.config['DEBUG'])
