import json
from datetime import timedelta
from flask import request, jsonify
from app import create_app
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity
from views import authenticate
from models import User
import views
import status

app = create_app('config')
# jwt = JWT(app, views.authenticate, views.identity)


@app.route('/api/v1/login/', methods=['POST'])
def login():
    request_dict = request.get_json()
    username = request_dict['username']
    password = request_dict['password']

    if authenticate(username, password):
        user = User.query.filter_by(username=username).first()
        if user is None:
            response = jsonify({"error": "No user by that name exists"})
            return response, status.HTTP_400_BAD_REQUEST
        if user.verify_password(password):
            expiration_time = timedelta(hours=2)
            token = create_access_token(identity=username,
                expires_delta=expiration_time)
            response = jsonify({"token": token})
            return response, status.HTTP_200_OK
        else:
            response = {'error': 'Incorrect password'}
            return response, status.HTTP_400_BAD_REQUEST

jwt = JWTManager(app)

if __name__ == '__main__':
    app.run(host=app.config['HOST'],
            port=app.config['PORT'],
            debug=app.config['DEBUG'])
