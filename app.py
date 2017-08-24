import status
from datetime import timedelta
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token
from models import db, User
from views import api_bp, authenticate


def create_app(config_filename):
    """
    Create a flask application instance using configurations obtained
    from a file.
    """
    app = Flask(__name__)
    app.config.from_object(config_filename)
    jwt = JWTManager(app)

    db.init_app(app)
    app.register_blueprint(api_bp, url_prefix='/api/v1')

    @jwt.user_claims_loader
    def add_claims_to_access_token(username):
        data = {'username': username}
        return data

    @app.route('/api/v1/auth/login/', methods=['POST'])
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
                # The token should be valid for at least 2 hours to
                # avoid numerous logins.
                expiration_time = timedelta(hours=2)
                token = create_access_token(identity=user.username,
                                            expires_delta=expiration_time)
                # The subsequent requests after successfully generating
                # an authentication token should be for only the logged
                # in user.
                response = jsonify({"access_token": token})
                return response, status.HTTP_200_OK
            else:
                response = jsonify({'error': 'Incorrect password'})
                return response, status.HTTP_400_BAD_REQUEST

    return app
