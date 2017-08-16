from flask_jwt import JWT
from app import create_app
from views import authenticate, identity

app = create_app('config')
jwt = JWT(app, authenticate, identity)

if __name__ == '__main__':
    app.run(host=app.config['HOST'],
            port=app.config['PORT'],
            debug=app.config['DEBUG'])
