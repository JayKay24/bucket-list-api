from flask_jwt import JWT
from app import create_app
import views

app = create_app('config')
jwt = JWT(app, views.authenticate, views.identity)

if __name__ == '__main__':
    app.run(host=app.config['HOST'],
            port=app.config['PORT'],
            debug=app.config['DEBUG'])
