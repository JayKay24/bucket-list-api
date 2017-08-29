import re
from marshmallow import Schema, fields, pre_load
from marshmallow import validate
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from passlib.apps import custom_app_context as password_context

db = SQLAlchemy()
ma = Marshmallow()


class AddUpdateDelete:
    """
    Helper class to manage add, update, delete functions
    of the database.
    """

    def add(self, resource):
        db.session.add(resource)
        return db.session.commit()

    def update(self):
        return db.session.commit()

    def delete(self, resource):
        db.session.delete(resource)
        return db.session.commit()


class User(db.Model, AddUpdateDelete):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    hashed_password = db.Column(db.String(120), nullable=False)
    creation_date = db.Column(db.TIMESTAMP,
                              server_default=db.func.current_timestamp(), nullable=False)

    def verify_password(self, password):
        return password_context.verify(password, self.hashed_password)

    def check_password_strength_and_hash_if_ok(self, password):
        if len(password) < 8:
            return 'The password is too short', False
        if len(password) > 32:
            return 'The password is too long', False
        if re.search(r'[A-Z]', password) is None:
            return 'The password must include at least one uppercase letter', False
        if re.search(r'[a-z]', password) is None:
            return 'The password must include at least one lowercase letter', False
        if re.search(r'\d', password) is None:
            return 'The password must include at least one number', False
        if re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~" + r'"]', password) is None:
            return 'The password must include at least one symbol', False
        self.hashed_password = password_context.encrypt(password)
        return '', True

    def __init__(self, username):
        self.username = username


class UserSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    username = fields.String(required=True, validate=validate.Length(3))
    bucketlists = fields.Nested(
        'BucketListSchema', many=True, exclude=('user',))
    url = ma.URLFor('api.userresource', id='<id>', _external=True)


class Bucketlist(db.Model, AddUpdateDelete):
    id = db.Column(db.Integer, primary_key=True)
    bkt_name = db.Column(db.String(150), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id',
                                                  ondelete='CASCADE'), nullable=False)
    user = db.relationship('User', backref=db.backref('bucketlists',
                                                      lazy='dynamic', order_by='Bucketlist.bkt_name'))

    def __init__(self, bkt_name, user):
        self.bkt_name = bkt_name
        self.user = user


class Bucketlistitem(db.Model, AddUpdateDelete):
    id = db.Column(db.Integer, primary_key=True)
    bkt_item_name = db.Column(db.String(150), unique=True, nullable=False)
    bkt_id = db.Column(db.Integer, db.ForeignKey('bucketlist.id',
                                                 ondelete='CASCADE'), nullable=False)
    bucketlist = db.relationship('Bucketlist', backref=db.backref('bucket_list_items',
                                                                  lazy='dynamic', order_by='Bucketlistitem.bkt_item_name'))

    def __init__(self, bkt_item_name, bucketlist):
        self.bkt_item_name = bkt_item_name
        self.bucketlist = bucketlist


class BucketListSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    bkt_name = fields.String(required=True, validate=validate.Length(3))
    user = fields.Nested('UserSchema', only=[
                         'id', 'url', 'username'], required=True)
    bucket_items = fields.Nested(
        'BucketListItemSchema', many=True, exclude=('bucketlist',))
    url = ma.URLFor('api.bucketlistresource', id='<id>', _external=True)


class BucketListItemSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    bkt_item_name = fields.String(required=True, validate=validate.Length(3))
    bkt_name = fields.String(required=True, validate=validate.Length(3))
    bucketlist = fields.Nested('BucketListSchema', only=[
                               'id', 'bkt_name'], required=True)
    url = ma.URLFor('api.bucketlistitemresource', bkt_id='<bkt_id>',
                    id='<id>', _external=True)
