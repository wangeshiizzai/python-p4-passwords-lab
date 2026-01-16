#!/usr/bin/env python3

from flask import Flask, request, session
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_restful import Api, Resource
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

# ---------------------------
# App and Config
# ---------------------------
app = Flask(__name__)
app.secret_key = b'Y\xf1Xz\x00\xad|eQ\x80t \xca\x1a\x10K'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact = False

# ---------------------------
# Extensions
# ---------------------------
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
api = Api(app)

# ---------------------------
# Models
# ---------------------------
class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String, nullable=False)

    @hybrid_property
    def password_hash(self):
        raise Exception("Password hashes may not be viewed.")

    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8')
        ).decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))

    def __repr__(self):
        return f"<User {self.username}, ID: {self.id}>"

# ---------------------------
# Resources
# ---------------------------
class ClearSession(Resource):
    def delete(self):
        session.clear()
        return {}, 204

class Signup(Resource):
    def post(self):
        json_data = request.get_json()
        user = User(username=json_data['username'])
        user.password_hash = json_data['password']
        db.session.add(user)
        db.session.commit()
        session['user_id'] = user.id
        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            return user.to_dict(), 200
        return {}, 204

class Login(Resource):
    def post(self):
        json_data = request.get_json()
        username = json_data['username']
        password = json_data['password']
        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {"error": "Invalid username or password"}, 401

class Logout(Resource):
    def delete(self):
        session.clear()
        return {}, 204

# ---------------------------
# Routes
# ---------------------------
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

# ---------------------------
# Run Server
# ---------------------------
if __name__ == '__main__':
    app.run(port=5555, debug=True)
