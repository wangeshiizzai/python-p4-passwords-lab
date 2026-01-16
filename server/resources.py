from flask import request, session
from flask_restful import Resource
from config import db
from models import User

class ClearSession(Resource):
    def delete(self):
        session.clear()
        return {}, 204

class Signup(Resource):
    def post(self):
        data = request.get_json()
        user = User(username=data['username'])
        user.password_hash = data['password']
        db.session.add(user)
        db.session.commit()
        session['user_id'] = user.id
        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {}, 204
        user = User.query.get(user_id)
        return user.to_dict(), 200

class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        if user and user.authenticate(data['password']):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {"error": "Invalid credentials"}, 401

class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)
        return {}, 204
