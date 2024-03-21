from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User

class ClearSession(Resource):

    def delete(self):
        session.clear()
        return {}, 204

class Signup(Resource):
    
    def post(self):
        json_data = request.get_json()
        if 'username' not in json_data or 'password' not in json_data:
            return {'error': 'Username and password are required'}, 400
        
        username = json_data['username']
        password = json_data['password']
        
        # Create a new user
        user = User(username=username)
        user.password_hash = password  # Assuming password_hash is the hashed password
        
        # Add the user to the database
        db.session.add(user)
        db.session.commit()
        
        session['user_id'] = user.id
        return user.to_dict(), 201

class CheckSession(Resource):
    
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            return user.to_dict()
        else:
            return {}, 204

class Login(Resource):
    
    def post(self):
        json_data = request.get_json()
        if 'username' not in json_data or 'password' not in json_data:
            return {'error': 'Username and password are required'}, 400
        
        username = json_data['username']
        password = json_data['password']
        
        # Query user by username
        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict()
        else:
            return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    
    def delete(self):
        session.pop('user_id', None)
        return {}, 204

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
