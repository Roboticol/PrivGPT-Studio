from flask import Blueprint, request, jsonify, current_app
from server import mongo, bcrypt
import jwt
import datetime

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing email or password'}), 400
    
    email = data.get('email')
    password = data.get('password')
    
    # user already exists
    if mongo.db.users.find_one({'email': email}):
        return jsonify({'message': 'User already exists'}), 409
    
    # hash password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    # handle optional fields
    username = data.get('username')
    if not username:
        username = email.split('@')[0]
        
    gender = data.get('gender')
    dob = data.get('dob')
    phone = data.get('phone')
    
    # create user
    user = {
        'email': email,
        'password': hashed_password,
        'username': username,
        'gender': gender if gender else None,
        'dob': dob if dob else None,
        'phone': phone if phone else None,
        'created_at': datetime.datetime.utcnow(),
        'chat_sessions': []
    }
    
    mongo.db.users.insert_one(user)
    
    return jsonify({'message': 'User registered successfully'}), 201

@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing email or password'}), 400
    
    email = data.get('email')
    password = data.get('password')
    
    user = mongo.db.users.find_one({'email': email})
    
    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify({'message': 'Invalid email or password'}), 401
    
    # generate JWT
    token = jwt.encode({
        'user_id': str(user['_id']),
        'email': user['email'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, current_app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({'token': token, 'message': 'Login successful'}), 200
