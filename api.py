from flask import Flask, request, jsonify, make_response
from flask_api import status
from flask_jwt_extended import (
    JWTManager, jwt_required, get_jwt_identity,
    create_access_token, create_refresh_token,
    jwt_refresh_token_required, get_raw_jwt, unset_jwt_cookies
)
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['PROPAGATE_EXCEPTIONS'] = True

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
# app.config['JWT_TOKEN_LOCATION'] = ['headers']
# app.config['JWT_HEADER_NAME'] = ['Authorization']
# app.config['JWT_HEADER_TYPE'] = ['Bearer']

app.config['JWT_SECRET_KEY'] = 'secretkey'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization'in request.headers:
            token = request.headers['Authorization']

        if not token:
            return jsonify({'message':'Token is missing!'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message':'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    users = User.query.all()

    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users':output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_user(current_user, public_id):

    user = User.query.filter_by(public_id=public_id).first()
    
    if not user:
        return jsonify({'message':'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['admin'] = user.admin

    return jsonify({'users':user_data})

@app.route('/user', methods=['POST'])
def create_user():

    data = request.get_json()

    hash_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hash_password, admin=False)

    db.session.add(new_user)
    db.session.commit()

    user_data = {}
    user_data['public_id'] = new_user.public_id
    user_data['name'] = new_user.name

    return jsonify({'data':user_data, 'message': 'New user created successfully!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify({'message':'Username OR Password is required.'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return jsonify({'message' : 'could not verify'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id':user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'Username':user.name, 'message':'Login Successful', 'token':token.decode('ascii')})
    
    return jsonify({'message' : 'could not verify'})
    
if __name__ == '__main__':
    app.run(debug=True)