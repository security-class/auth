from datetime import datetime, timedelta
from functools import wraps
import logging
import os

from jose import jwt
from redis import Redis
from redis.exceptions import ConnectionError
from flask import Flask, Response, jsonify, request, json, url_for, make_response
from flask_api import status    # HTTP Status Codes
from werkzeug.exceptions import NotFound, Unauthorized

from models import Client, User, Token
from . import app

# Decorator for protecting routes with JWT tokens
def required_auth(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return Unauthorized("No authorization header.")

            auth_type, jwt_token = auth_header.split()

            token = Token.is_valid(jwt_token)
            if not token:
                return Unauthorized("Invalid JWT Token.")

            for grant in token.grants.split():
                for role in roles:
                    if grant in role:
                        return f(*args, **kwargs)

            return Unauthorized("JWT doesn't contain required grants.")
        return decorated
    return decorator

@app.route('/')
def index():
    return jsonify(name='SAM backing User/AuthenticationREST API', version='1.0')

# User Functions

@app.route('/users', methods=['GET'])
@required_auth('admin')
def list_users():
    users = []
    email = request.args.get('email')
    if email:
        users = User.find_by_email(email)
    else:
        users = User.all()

    results = [user.serialize() for user in users]
    return make_response(jsonify(results), status.HTTP_200_OK)

@app.route('/users/<int:id>', methods=['GET'])
@required_auth('user admin')
def get_user(id):
    user = User.find_or_404(id)
    return make_response(jsonify(user.serialize()), status.HTTP_200_OK)

@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    user = User()
    user.deserialize(data['user_info'])
    user.set_password(data['password'])
    user.save()
    message = user.serialize()
    return make_response(jsonify(message), status.HTTP_201_CREATED, {'Location': user.self_url() })

@app.route('/users/<int:id>', methods=['DELETE'])
def delete_user(id):
    user = User.find(id)
    if user:
        user.delete()
    return make_response('', status.HTTP_204_NO_CONTENT)

@app.route('/users/<int:id>', methods=['PUT'])
@required_auth('admin')
def update_user(id):
    user = User.find_or_404(id)
    user.deserialize(request.get_json())
    user.save()
    return make_response(jsonify(user.serialize()), status.HTTP_200_OK)

# Client management utilities

@app.route('/clients', methods=['GET'])
@required_auth('admin')
def list_clients():
    clients = Client.all()
    clients_new = []
    for client in clients:
        clients_new.append(client.serialize())
    return make_response(jsonify(clients_new), status.HTTP_200_OK)

@app.route('/clients', methods=['POST'])
def create_client():
    data = request.get_json()

    name = data['name']
    url = data['url']

    client = Client(name, url)
    client.save()
    message = client.serialize()

    return make_response(jsonify(message), status.HTTP_201_CREATED)

# Token generation/verification

@app.route('/auth/token', methods=['POST'])
def issue_token():
    data = request.get_json()
    user = User.find_or_404(email=data['email'])
    is_valid = user.check_password(data['password'])

    # Wrong
    if not is_valid:
        message = {"Error": "Invalid login credentials."}
        return make_response(jsonify(message), status.HTTP_401_UNAUTHORIZED)

    token = Token.find_by_user_id(user.id)

    if token:
        token.delete()

    token = Token(user.id)
    token.save()
    return token.generate_jwt_token()

@app.route('/auth/verify', methods=['POST'])
def verify_token():
    data = request.get_json()
    valid = Token.is_valid(data['token'])
    message = {"Authorized": valid}
    return make_response(jsonify(message), status.HTTP_200_OK)

# Utility Functions
@app.route('/reset')
@required_auth('admin')
def reset():
    User.remove_all()
    make_admin()
    return make_response("User Service Reset", status.HTTP_200_OK)

def connect_to_redis(hostname, port, password):
    redis = Redis(host=hostname, port=port, password=password)
    try:
        redis.ping()
    except ConnectionError:
        redis = None
    return redis

def initialize_redis():
    global redis
    redis = None

    # Get the crdentials from the Bluemix environment
    if 'VCAP_SERVICES' in os.environ:
        app.logger.info("Using VCAP_SERVICES...")
        VCAP_SERVICES = os.environ['VCAP_SERVICES']
        services = json.loads(VCAP_SERVICES)
        creds = services['rediscloud'][0]['credentials']
        app.logger.info("Conecting to Redis on host %s port %s" % (creds['hostname'], creds['port']))
        redis = connect_to_redis(creds['hostname'], creds['port'], creds['password'])
    else:
        app.logger.info("VCAP_SERVICES not found, checking localhost for Redis")
        redis = connect_to_redis('127.0.0.1', 6379, None)
        if not redis:
            app.logger.info("No Redis on localhost, using: redis")
            redis = connect_to_redis('redis', 6379, None)
    if not redis:
        # if you end up here, redis instance is down.
        app.logger.error('*** FATAL ERROR: Could not connect to the Redis Service')

    User.use_db(redis)
    Client.use_db(redis)
    Token.use_db(redis)

def make_admin():
    user = User.find_by_email('wesleyppainter@gmail.com')
    if not user:
        user = User()
        user.set_name('wesley', 'painter')
        user.set_password(app.config['ADMIN_PASS'])
        user.set_email('wesleyppainter@gmail.com')
        user.set_grants("user admin")
        user.save()
