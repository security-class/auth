from datetime import datetime, timedelta
import json

import bcrypt
from jose import jwt
from flask import url_for
from werkzeug.exceptions import NotFound, BadRequest
from werkzeug.security import gen_salt

from . import app

class User(object):
    '''SAM User model object

    '''

    __redis = None

    def __init__(self, id=0):
        self.id = int(id)
        self.email = None
        self.first_name = None
        self.last_name = None
        self.password = None
        self.grants = "user"

    def set_email(self, email):
        self.email = email

    def set_name(self, first_name, last_name):
        self.first_name = first_name
        self.last_name = last_name

    def set_password(self, password):
        self.password = bcrypt.hashpw(bytes(password), bcrypt.gensalt())

    def set_grants(self, grants):
        self.grants = grants

    def check_password(self, password):
        password = bytes(password)
        return bcrypt.hashpw(password, self.password) == self.password

    def self_url(self):
        return url_for('get_user', id=self.id, _external=True)

    def save(self):
        if self.password == None:
            raise AttributeError('Password has not been set.')
        if self.id == 0:
            self.id = User.__redis.incr('index')
        User.__redis.hmset(self.id, self.serialize_with_pass())

    def delete(self):
        User.__redis.delete(self.id)

    def serialize(self):
        return {'id': self.id,
                'email': self.email,
                'first_name': self.first_name,
                'last_name': self.last_name,
                'grants': self.grants,}

    def serialize_with_pass(self):
        data = self.serialize()
        data['password'] = self.password
        return data

    def deserialize(self, data):
        try:
            self.first_name = data['first_name']
            self.last_name = data['last_name']
            self.email = data['email']
            self.grants = data['grants']
        except KeyError as e:
            pass
        except TypeError as e:
            pass
        return self

    # Static database methods

    @staticmethod
    def use_db(redis):
        User.__redis = redis

    @staticmethod
    def remove_all():
        User.__redis.flushall()

    @staticmethod
    def all():
        users = []
        for key in User.__redis.keys():
            if key != 'index':
                data = User.__redis.hgetall(key)
                user = User(data['id']).deserialize(data)
                user.password = data['password']
                users.append(user)
        return users

    @staticmethod
    def find(id):
        if User.__redis.exists(id):
            data = User.__redis.hgetall(id)
            user = User(data['id']).deserialize(data)
            user.password = data['password']
            return user
        else:
            return None

    @staticmethod
    def find_or_404(id=None,email=None):
        if id:
            user = User.find(id)
            if not user:
                raise NotFound("User with id '{}' was not found.".format(id))
        else:
            user = User.find_by_email(email)
            if not user:
                raise NotFound("User with email '{}' was not found.".format(email))
        return user

    @staticmethod
    def find_by_email(email):
        for key in User.__redis.keys():
            if key != 'index' and key != 'clients' and key != 'tokens':
                data = User.__redis.hgetall(key)
                if data['email'] == email:
                    user = User(data['id']).deserialize(data)
                    user.password = data['password']
                    return user
        return None

    @staticmethod
    def validate_user_post(data):
        valid = False
        try:
            email = data['user_info']['email']
            first_name = data['user_info']['first_name']
            last_name = data['user_info']['last_name']
            password = data['password']
            valid = True
        except KeyError:
            valid = False
        except TypeError:
            valid = False

        if not valid:
            raise BadRequest("Not a valid post object for user.")
        return valid

    @staticmethod
    def validate_user_login(data):
        valid = False
        try:
            email = data['email']
            password = data['password']
            valid = True
        except KeyError:
            valid = False
        except TypeError:
            valid = False

        if not valid:
            raise BadRequest("Not a valid login object for user.")
        return valid

class Client(object):
    '''Resource endpoint registered with auth server to verify users.

    '''
    __redis = None

    def __init__(self, name, url, description = None, client_id = None, grant_types=None):
        if not client_id:
            self.client_id = gen_salt(40)
        else:
            self.client_id = client_id

        self.name = name
        self.url = url
        self.description = description

    def serialize(self):
        return {
            "name": self.name,
            "client_id": self.client_id,
            "url": self.url,
            "description": self.description,
            "grant_types": self.grant_types
        }

    def save(self):
        Client.__redis.hset('clients', self.client_id, json.dumps(self.serialize()))

    @staticmethod
    def use_db(redis):
        Client.__redis = redis

    @staticmethod
    def find(client_id):
        data = json.loads(Client.__redis.hget('clients', client_id))
        return Client(**data)

    @staticmethod
    def all():
        clients = []
        for client_id, data in Client.__redis.hgetall('clients').iteritems():
            data = json.loads(data)
            client = Client(**data)
            clients.append(client)
        return clients

class Token(object):
    '''Authorization tokens for registered resources

    '''

    __redis = None

    def __init__(self, user_id, client_id=None, token_id=None, iat = None,
                 exp = None, grants = None):
        self.user_id = user_id
        self.client_id = client_id

        if not token_id:
            self.token_id = gen_salt(40)
        else:
            self.token_id = token_id

        if not iat:
            self.iat = float(datetime.utcnow().strftime('%s'))
        else:
            self.iat = iat

        if not grants:
            self.grants = User.find(user_id).grants
        else:
            self.grants = grants

        if not exp:
            iat = datetime.fromtimestamp(self.iat)
            exp = iat + timedelta(seconds = app.config['TOKEN_TIMEOUT'])
            self.exp = float(exp.strftime('%s'))
        else:
            self.exp = exp

    def serialize(self):
        return {
            "token_id": self.token_id,
            "user_id": self.user_id,
            "client_id": self.client_id,
            "iat": self.iat,
            "exp": self.exp,
            "grants": self.grants
        }

    def save(self):
        Token.__redis.hset('tokens', self.token_id, json.dumps(self.serialize()))

    def delete(self):
        Token.__redis.hdel('tokens', self.token_id)

    def generate_jwt_token(self):
        jwt_token = jwt.encode(self.serialize(), app.config['SECRET_KEY'], algorithm='HS256')
        return jwt_token

    @staticmethod
    def is_valid(jwt_token):
        try:
            data = jwt.decode(jwt_token, app.config['SECRET_KEY'], algorithms=['HS256'])
            token = Token.find(data["token_id"])
            token_data = token.serialize()
            diff = [k for k in token_data if token_data[k] != data[k]]

            if len(diff) != 0:
                return None

            if datetime.fromtimestamp(data['exp']) < datetime.utcnow():
                return None

            return token
        except jwt.JWTError as e:
            print(e)
            return None

    @staticmethod
    def find(token_id):
        data = json.loads(Token.__redis.hget('tokens', token_id))
        return Token(**data)

    @staticmethod
    def find_by_user_id(user_id):
        for token_id, data in Token.__redis.hgetall('tokens').iteritems():
            data = json.loads(data)
            if data['user_id'] == user_id:
                return Token(**data)
        return None

    @staticmethod
    def all():
        tokens = []
        for token_id, data in Token.__redis.hgetall('tokens').iteritems():
            data = json.loads(data)
            token = Token(**data)
            tokens.append(client)
        return tokens

    @staticmethod
    def use_db(redis):
        Token.__redis = redis
