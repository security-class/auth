import logging
import os

from werkzeug.security import gen_salt

TOKEN_TIMEOUT = 3600
SECRET_KEY = gen_salt(50)
SERVICE_NAME = 'auth'
GRANT_TYPES = ['user', 'admin']
ADMIN_PASS = os.getenv('ADMIN_PASS', 'secret')
