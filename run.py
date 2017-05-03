import os
from app import app, server
from app.models import User

debug = (os.getenv('DEBUG', 'False') == 'True')
port = os.getenv('PORT', '5000')

if __name__ == "__main__":
    print "User service starting..."
    server.initialize_redis()
    server.make_admin()
    app.run(host='0.0.0.0', port=int(port), debug=debug)
