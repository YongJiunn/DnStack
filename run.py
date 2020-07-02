"""
Author: @ Tan Zhao Yea
This part holds all the codes to make the Friend Finder GUI workable.
The GUI runs on a webserver, WSGIserver.
    1. Start the application's GUI on localhost.
    2. Simply run python run.py and go to browswer and enter localhost:1000 to access the Friend Finder GUI
Monkey:
The primary purpose of this module is to carefully patch, in place, portions of the standard library with gevent-friendly functions that behave in the same way as the original
Read More:
WSGIserver: https://pypi.org/project/WSGIserver/
gevent.Monkey:
"""

import warnings

from gevent import monkey
# Patching should be done as early as possible in the lifecycle of the program
monkey.patch_all()

from app import app
from gevent.pywsgi import WSGIServer

HOST, PORT = '0.0.0.0', 1337

try:
    warnings.filterwarnings('ignore')
    print(f"[*] Starting GUI on addr: {HOST}:{PORT}")

    # Intialize the WSGI Server
    http_server = WSGIServer((HOST, PORT), app)
    http_server.serve_forever()

except KeyboardInterrupt:
    pass

except Exception as e:
    print('Exception: {}'.format(e))
