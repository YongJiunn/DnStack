"""
Author: @ Zhao Yea

Flask is a microframework for Python based on Werkzeug, Jinja 2 and good intentions.
Form Validation with WTForms.
More Info:
Flask: http://flask.pocoo.org/
WTForms: http://flask.pocoo.org/docs/1.0/patterns/wtforms/
"""

import os
import re
import json
from flask import Flask, render_template, request, redirect, flash, session
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)  # initialise the flask app
app.config['SECRET_KEY'] = os.urandom(24)  # create the secret key

csrf = CSRFProtect(app)  # protect the csrf app
csrf.init_app(app)  # initialise the csrf with the app

profiles_dir = []  # specify and empty list to store the directory of the profiles
name_list = []  # specify an empty name list to store the name
main_class = {}  # store the main class to call the main method in main.py

# Broker Log File
SYSLOG = r"D:\DnStack\logs\sysinfo.log"
CLIENT_SESS_LOG = r"D:\DnStack\logs\client_session.log"
DOMAIN_PROFILES_LOG = r"D:\DnStack\logs\domain_profiles.log"
BLOCKCHAIN_LOG = r"D:\DnStack\logs\blockchain.log"


@app.route('/')
def index():
    # Check for Session
    if not session.get('active'):
        return render_template('login.html')

    else:
        # try:
        # Load the Blockchain
        with open(BLOCKCHAIN_LOG, "r") as bc_log:
            blockchain = json.loads(bc_log.read())

        # Load the Client Session
        with open(CLIENT_SESS_LOG, "r") as sess_log:
            active_clients = sess_log.read().split(",")

        # Load the Transaction Session
        sys_log = []
        with open(SYSLOG, "r") as sys_log_file:
            for _ in range(3):
                next(sys_log_file)
            for line in sys_log_file:
                sys_log.append(re.search(r".*INFO\]\s(.*)", line).group(1))

        # Load the Domain Page
        new_domain = sum(1 for line in open(DOMAIN_PROFILES_LOG))

        templateData = {
            'blockchain': blockchain,
            'active_clients': active_clients,
            'sys_log': sys_log,
            'new_domain': new_domain
        }

        return render_template('index.html', **templateData)

        # except:
        #     # if session expire, set the session to False
        #     session['active'] = False
        #     flash('Session Expire')
        #     return redirect('/')


@app.route('/login', methods=["POST"])
def login():
    if request.method == "POST":
        if request.form['password'] == "P@ssw0rd":
            session['active'] = True
            return redirect('/')

        else:
            flash("Wrong Password")
            return redirect('/')


# reset the session if the file cannot load the profiles dir
@app.route("/logout")
def logout():
    session['active'] = False
    return redirect('/')


# display the error if the user tries to attempt to go to a site without providing a profiles dir
@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404


# display the error if the user tries to attempt to go to a site without providing a profiles dir
@app.errorhandler(500)
def internal_server_error(e):
    # note that we set the 500 status explicitly
    return render_template('500.html'), 500
