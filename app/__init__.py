"""
Author: @ Tan Zhao Yea
Flask is a microframework for Python based on Werkzeug, Jinja 2 and good intentions.
Form Validation with WTForms.
More Info:
Flask: http://flask.pocoo.org/
WTForms: http://flask.pocoo.org/docs/1.0/patterns/wtforms/
"""

import os
from flask import Flask, render_template, request, redirect, flash, session
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)  # initialise the flask app
app.config['SECRET_KEY'] = os.urandom(24)  # create the secret key

csrf = CSRFProtect(app)  # protect the csrf app
csrf.init_app(app)  # initialise the csrf with the app

profiles_dir = []  # specify and empty list to store the directory of the profiles
name_list = []  # specify an empty name list to store the name
main_class = {}  # store the main class to call the main method in main.py


@app.route('/')
def index():
    # Check for Session
    if not session.get('active'):
        return render_template('welcome.html')

    else:
        try:
            return render_template('index.html')

        except:
            # if session expire, set the session to False
            session['profiles'] = False
            flash('Session Expire')
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
    # note that we set the 404 status explicitly
    return render_template('500.html'), 500
