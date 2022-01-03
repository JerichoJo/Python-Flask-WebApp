"""
Author: Joe Santucci
Date: 05/04/21
Purpose: Using flask to create a locally hosted webpage with username and password validation
"""

import datetime
import flask
from password_validation import PasswordPolicy
from flask import Flask, request, render_template, flash, url_for, session
from werkzeug.utils import redirect

# Setting flask app
app = Flask(__name__)
# Setting secret key
app.secret_key = "super secret key"
# If statement for debugging
if __name__ == '__main__':
    app.debug = True
    app.run()


@app.route('/update', methods=['GET', 'POST'])
def update_password():
    """Function to update password"""
    policy = PasswordPolicy(lowercase=1, uppercase=1, symbols=1, min_length=12, numbers=1)
    if 'visited' in session and request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        updated_password = request.form['new_password']
        if policy.validate(password):
            # opening database
            open_data = open("data.txt", "r")
            # creating reader variable for database
            read_data = open_data.readlines()
            # closing reader
            open_data.close()
            line = [j.split() for j in read_data]
            # For statement verifying the username and password exists in database
            for k in line:
                if username == k[0].strip() and password == k[1].strip():
                    data2 = open("data.txt", "r")
                    for line in data2:
                        data = line.split(" ")
                        # if statement replacing password if matched
                        if data[0] == username.strip():
                            replace_password = line.replace(data[1], updated_password)
                        else:
                            flash("Username and password combination does not exist")
                            session['visited'] = request.form['username']

                    with open('commonpasswords.txt') as pass_file:
                        # Verifying that the password is not in the common passwords file
                        if updated_password in pass_file.read():
                            flash("This password has previously "
                                  "been compromised, enter another password")
                            return render_template('update.html')
                    data2.close()
                    data3 = open("data.txt", "w")
                    data3.write(replace_password)
                    data3.close()
                    flash("Password successfully updated!")
        else:
            for requirement in policy.test_password(password):
                alert = f"{requirement.name} not satisfied: " \
                        f"expected: {requirement.requirement}, " \
                        f"got: {requirement.actual} "
                flash(alert)
    return render_template('update.html')


@app.route('/hello/')
def hello():
    """Function to show /hello web page"""
    return render_template('hello.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Function to display the register webpage and setup the verification of submission"""
    policy = PasswordPolicy(lowercase=1, uppercase=1, symbols=1, min_length=12, numbers=1)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        write_pass = open('data.txt', "a")
        # Verifying that the password does not exist in the common passwords file
        with open('commonpasswords.txt') as pass_file:
            if password in pass_file.read():
                flash("This password has previously been compromised, enter another password")
                return render_template('register.html')
        if len(username) > 20:
            flash("Username is too long")
        # If statement validating password and writing to data file
        elif policy.validate(password):
            write_pass.write("%s %s\n" % (username, password))
            write_pass.close()
            session['visited'] = request.form['username']
            return redirect(url_for('welcome'))
        else:
            for requirement in policy.test_password(password):
                alert = f"{requirement.name} not satisfied: expected: {requirement.requirement}, " \
                        f"got: {requirement.actual} "
                flash(alert)
    return render_template("register.html")


@app.route('/welcome', methods=['GET', 'POST'])
def welcome():
    """Function to return the /welcome page"""
    # if statement verifying user is logged in
    if 'visited' not in session:
        return redirect(url_for('hello'))
    return render_template('welcome.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Function for login"""
    policy = PasswordPolicy(lowercase=1, uppercase=1, symbols=1, min_length=12, numbers=1)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if len(username) > 20:
            flash("Username is too long")
        # if statement validating password and allowing user access
        elif policy.validate(password):
            open_data = open("data.txt", "r")
            read_data = open_data.readlines()
            open_data.close()
            line = [j.split() for j in read_data]
            # for statement to verify user exists and username and password match
            for k in line:
                if username == k[0].strip() and password == k[1].strip():
                    session['visited'] = request.form['username']
                    return render_template('home')
                else:
                    flash('Username and password combination does not exist, please try again')
                    log()
                    return render_template("login.html")
        else:
            log()
            for requirement in policy.test_password(password):
                alert = f"{requirement.name} not satisfied: expected: {requirement.requirement}, " \
                        f"got: {requirement.actual} "
                flash(alert)
                return render_template("login.html")
    return render_template("login.html")


@app.route('/home', methods=['GET', 'POST'])
def home():
    """Function for returning to the home page"""
    # if statement verifying user is logged in
    if 'visited' not in session:
        return redirect(url_for('hello'))
    return render_template('home.html')


def log():
    """Function that appends IP, date and time to log file"""
    # Opens log file for appending
    log_file = open('failed_login.txt', "a")
    # Retrieving client IP
    ip_address = flask.request.remote_addr
    # Getting Date and time
    date_time = datetime.datetime.now()
    # Writing to log file
    log_file.write("%s %s\n" % (ip_address, date_time))
    # Closing log file
    log_file.close()
