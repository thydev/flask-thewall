from flask import Flask, render_template, request, session, flash, redirect
import re, datetime, md5, os, binascii
from mysqlconnection import MySQLConnector

app = Flask(__name__)
app.secret_key = "fs@#dSd@3323cxdsf132SF$#$@#[]"
mysql = MySQLConnector(app, 'thewall')

# create a regular expression object that we can use run operations on
email_reg = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
pwd_reg = re.compile('^(?=\S{8,20}$)(?=.*?\d)(?=.*?[a-z])(?=.*?[A-Z])(?=.*?[^A-Za-z\s0-9])')


@app.route('/')
def index():
    session.modified = True
    if 'loggedin' not in session:
        session['loggedin'] = {
            'id': -1,
            'name': "undefined"
        }
    return render_template('index.html')

@app.route('/create', methods=["POST"])
def create():
    session.modified = True
    # print request.form
    isValid = True
    firstname = request.form['firstname'].strip()
    lastname = request.form['lastname'].strip()
    fullname =  firstname + " " + lastname
    email = request.form['email']
    password = request.form['password']
    password_confirm = request.form['password_confirm']

    salt =  binascii.b2a_hex(os.urandom(15))
    hashed_pw = md5.new(password + salt).hexdigest()

    # 1. First Name - letters only, at least 2 characters and that it was submitted
    # 2. Last Name - letters only, at least 2 characters and that it was submitted
    # 3. Email - Valid Email format, and that it was submitted
    # 4. Password - at least 8 characters, and that it was submitted
    # 5. Password Confirmation - matches password

    if not (len(firstname) > 1):
        flash("First Name - letters only, at least 2 characters!", "error")
        isValid = False
    if not (len(lastname) > 1):
        flash("Last Name - letters only, at least 2 characters!", "error")
        isValid = False
    if not email_reg.match(email):
        flash("Invalid Email Address!", "error")
        isValid = False
    if (len(password) < 0):
        flash("Please input your password", "error")
        isValid = False
    elif not pwd_reg.match(password):
        flash("Password must contain at least 8 characters, 1 uppercase, 1 lowercase, 1 number and 1 symbol", "error")
        isValid = False
    elif password != password_confirm:
        flash("Password does not match!", "error")
        isValid = False

    if isValid:
        query = "INSERT INTO users (first_name, last_name, email, password, salt, created_at, updated_at) " 
        query += "VALUES (:first_name, :last_name, :email, :password, :salt, NOW(), NOW())"
        data = { 
            'first_name': firstname,
            'last_name': lastname,
            'email': email,
            'password': hashed_pw,
            'salt': salt
            }

        user_id = mysql.query_db(query, data)
        if 'loggedin' in session:
            session['loggedin'] = {
                'id': user_id,
                'name': firstname + ' ' + lastname
            }

        print session['loggedin']
        flash("Registered sucessfully!", "sucess")
        # return render_template('result.html', fullname = fullname, location = location, language = language, comment = comment )
        return redirect('/')
    else:
        return redirect('/')

@app.route('/logout', methods=['POST'])
def logout():
    session.modified = True
    session['loggedin'] = {
            'id': -1,
            'name': "undefined"
        }
    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    session.modified = True
    email = request.form['email']
    password = request.form['password']
    user_query = "SELECT * FROM users WHERE users.email = :email LIMIT 1"
    query_data = {'email': email}
    user = mysql.query_db(user_query, query_data)
    if len(user) == 0:
        # invalid email!
        flash("There is not this email {} in the system!".format(email), "error_login")
        return redirect('/')
    print user
    encrypted_password = md5.new(password + user[0]['salt']).hexdigest()
    if user[0]['password'] == encrypted_password:
    # this means we have a successful login!
        session['loggedin'] = {
                'id': user[0]['id'],
                'name': user[0]['first_name'] + ' ' + user[0]['last_name']
            }
    else:
        # invalid password!
        flash("Wrong Password!", "error_login")
    return redirect('/')

app.run(debug = True)
