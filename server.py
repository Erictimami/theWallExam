from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
import re #means regex for regular expression. using to sort( adding a long string after the real password before hashing )
from flask_bcrypt import Bcrypt    #for salting and hashing the password    
       
# create a regular expression object that we can use run operations on
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

#opening the app using Flask
app = Flask(__name__)
bcrypt = Bcrypt(app) 
app.secret_key="dajlhayjsvsckjfk" #secret key for opening the session

@app.route('/log_off')
def log_off():
    session.clear()
    flash("You have been logged out", 'logged_out')
    return redirect('/')


@app.route('/')
def index():  
    if ('logged' or 'id' or 'first_name') not in session:
        session['logged']=False
        session['id']=0
        session['first_name']=""
    elif session['logged']==None:
        flash("You have been logged out", 'logged_out')
    return render_template("index.html")


@app.route('/process_registration', methods=['POST'])
def process_registration():
    
    if request.method != 'POST':
        return redirect('/')

    valid_form_ok = True
    # Let's add validation rules

    if (len(request.form['first_name']) <= 2) or (bool(re.search(r'\d', request.form['first_name'])) == True) :   #check if at least 2 characters and if only the letter by using REGEX
        flash("First name must contain at least two and contain only letters", 'first_name')
        valid_form_ok=False

    if (len(request.form['last_name']) <= 2) or (bool(re.search(r'\d', request.form['last_name'])) == True) :
        flash("Last name must contain at least two and contain only letters", 'last_name')
        valid_form_ok=False

    if not EMAIL_REGEX.match(request.form['email']):  #checking validation email
        flash("Invalid email address!", 'email')
        valid_form_ok=False
    else:
        mysql = connectToMySQL('wall_db')
        email_query = "SELECT * FROM users WHERE users.email LIKE %(new_email)s;"
        data = {"new_email": request.form['email']}
        if mysql.query_db(email_query,data):
            flash("This email is already used by another user", 'email')
            valid_form_ok=False

    if (len(request.form['password']) < 8) or (len(request.form['password']) > 15):
        flash("Password must contain a number, a capital letter, and be between 8-15 characters", 'password')
        valid_form_ok=False
    elif request.form['password'] != request.form['confirm_pw']:
        flash("Passwords must match", 'confirm_pw')
        valid_form_ok=False

    if valid_form_ok == False :
        if '_flashes' in session.keys():
            session['first_name'], session['last_name'], session['email'] = request.form['first_name'], request.form['last_name'], request.form['email']
            return redirect('/')
    else:
        # include some logic to validate user input before adding them to the database!
        # create the hash
        password_hash = bcrypt.generate_password_hash(request.form['password'])  
        print('=====================================================',password_hash)  
        # be sure you set up your database so it can store password hashes this long (60 characters)

        mysql = connectToMySQL('wall_db')
        insert_query = "INSERT INTO users (first_name, last_name, email, password, created_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, now());"
        data = {
            "first_name": request.form['first_name'],
            "last_name": request.form['last_name'],
            "email": request.form['email'],
            "password": password_hash
            }
        print("error here")
        id_new_user=mysql.query_db(insert_query, data)
        print(id_new_user)
        
        if ('logged' or 'id' or 'first_name') not in session:
            session['first_name']=request.form['first_name']
            session['logged']= True
            session['id']=id_new_user
        else:
            session['logged']= True
            session['id']=id_new_user
            session['first_name']=request.form['first_name']
        return redirect('/wall')

@app.route('/process_login', methods=['POST'])
def process_loggin():

    if request.method != 'POST':
        return redirect('/')

    if not EMAIL_REGEX.match(request.form['email']):  #checking validation email
        flash("Email and/or password are INVALID!", 'login')
        return redirect('/')
    else:
        mysql = connectToMySQL('wall_db')
        query = "SELECT users.email, users.password, users.first_name, users.id FROM users WHERE users.email=%(new_email)s;"
        data = {"new_email": request.form['email'].strip().lower() }

        print('$$$$$$$$$$$$$$$$$$$$$$$$$$ new_email', data)
        result_data = mysql.query_db(query,data) 
        print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!result_data:', result_data)
        if not result_data:
            flash("Email and/or password are INVALID!", 'login') #this email never registered
            return redirect('/')
        elif bcrypt.check_password_hash(result_data[0]['password'], request.form['password']):
            # if we get True after checking the password, we may put the user id in session
            print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@', result_data)
            session['id'] = result_data[0]['id']
            session['logged']=True
            session['first_name']=result_data[0]['first_name']
            return redirect('/wall')
    flash("Email and/or password are INVALID!", 'login')
    return redirect('/')

@app.route('/wall')
def wall():  

    if request.method != 'GET':
        return redirect('/')
    
    #total msg received
    mysql = connectToMySQL('wall_db')
    query= "SELECT users.first_name, users.last_name, messages.created_at, messages.message, messages.id, users.id AS id_user_del FROM users JOIN messages ON users.id=messages.users_id ORDER BY messages.created_at DESC;"
    # data = {"id": session['id']}
    result_msg=mysql.query_db(query)
    print('+++++++++++++++result_msg++++++++++++++++++++++', result_msg)

    if len(result_msg)==0:
        first_name=''
    else:
        first_name=result_msg[0]['first_name']
   
    # display comments
    mysql = connectToMySQL('wall_db')
    query= "SELECT users.first_name, users.last_name, comments.id, comments.comment, comments.messages_id, comments.created_at, users.id AS id_user_del FROM users JOIN comments ON users.id=comments.users_id JOIN messages ON comments.messages_id=messages.id ORDER BY comments.created_at;"
    result_cmt=mysql.query_db(query)
    print('*************result_s_msg********************', result_cmt)

    return render_template("wall.html", result_msg=result_msg, result_cmt = result_cmt)



@app.route('/add_msg', methods=['POST'])
def add_msg():  

    if request.method != 'POST':
        return redirect('/')

    print('^^^^^Testingggggggggg^^^^^^^^^^^^^^^^^^^^^', request.form)
    print('^^^^^Testingggggggggg^^^^^^^^^^^^^^^^^^^^^', request.form['message'])
    data = {
        'message': request.form['message'],
        'users_id': session['id']
    }
    query= "INSERT INTO messages (message, users_id, created_at) VALUES (%(message)s, %(users_id)s, Now());"
    mysql = connectToMySQL('wall_db')
    mysql.query_db(query, data)
    print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
    return redirect('/wall')

@app.route('/add_cmt/<msg_id>', methods=['POST'])
def add_cmt(msg_id):  

    if request.method != 'POST':
        return redirect('/')
    data = {
        'comment': request.form['comment'],
        'users_id': session['id'],
        'messages_id': msg_id
    }
    query= "INSERT INTO comments (comment, users_id, messages_id, created_at) VALUES (%(comment)s, %(users_id)s, %(messages_id)s, Now());"
    mysql = connectToMySQL('wall_db')
    mysql.query_db(query, data)
    print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
    return redirect('/wall')

@app.route('/del_msg/<msg_id>')
def del_msg(msg_id):  
    print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
    query = "DELETE FROM messages WHERE messages.id = %(msg_id)s"
    data = {
        'msg_id': msg_id
    }
    mysql = connectToMySQL('wall_db')
    mysql.query_db(query, data)
    return redirect('/wall')

@app.route('/del_cmt/<cmt_id>')
def del_cmt(cmt_id):  
    print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
    query = "DELETE FROM comments WHERE comments.id = %(cmt_id)s"
    data = {
        'cmt_id': cmt_id
    }
    mysql = connectToMySQL('wall_db')
    mysql.query_db(query, data)
    return redirect('/wall')

if __name__ == "__main__":
    app.run(debug = True)


