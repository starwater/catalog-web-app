from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from database_setup import Base, Category, Category_Item, User
from flask import session as flask_session
import random, string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"

engine = create_engine('sqlite:///categories.db', connect_args={'check_same_thread': False}, echo=True)
Base.metadata.bind = engine
DBSession = scoped_session(sessionmaker(bind=engine))
session = DBSession()


# decorator, wraps our function inside / if / or /hello is execute in the browser, then def HelloWorld will be executed
@app.route('/')
def index():
    category = session.query(Category)
    return render_template('catelog.html', category=category, flask_session=flask_session)

@app.route('/catalog/<int:id>')
def cataloglist(id):
    items = session.query(Category_Item).filter_by(category_id=id)
    return render_template('item.html', items=items, cid=id, flask_session=flask_session)


@app.route('/item/<int:id>')
def item_desc(id):
    item = session.query(Category_Item).filter_by(id=id)
    return render_template('item_desc.html', item=item, flask_session=flask_session)

# takes in category_id and add the correspond list
# directs to the create page and pass in the selected category
@app.route('/create/<int:id>', methods=['GET', 'POST'])
def newitem(id):
    if request.method == 'POST':
        newitem = Category_Item(
            name=request.form['name'],
            description=request.form['desc'],
            category_id=id,
            author_id=flask_session['user_id']
        )
        session.add(newitem)
        session.commit()
        flash('new item created!')
        return redirect(url_for('index'))
    else:
        category = session.query(Category).filter_by(id=id).first()
        return render_template('create.html', id=id, cname=category.name)


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    # return "search in the query, update the info, then redirect to index page"
    if request.method == 'POST':
        edit = session.query(Category_Item).filter_by(id=id).one()
        edit.name = request.form['name']
        edit.description = request.form['desc']
        session.add(edit)
        session.commit()
        return redirect(url_for('index'))
    else:
        item = session.query(Category_Item).filter_by(id=id).one()
        # render edit page and pass in the obj data to set default value of the edit page
        return render_template('edit.html', item=item)


@app.route('/delete/<int:id>', methods=['GET', 'POST'])
def deleteItem(id):
    item = session.query(Category_Item).filter_by(id=id).one()
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        return redirect(url_for('index'))
    else:
        return render_template('delete.html', item=item)


@app.route('/catalog/<int:id>/JSON', methods=['GET'])
def cat_json(id):
    items = session.query(Category_Item).filter_by(category_id=id)
    return jsonify(Category_Item=[i.serialize for i in items])


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # check if the username exists
        find = session.query(User).filter_by(username=request.form['username']).first()
        if not find:
            newUser = User(username=request.form['username'], password=request.form['password'])
            session.add(newUser)
            session.commit()
            flash('You account is created!')
        # add new user to the database
        # redirect to the main page
        return redirect(url_for('index'))
        # password invalid not yet implemented
    else:
        print('GET method called, return to register page')
        return render_template('register.html')

# def category(id):
#     category = session.query(Category_Item).filter_by(category_id=id)
#     return render
# @app.route('/login')
# def login():
#     state = ''.join(random.choice(string.ascii_uppercase + string.digits)
#                     for x in range(32))
#     flask_session['state'] = state
#     return "The current session state is %s" % flask_session['state']
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = session.query(User).filter_by(username=request.form['username']).one()
        if user.password == request.form['password']:
            flask_session['username'] = user.username
            flask_session['user_id'] = user.id
            flash('Welcome back!'+user.username)
            return redirect(url_for('index'))
        else:
            flash('Error, invalid credentials!')
            return redirect(url_for('login'))
    else:
        return render_template('login.html')


@app.route('/logout')
def logout():
    flask_session.clear()
    return redirect(url_for('index'))

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != flask_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = flask_session.get('access_token')
    stored_gplus_id = flask_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    flask_session['access_token'] = credentials.access_token
    flask_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = request.get(userinfo_url, params=params)

    data = answer.json()

    flask_session['username'] = data['name']
    flask_session['picture'] = data['picture']
    flask_session['email'] = data['email']

    user_id = getUserID(flask_session['email'])
    if not user_id:
        user_id = createUser(flask_session)
    flask_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += flask_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += flask_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % flask_session['username'])
    print("done!")
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = flask_session.get('access_token')
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ')
    print(flask_session['username'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % flask_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print(result)
    if result['status'] == '200':
        del flask_session['access_token']
        del flask_session['gplus_id']
        del flask_session['username']
        del flask_session['email']
        del flask_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


def createUser(login_session):
    newUser = User(name=login_session['username'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# do this if execute with python interpreter, if import to other files, dont do this
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True  # reload itself each time it detects a code change
    # listen on all public ip addresses
    app.run(host='10.128.0.2', port=80)
