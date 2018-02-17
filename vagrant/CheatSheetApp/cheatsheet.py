# THIS IS AN APPLICATION FOR DISPLAYING ITEMS FROM A CATALOG
# IT INCLUDES OAUTH AND CRUD OPERATIONS ASWELL AS API ENDPOINTS
from flask import Flask, render_template, request
from flask import redirect, jsonify, url_for, flash, g, make_response
from sqlalchemy import create_engine, asc, func, desc
from sqlalchemy.orm import sessionmaker
from models import Base, User, Category, Concept, Links
from flask import session as login_session
from functools import update_wrapper
import os
import random
import string
import httplib2
import json
import requests
import time
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from redis import Redis

app = Flask(__name__)
redis = Redis()

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Code Cheat Sheet App"

# Connect to Database and create database session
engine = create_engine('sqlite:///codeCheatSheet.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Define RateLimit Class
class RateLimit(object):
    expiration_window = 10

    def __init__(self, key_prefix, limit, per, send_x_headers):
        self.reset = (int(time.time()) // per) * per + per
        self.key = key_prefix + str(self.reset)
        self.limit = limit
        self.per = per
        self.send_x_headers = send_x_headers
        p = redis.pipeline()
        p.incr(self.key)
        p.expireat(self.key, self.reset + self.expiration_window)
        self.current = min(p.execute()[0], limit)

    remaining = property(lambda x: x.limit - x.current)
    over_limit = property(lambda x: x.current >= x.limit)


def get_view_rate_limit():
    return getattr(g, '_view_rate_limit', None)


def on_over_limit(limit):
    return (jsonify({'data': 'You hit the rate limit', 'error': '429'}), 429)


def ratelimit(limit, per=300, send_x_headers=True,
              over_limit=on_over_limit,
              scope_func=lambda: request.remote_addr,
              key_func=lambda: request.endpoint):
    def decorator(f):
        def rate_limited(*args, **kwargs):
            key = 'rate-limit/%s/%s/' % (key_func(), scope_func())
            rlimit = RateLimit(key, limit, per, send_x_headers)
            g._view_rate_limit = rlimit
            if over_limit is not None and rlimit.over_limit:
                return over_limit(rlimit)
            return f(*args, **kwargs)
        return update_wrapper(rate_limited, f)
    return decorator


@app.after_request
def inject_x_rate_headers(response):
    limit = get_view_rate_limit()
    if limit and limit.send_x_headers:
        h = response.headers
        h.add('X-RateLimit-Remaining', str(limit.remaining))
        h.add('X-RateLimit-Limit', str(limit.limit))
        h.add('X-RateLimit-Reset', str(limit.reset))
    return response


@app.route('/rate-limited')
@ratelimit(limit=300, per=30 * 1)
def index():
    return jsonify({'response': 'This is a rate limited response'})


# Login
# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


#  Facebook Connect
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token\
            &client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
            app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange
        we have to split the token first on commas and select the first index
        which gives us the key : value for the server access token then
        we split it on colons to pull out the actual token value and replace
        the remaining quotes with nothing so that it can be used directly
        in the graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s\
            &fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s\
            &redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h3>Welcome, '
    output += login_session['username']

    output += '!</h3>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style="width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


# Facebook Disconnect
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
            facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "You have been logged out!"


# Google Connect
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
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
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
                                'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = json.loads(answer.text)

    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h3>Welcome, '
    output += login_session['username']
    output += '!</h3>'
    output += '<img src="'
    output += login_session['picture']
    output += ''' " style = "width: 300px; height: 300px; border-radius:
                150px;-webkit-border-radius:
                150px;-moz-border-radius: 150px;"> '''
    flash("You are now logged in as %s" % login_session['username'])
    print "Done!"
    return output

# User Helper Functions


# Create User info in Database
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# Get User Info from Database
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# Get User ID from Database
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except(ValueError):
        return None


# GOOGLE DISCONNECT - Revoke a current user's token and reset their
# login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
                    'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            if login_session.get('gplus_id'):
                del login_session['gplus_id']
            if login_session.get('access_token'):
                del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        if login_session.get('username'):
            del login_session['username']
        if login_session.get('email'):
            del login_session['email']
        if login_session.get('picture'):
            del login_session['picture']
        if login_session.get('user_id'):
            del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('getCategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('getCategories'))


# Append a timestamp to any url_for('static') CSS Link to bypass Browser Cache
@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)


def dated_url_for(endpoint, **values):
    if endpoint == 'static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(app.root_path,
                                     endpoint, filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    return url_for(endpoint, **values)


# Get all categories
@app.route('/')
@app.route('/categories/')
def getCategories():
    stmt = session.query(Concept.category_id, func.count(Concept.category_id)
                         .label('concept_count')).group_by(
                         Concept.category_id).subquery()
    categories = session.query(
                    Category, stmt.c.concept_count).outerjoin(
                    stmt, Category.id == stmt.c.category_id).order_by(
                    asc(Category.name))
    concepts = session.query(Concept).order_by(desc(
                Concept.id)).limit(30).all()
    return render_template('categories.html',
                           categories=categories,
                           concepts=concepts,
                           stmt=stmt,
                           login_session=login_session)


# JSON APIs to view Category Information
@app.route('/categories/JSON')
def categoriesJSON():
    categories = session.query(Category).order_by(asc(Category.name))
    return jsonify(Categories=[c.serialize for c in categories])


@app.route('/edit_categories')
def getEditCategories():
    categories = session.query(Category).order_by(asc(Category.name))
    user = session.query(User).filter_by(email=login_session['email']).one()
    return render_template('editCategories.html', categories=categories,
                           login_session=login_session, user=user)


# Create new Category
@app.route('/categories/new/', methods=['GET', 'POST'])
@ratelimit(limit=300, per=30 * 1)
def createCategory():
    user = session.query(User).filter_by(email=login_session['email']).one()
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'],
                               picture=request.form['picture'],
                               user_id=user.id)
        session.add(newCategory)
        flash('New Category "%s" Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('getCategories'))
    else:
        return render_template('newCategory.html',
                               login_session=login_session)


# Update Category
@app.route('/categories/<int:category_id>/edit/', methods=['GET', 'POST'])
@ratelimit(limit=300, per=30 * 1)
def editCategory(category_id):
    editedCategory = session.query(
        Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            editedCategory.picture = request.form['picture']
            flash('Successfully Edited "%s"' % editedCategory.name)
            return redirect(url_for('getCategories'))
    else:
        return render_template('editCategory.html', category=editedCategory,
                               login_session=login_session)


# Delete Category
@app.route('/categories/<int:category_id>/delete', methods=['GET', 'POST'])
@ratelimit(limit=300, per=30 * 1)
def deleteCategory(category_id):
    category = session.query(
        Category).filter_by(id=category_id).one()
    concepts = session.query(Concept).filter_by(category_id=category_id).all()
    links = session.query(Links).filter_by(category_id=category_id).all()
    if request.method == 'POST':
        session.delete(category)
        if links:
            session.delete(links)
        if concepts:
            session.delete(concepts)
        session.commit()
        flash('"%s" Successfully Deleted' % category.name)
        return redirect(url_for('getCategories', category_id=category_id))
    else:
        return render_template('deleteCategory.html', category=category,
                               login_session=login_session)


# Get Concepts in Category
@app.route('/categories/<int:category_id>/concepts/',
           methods=['GET', 'POST'])
def getConcepts(category_id):
    categories = session.query(Category).filter_by(id=category_id).one()
    concepts = session.query(Concept).filter_by(category_id=category_id)
    links = session.query(Links).filter_by(category_id=category_id)
    if request.method == 'POST':
        newLink = Links(name=request.form['name'],
                        link=request.form['link'],
                        category_id=category_id)
        session.add(newLink)
        flash('New Link "%s" Successfully Added' % newLink.name)
        session.commit()
        return redirect(url_for('getConcepts', category_id=category_id))
    else:
        return render_template('concepts.html',
                               categories=categories,
                               concepts=concepts,
                               links=links,
                               login_session=login_session)


# JSON APIs to view Category Information
@app.route('/categories/<int:category_id>/concepts/JSON')
def conceptsJSON(category_id):
    if category_id != 0:
        concepts = session.query(Concept).filter_by(category_id=category_id)
    else:
        concepts = session.query(Concept).all()
    return jsonify(Concepts=[c.serialize for c in concepts])


# JSON APIs to view Category Information
@app.route('/categories/<int:category_id>/links/JSON')
def linksJSON(category_id):
    if category_id != 0:
        links = session.query(Links).filter_by(category_id=category_id)
    else:
        links = session.query(Links).all()
    return jsonify(Links=[l.serialize for l in links])


# Create new Concept
@app.route('/categories/<int:category_id>/concepts/new/',
           methods=['GET', 'POST'])
@ratelimit(limit=300, per=30 * 1)
def createConcept(category_id):
    user = session.query(User).filter_by(email=login_session['email']).one()
    if request.method == 'POST':
        newConcept = Concept(name=request.form['name'],
                             description=request.form['definition'],
                             code=request.form['example'],
                             category_id=category_id,
                             user_id=user.id)
        session.add(newConcept)
        flash('New Concept "%s" Successfully Created' % newConcept.name)
        session.commit()
        return redirect(url_for('getConcepts', category_id=category_id))
    else:
        return render_template('newConcept.html', category_id=category_id,
                               login_session=login_session)


# Get Concept List to Update and Delete
@app.route('/categories/<int:category_id>/concepts/edit_concepts/')
@ratelimit(limit=300, per=30 * 1)
def getEditConcepts(category_id):
    concepts = session.query(Concept).filter_by(category_id=category_id)
    user = session.query(User).filter_by(email=login_session['email']).one()
    return render_template('editConcepts.html', concepts=concepts,
                           category_id=category_id,
                           login_session=login_session, user=user)


# Update Concept
@app.route('/categories/<int:category_id>/concepts/<int:concept_id>/edit/',
           methods=['GET', 'POST'])
@ratelimit(limit=300, per=30 * 1)
def editConcept(concept_id, category_id):
    editedConcept = session.query(
        Concept).filter_by(id=concept_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedConcept.name = request.form['name']
            editedConcept.description = request.form['definition']
            editedConcept.code = request.form['example']
            flash('Successfully Edited "%s"' % editedConcept.name)
            return redirect(url_for('getConceptInfo',
                                    concept_id=concept_id,
                                    category_id=category_id))
    else:
        return render_template('editConcept.html',
                               concept=editedConcept,
                               category_id=category_id,
                               login_session=login_session)


# Delete Concept
@app.route('/categories/<int:category_id>/concepts/<int:concept_id>/delete/',
           methods=['GET', 'POST'])
@ratelimit(limit=300, per=30 * 1)
def deleteConcept(concept_id, category_id):
    concept = session.query(
        Concept).filter_by(id=concept_id).one()
    if request.method == 'POST':
        session.delete(concept)
        session.commit()
        flash('"%s" Successfully Deleted' % concept.name)
        return redirect(url_for('getConcepts', category_id=category_id))
    else:
        return render_template('deleteConcept.html',
                               concept=concept,
                               category_id=category_id,
                               login_session=login_session)


# Get Concept information
@app.route('/categories/<int:category_id>/concepts/<int:concept_id>')
def getConceptInfo(concept_id, category_id):
    categories = session.query(Category).filter_by(id=category_id).one()
    concepts = session.query(Concept).filter_by(category_id=category_id)
    conceptInfo = session.query(Concept).filter_by(id=concept_id).one()
    return render_template('conceptInfo.html',
                           categories=categories,
                           concepts=concepts,
                           conceptInfo=conceptInfo,
                           login_session=login_session)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
