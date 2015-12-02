from flask import (
    render_template,
    url_for,
    request,
    redirect,
    flash,
    jsonify,
    make_response
)

from catalog_app import app, session

from catalog_app.forms import NewItem, EditItem, CategoryForm

from database_setup import User, Category, Item

from flask import session as login_session

from oauth2client.client import (
    flow_from_clientsecrets,
    FlowExchangeError,
    OAuth2Credentials
)

import httplib2
import requests
import random
import string
import json
import os


@app.route('/')
def index():
    categories = getAllCategories()
    return render_template('index.html', categories=categories)


########
# CRUD #
########


############
# Category #
############
# Obs.: Category does not have an edit route on purpose.
# Considering that any one can register an item to a category, it wouldn't make
# sense if suddenly the category could be edited.
# Further to this, a category does not reference it's creator and may be
# deleted by anyone if, and only if, it does not have any items attached to it.


# CREATE
@app.route('/catalog/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect(url_for('login'))
    # Create the WTForm
    form = CategoryForm(request.form)
    if request.method == 'POST' and form.validate():
        # If it's a post and the form is valid, we format the title and Create
        # the new category
        new_category = Category(
            title=' '.join(
                name.capitalize() for name in form.title.data.split()
            )
        )
        session.add(new_category)
        session.commit()
        flash("New category %s successfully created!" % new_category.title)
        return redirect(url_for('index'))
    else:
        return render_template('newcategory.html', form=form)


# READ
@app.route('/catalog/<int:category_id>/')
def showCategory(category_id):
    # We still need all categories here to show the categories sidebar
    categories = getAllCategories()
    category = getCategoryInfo(category_id)
    # get the category items for display
    items = getCategoryItems(category_id)
    # we will let jinja know if there aren't items in this category, so it may
    # render the delete button
    is_empty = not items
    return render_template(
        'category.html',
        categories=categories,
        category=category,
        items=items,
        is_empty=is_empty
    )


# DELETE
@app.route('/catalog/<int:category_id>/delete', methods=['GET', 'POST'])
def deleteCategory(category_id):
    category = getCategoryInfo(category_id)
    # we still need to check for the emptiness of the category so we may
    # protect categories that are not empty from deletion
    items = getCategoryItems(category_id)
    is_empty = not items
    # protect not empty categories and restrict to logged in users
    if 'username' in login_session and is_empty:
        if request.method == 'GET':
            return render_template('deletecategory.html', category=category)
        else:
            session.delete(category)
            session.commit()
            flash("Successfully deleted category %s" % category.title)
            return redirect(url_for('index'))
    return unauthorizedAccess()


################
# End Category #
################


########
# Item #
########


# CREATE
@app.route('/catalog/<int:category_id>/new', methods=['GET', 'POST'])
def newItem(category_id):
    # restrict item creation to logged in users
    if 'username' not in login_session:
        return redirect(url_for('login'))

    category = getCategoryInfo(category_id)
    # create the WTForm
    form = NewItem(request.form)
    # The picture is mandatory, but we need to pass it separately to WTForm as
    # the constructor only receives the form itself..
    if request.files:
        form.picture.data = request.files['picture']
    if request.method == 'POST' and form.validate():
        # After validating the form, we build the item object with the
        # formatted title and with an empty string for the picture.
        # We need to do this because we will use the item id to save the
        # picture.
        new_item = Item(
            title=' '.join(
                name.capitalize() for name in form.title.data.split()
            ),
            description=form.description.data,
            picture='',
            category_id=category.id,
            user_id=login_session['user_id']
        )
        session.add(new_item)
        session.commit()
        # Now that we have the new item id, we save the picture and update the
        # item with the picture path
        path = saveItemPicture(form.picture.data, new_item.id)
        new_item.picture = path
        session.add(new_item)
        session.commit()
        flash("Added %s to %s!" % (new_item.title, category.title))
        return redirect(url_for('showCategory', category_id=category.id))
    else:
        return render_template(
            'newitem.html',
            category=category,
            form=form
        )


# READ
@app.route('/catalog/<int:category_id>/<int:item_id>/')
def showItem(category_id, item_id):
    category = getCategoryInfo(category_id)
    item = getItemInfo(item_id)
    # We need to check if the user is the owner (creator) of the item.
    # If this is the case, jinja will render the edit and delete buttons.
    is_owner = False
    if 'user_id' in login_session:
        is_owner = (item.user_id == login_session['user_id'])
    return render_template(
        'item.html',
        category=category,
        item=item,
        is_owner=is_owner
    )


# UPDATE
@app.route(
    '/catalog/<int:category_id>/<int:item_id>/edit',
    methods=['GET', 'POST']
)
def editItem(category_id, item_id):
    item = getItemInfo(item_id)
    category = getCategoryInfo(category_id)
    # Only the item creator may edit it
    if (item.user_id == login_session['user_id']):
        # Create the WTForm
        form = EditItem(request.form)
        # Same as for the newItem.. we need to pass the file separately
        # The difference is that this time it is not mandatory (only one of
        # the fields are required for editing the item)
        if request.files:
            form.picture.data = request.files['picture']
        if request.method == 'POST' and form.validate():
            # We check which fields have been submitted for editing the item
            # If we have a new title, format it accordingly
            if form.title.data:
                item.title = ' '.join(
                    name.capitalize() for name in form.title.data.split()
                )
            if form.description.data:
                item.description = form.description.data
            if form.picture.data:
                item.picture = saveItemPicture(form.picture.data, item.id)
            session.add(item)
            session.commit()
            flash("Succesfully edited item %s" % item.title)
            return redirect(
                url_for(
                    'showItem',
                    category_id=category_id,
                    item_id=item.id
                )
            )
        return render_template(
            'edititem.html',
            category=category,
            item=item,
            form=form
        )
    return unauthorizedAccess()


# DELETE
@app.route(
    '/catalog/<int:category_id>/<int:item_id>/delete',
    methods=['GET', 'POST']
)
def deleteItem(category_id, item_id):
    item = getItemInfo(item_id)
    category = getCategoryInfo(category_id)
    # Only the item creator may delete it
    if (item.user_id == login_session['user_id']):
        if request.method == 'GET':
            return render_template(
                'deleteitem.html',
                category=category,
                item=item
            )
        else:
            # Before deleting the item from the db, we delete it's picture file
            deleteItemPicture(item.picture)
            session.delete(item)
            session.commit()
            flash("Successfully deleted item %s" % item.title)
            return redirect(url_for('showCategory', category_id=category.id))
    return unauthorizedAccess()


############
# End Item #
############


########
# User #
########
# Obs.: A user may not be editted. Considering that we are relying on the
# information passed to us by the OAuth provider, it doesn't make sense to
# alter such information.


# CREATE
# No route here, as we do not have our own auth implementation
def createUser(login_session):
    ''' Method for creating an user from the login_session

    This method should be called after the successful completion of the oauth
    flow and consequent acquisition of the required user info:
        - username
        - email
        - picture
    '''
    # We are presuming that the username and email will be formatted correctly
    new_user = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture']
    )
    session.add(newUser)
    session.commit()
    user = getUserByEmail(login_session['email'])
    return user.id


# READ
@app.route('/user/<int:user_id>')
def showUser(user_id):
    # Only the user may have access to it's profile
    if (user_id == login_session['user_id']):
        user = session.query(User).filter_by(id=user_id).one()
        return render_template('user.html', user=user)
    return unauthorizedAccess()


# Second page of the profile. Displays all items created by the user
@app.route('/user/<int:user_id>/items')
def showUserItems(user_id):
    # Again, only the user has access to this page
    if (user_id == login_session['user_id']):
        user = getUserInfo(user_id)
        items = getUserItems(user_id)
        return render_template('useritems.html', user=user, items=items)
    return unauthorizedAccess()


# DELETE
@app.route('/user/<int:user_id>/delete', methods=['GET', 'POST'])
def deleteUser(user_id):
    # Only the user may delete it's profile
    if (user_id == login_session['user_id']):
        user = getUserInfo(user_id)
        if request.method == 'GET':
            return render_template('deleteuser.html', user=user)
        session.delete(user)
        session.commit()
        flash("Successfully deleted user")
        return redirect(url_for('logout'))
    return unauthorizedAccess()


############
# End user #
############


############
# End CRUD #
############


#############
# JSON APIs #
#############


@app.route('/catalog/categories')
def categoryJSON():
    ''' Route responsible for returning a json containing all categories
    '''
    categories = getAllCategories()
    return jsonify(Categories=[c.serialize for c in categories])


@app.route('/catalog/<int:category_id>/items')
def categoryItemsJSON(category_id):
    ''' Route responsible for returning a json containing all items in a
    category
    '''
    category_items = getCategoryItems(category_id)
    return jsonify(Items=[i.serialize for i in category_items])


#################
# End JSON APIs #
#################


#################
# Login / OAuth #
#################


@app.route('/login')
def login():
    if 'username' not in login_session:
        state = ''.join(
            random.choice(string.ascii_uppercase + string.digits)
            for x in xrange(32)
        )
        login_session['state'] = state
        return render_template('login.html', STATE=login_session['state'])
    flash('You are already logged in!!!')
    return redirect(url_for('index'))


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    ''' Generic log out method
    '''
    # first check if the login session is dully poppulated
    if 'provider' in login_session:
        # check the provider, invalidate the respective token and clear
        # provider specific settings from the login_session
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']

        # then we clear the common stuff from the login_session
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash('Successfully logged out!')

    else:
        flash('You are not logged in..')

    # in any case, we will redirect to the start page
    return redirect(url_for('index'))


##########
# Google #
##########


@app.route('/gconnect', methods=['POST'])
def gconnect():
    ''' Method responsible for implementing google oauth exchange flow
    '''
    # check if the state is valid
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # if so, grab the exchange token acquired by the JS SDK
    code = request.data
    try:
        # try to exchange the token for the credentials
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # if sucessful, we now have an access_token
    access_token = credentials.access_token

    # validate the access_token
    url = (
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
        % access_token
    )
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # check if we got no errors or any odd result
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    client_id = json.loads(
        open('client_secrets.json', 'r').read())['web']['client_id']
    if result['issued_to'] != client_id:
        response = make_response(
            json.dumps("Token's client ID does not match app's"), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    # just a double check to see if the user is not already logged in
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # all tests passed, store the credentials
    login_session['credentials'] = credentials.to_json()
    login_session['gplus_id'] = gplus_id

    # get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    # populate the login_session
    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]
    login_session['provider'] = 'google'

    # check if email already exists on the db. if not, create a new user
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    flash("Successfully logged in as %s" % login_session['username'])
    return render_template('successfullogin.html')


@app.route('/gdisconnect')
def gdisconnect():
    ''' Method for invalidating stored google's access token
    '''
    credentials = OAuth2Credentials.from_json(login_session.get('credentials'))
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    return result


##############
# End Google #
##############


############
# Facebook #
############


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    ''' Method responsible for implementing Facebook oauth flow
    '''
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # get exchange token acquired from the js sdk
    access_token = request.data

    # get the app_id and app_secret from the json file
    app_id = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']

    # url for exchanging the exchange token for the access token
    url = (
        "https://graph.facebook.com/oauth/access_token?"
        "grant_type=fb_exchange_token&"
        "client_id=%s&client_secret=%s&fb_exchange_token=%s" %
        (app_id, app_secret, access_token)
    )
    # request the access token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # access_token
    token = result.split("&")[0]

    # url for requesting the user info
    userinfo_url = "https://graph.facebook.com/v2.5/me"

    # we add the fields option so we only need to make one request
    url = '%s?fields=name,email,picture&%s' % (userinfo_url, token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # now our result contains all the information we need to populate the
    # login_session
    # print 'result: %s'%result
    data = json.loads(result)

    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']
    login_session['picture'] = data["picture"]["data"]["url"]
    login_session['provider'] = 'facebook'

    # check if there is a user with this email on the db
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    flash("Successfully logged in as %s" % login_session['username'])
    return render_template('successfullogin.html')


@app.route('/fbdisconnect')
def fbdisconnect():
    '''Method for invalidating the stored facebook access token
    '''
    facebook_id = login_session['facebook_id']
    url = 'https://graph.facebook.com/%s/permissions' % facebook_id
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]


################
# End Facebook #
################


#####################
# End Login / OAuth #
#####################


####################
# Querying helpers #
####################


def getCategoryInfo(category_id):
    ''' Returns the category object given it's id
    '''
    category = session.query(Category).filter_by(id=category_id).one()
    return category


def getAllCategories():
    ''' Returns all categories
    '''
    categories = session.query(Category).all()
    return categories


def getCategoryItems(category_id):
    ''' Returns all items of a category, given it's id
    '''
    items = session.query(Item).filter_by(category_id=category_id).all()
    return items


def getItemInfo(item_id):
    ''' Returns an item object, given it's id
    '''
    item = session.query(Item).filter_by(id=item_id).one()
    return item


def getUserInfo(user_id):
    ''' Returns an user object, given it's id
    '''
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserByEmail(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return User
    except:
        return None


def getUserID(email):
    ''' Returns an user's id, given it's email.

    This method is used by the oauth login methods to check if there's an
    user with the received email.
    '''
    user = getUserItems(email)
    try:
        return user.id
    except:
        return None


def getUserItems(user_id):
    ''' Returns all items of an user, given it's id
    '''
    items = session.query(Item).filter_by(user_id=user_id).all()
    return items


########################
# End Querying helpers #
########################


###################
# Generic helpers #
###################


def unauthorizedAccess():
    ''' Default unauthorized access message method.
    '''
    response = make_response(json.dumps('Unauthorized access'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response


def saveItemPicture(picture, item_id):
    ''' Method for saving the item's picture and returnning the relative path
        to be stored in the item object in the database row.

        This method is called both when creating and editing an item with a new
        picture. We chose to allow a item to have one single picture. In case,
        an item is updated with a new picture, we first delete the old one and
        save the new.
    '''
    # the filename will simply be the item's id (followed by the original file
    # extension)
    filename = '.'.join(
        (
            str(item_id),
            picture.filename.rsplit('.')[1]
        )
    )
    # we then build the relative path that will be returned by the function
    # and pass it to the delete item picture method
    relative_path = '/'.join(('images', filename))

    # the deleteItemPicture method will try to delete any already existing
    # picture for the item, before saving the new one
    deleteItemPicture(relative_path)

    # make the full path (upload_folder + filename) and save the file
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    picture.save(full_path)

    return relative_path


def deleteItemPicture(relative_path):
    ''' Method for deleting an item's picture.
        This method is called when creating, editing or deleting an item.

        We need relative_path here because it's the info we get from the item
        row in the database.
    '''
    # builds the full_path from the filename and the upload folder configured
    # in __init__.py
    full_path = os.path.join(
        app.config['UPLOAD_FOLDER'], relative_path.split('/')[1]
    )
    # tries to delete and if it fails (in case the file does not exist, for
    # example), it simply passes
    try:
        os.remove(full_path)
    except OSError:
        pass


#######################
# End Generic helpers #
#######################
