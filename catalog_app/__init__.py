from flask import Flask
from instance.secret import install_secret_key
from flask_bootstrap import Bootstrap
from flask_wtf.csrf import CsrfProtect
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item


app = Flask(__name__)
# images upload folder
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/images/')
# script for generating random secret key and configuring it for the app
install_secret_key(app)
# needed for wtf.quick_form
Bootstrap(app)
# csrf protection for formless views and ajax requests
CsrfProtect(app)


# create the session here so we can import it easily from other places
engine = create_engine('sqlite:///catalog_app/catalog_app.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


import catalog_app.project
