import sys, os
sys.stdout = sys.stderr
sys.path.insert(0,'/var/www/catalog_app')
os.chdir('/var/www/catalog_app')
from catalog_app import app as application
