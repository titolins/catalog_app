USER = 'catalog'
PASSWORD = 'n43t20h8'
DRIVER = 'psycopg2'
DB = 'catalog_app'

def config_db_string(app):
    app.config['DB_STRING'] = "postgresql+%s://%s:%s@localhost/%s" \
        % (DRIVER, USER, PASSWORD, DB,)

def get_db_string():
    return "postgresql+%s://%s:%s@localhost/%s" \
        % (DRIVER, USER, PASSWORD, DB,)
    
