import sys
import os.path


def install_secret_key(app, filename='secret_key'):
    filename = os.path.join(app.instance_path, filename)
    try:
        app.config['SECRET_KEY'] = open(filename, 'rb').read()
    except IOError:
        print 'Error: No secret key. Create it with:'
        if not os.path.isdir(os.path.dirname(filename)):
            print 'mkdir -p', os.path.dirname(filename)
        print 'heade -c 24 /dev/urandom >', filename
        sys.exit(1)
