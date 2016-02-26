
def config_logger(app):
    if not app.debug:
        import logging
        from logging.handlers import RotatingFileHandler
        handler = RotatingFileHandler(
            'log/python.log',maxBytes=1024*1024*100, backupCount=20)
        formatter = logging.Formatter(
            ("[%(asctime)s]",
            "{%(pathname)s:%(lineno)d} %(levelname)s - %(message)s"))
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        app.logger.addHandler(handler)
        # get werkzeug logger too
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.DEBUG)
        log.addHandler(handler)

