# gunicorn.conf.py
bind = "0.0.0.0:5000"
workers = 1
wsgi_app = "null_idp:app"

# Access log - records incoming HTTP requests
accesslog = "/var/log/null-idp/gunicorn.access.log"

# Error log - records Gunicorn server goings-on
errorlog = "/var/log/null-idp/gunicorn.error.log"

# Whether to send python output to the error log
capture_output = True

# How verbose the Gunicorn error logs should be
loglevel = "info"

# SSL key and cert for your domain
keyfile = "./ssl/null-idp.key"
certfile = "./ssl/null-idp.crt"