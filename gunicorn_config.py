# gunicorn_config.py

import multiprocessing

# Bind to the IP and port where your application should listen.
bind = "0.0.0.0"  # Replace with your desired IP and port.

# Number of Gunicorn worker processes to spawn.
# Adjust as needed based on your server's resources.
workers = multiprocessing.cpu_count() * 2 + 1

# Set the worker class to use. 'gevent' and 'eventlet' are alternative worker classes
# that can be more efficient for I/O-bound applications. The default is 'sync'.
worker_class = "sync"

# Number of worker threads per worker process. Adjust as needed.
threads = 2

# Specify your Flask application's entry point (usually the app variable in your app.py).
# Replace 'app_name' with your actual application's name.
# You can also specify the Python module that contains your app using the syntax 'module:app'.
app = "app:app"

# Enable or disable daemon mode. Daemon mode runs Gunicorn in the background.
daemon = False

# Set the location of Gunicorn's error log.
errorlog = "/var/log/gunicorn/error.log"  # Adjust the path as needed.

# Set the location of Gunicorn's access log.
accesslog = "/var/log/gunicorn/access.log"  # Adjust the path as needed.

# Enable access log format. Common options are "combined", "common", "short", and "tiny".
# You can also specify your custom log format.
access_log_format = "%(h)s %(l)s %(u)s %(t)s \"%(r)s\" %(s)s %(b)s \"%(f)s\" \"%(a)s\""

# Configure the maximum number of requests a worker will process before restarting.
max_requests = 1000

# Configure the maximum number of requests a worker will process before graceful restart.
max_requests_jitter = 50

# Set the timeout for requests (in seconds). Adjust as needed.
timeout = 60

# Enable keep-alive connections.
keepalive = 2

# Set the maximum number of headers that the server will accept.
max_request_header_size = 8192

# Set the maximum size of the request body.
max_request_body_size = 1048576  # 1 MB

# Preload the application before the worker processes are forked.
preload_app = True

# Disable worker process auto-reloading.
reload = False
