#from gevent import monkey
#monkey.patch_all()
from flask_sqlalchemy import SQLAlchemy

from interlex.core import run_curies
app = run_curies()
