from pyontutils.utils import setPS1
#from gevent import monkey
#monkey.patch_all()
from flask_sqlalchemy import SQLAlchemy

setPS1(__file__)

from interlex.core import run_curies
app = run_curies()
