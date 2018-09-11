import os
from sqlalchemy import create_engine
from sqlalchemy.orm.session import sessionmaker
from interlex import config
from interlex.core import dbUri

# remember to only import this once somehow ...

#os.system(f'interlex-dbsetup 54321 {testingdb}')

# TODO interlex-user tests ...

def getSession(dburi=dbUri(user='interlex-admin',
                           database=config.test_database)):
    engine = create_engine(dburi)

    Session = sessionmaker()
    Session.configure(bind=engine)
    session = Session()
    return session
