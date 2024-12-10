import os
from sqlalchemy import create_engine
from sqlalchemy.orm.session import sessionmaker
from interlex import config
from interlex.core import dbUri

# remember to only import this once somehow ...

#os.system(f'interlex-dbsetup 54321 {testingdb}')

# TODO interlex-user tests ...

def getSession(dburi=dbUri(dbuser='interlex-admin',
                           database=config.test_database,
                           port=config.test_database_port,),
               echo=False):
    engine = create_engine(dburi)
    engine.echo = echo

    Session = sessionmaker()
    Session.configure(bind=engine)
    session = Session()
    return session
