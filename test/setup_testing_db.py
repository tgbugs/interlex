import os
from sqlalchemy import create_engine
from sqlalchemy.orm.session import sessionmaker
from interlex.core import dbUri

# remember to only import this once somehow ...

testingdb = '__interlex_testing'

#os.system(f'interlex-dbsetup 54321 {testingdb}')

def getSession(dburi=dbUri(database=testingdb)):
    engine = create_engine(dburi)

    Session = sessionmaker()
    Session.configure(bind=engine)
    session = Session()
    return session

session = getSession()
