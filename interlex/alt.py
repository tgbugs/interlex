import socket
from flask import Flask, request, abort
from flask_sqlalchemy import SQLAlchemy
from pyontutils.utils import mysql_conn_helper, TermColors as tc
from pyontutils.core import makeGraph
from pyontutils.namespaces import PREFIXES as uPREFIXES  # FIXME
from interlex import config
from interlex import exc
from interlex.dump import MysqlExport
from interlex.render import TripleRender  # FIXME need to move the location of this


def dbUri(user='nif_eelg_secure', host='nif-mysql.crbs.ucsd.edu', port=3306, database='nif_eelg'):
    DB_URI = 'mysql+pymysql://{user}:{password}@{host}:{port}/{db}'  # FIXME db => pyontutils refactor
    if socket.gethostname() in config.dev_remote_hosts:
        db_cfg_kwargs = mysql_conn_helper('localhost', database, user, 33060)  # see .ssh/config
    else:
        db_cfg_kwargs = mysql_conn_helper(host, database, user, port)

    return DB_URI.format(**db_cfg_kwargs)


def server_alt(db=None, dburi=dbUri()):
    app = Flask('InterLex alt server')
    app.config['SQLALCHEMY_DATABASE_URI'] = dburi
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    database = db
    session = db.session
    ilxexp = MysqlExport(session)

    tripleRender = TripleRender()
    object_to_existing = {}

    @app.route('/base/ilx_<id>')
    def ilx(id):
        user = 'base'  # TODO
        if user == 'base':
            title = f'ILX:{id}'
        else:
            title = f'ilx.{user}:ilx_{id}'

        try:
            tripleRender.check(request)
        except exc.UnsupportedType as e:
            return e.message, e.code

        mgraph = makeGraph('base' + '_export_helper', prefixes=uPREFIXES)
        [mgraph.g.add(t) for t in ilxexp(id)]
        try:
            return tripleRender(request, mgraph, user, id, object_to_existing, title)
        except BaseException as e:
            print(tc.red('ERROR'), e)
            raise e
            return abort(404)

    @app.route('/base/ilx_<id>.<extension>')
    def ilx_get(id, extension):
        return ilx(id)

    return app


def run_alt():
    return server_alt(db=SQLAlchemy())


def main():
    from sqlalchemy import create_engine
    from sqlalchemy.orm.session import sessionmaker
    engine = create_engine(dbUri(), echo=True)
    Session = sessionmaker()
    Session.configure(bind=engine)
    session = Session()

    ilxexp = MysqlExport(session)
    ilx_fragment = 'ilx_0101431'
    trips = list(ilxexp(ilx_fragment))


if __name__ == '__main__':
    main()
