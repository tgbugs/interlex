import pytest
from time import time
from interlex.config import auth
from interlex.core import getScopedSession, dbUri
from interlex.dump import Queries
from interlex.utils import log


@pytest.mark.skip('manual test')
def test_psycopg_compat(test=False):
    kwargs = {k:auth.get(f'test-{k}'
                        if test and k != 'user' else
                        f'db-{k}')
            for k in ('user', 'host', 'port', 'database')}
    kwargs['dbuser'] = kwargs.pop('user')
    dburis = dbUri(**kwargs), dbUri(**kwargs, dialect='psycopg')
    sessions = []
    for dburi in dburis:
        log.info(dburi)
        session = getScopedSession(dburi=dburi, echo=True, query_cache_size=0)
        sessions.append(session)
        queries = Queries(session)
        wat0 = queries.getGroupPers('tgbugs', 'npo')
        wat1 = queries.getGroupIds('tgbugs', 'npo')
        wat2 = queries.getExistingIrisForIlxId('0101431')
        wat3 = list(queries.tripleIdentityOld(2, 3, 4))
        #breakpoint()

    #breakpoint()


@pytest.mark.skip('manual test')
def test_vervar(test=False):
    kwargs = {k:auth.get(f'test-{k}'
                        if test and k != 'user' else
                        f'db-{k}')
            for k in ('user', 'host', 'port', 'database')}
    kwargs['dbuser'] = kwargs.pop('user')
    dburi = dbUri(**kwargs)
    log.info(dburi)
    session = getScopedSession(dburi=dburi, echo=True, query_cache_size=0)
    queries = Queries(session)
    start0 = time()
    wat0 = queries.getVerVarBySubject('http://uri.interlex.org/base/ilx_0101431')
    stop0 = time()

    start1 = time()
    wat1 = queries._getVerVarBySubject('http://uri.interlex.org/base/ilx_0101431')
    stop1 = time()

    new = stop0 - start0
    old = stop1 - start1
    print(f'old: {old} new: {new}')
    assert sorted([tuple(t) for t in sorted(wat0)[0]]) == sorted([tuple(t) for t in sorted(wat1)[0]])
    assert sorted([tuple(t) for t in sorted(wat0)[1]]) == sorted([tuple(t) for t in sorted(wat1)[1]])
    assert sorted([tuple(t) for t in sorted(wat0)[2]]) == sorted([tuple(t) for t in sorted(wat1)[2]])
    assert sorted([tuple(t) for t in sorted(wat0)[3]]) == sorted([tuple(t) for t in sorted(wat1)[3]])  # somehow the sort order on this is different before and after conversion to tuple ...
    #breakpoint()
    pass
