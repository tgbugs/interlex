from pyontutils.utils_fast import makeSimpleLogger

log = makeSimpleLogger('interlex')

try:
    from misc.debug import TDB
    tdb=TDB()
    printD=tdb.printD
    #printFuncDict=tdb.printFuncDict
    #tdbOff=tdb.tdbOff
except ImportError:
    log.info('you do not have tgbugs misc on this system')
    printD = print
