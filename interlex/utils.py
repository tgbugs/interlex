import logging


def makeSimpleLogger(name):
    # TODO use extra ...
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()  # FileHander goes to disk
    formatter = logging.Formatter('[%(asctime)s] - %(levelname)s - '
                                  '%(name)s - '
                                  '%(filename)s:%(lineno)d - '
                                  '%(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger


logger = makeSimpleLogger('ilx_utils')


try:
    from misc.debug import TDB
    tdb=TDB()
    printD=tdb.printD
    #printFuncDict=tdb.printFuncDict
    #tdbOff=tdb.tdbOff
except ImportError:
    logger.info('you do not have tgbugs misc on this system')
    printD = print
