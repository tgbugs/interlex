import unittest
from pathlib import Path
from sqlalchemy.exc import IntegrityError
from pyontutils.config import devconfig  # FIXME this will cause issues down the line
from test.test_stress import nottest  # FIXME put nottest in test utils


class TestSQLs(unittest.TestCase):
    def setUp(self):
        self.positive_f = Path(devconfig.git_local_base, 'interlex/sql/test.sql')
        self.negative_f = Path(devconfig.git_local_base, 'interlex/sql/test-fail.sql')

    @staticmethod
    def load_sql(path):
        with open(path.as_posix(), 'rt') as f:
            raw = f.read()
        for maybe_test in raw.split('\n\n'):
            in_comment = False
            test = []
            for line in maybe_test.split('\n'):
                if line.strip().startswith('--'):
                    # FIXME I was doing something tricksy with moving -- in a space
                    # to prevent something from triggering ...
                    continue
                elif line.startswith('/*'):
                    in_comment = True
                elif line.endswith('*/'):
                    in_comment = False
                elif in_comment:
                    continue
                elif line:
                    test.append(line)

            if test:
                yield '\n'.join(test)
        
    @nottest
    def test_positive(self):
        from test.setup_testing_db import session
        failed = []
        for test in self.load_sql(self.positive_f):
            try:
                session.execute(test)
            except BaseException as e:
                session.rollback()
                failed.append((test, e))

        if failed:
            sep = '=' * 40
            raise AssertionError('\n' +
                                 f'\n{sep}\n'.join((f'test:\n\n{t}\n\nerror:\n\n{e}\n'
                                                    for t, e in failed)))

    @nottest
    def test_negative(self):
        from test.setup_testing_db import session
        for test in self.load_sql(self.negative_f):
            try:
                session.execute(test)
                raise AssertionError(test)
            except (IntegrityError, ) as e:
                print(e.orig.pgerror)
                session.rollback()
