import os
import unittest
import pytest
from pathlib import Path
from sqlalchemy.exc import IntegrityError
from pyontutils.utils import TermColors as tc
from .common import working_dir


class TestSQLs(unittest.TestCase):
    def setUp(self):
        # FIXME share/interlex/sql is from setup.py
        self.positive_f = working_dir / 'sql/test.sql'
        self.negative_f = working_dir / 'sql/test-fail.sql'

    @staticmethod
    def load_sql(path):
        with open(path.as_posix(), 'rt') as f:
            raw = f.read()
        in_comment = False
        for maybe_test in raw.split('\n\n'):
            test = []
            print(tc.blue(maybe_test))
            for line in maybe_test.split('\n'):
                if line.strip().startswith('--'):
                    # FIXME I was doing something tricksy with moving -- in a space
                    # to prevent something from triggering ...
                    continue
                elif line.startswith('/*'):
                    if '*/' in line:
                        continue
                    else:
                        in_comment = True
                elif line.endswith('*/'):
                    in_comment = False
                elif in_comment:
                    continue
                elif line:
                    print(tc.yellow(line))
                    test.append(line)

            if test:
                yield '\n'.join(test)
        
    @pytest.mark.skipif('DBSETUPTEST' not in os.environ, reason='not setting up the database')
    def test_0_positive(self):
        from test.setup_testing_db import getSession
        session = getSession()
        failed = []
        for test in self.load_sql(self.positive_f):
            print(f'++++++++++++++\n{test}')
            try:
                out = session.execute(test)
                if test.startswith('SELECT') or 'RETURNING' in test:
                    print(list(out))
                session.commit()
            except BaseException as e:
                session.rollback()
                failed.append((test, e))

        if failed:
            sep = '=' * 40
            raise AssertionError('\n' +
                                 f'\n{sep}\n'.join((f'test:\n\n{t}\n\nerror:\n\n{e}\n'
                                                    for t, e in failed)))

    @pytest.mark.skipif('DBSETUPTEST' not in os.environ, reason='not setting up the database')
    def test_1_negative(self):
        from test.setup_testing_db import getSession
        session = getSession()
        failed = []
        for test in self.load_sql(self.negative_f):
            try:
                session.execute(test)
                failed.append((test, AssertionError('THIS TEST SHOULD HAVE FAILED')))
                #raise AssertionError(test)
            except (IntegrityError, ) as e:
                print('---------------\nGot expected error:')
                print(e.orig.pgerror)
                session.rollback()

        if failed:
            sep = '=' * 40
            raise AssertionError('\n' +
                                 f'\n{sep}\n'.join((f'test:\n\n{t}\n\nerror:\n\n{e}\n'
                                                    for t, e in failed)))

