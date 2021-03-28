import unittest
import pytest
from interlex import exceptions as exc
from interlex.load import UnsafeBasicDBFactory
from .setup_testing_db import getSession


class TestAuth(unittest.TestCase):
    @pytest.mark.skip('manual')
    def test_not_group(self):
        session = getSession()
        try:
            UnsafeBasicDB = UnsafeBasicDBFactory(session)
            try:
                UnsafeBasicDB('not a group', 'not a user')
                raise AssertionError('this should have failed due to not being group')
            except exc.NotGroup as e:
                pass
        finally:
            session.close()
