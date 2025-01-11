import unittest
import pytest
import secrets
from interlex import exceptions as exc
from interlex.load import UnsafeBasicDBFactory
from interlex.auth import Auth, gen_key, _gen_key, _decompose_key, key_from_auth_value, max_30
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

    def test_api_key_gen(self):
        bads = []
        for i in range(99999):
            int_key = secrets.randbelow(max_30)
            actual_key = int.to_bytes(int_key, 23, byteorder='big')
            k = _gen_key(actual_key)
            av = f'Bearer: {k}'
            rk = key_from_auth_value(av)
            key, crc = _decompose_key(k, fail=False)
            row = (actual_key, k, av, rk, key, crc)
            if key != actual_key or len(k) != 40:
                bads.append(row)

        if bads:
            breakpoint()

        assert not bads

    def test_api_key_gen_2(self):
        bads = []
        for i in range(99999):
            k = gen_key()
            av = f'Bearer: {k}'
            rk = key_from_auth_value(av)
            if len(k) != 40:
                bads.append(row)

        if bads:
            breakpoint()

        assert not bads

