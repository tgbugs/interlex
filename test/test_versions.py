import unittest


class TestVersions(unittest.TestCase):
    def test_new_serialization(self): pass
    def test_new_metadata(self): pass
    def test_new_data(self): pass
    def test_new_local_conventions(self): pass  # need these for roundtrip fidelity

    def test_duplicate_serialization(self): pass
    def test_duplicate_data(self): pass
    def test_duplicate_metadata(self): pass

    def test_version_serialization(self): pass
    def test_version_data(self): pass
    def test_version_metadata(self): pass

    def test_diff_add_triples(self): pass
    def test_diff_remove_triples(self): pass  # really "exclude" ? since we never delete
    def test_diff_update_triples(self):
        # reference qualifier versions can be thought of as
        # differences from a preferred 'reference' set of triples

        # qualifier relations
        # reference set RID <- NOTE this ID only exists once and is the starting point
                             # UNLESS there is a major change, THEN we do need a successor relation
        # reference event
        # set added AID
        # set removed RID
        # compute -> set stayed the same
        pass


class TestQualifierComposition(unittest.TestCase):
    """ the functionality needed for versioning is a subset of the full qualifier relations """
    def test_include(self): pass
    def test_exclude(self): pass  # needed for cases where we need to mask upstream
    def test_start_from_qualifier(self): pass
