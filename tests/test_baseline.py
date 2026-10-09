import pytest
from fim.baseline import compare, sign_baseline, verify_baseline, IntegrityError


def test_classification():
    assert compare({"same": "a", "changed": "b", "gone": "c"},
                   {"same": "a", "changed": "z", "added": "d"}) == {
                       "same": "unchanged", "changed": "modified", "gone": "deleted", "added": "new"}


def test_authentication():
    key = b"k" * 32
    signature = sign_baseline(key, "/root", ["*.log"], {"file": "abc"})
    verify_baseline(key, "/root", ["*.log"], {"file": "abc"}, signature)
    for root, excludes, hashes in [("/other", ["*.log"], {"file": "abc"}),
                                   ("/root", [], {"file": "abc"}),
                                   ("/root", ["*.log"], {"file": "changed"})]:
        with pytest.raises(IntegrityError):
            verify_baseline(key, root, excludes, hashes, signature)
    with pytest.raises(IntegrityError):
        verify_baseline(b"z" * 32, "/root", ["*.log"], {"file": "abc"}, signature)
