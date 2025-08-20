import pytest

from concil.cli import _resolve_one_digest, find_digest

DIGESTS_TO_TITLE = {
    "e7d92cdc7f34e6f6181f04e21bdf7a990cb796cc759ca07059c3fd4504e9869f": "a",
    "e7d91b0f2b8af79dc3bb299dd8828bed17d392eb786501437f9eb52918a6399a": "b",
    "e7d92cdb1fd722db46b50bc115fe3234d369b0524e3591bcb380c01862a14d97": "c",
    "976125050d1c1404e7c208c939c79366dd74fa266310b409a9165d1715e2a946": "d",
}


def test_find_digest():
    assert (
        find_digest(DIGESTS_TO_TITLE, "97")
        == "976125050d1c1404e7c208c939c79366dd74fa266310b409a9165d1715e2a946"
    )
    with pytest.raises(KeyError):
        find_digest(DIGESTS_TO_TITLE, "e7d9")
    with pytest.raises(KeyError):
        find_digest(DIGESTS_TO_TITLE, "e7d92")
    assert (
        find_digest(DIGESTS_TO_TITLE, "e7d91")
        == "e7d91b0f2b8af79dc3bb299dd8828bed17d392eb786501437f9eb52918a6399a"
    )
    assert (
        find_digest(DIGESTS_TO_TITLE, "e7d92cdc7f")
        == "e7d92cdc7f34e6f6181f04e21bdf7a990cb796cc759ca07059c3fd4504e9869f"
    )
    with pytest.raises(KeyError):
        find_digest(DIGESTS_TO_TITLE, "e7d93")


def test_resolve_one_digest():
    digests = [(None, d) for d in DIGESTS_TO_TITLE]
    assert _resolve_one_digest(DIGESTS_TO_TITLE, "97") == digests[3:]
    assert _resolve_one_digest(DIGESTS_TO_TITLE, "e7d91..97") == digests[1:]
    assert _resolve_one_digest(DIGESTS_TO_TITLE, "e7d91..e7d92cdb") == digests[1:3]
    assert _resolve_one_digest(DIGESTS_TO_TITLE, "e7d91..") == digests[1:]
    assert _resolve_one_digest(DIGESTS_TO_TITLE, "..e7d91") == digests[:2]
    with pytest.raises(KeyError):
        assert _resolve_one_digest(DIGESTS_TO_TITLE, "e7d9..e7d92cdb")
