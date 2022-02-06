from concil.cli import find_digest, resolve_one_digest

def test_find_digest():
    digests = [
        "e7d92cdc7f34e6f6181f04e21bdf7a990cb796cc759ca07059c3fd4504e9869f",
        "e7d91b0f2b8af79dc3bb299dd8828bed17d392eb786501437f9eb52918a6399a",
        "e7d92cdb1fd722db46b50bc115fe3234d369b0524e3591bcb380c01862a14d97",
        "976125050d1c1404e7c208c939c79366dd74fa266310b409a9165d1715e2a946",
    ]
    assert find_digest(digests, "97") == digests[3]
    assert find_digest(digests, "e7d9") is None
    assert find_digest(digests, "e7d92") is None
    assert find_digest(digests, "e7d91") == digests[1]
    assert find_digest(digests, "e7d92cdc7f") == digests[0]
    assert find_digest(digests, "e7d93") is None

def test_resolve_one_digest():
    digests = [
        "e7d92cdc7f34e6f6181f04e21bdf7a990cb796cc759ca07059c3fd4504e9869f",
        "e7d91b0f2b8af79dc3bb299dd8828bed17d392eb786501437f9eb52918a6399a",
        "e7d92cdb1fd722db46b50bc115fe3234d369b0524e3591bcb380c01862a14d97",
        "976125050d1c1404e7c208c939c79366dd74fa266310b409a9165d1715e2a946",
    ]
    assert resolve_one_digest(digests, "97") == digests[3:]
    assert resolve_one_digest(digests, "e7d91..97") == digests[1:]
    assert resolve_one_digest(digests, "e7d91..e7d92cdb") == digests[1:3]
    assert resolve_one_digest(digests, "e7d91..") == digests[1:]
    assert resolve_one_digest(digests, "..e7d91") == digests[:2]
    assert resolve_one_digest(digests, "e7d9..e7d92cdb") is None
