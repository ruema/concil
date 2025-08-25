import io
import tarfile
from pathlib import Path

import pytest

from concil.squashfs import SquashTarStream


@pytest.mark.parametrize(
    "squashfs_file",
    [
        "test_plain.sqfs",
        "test_plain_zstd.sqfs",
        "test_xattr.sqfs",
        "test_xattr_zstd.sqfs",
        "test_no_fragment.sqfs",
        "test_large_inode.sqfs",
        "test_long_symlink.sqfs",
        "test_large_dir.sqfs",
    ],
)
def test_squashfs_to_tar_stream(squashfs_file):
    test_file = Path(__file__).parent / "data" / squashfs_file
    tar_stream = SquashTarStream(test_file)

    with tarfile.open(fileobj=tar_stream, mode="r|") as tar:
        if squashfs_file == "test_no_fragment.sqfs":
            large_file_info = tar.getmember("./large_file")
            assert large_file_info.size == 130 * 1024
        elif squashfs_file == "test_large_inode.sqfs":
            large_file_info = tar.getmember("./large_sparse_file")
            assert large_file_info.size == 8 * 1024 * 1024
        elif squashfs_file == "test_long_symlink.sqfs":
            symlink_info = tar.getmember("./long_symlink")
            assert len(symlink_info.linkname) == 8100
        elif squashfs_file == "test_large_dir.sqfs":
            names = tar.getnames()
            assert len(names) == 401  # 400 files + 1 root dir
            assert "./file_399" in names
        else:
            # assert './a' in names
            # assert './a/b' in names
            # assert './c' in names

            b_file = tar.extractfile("./a/b")
            # assert b_file.read() == b'hello\n'

            c_file = tar.extractfile("./c")
            # assert c_file.read() == b'world\n'
