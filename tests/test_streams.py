import gzip
import os
import tarfile
from io import BytesIO

from concil.streams import DirTarStream, GZipStream, MergedTarStream, _Stream


def test_stream():
    stream = _Stream()
    assert not stream.closed
    stream.write(b"a" * 1000)
    assert not stream.is_available(1100)
    assert stream.is_available(100)
    assert stream.pos == 1000
    assert stream.read_block(100) == b"a" * 100
    assert not stream.is_available(901)
    stream.write(b"a" * 1000)
    assert stream.pos == 2000
    stream.close()
    assert stream.closed


def test_gzipstream():
    data = b"abcdefgh" * 1000
    result = BytesIO()
    output = gzip.GzipFile(fileobj=result, mode="wb", mtime=0)
    output.write(data)
    output.close()
    result = result.getvalue()
    input_stream = BytesIO(data)
    with GZipStream(input_stream) as output:
        result2 = output.read()
    assert result == result2


def test_dirtarstream():
    with DirTarStream(os.path.join(os.path.dirname(__file__), "test_dir")) as output:
        result = output.read()
    input_stream = BytesIO(result)
    with tarfile.open(fileobj=input_stream) as tar:
        assert set(tar.getnames()) == {"", "a", "a/c", "b"}
        assert tar.extractfile("a/c").read() == b"ccc\n"
        tarinfo = tar.getmember("b")
        assert tarinfo.uid == 0


def mk_tar(files):
    output_stream = BytesIO()
    with tarfile.open(fileobj=output_stream, mode="w") as tar:
        for name, data in files:
            tarinfo = tarfile.TarInfo(name)
            tarinfo.size = len(data)
            tar.addfile(tarinfo, BytesIO(data))
    return output_stream.getvalue()


def test_mergetar():
    input_stream1 = BytesIO(
        mk_tar(
            [
                ("a/b", b"a"),
                ("b", b"ab"),
                ("c/a", b"a"),
                ("c/b", b"a"),
                ("c/c", b"a"),
                ("d", b"a"),
            ]
        )
    )
    input_stream2 = BytesIO(
        mk_tar(
            [
                ("a", b"abc"),
                ("b", b"abc"),
                ("c/.wh..wh..opq", b""),
                ("c/d", b"a"),
            ]
        )
    )
    with MergedTarStream([input_stream1, input_stream2]) as output:
        result = output.read()
    with tarfile.open(fileobj=BytesIO(result)) as tar:
        assert {(m.name, m.size) for m in tar.getmembers()} == {
            ("a", 3),
            ("b", 3),
            ("c/.wh..wh..opq", 0),
            ("c/d", 1),
            ("d", 1),
        }


def test_dir_tar_stream_empty_dir(tmp_path):
    """Tests that DirTarStream can handle an empty directory."""
    dir_path = tmp_path / "empty_dir"
    dir_path.mkdir()

    dir_stream = DirTarStream(dir_path)
    with tarfile.open(fileobj=dir_stream, mode="r|") as tar:
        names = {member.name for member in tar.getmembers()}
        assert names == {""}


def test_merged_tar_stream_three_files(tmp_path):
    """Tests that MergedTarStream can merge three tar files."""
    tar1_path = tmp_path / "tar1.tar"
    with tarfile.open(tar1_path, "w") as tar:
        tar.addfile(tarfile.TarInfo("file1.txt"), BytesIO(b"content1"))

    tar2_path = tmp_path / "tar2.tar"
    with tarfile.open(tar2_path, "w") as tar:
        tar.addfile(tarfile.TarInfo("file2.txt"), BytesIO(b"content2"))

    tar3_path = tmp_path / "tar3.tar"
    with tarfile.open(tar3_path, "w") as tar:
        tar.addfile(tarfile.TarInfo("file3.txt"), BytesIO(b"content3"))

    with open(tar1_path, "rb") as f1, open(tar2_path, "rb") as f2, open(
        tar3_path, "rb"
    ) as f3:
        merged_stream = MergedTarStream([f1, f2, f3])
        with tarfile.open(fileobj=merged_stream, mode="r|") as tar:
            names = {member.name for member in tar.getmembers()}
            assert "file1.txt" in names
            assert "file2.txt" in names
            assert "file3.txt" in names
