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
