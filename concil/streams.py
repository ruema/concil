"""The streams module provide different classes for stream processing
various compression formats.
"""
import gzip
import os
from pathlib import PurePosixPath
from tarfile import BLOCKSIZE, TarFile


class _Stream:
    """Internal class for memory based file writes."""

    def __init__(self):
        """Initializes the stream."""
        self.buf = b""
        self.pos = 0
        self.closed = False

    def tell(self):
        """Returns the current stream position."""
        return self.pos

    def write(self, buf):
        """Writes to the stream.

        Args:
            buf (bytes): The bytes to write.
        """
        self.pos += len(buf)
        self.buf += buf

    def close(self):
        """Closes the stream."""
        self.closed = True

    def is_available(self, length):
        """Checks if a certain number of bytes are available for reading.

        Args:
            length (int): The number of bytes to check for.

        Returns:
            bool: True if the bytes are available, False otherwise.
        """
        return self.closed or len(self.buf) >= length

    def read_block(self, length):
        """Reads a block of bytes from the stream.

        Args:
            length (int): The number of bytes to read.

        Returns:
            bytes: The bytes read.
        """
        result = self.buf[:length]
        self.buf = self.buf[length:]
        return result

    def __enter__(self):
        """Enters the context manager."""
        return self

    def __exit__(self, *args):
        """Exits the context manager."""
        return


class _AbstractStream:
    """Internal class used as a base for input streams."""

    def __init__(self):
        """Initializes the stream."""
        self._stream = _Stream()
        self._processor = self._process()

    def _process(self):
        """The main processing generator.

        This should be implemented by subclasses.
        """
        self._stream.close()
        yield

    def read(self, length=-1):
        """Reads from the stream.

        Args:
            length (int, optional): The number of bytes to read. If -1, reads
                the entire stream. Defaults to -1.

        Returns:
            bytes: The bytes read.
        """
        if length < 0:
            while not self._stream.closed:
                next(self._processor)
            return self._stream.buf
        else:
            while not self._stream.is_available(length):
                next(self._processor)
            return self._stream.read_block(length)

    def __enter__(self):
        """Enters the context manager."""
        return self

    def __exit__(self, *args):
        """Exits the context manager."""
        return


class MergedTarStream(_AbstractStream):
    """Merges multiple tar file streams into one stream."""

    def __init__(self, input_streams):
        """Initializes the MergedTarStream.

        Args:
            input_streams (list): A list of file-like objects for the input
                tar streams.
        """
        self._input_streams = input_streams
        _AbstractStream.__init__(self)

    def _process(self):
        """The main processing generator for merging tar streams."""
        seen = set()
        removed_dirs = set()
        output = TarFile.open(fileobj=self._stream, mode="w:")
        for fileobject in self._input_streams[::-1]:
            seen_here = set()
            removed_dirs_here = set()
            tarfile = TarFile.open(fileobj=fileobject, mode="r|")
            for info in tarfile:
                path = PurePosixPath(info.name)
                if path.name.startswith(".wh."):
                    if path.name == ".wh..wh..opq":
                        removed_dirs_here.add(path.parent)
                    else:
                        path = path.with_name(path.name[4:])
                if path in seen or not removed_dirs.isdisjoint(path.parents):
                    continue
                seen_here.add(path)
                if not info.isdir():
                    removed_dirs_here.add(path)
                seen_here.update(path.parents)
                output.addfile(info)
                yield
                if info.sparse is not None:
                    size = sum(size for offset, size in info.sparse)
                else:
                    size = info.size
                blocks = (size + BLOCKSIZE - 1) // BLOCKSIZE
                while blocks > 0:
                    cnt = 32 if blocks > 32 else blocks
                    buf = tarfile.fileobj.read(cnt * BLOCKSIZE)
                    output.fileobj.write(buf)
                    yield
                    blocks -= cnt
            seen.update(seen_here)
            removed_dirs.update(removed_dirs_here)
        output.close()
        self._stream.close()
        yield


class GZipStream(_AbstractStream):
    """Takes an input stream and outputs a gzipped stream."""

    def __init__(self, input_stream):
        """Initializes the GZipStream.

        Args:
            input_stream: A file-like object for the input stream.
        """
        self._input_stream = input_stream
        _AbstractStream.__init__(self)

    def _process(self):
        """The main processing generator for gzipping a stream."""
        output = gzip.GzipFile(None, "wb", 9, self._stream, mtime=0)
        while True:
            buf = self._input_stream.read(10240)
            if not buf:
                break
            output.write(buf)
            yield
        output.close()
        self._stream.close()
        yield


class DirTarStream(_AbstractStream):
    """Creates a tar file stream from a directory."""

    def __init__(self, input_path):
        """Initializes the DirTarStream.

        Args:
            input_path (str or Path): The path to the input directory.
        """
        self._input_path = input_path
        _AbstractStream.__init__(self)

    def _process(self):
        """The main processing generator for creating a tar stream."""
        output = TarFile.open(fileobj=self._stream, mode="w")
        for name, tarinfo in self.iter_files(output, self._input_path, "/"):
            output.addfile(tarinfo)
            if tarinfo.isreg():
                with open(name, "rb") as f:
                    while True:
                        buf = f.read(32 * BLOCKSIZE)
                        if not buf:
                            break
                        output.fileobj.write(buf)
                        yield
                blocks, remainder = divmod(tarinfo.size, BLOCKSIZE)
                if remainder > 0:
                    output.fileobj.write(b"\0" * (BLOCKSIZE - remainder))
                    blocks += 1
                output.offset += blocks * BLOCKSIZE
            yield
        output.close()
        self._stream.close()
        yield

    def iter_files(self, output, name, arcname):
        """Recursively yields files in a directory for tarring.

        Args:
            output (TarFile): The TarFile object to add files to.
            name (str): The path to the file or directory.
            arcname (str): The archive name for the file or directory.

        Yields:
            tuple: A tuple of (name, tarinfo).
        """
        # Create a TarInfo object from the file.
        tarinfo = output.gettarinfo(name, arcname)

        if tarinfo is None:
            output._dbg(1, "tarfile: Unsupported type %r" % name)
            return

        # Change the TarInfo object.
        tarinfo.uid = tarinfo.gid = 0
        tarinfo.uname = tarinfo.gname = "root"

        yield name, tarinfo

        if tarinfo.isdir():
            for f in sorted(os.listdir(name)):
                yield from self.iter_files(
                    output,
                    os.path.join(name, f),
                    os.path.join(arcname, f),
                )
