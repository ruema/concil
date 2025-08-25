"""
Pure Python implementation for reading squashfs files.
"""

import io
import logging
import shutil
import struct
import sys
import tarfile
from stat import S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFREG, S_IFSOCK

from ..streams import _AbstractStream

logger = logging.getLogger(__name__)

# Superblock flags
UNCOMPRESSED_INODES = 0x0001
UNCOMPRESSED_DATA = 0x0002
UNCOMPRESSED_FRAGMENTS = 0x0008
NO_FRAGMENTS = 0x0010
ALWAYS_FRAGMENTS = 0x0020
DUPLICATES = 0x0040
EXPORTABLE = 0x0080
UNCOMPRESSED_XATTRS = 0x0100
NO_XATTRS = 0x0200
COMPRESSOR_OPTIONS = 0x0400
UNCOMPRESSED_IDS = 0x0800

# Inode types
BASIC_DIRECTORY = 1
BASIC_FILE = 2
BASIC_SYMLINK = 3
BASIC_BLOCK_DEVICE = 4
BASIC_CHAR_DEVICE = 5
BASIC_FIFO = 6
BASIC_SOCKET = 7
EXTENDED_DIRECTORY = 8
EXTENDED_FILE = 9
EXTENDED_SYMLINK = 10
EXTENDED_BLOCK_DEVICE = 11
EXTENDED_CHAR_DEVICE = 12
EXTENDED_FIFO = 13
EXTENDED_SOCKET = 14

COMPRESSION_METHODS = {
    1: "gzip",
    2: "lzma",
    3: "lzo",
    4: "xz",
    5: "lz4",
    6: "zstd",
}

INODE_TYPE_TO_STAT = {
    BASIC_DIRECTORY: S_IFDIR,
    EXTENDED_DIRECTORY: S_IFDIR,
    BASIC_FILE: S_IFREG,
    EXTENDED_FILE: S_IFREG,
    BASIC_SYMLINK: S_IFLNK,
    EXTENDED_SYMLINK: S_IFLNK,
    BASIC_BLOCK_DEVICE: S_IFBLK,
    EXTENDED_BLOCK_DEVICE: S_IFBLK,
    BASIC_CHAR_DEVICE: S_IFCHR,
    EXTENDED_CHAR_DEVICE: S_IFCHR,
    BASIC_FIFO: S_IFIFO,
    EXTENDED_FIFO: S_IFIFO,
    BASIC_SOCKET: S_IFSOCK,
    EXTENDED_SOCKET: S_IFSOCK,
}


class SpanningReader:
    def __init__(self, fs, table_start, block_start, offset):
        self.fs = fs
        self.table_start = table_start
        self.block_start = block_start

        first_block_data, self.on_disk_size = self.fs._read_metadata_block(
            self.table_start + self.block_start
        )
        self.buffer = first_block_data[offset:]
        self.pos = 0

    def read(self, size):
        while len(self.buffer) < self.pos + size:
            self.block_start += self.on_disk_size
            logger.debug(
                f"Spanning metadata blocks, reading next block at offset {self.block_start}"
            )
            next_block_data, self.on_disk_size = self.fs._read_metadata_block(
                self.table_start + self.block_start
            )
            self.buffer += next_block_data

        data_to_return = self.buffer[self.pos : self.pos + size]
        self.pos += size
        return data_to_return


class SquashFS:
    def __init__(self, filename):
        self._offset_meta = None
        self._meta_cache = None
        self.filename = filename
        logger.debug(f"Opening squashfs file: {self.filename}")
        self.f = open(filename, "rb")
        self._read_superblock()
        self._decompressor = self._get_decompressor()
        self._inode_cache = {}
        self._directory_cache = {}
        self._id_table = self._read_id_table()
        self._fragment_table = self._read_fragment_table()

    def _read_superblock(self):
        logger.debug("Reading superblock")
        self.f.seek(0)
        superblock_bytes = self.f.read(96)
        (
            self.magic,
            self.inode_count,
            self.modification_time,
            self.block_size,
            self.fragment_entry_count,
            self.compression_id,
            self.block_log,
            self.flags,
            self.id_count,
            self.version_major,
            self.version_minor,
            self.root_inode_ref,
            self.bytes_used,
            self.id_table_start,
            self.xattr_id_table_start,
            self.inode_table_start,
            self.directory_table_start,
            self.fragment_table_start,
            self.export_table_start,
        ) = struct.unpack("<IIIIIHHHHHHQQQQQQQQ", superblock_bytes)

        logger.debug(f"  magic: {hex(self.magic)}")
        logger.debug(f"  inode_count: {self.inode_count}")
        logger.debug(f"  modification_time: {self.modification_time}")
        logger.debug(f"  block_size: {self.block_size}")
        logger.debug(f"  fragment_entry_count: {self.fragment_entry_count}")
        logger.debug(
            f"  compression_id: {self.compression_id} ({COMPRESSION_METHODS.get(self.compression_id)})"
        )
        logger.debug(f"  flags: {hex(self.flags)}")
        logger.debug(f"  id_count: {self.id_count}")
        logger.debug(f"  version: {self.version_major}.{self.version_minor}")
        logger.debug(f"  root_inode_ref: {hex(self.root_inode_ref)}")
        logger.debug(f"  bytes_used: {self.bytes_used}")
        logger.debug(f"  inode_table_start: {self.inode_table_start}")
        logger.debug(f"  directory_table_start: {self.directory_table_start}")

        if self.magic != 0x73717368:
            raise ValueError("Not a squashfs file")

        if self.version_major != 4 or self.version_minor != 0:
            raise ValueError("Unsupported squashfs version")

    def _get_decompressor(self):
        method = COMPRESSION_METHODS.get(self.compression_id)
        logger.debug(f"Selected decompressor: {method}")
        if method == "gzip":
            import zlib

            return zlib.decompress
        if method == "lzma":
            import lzma

            return lzma.decompress
        if method == "zstd":
            import zstd

            return zstd.decompress
        # TODO: Add other decompression methods
        raise NotImplementedError(f"Compression method {method} not supported")

    def _read_metadata_block(self, offset, uncompressed_flag=UNCOMPRESSED_INODES):
        if self._offset_meta == offset:
            return self._meta_cache
        logger.debug(f"Reading metadata block at offset {offset}")
        self.f.seek(offset)
        header = self.f.read(2)
        size = struct.unpack("<H", header)[0]
        compressed = not (size & 0x8000)
        size &= 0x7FFF
        logger.debug(f"  size: {size}, compressed: {compressed}")
        data = self.f.read(size)
        on_disk_size = 2 + size
        if compressed and not (self.flags & uncompressed_flag):
            data = self._decompressor(data)
            logger.debug(f"  decompressed size: {len(data)}")
        self._offset_meta = offset
        self._meta_cache = data, on_disk_size
        return data, on_disk_size

    def _read_id_table(self):
        logger.debug("Reading ID table")
        id_table = []
        if self.id_table_start == -1 or self.id_count == 0:
            return [0] * self.id_count

        self.f.seek(self.id_table_start)
        num_blocks = (self.id_count + 2047) // 2048
        block_locs_bytes = self.f.read(num_blocks * 8)
        block_locs = struct.unpack(f"<{num_blocks}Q", block_locs_bytes)

        for loc in block_locs:
            block, _ = self._read_metadata_block(loc, UNCOMPRESSED_IDS)
            for i in range(0, len(block), 4):
                id_table.append(struct.unpack_from("<I", block, i)[0])

        logger.debug(f"Read {len(id_table)} IDs")
        return id_table

    def _read_fragment_table(self):
        logger.debug("Reading fragment table")
        fragment_table = []
        if self.fragment_table_start == -1 or self.fragment_entry_count == 0:
            return []

        self.f.seek(self.fragment_table_start)
        num_blocks = (self.fragment_entry_count + 511) // 512
        block_locs_bytes = self.f.read(num_blocks * 8)
        block_locs = struct.unpack(f"<{num_blocks}Q", block_locs_bytes)

        for loc in block_locs:
            block, _ = self._read_metadata_block(loc)
            for i in range(0, len(block), 16):
                start, size, unused = struct.unpack_from("<QII", block, i)
                fragment_table.append({"start": start, "size": size, "unused": unused})

        logger.debug(f"Read {len(fragment_table)} fragment table entries")
        return fragment_table

    def _read_inode(self, inode_ref):
        if inode_ref in self._inode_cache:
            return self._inode_cache[inode_ref]

        block_start = (inode_ref >> 16) & 0xFFFFFFFFFFFF
        offset = inode_ref & 0xFFFF
        logger.debug(
            f"Reading inode at ref {hex(inode_ref)} (block: {block_start}, offset: {offset})"
        )

        reader = SpanningReader(self, self.inode_table_start, block_start, offset)

        header_data = reader.read(16)
        inode_type, permissions, uid_idx, gid_idx, modified_time, inode_number = (
            struct.unpack_from("<HHHHII", header_data)
        )

        inode = {
            "type": inode_type,
            "permissions": permissions,
            "uid": self._id_table[uid_idx],
            "gid": self._id_table[gid_idx],
            "modified_time": modified_time,
            "inode_number": inode_number,
        }
        logger.debug(f"  inode number: {inode_number}, type: {inode_type}")

        if inode_type == BASIC_DIRECTORY:
            inode_data = reader.read(16)
            (
                inode["dir_block_start"],
                inode["hard_link_count"],
                inode["file_size"],
                inode["block_offset"],
                inode["parent_inode_number"],
            ) = struct.unpack_from("<IIHHI", inode_data)
        elif inode_type == EXTENDED_DIRECTORY:
            inode_data = reader.read(24)
            (
                inode["hard_link_count"],
                inode["file_size"],
                inode["dir_block_start"],
                inode["parent_inode_number"],
                inode["index_count"],
                inode["block_offset"],
                inode["xattr_idx"],
            ) = struct.unpack_from("<IIIIHHI", inode_data)
        elif inode_type == BASIC_FILE:
            inode_data = reader.read(16)
            (
                inode["blocks_start"],
                inode["fragment_block_index"],
                inode["block_offset"],
                inode["file_size"],
            ) = struct.unpack_from("<IIII", inode_data)
            if inode["fragment_block_index"] == 0xFFFFFFFF:
                num_blocks = (
                    inode["file_size"] + self.block_size - 1
                ) // self.block_size
            else:
                num_blocks = inode["file_size"] // self.block_size

            block_sizes_data = reader.read(num_blocks * 4)
            inode["block_sizes"] = struct.unpack_from(
                f"<{num_blocks}I", block_sizes_data
            )
            logger.debug(
                f"  file size: {inode['file_size']}, num_blocks: {num_blocks}, fragment_index: {inode['fragment_block_index']}"
            )
        elif inode_type == EXTENDED_FILE:
            inode_data = reader.read(40)
            (
                inode["blocks_start"],
                inode["file_size"],
                inode["sparse"],
                inode["hard_link_count"],
                inode["fragment_block_index"],
                inode["block_offset"],
                inode["xattr_idx"],
            ) = struct.unpack_from("<QQQIIII", inode_data)
            if inode["fragment_block_index"] == 0xFFFFFFFF:
                num_blocks = (
                    inode["file_size"] + self.block_size - 1
                ) // self.block_size
            else:
                num_blocks = inode["file_size"] // self.block_size

            block_sizes_data = reader.read(num_blocks * 4)
            inode["block_sizes"] = struct.unpack_from(
                f"<{num_blocks}I", block_sizes_data
            )
            logger.debug(
                f"  file size: {inode['file_size']}, num_blocks: {num_blocks}, fragment_index: {inode['fragment_block_index']}, xattr_idx: {inode['xattr_idx']}"
            )
        elif inode_type in (BASIC_SYMLINK, EXTENDED_SYMLINK):
            inode_data = reader.read(8)
            inode["hard_link_count"], inode["target_size"] = struct.unpack_from(
                "<II", inode_data
            )
            target_path_bytes = reader.read(inode["target_size"])
            inode["target_path"] = target_path_bytes.decode("utf-8")
            logger.debug(f"  symlink to: {inode['target_path']}")
        # TODO: Add other inode types

        self._inode_cache[inode_ref] = inode
        return inode

    def _read_directory(self, inode):
        dir_ref = (inode["dir_block_start"], inode["block_offset"])
        # if dir_ref in self._directory_cache:
        #    return self._directory_cache[dir_ref]

        logger.debug(
            f"Reading directory at block {inode['dir_block_start']}, offset {inode['block_offset']}. Total size: {inode['file_size']}"
        )
        reader = SpanningReader(
            self,
            self.directory_table_start,
            inode["dir_block_start"],
            inode["block_offset"],
        )

        entries = []
        processed_bytes = 0
        while processed_bytes < inode["file_size"] - 3:
            header_data = reader.read(12)
            count, start, inode_number = struct.unpack_from("<III", header_data)
            processed_bytes += 12
            logger.debug(
                f"  dir header: count={count}, start={start}, inode_number={inode_number}, processed_bytes={processed_bytes}"
            )

            for _ in range(count + 1):
                entry_header_data = reader.read(8)
                offset, inode_offset, type, name_size = struct.unpack_from(
                    "<HHhH", entry_header_data
                )

                name_bytes = reader.read(name_size + 1)
                name = name_bytes.decode("utf-8")

                processed_bytes += 8 + name_size + 1

                entry_inode_ref = (start << 16) | offset
                entries.append(
                    {"name": name, "inode_ref": entry_inode_ref, "type": type}
                )
                logger.debug(
                    f"    entry: name='{name}', inode_ref={hex(entry_inode_ref)}, type={type}"
                )

        logger.debug(f"Finished reading directory. Found {len(entries)} entries.")
        self._directory_cache[dir_ref] = entries
        return entries

    def _iter_file_content(self, inode):
        logger.debug(f"Reading content for file inode {inode['inode_number']}")
        current_pos = inode["blocks_start"]
        content_length = 0
        for i, block_size_on_disk in enumerate(inode["block_sizes"]):
            if block_size_on_disk == 0:
                # Sparse block
                uncompressed_size = min(
                    self.block_size, inode["file_size"] - content_length
                )
                yield b"\x00" * uncompressed_size
                content_length += uncompressed_size
                logger.debug(f"  reading sparse block {i}, size {uncompressed_size}")
                continue

            uncompressed = block_size_on_disk & 0x1000000
            block_size_on_disk &= 0xFFFFFF
            logger.debug(
                f"  reading block {i} at offset {current_pos}, size {block_size_on_disk}, compressed={not uncompressed}"
            )

            self.f.seek(current_pos)
            data = self.f.read(block_size_on_disk)

            if not uncompressed and not (self.flags & UNCOMPRESSED_DATA):
                data = self._decompressor(data)

            yield data
            content_length += len(data)
            current_pos += block_size_on_disk

        if inode["fragment_block_index"] != 0xFFFFFFFF:
            logger.debug("  reading fragment")
            fragment_entry = self._fragment_table[inode["fragment_block_index"]]
            start = fragment_entry["start"]
            size = fragment_entry["size"]

            uncompressed = size & 0x1000000
            size &= 0xFFFFFF
            logger.debug(
                f"  fragment block at offset {start}, size {size}, compressed={not uncompressed}"
            )

            self.f.seek(start)
            data = self.f.read(size)

            if not uncompressed and not (self.flags & UNCOMPRESSED_FRAGMENTS):
                data = self._decompressor(data)

            offset = inode["block_offset"]
            fragment_size = inode["file_size"] % self.block_size
            logger.debug(f"  fragment offset: {offset}, fragment size: {fragment_size}")
            yield data[offset : offset + fragment_size]
            content_length += fragment_size

        logger.debug(f"  total file size: {content_length}")

    def _read_file_content(self, inode):
        return b"".join(self._iter_file_content(inode))


class SquashTarStream(_AbstractStream):
    """Creates a tar file stream from a squashfs-file."""

    def __init__(self, filename):
        """Initializes the SquashTarStream.

        Args:
            filename (str or Path): The path to the squashfs file.
        """
        self._fs = SquashFS(filename)
        _AbstractStream.__init__(self)

    def _process(self):
        """The main processing generator for creating a tar stream."""
        output = tarfile.TarFile.open(fileobj=self._stream, mode="w")
        for inode, tarinfo in self.iter_files("./", self._fs.root_inode_ref):
            output.addfile(tarinfo)
            if tarinfo.isreg():
                for block in self._fs._iter_file_content(inode):
                    output.fileobj.write(block)
                    yield
                blocks, remainder = divmod(tarinfo.size, tarfile.BLOCKSIZE)
                if remainder > 0:
                    output.fileobj.write(b"\0" * (tarfile.BLOCKSIZE - remainder))
                    blocks += 1
                output.offset += blocks * tarfile.BLOCKSIZE
            yield
        output.close()
        self._stream.close()
        yield

    def iter_files(self, path, inode_ref):
        """Recursively yields files in a directory for tarring.

        Args:
            path (str): The path to the file or directory.
            inode_ref (int): The inode to the path.

        Yields:
            tuple: A tuple of (inode, tarinfo).
        """
        logger.debug(f"Adding to tar: {path}")
        inode = self._fs._read_inode(inode_ref)

        info = tarfile.TarInfo(name=path)
        info.mtime = inode["modified_time"]
        info.uid = inode["uid"]
        info.gid = inode["gid"]
        info.mode = inode["permissions"]

        if inode["type"] in (BASIC_DIRECTORY, EXTENDED_DIRECTORY):
            path = path.rstrip("/")
            info.type = tarfile.DIRTYPE
            info.mode |= S_IFDIR
            yield inode, info
            for entry in self._fs._read_directory(inode):
                if entry["name"] in (".", ".."):
                    continue
                yield from self.iter_files(
                    f"{path}/{entry['name']}", entry["inode_ref"]
                )
        elif inode["type"] in (BASIC_FILE, EXTENDED_FILE):
            info.type = tarfile.REGTYPE
            info.mode |= S_IFREG
            info.size = inode["file_size"]
            yield inode, info
        elif inode["type"] in (BASIC_SYMLINK, EXTENDED_SYMLINK):
            info.type = tarfile.SYMTYPE
            info.mode |= S_IFLNK
            info.linkname = inode["target_path"]
            yield inode, info
        # TODO: Add other inode types


def main():
    with open(sys.argv[2], "wb") as f:
        stream = SquashTarStream(sys.argv[1])
        shutil.copyfileobj(stream, f)


if __name__ == "__main__":
    main()
