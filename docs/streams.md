# Streams Module (`concil.streams`)

The `concil.streams` module provides a collection of custom stream classes designed to facilitate various data manipulation tasks within `concil`, particularly related to image layer processing, compression, and archiving.

## Core Functionalities

-   Provides a base class for buffered stream operations.
-   Offers on-the-fly GZip compression for output streams.
-   Enables creating TAR archives from directory contents.
-   Supports merging multiple TAR archives into a single stream, correctly handling OCI/Docker style whiteouts for overlay effects.

## Stream Classes

### `class _Stream`

This is a base class designed to help with managing data streams, especially when the full content is not available at once or needs to be processed in chunks.

-   **Key Attributes:**
    *   `_buf` (bytes): An internal buffer to hold data that has been written but not yet read, or data that has been read from an underlying source but not yet consumed by a `read()` call.
    *   `_pos` (int): Current position within the stream (conceptual, based on bytes written/processed).
    *   `_closed` (bool): Flag indicating if the stream is closed.
-   **Key Methods:**
    *   `__init__(self)`: Initializes the buffer and stream state.
    *   `closed` (property): Returns `True` if the stream is closed.
    *   `pos` (property): Returns the current position.
    *   `is_available(self, size)`: Checks if at least `size` bytes are available in the internal buffer for reading.
    *   `read_block(self, size)`: Reads a block of up to `size` bytes from the internal buffer.
    *   `write(self, data)`: Appends `data` to the internal buffer.
    *   `read(self, size=-1)`: Reads up to `size` bytes from the stream. This method is expected to be implemented by subclasses to define how data is actually produced or fetched if not already in `_buf`. The base implementation likely just works with `_buf`.
    *   `close(self)`: Marks the stream as closed. Subclasses should implement specific cleanup.
    *   `__enter__`, `__exit__`: Implements the context manager protocol.

### `class GZipStream(_Stream)`

A stream that compresses data written to it using GZip format on-the-fly. It's designed to wrap another output stream or write to its internal buffer.

-   **`__init__(self, stream_out, level=9, buffer_size=1024*1024)`:**
    *   `stream_out`: The underlying output stream where compressed data will be written.
    *   `level`: GZip compression level (1-9).
    *   `buffer_size`: Size of the internal buffer for the GZip compressor.
    *   Initializes a `gzip.GzipFile` object for compression.
-   **`write(self, data)`:** Compresses the input `data` and writes the compressed bytes to `stream_out`.
-   **`flush(self)`:** Flushes any pending compressed data from the GZip compressor to `stream_out`.
-   **`close(self)`:** Flushes and closes the GZip compressor and the underlying `stream_out`.
-   **Note:** The `read()` method is typically not used for this class as it's primarily an output/write stream. If it were to be readable, it would serve the compressed GZip bytes.

### `class DirTarStream(_Stream)`

A stream that generates a TAR archive from the contents of a specified directory. This stream is readable; calling `read()` produces chunks of the TAR archive.

-   **`__init__(self, dir_path, buffer_size=1024*1024)`:**
    *   `dir_path` (Path or str): The path to the directory to be archived.
    *   `buffer_size`: Internal buffer size for reading files from the directory.
    *   It likely uses `tarfile` module internally, possibly in a non-blocking or iterative way to produce the TAR stream without loading the entire archive into memory.
-   **`read(self, size=-1)`:** Returns the next chunk of the generated TAR archive. It iterates through files and directories under `dir_path`, creates TAR headers and adds file content, managing the TAR format structure.

### `class MergedTarStream(_Stream)`

A stream that merges multiple input TAR streams (tarballs) into a single output TAR stream. This is particularly useful for combining image layers or applying changes to a base layer. It correctly handles OCI/Docker "whiteout" files (files named `.wh..wh..opq` or having specific xattrs) to signify deletions of files/directories from lower layers.

-   **`__init__(self, tar_streams)`:**
    *   `tar_streams` (list): A list of readable TAR stream objects (e.g., file objects opened in 'rb' mode, or other `_Stream` instances that produce TAR data). The order typically matters: later streams can override or delete entries from earlier streams.
-   **`read(self, size=-1)`:** Produces the merged TAR archive.
    *   It reads entries (headers and data) from all input `tar_streams`.
    *   It keeps track of file paths already added to the output.
    *   If a whiteout file (e.g., `path/to/.wh.somefile`) is encountered in a later stream, it ensures that `path/to/somefile` from an earlier stream is excluded from the output.
    *   If a file appears in a later stream with the same path as a file from an earlier stream, the one from the later stream takes precedence.
    *   The output is a valid TAR stream containing the merged result.

## Usage Context

These stream classes are primarily used within `concil.image.LayerDescriptor` during the `export()` process:

-   `DirTarStream` is used when a new layer is being created from a local directory.
-   `GZipStream` could be used if a layer needs to be gzipped before being written to disk or uploaded (though often compression is handled by external tools or registry interactions).
-   `MergedTarStream` is crucial when implementing operations like `concil copy` with layer modifications (e.g., adding files to an existing image, which effectively means creating a new layer that's a merged version of an old layer and a new layer with the changes). It allows for the correct application of overlay semantics where new files overwrite old ones and whiteouts delete them.
