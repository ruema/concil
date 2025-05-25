# OCI Specification Module (`concil.oci_spec`)

The `concil.oci_spec` module provides foundational constants, data structures, and helper functions related to the Open Container Initiative (OCI) image and distribution specifications. It helps ensure that `concil` handles image metadata in a way that is compliant with OCI and Docker standards.

## Key Constants

This module defines several important constants for media types:

-   **`DIRECTORY_TRANSPORT` (str):**
    *   Value: `"Directory Transport Version: 1.1
"`
    *   Purpose: Likely used as a marker or version string when images are stored or transported as a simple directory layout on the filesystem, perhaps for an internal OCI layout representation before it's fully packaged or if `concil` supports a specific directory-based transport mechanism.

-   **`MANIFEST_DOCKER_MEDIA_TYPE` (str):**
    *   Value: `"application/vnd.docker.distribution.manifest.v2+json"`
    *   Purpose: The standard media type for a Docker V2 Schema 2 manifest.

-   **`MANIFEST_OCI_MEDIA_TYPE` (str):**
    *   Value: `"application/vnd.oci.image.manifest.v1+json"`
    *   Purpose: The standard media type for an OCI Image Manifest.

-   **`MEDIA_TYPES` (dict):**
    *   Structure: A nested dictionary mapping a primary manifest media type (either `MANIFEST_OCI_MEDIA_TYPE` or `MANIFEST_DOCKER_MEDIA_TYPE`) to a dictionary of its specific component media types.
    *   Component media types include:
        *   `"config"`: The media type for the image configuration blob.
        *   `"tar"`, `"tar+gzip"`, `"tar+zstd"`: Media types for uncompressed, gzipped, or zstd-compressed tarball layers.
        *   `"...+encrypted"`: Variants of layer media types indicating OCI layer encryption.
        *   `"squashfs"`, `"squashfs+encrypted"`: Media types for layers stored as squashfs filesystems (a format `concil` uses for its runtime).
    *   Purpose: This dictionary allows `concil` to determine the correct media type for image components (config, layers) based on the overall manifest type being processed or generated. For example, OCI manifests and Docker manifests use slightly different media types for their layers and configurations.

-   **`REVERSED_MEDIA_TYPES` (dict):**
    *   Structure: A reverse mapping of `MEDIA_TYPES`. It maps specific component media types (e.g., `"application/vnd.docker.image.rootfs.diff.tar.gzip"`) back to their more generic category or primary association if needed (though the provided implementation seems to map specific types to their more generic OCI/Docker equivalent if one exists, or to themselves).
    *   Purpose: Potentially used for normalizing or identifying the canonical type of a layer or config blob when its specific media type is known.

## `class Descriptor`

Represents an OCI Content Descriptor. A descriptor provides metadata about a referenced content blob (like an image layer, configuration object, or another manifest).

-   **Attributes:**
    *   `media_type` (str): The media type of the referenced content.
    *   `size` (int): The size of the content in bytes.
    *   `digest` (str): The digest of the content (e.g., `"sha256:abcdef..."`).
    *   `annotations` (dict, optional): An optional dictionary containing arbitrary metadata related to the content.

-   **`__init__(self, media_type, size, digest, annotations=None)`:**
    *   Standard constructor to initialize a `Descriptor` object.

-   **`from_data(cls, data, media_type, annotations=None)` (classmethod):**
    *   Creates a `Descriptor` object from in-memory byte `data`.
    *   Calculates the `sha256` digest and size of the `data`.
    *   `data` (bytes): The actual content blob.
    *   `media_type` (str): The media type to assign to this content.
    *   `annotations` (dict, optional): Annotations for the descriptor.
    *   Returns a new `Descriptor` instance.

## Helper Functions

-   **`descriptor_to_dict(descriptor, manifest_format=MANIFEST_OCI_MEDIA_TYPE)`:**
    *   Converts a `Descriptor` object into a Python dictionary that conforms to the OCI descriptor JSON structure.
    *   `descriptor` (`Descriptor`): The `Descriptor` instance to convert.
    *   `manifest_format` (str): The target manifest media type (e.g., `MANIFEST_OCI_MEDIA_TYPE` or `MANIFEST_DOCKER_MEDIA_TYPE`). This is important because the function uses `MEDIA_TYPES` to look up the appropriate specific media type for the `descriptor.media_type` based on the target `manifest_format`. For example, a generic `descriptor.media_type` of `"tar+gzip"` would be translated to `"application/vnd.oci.image.layer.v1.tar+gzip"` if `manifest_format` is OCI, or `"application/vnd.docker.image.rootfs.diff.tar.gzip"` if Docker. If a direct mapping isn't found, the original `descriptor.media_type` is used.
    *   The resulting dictionary includes `"mediaType"`, `"size"`, and `"digest"`. If `descriptor.annotations` exist, an `"annotations"` field is also included.
    *   Returns a `dict`.

-   **`manifest_to_dict(config_descriptor, layer_descriptors, manifest_format=MANIFEST_OCI_MEDIA_TYPE)`:**
    *   Constructs an OCI-compliant (or Docker-compliant) image manifest dictionary.
    *   `config_descriptor` (`Descriptor`): A `Descriptor` object for the image's configuration blob.
    *   `layer_descriptors` (list of `Descriptor`): A list of `Descriptor` objects for the image's layers.
    *   `manifest_format` (str): The overall media type for the manifest being created (e.g., `MANIFEST_OCI_MEDIA_TYPE` or `MANIFEST_DOCKER_MEDIA_TYPE`).
    *   The function creates a dictionary with:
        *   `"schemaVersion": 2`
        *   `"mediaType"`: Set to `manifest_format` *only if* `manifest_format` is not the default OCI type (`MANIFEST_OCI_MEDIA_TYPE`). This is because OCI manifests default their media type if not specified, whereas Docker manifests require it.
        *   `"config"`: The dictionary representation of `config_descriptor` (obtained via `descriptor_to_dict`).
        *   `"layers"`: A list of dictionary representations of `layer_descriptors` (obtained via `descriptor_to_dict`).
    *   Returns a `dict` ready for JSON serialization.

## Usage

This module is used extensively by other parts of `concil`, particularly:
-   `concil.image`: When loading, creating, or exporting image manifests and layers.
-   `concil.store`: When dealing with manifests fetched from registries or stored in cache.
-   Any component that needs to generate or parse OCI-compliant metadata.

By centralizing these definitions and helpers, `concil.oci_spec` ensures consistency and adherence to container standards throughout the application.
