import argparse
import os
import re
import shlex
import sys
import warnings
from collections import Counter
from getpass import getpass
from itertools import chain
from pathlib import Path

import urllib3.exceptions

from . import oci_spec, store
from .image import ImageManifest, LayerDescriptor


def generate_key(outputfilename, password):
    """Generates a new private key.

    Args:
        outputfilename (str): The base name for the output key files.
        password (str): The password to encrypt the private key.
    """
    from jwcrypto import jwk

    key = jwk.JWK.generate(kty="EC", crv="P-521")

    with open(outputfilename + ".private.pem", "wb") as output:
        output.write(key.export_to_pem(True, password.encode()))
    with open(outputfilename + ".pem", "wb") as output:
        output.write(key.export_to_pem())


def load_encryption_keys(filenames):
    """Loads encryption keys from files.

    Args:
        filenames (list of list of str): A list of lists of key filenames.

    Returns:
        list: A list of loaded JWK keys.
    """
    from jwcrypto import jwk

    keys = []
    for key in chain.from_iterable(filenames or []):
        with open(key, "rb") as inp:
            keys.append(jwk.JWK.from_pem(inp.read()))
    return keys


def split_env(key_value):
    """Splits an environment variable string into a key-value pair.

    If only a key is given, the value is None.

    Args:
        key_value (str): The environment variable string (e.g., "KEY=VALUE").

    Returns:
        tuple: A tuple of (key, value).
    """
    if "=" in key_value:
        return key_value.split("=", 1)
    return (key_value, None)


def split_title(filename):
    if "=" in filename:
        title, filename = filename.split("=", 1)
        if (title[:1] == '"' and title[-1:] == '"') or (
            title[:1] == "'" and title[-1:] == "'"
        ):
            title = title[1:-1]
    else:
        title = None
    return title, filename


def find_digest(digests_to_title, short_digest_or_title):
    """Looks up a short digest or title in the mapping digests to title.

    A digest has to be given with only its first digits.
    This function checks if the short digest exists and is unambiguous.

    Args:
        digests_to_title (mapping): A mapping of digests to titles.
        short_digest_or_title (str): The first digits of a digest or a title.

    Returns:
        str: The full digest.

    Raises:
        KeyError: If the digest is not found or is ambiguous.
    """
    if re.fullmatch(r"%\d+", short_digest_or_title):
        found = [list(digests_to_title)[int(short_digest_or_title[1:]) - 1]]
    else:
        found = [
            digest
            for digest, title in digests_to_title.items()
            if digest.startswith(short_digest_or_title)
            or short_digest_or_title == title
        ]
    if len(found) != 1:
        if not found:
            print(f"{short_digest_or_title} not found!")
        else:
            print(f"{short_digest_or_title} ambiguous: {', '.join(found)}!")
        raise KeyError(short_digest_or_title)
    return found[0]


def _resolve_one_digest(digests_to_title, short_digest_or_title):
    """resolves a single short digests or a range of digests
    to a list of full digests"""
    title, short_digest_or_title = split_title(short_digest_or_title)
    start_digest, sep, stop_digest = short_digest_or_title.partition("..")
    if start_digest:
        start_digest = find_digest(digests_to_title, start_digest)
    if stop_digest:
        stop_digest = find_digest(digests_to_title, stop_digest)
    if sep:
        # range of digests
        digests = list(digests_to_title)
        start_index = digests.index(start_digest) if start_digest else None
        stop_index = digests.index(stop_digest) + 1 if stop_digest else None
        return [(title, digest) for digest in digests[start_index:stop_index]]
    else:
        return [(title, start_digest)]


def resolve_digests(digests_to_title, short_digests_or_titles):
    """Resolves a list of short digests into full digests.

    Args:
        digests_to_title (mapping): A mapping of digests to titles.
        short_digests_or_titles (list of list of str): A list of lists of
            short digests or titles.

    Returns:
        tuple: A tuple containing the list of resolved digests and an error flag.
    """
    result = []
    error = False
    for inner_short_digests_or_titles in short_digests_or_titles or []:
        inner_result = []
        for short_digest_or_title in inner_short_digests_or_titles:
            try:
                resolved = _resolve_one_digest(digests_to_title, short_digest_or_title)
            except KeyError:
                error = True
            else:
                inner_result.extend(resolved)
        result.append(inner_result)
    return result, error


def guess_media_type(path):
    """Guesses the media type of a file.

    Args:
        path (Path): The path to the file.

    Returns:
        str or None: The guessed media type, or None if it cannot be
            determined.
    """
    try:
        with path.open("rb") as file:
            data = file.read(1024)
            if data[:2] == b"\x1f\x8b":
                import zlib

                decompressor = zlib.decompressobj(15 + 32)
                data = decompressor.decompress(data, 270)
                if data[258:262] == b"ustar":
                    return "tar+gzip"
            if data[258:262] == b"ustar":
                return "tar"
            if data[:4] == b"hsqs":
                return "squashfs"
    except Exception:
        pass
    return None


def do_list(args):
    """Handles the 'list' command.

    Args:
        args: The command-line arguments.

    Returns:
        int: 0 on success, 1 on failure.
    """
    import json
    import shlex

    try:
        image = ImageManifest.from_path(args.image)
    except FileNotFoundError:
        print(f"Image {args.image} not found")
        return 1

    if args.print_layer:
        if args.config or args.history:
            print("You cannot use --print-layer with --config or --history")
            return 1
        digests_to_title = {
            layer.digest.split(":", 1)[1]: layer.title for layer in image.layers
        }
        digest = find_digest(digests_to_title, args.print_layer)
        print(digest)
        return

    configuration = image.configuration
    for key in ["Created", "Author", "Architecture", "OS", "Variant"]:
        if key.lower() in configuration:
            print(f"{key}: {configuration[key.lower()]}")

    print()
    print(f"{'Digest':65s} {'Size':12s} Media-Type Name")
    for layer in image.layers:
        title = " " + layer.title if layer.title else ""
        print(
            f"{layer.digest.split(':',1)[1]:65s} {layer.size:12d} {layer.media_type:10}{title}"
        )

    if args.config:
        print()
        print("Configuration:")
        config = configuration["config"]
        if config.get("Entrypoint"):
            entrypoint = " ".join(map(shlex.quote, config["Entrypoint"]))
            print(f"Entrypoint: {entrypoint}")
        if config.get("Cmd"):
            cmd = " ".join(map(shlex.quote, config["Cmd"]))
            print(f"Cmd: {cmd}")
        for key in ["User", "ExposedPorts", "WorkingDir", "Labels", "StopSignal"]:
            if key in config:
                print(f"{key}: {config[key]}")
        if config.get("Env"):
            print()
            print("Environment:")
            for env in config["Env"]:
                print(env)
        if config.get("Volumes"):
            print()
            print("Volumes:")
            for volume in config["Volumes"]:
                print(f"- {volume}")

    if args.history:
        print()
        print("History:")
        for history in configuration["history"]:
            print()
            if "created" in history:
                print(f"Date: {history['created']}")
            if "author" in history:
                print(f"Author: {history['author']}")
            if "comment" in history:
                print(f"Comment: {history['comment']}")
            if "created_by" in history:
                print(history["created_by"])


def do_copy(args):
    """Handles the 'copy' command.

    Args:
        args: The command-line arguments.
    """
    keys = load_encryption_keys(args.encryption)
    image = ImageManifest.from_path(getattr(args, "source-image"))
    if args.remove_layer or args.merge_layers:
        digests_to_title = {
            layer.digest.split(":", 1)[1]: layer.title for layer in image.layers
        }
        to_be_removed, errors_remove = resolve_digests(
            digests_to_title, args.remove_layer
        )
        to_be_merged, errors_merged = resolve_digests(
            digests_to_title, args.merge_layers
        )
        to_be_removed = [d for digests in to_be_removed for _, d in digests]
        all_to_be_merged = [d for digests in to_be_merged for _, d in digests]
        counter = Counter()
        counter.update(to_be_removed)
        counter.update(all_to_be_merged)
        for digest, count in counter.items():
            if count > 1:
                print(f"{digest} appears more than once")
                errors_merged = True
        if errors_remove or errors_merged:
            return
        print(f"{'Digest':65s} {'Size':12s} Media-Type")
        layers = {layer.digest.split(":", 1)[1]: layer for layer in image.layers}
        for layer in image.layers:
            digest = layer.digest.split(":", 1)[1]
            if digest in to_be_removed:
                print(f"{digest:65s} {layer.size:12d} {layer.media_type} removed.")
                layer.status = "remove"
            elif digest in all_to_be_merged:
                others = next(m for m in to_be_merged if digest in [d for _, d in m])
                title = others[0][0]
                if title:
                    layer.title = title
                if len(others) == 1:
                    pass
                elif digest == others[0]:
                    print(f"{digest:65s} {layer.size:12d} {layer.media_type} merged.")
                    layer.status = "merge"
                    layer.merge_with = [layers[d] for _, d in others[1:]]
                else:
                    layer.status = "remove"
            else:
                print(f"{digest:65s} {layer.size:12d} {layer.media_type} kept.")
    if args.add_layer:
        new_layers = []
        for filename in chain.from_iterable(args.add_layer):
            if re.match(r"^\d+:", filename):
                index, filename = filename.split(":", 1)
            else:
                index = None
            title, filename = split_title(filename)
            path = Path(filename)
            if path.suffix in (".sq", ".sqfs", ".sfs"):
                media_type = "squashfs"
            elif path.suffix == ".tar":
                media_type = "tar"
            elif path.suffix in (".gz", ".tgz"):
                media_type = "tar+gzip"
            elif path.is_dir():
                media_type = "dir"
            else:
                media_type = guess_media_type(path)
                if media_type is None:
                    raise RuntimeError("unsupported file type")
            layer = LayerDescriptor(path, media_type, None)
            layer.status = "new"
            if title is not None:
                layer.title = title
            print(
                f"{layer.digest.split(':',1)[1]:65s} {layer.size:12d} {layer.media_type} added."
            )
            new_layers.append((index, layer))
        for index, layer in reversed(new_layers):
            if index is None:
                image.layers.append(layer)
            else:
                image.layers.insert(int(index) - 1, layer)
    if args.squashfs:
        for layer in image.layers:
            layer.convert("squashfs")
    if args.tar:
        for layer in image.layers:
            layer.convert("tar+gzip")
    for layer in image.layers:
        layer.encryption_keys = keys
    config = image.configuration["config"]
    if args.env:
        env = dict(split_env(kv) for env in args.env for kv in env)
        environment = []
        if "Env" in config:
            for kv in config["Env"]:
                k, v = split_env(kv)
                if k not in env:
                    environment.append(kv)
        for k, v in env.items():
            if v == "":
                pass
            elif v is None:
                environment.append(k)
            else:
                environment.append(f"{k}={v}")
        config["Env"] = environment
    if args.user:
        config["User"] = args.user
    if args.volumes:
        config["Volumes"] = {v: {} for vols in args.volumes for v in vols}
    if args.entrypoint is not None:
        import shlex

        config["Entrypoint"] = shlex.split(args.entrypoint)
        if "Cmd" in config:
            del config["Cmd"]
    if args.working_dir is not None:
        config["WorkingDir"] = args.working_dir
    image.export(
        getattr(args, "destination-image"), oci_spec.MANIFEST_DOCKER_MEDIA_TYPE
    )


def do_shell(args):
    """Handles the 'shell' command.

    Args:
        args: The command-line arguments.

    Returns:
        int: The exit code of the shell process.
    """
    from .run import LocalConfig, run

    class ExtraConfig(LocalConfig):
        def get_layers(self):
            layers = super().get_layers()
            if args.extra_layer:
                layers.extend(chain.from_iterable(args.extra_layer))
            return layers

    config = ExtraConfig(args.image)
    config.config["Entrypoint"] = ["/bin/sh"]
    config.config["Cmd"] = []
    config.check_volumes = False
    config.args = args.args
    config.volumes = args.volume
    if args.overlay_dir:
        overlay_dir = os.path.join(args.overlay_dir, "root")
    else:
        overlay_dir = args.overlay_path
    return run(config, overlay_dir)


def do_publish(args):
    """Handles the 'publish' command.

    Args:
        args: The command-line arguments.
    """
    image = ImageManifest.from_path(args.image)
    image.publish(
        getattr(args, "docker-url"),
        oci_spec.MANIFEST_DOCKER_MEDIA_TYPE,
        args.root_certificate,
        args.cosign_key,
    )


def store_concil_key(cosign_path, key_id, key, password):
    """Stores a cosign key.

    Args:
        cosign_path (Path): The path to the cosign directory.
        key_id (str): The ID of the key.
        key (jwk.JWK): The key object.
        password (str): The password for the private key.
    """
    cosign_path.mkdir(parents=True, exist_ok=True)
    if key.has_private:
        print(f"Private key written to {key_id}.key")
        (cosign_path / f"{key_id}.key").write_bytes(
            key.export_to_pem(True, password.encode("utf8") or None)
        )
    print(f"Public key written to {key_id}.pub")
    (cosign_path / f"{key_id}.pub").write_bytes(key.export_to_pem())


def do_config_cosign_generate_key(config, args):
    """Handles the 'config cosign-generate-key' command.

    Args:
        config: The concil configuration.
        args: The command-line arguments.
    """
    from jwcrypto import jwk

    key_id = getattr(args, "key-id")
    key = jwk.JWK.generate(kty="EC", crv="P-256")
    password = getpass("Enter password for private key:")
    password_again = getpass("Enter password for private key again:")
    if password != password_again:
        print("passwords differ")
        sys.exit(1)
    store_concil_key(config.cosign_path, key_id, key, password)


def do_config_cosign_list_keys(config, args):
    """Handles the 'config cosign-list-keys' command.

    Args:
        config: The concil configuration.
        args: The command-line arguments.
    """
    cosign_path = config.cosign_path
    if not cosign_path.is_dir():
        print("no keys found")
        return
    public_keys = {path.stem for path in cosign_path.glob("*.pub")}
    private_keys = {path.stem for path in cosign_path.glob("*.key")}
    keys = sorted(public_keys | private_keys)
    max_length = max(6, max(map(len, keys)))
    print(f"{'Key-ID':{max_length}s} public private")
    for key in keys:
        public = "  x   " if key in public_keys else ""
        private = "   x" if key in private_keys else ""
        print(f"{key:{max_length}s} {public} {private}")


def do_config_cosign_export_key(config, args):
    """Handles the 'config cosign-export-key' command.

    Args:
        config: The concil configuration.
        args: The command-line arguments.
    """
    cosign_path = config.cosign_path
    key_id = getattr(args, "key-id")
    if args.private:
        path = cosign_path / f"{key_id}.key"
    else:
        path = cosign_path / f"{key_id}.pub"
    if not path.is_file():
        print(f"key with id {key_id} not found")
        return
    data = path.read_bytes()
    Path(args.filename).write_bytes(data)


def do_config_cosign_import_key(config, args):
    """Handles the 'config cosign-import-key' command.

    Args:
        config: The concil configuration.
        args: The command-line arguments.
    """
    from jwcrypto import jwk

    key_id = getattr(args, "key-id")
    data = Path(args.filename).read_bytes()
    try:
        key = jwk.JWK.from_pem(data)
        password = ""
    except TypeError:
        password = getpass("Enter password for private key:")
        key = jwk.JWK.from_pem(data, password.encode("utf8"))
    store_concil_key(config.cosign_path, key_id, key, password)


def do_config(args):
    """Handles the 'config' command.

    Args:
        args: The command-line arguments.
    """
    config = store.ConcilConfig()
    if args.config_cmd == "cosign-list-keys":
        do_config_cosign_list_keys(config, args)
    elif args.config_cmd == "cosign-generate-key":
        do_config_cosign_generate_key(config, args)
    elif args.config_cmd == "cosign-export-key":
        do_config_cosign_export_key(config, args)
    elif args.config_cmd == "cosign-import-key":
        do_config_cosign_import_key(config, args)
    else:
        assert False, "unknown command"


COMMANDS = {
    "list": do_list,
    "copy": do_copy,
    "shell": do_shell,
    "publish": do_publish,
    "config": do_config,
}


def main():
    """The main entry point for the concil CLI."""
    warnings.simplefilter("default", urllib3.exceptions.SecurityWarning)
    store.TAR2SQFS[-1] = "level=19"
    parser = argparse.ArgumentParser(
        description="Convert container images.",
        epilog="Examples:\n"
        "    Download image from docker hub:\n"
        "    concil copy --squashfs docker://:@registry.hub.docker.com/library/ubuntu:22.04 image/ubuntu_22.04\n"
        "\n"
        "    Install additional packages:\n"
        "    concil shell --overlay-path overlay --extra-layer fakeroot.sqfs -- image/ubuntu_22.04 /usr/bin/fakeroot apt-get install python\n"
        "\n"
        "    Make a new container image:\n"
        "    concil copy --add-layer python=overlay --squashfs image/ubuntu_22.04 image/python\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(help="sub-command help", dest="cmd")
    parser_list = subparsers.add_parser("list", help="list layers of image")
    parser_list.add_argument("image", help="image directory")
    parser_list.add_argument("--config", action="store_true", help="show config")
    parser_list.add_argument("--history", action="store_true", help="show history")
    parser_list.add_argument(
        "--print-layer", metavar="layer", action="store", help="print hash of layer"
    )

    parser_copy = subparsers.add_parser("copy", help="modify the layers of image")
    parser_copy.add_argument("source-image", help="source directory")
    parser_copy.add_argument("destination-image", help="destination directory")
    parser_copy.add_argument(
        "--squashfs", action="store_true", help="convert layers to squashfs"
    )
    parser_copy.add_argument("--tar", action="store_true", help="convert layers to tar")
    parser_copy.add_argument(
        "--encryption",
        metavar="key",
        nargs="+",
        action="append",
        help="encryption keys",
    )
    parser_copy.add_argument(
        "--remove-layer",
        metavar="layer",
        nargs="+",
        action="append",
        help="ID of layers to remove",
    )
    parser_copy.add_argument(
        "--add-layer",
        metavar="layer",
        nargs="+",
        action="append",
        help="filename of new layers appended",
    )
    parser_copy.add_argument(
        "--merge-layers",
        metavar="layers",
        nargs="+",
        action="append",
        help="filename of new layers appended",
    )
    parser_copy.add_argument("--user", help="set user in container uid:gid")
    parser_copy.add_argument(
        "--env",
        metavar="env",
        nargs="+",
        action="append",
        help="updates the environment: Key=Value",
    )
    parser_copy.add_argument(
        "--volumes",
        metavar="volumes",
        nargs="+",
        action="append",
        help="list of volumes",
    )
    parser_copy.add_argument("--entrypoint", action="store", help="sets the entrypoint")
    parser_copy.add_argument(
        "--working-dir", action="store", help="sets the working dir"
    )

    parser_shell = subparsers.add_parser("shell", help="start a shell in the container")
    parser_shell.add_argument("image", help="image directory")
    parser_shell.add_argument(
        "--overlay-dir", action="store", help="overlay directory (deprecated)"
    )
    parser_shell.add_argument(
        "--overlay-path", action="store", help="overlay directory"
    )
    parser_shell.add_argument(
        "--extra-layer",
        metavar="layer",
        nargs="+",
        action="append",
        help="filename of an extra layer",
    )
    parser_shell.add_argument("-v", "--volume", action="append", help="volumes")
    parser_shell.add_argument("args", nargs=argparse.REMAINDER)

    parser_publish = subparsers.add_parser(
        "publish", help="publish image to docker hub"
    )
    parser_publish.add_argument(
        "--root-certificate", action="store", help="root certificate for notary"
    )
    parser_publish.add_argument(
        "--cosign-key", action="store", help="signing key for cosign"
    )
    parser_publish.add_argument("image", help="image directory")
    parser_publish.add_argument(
        "docker-url", help="docker url of the form docker://host/repository:tag"
    )

    parser_config = subparsers.add_parser("config", help="configuration commands")
    subparsers_config = parser_config.add_subparsers(
        help="config-command help", dest="config_cmd"
    )
    parser_cosign_list_keys = subparsers_config.add_parser(
        "cosign-list-keys", help="list all signing keys"
    )
    parser_cosign_generate_key = subparsers_config.add_parser(
        "cosign-generate-key", help="generates a signing key"
    )
    parser_cosign_generate_key.add_argument("key-id", help="the key-id")
    parser_cosign_export_key = subparsers_config.add_parser(
        "cosign-export-key", help="export a signing key"
    )
    parser_cosign_export_key.add_argument("key-id", help="the key-id")
    parser_cosign_export_key.add_argument("filename", help="output filename")
    parser_cosign_export_key.add_argument(
        "--private", action="store_true", help="export the private key"
    )
    parser_cosign_import_key = subparsers_config.add_parser(
        "cosign-import-key", help="import a private or public signing key"
    )
    parser_cosign_import_key.add_argument("key-id", help="the key-id")
    parser_cosign_import_key.add_argument("filename", help="key filename")

    args = parser.parse_args()
    try:
        do_cmd = COMMANDS[args.cmd]
    except KeyError:
        parser.print_help()
        sys.exit(1)
    sys.exit(do_cmd(args))


if __name__ == "__main__":
    main()
