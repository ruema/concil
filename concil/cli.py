import sys
import argparse
import warnings
from itertools import chain
from collections import Counter
from pathlib import Path
from getpass import getpass
import urllib3.exceptions
from .image import ImageManifest, LayerDescriptor
from . import store, oci_spec

def generate_key(outputfilename, password):
    from jwcrypto import jwk
    key = jwk.JWK.generate(kty='EC', crv='P-521')

    with open(outputfilename + '.private.pem', 'wb') as output:
        output.write(key.export_to_pem(True, password.encode()))
    with open(outputfilename + '.pem', 'wb') as output:
        output.write(key.export_to_pem())

def load_encryption_keys(filenames):
    from jwcrypto import jwk
    keys = []
    for key in chain.from_iterable(filenames or []):
        with open(key, 'rb') as inp:
            keys.append(jwk.JWK.from_pem(inp.read()))
    return keys

def split_env(key_value):
    """ splits a environment key=value into key and value.
    If only key is given, return (key, None)
    """
    if '=' in key_value:
        return key_value.split('=', 1)
    return (key_value, None)

def find_digest(digests, short_digest):
    """ Looks up a short digest in the list of digests.

    A digest has only to be given with it's first digits.
    This function checks if the short digests exists and
    is unambiguous.

    Args:
        digests (list): list of digests
        short_digest (str): the first digits of a digest
    
    Returns:
        None if digest is not found or is ambiguous.
        Otherwise a strings with the full digest.
    """
    found = [d for d in digests if d.startswith(short_digest)]
    if len(found) != 1:
        if not found:
            print(f"{short_digest} not found!")
        else:
            print(f"{short_digest} ambiguous: {', '.join(found)}!")
        return None
    return found[0]

def resolve_one_digest(digests, short_digest):
    """ resolves a single short digests or a range of digests
    to a list of full digests"""
    start_digest, sep, stop_digest = short_digest.partition('..')
    if start_digest:
        start_digest = find_digest(digests, start_digest)
    if stop_digest:
        stop_digest = find_digest(digests, stop_digest)
    if start_digest is None or stop_digest is None:
        # an error was found
        return None
    if sep:
        # range of digests
        start_index = digests.index(start_digest) if start_digest else None
        stop_index = digests.index(stop_digest) + 1 if stop_digest else None
        return digests[start_index : stop_index]
    else:
        return [start_digest]


def resolve_digests(digests, short_digests):
    """ resolves a list of short_digests into full digests
    returns the list of list of digests and an error flag
    """
    digests = list(digests)
    result = []
    error = False
    for inner_short_digests in (short_digests or []):
        inner_result = []
        for short_digest in inner_short_digests:
            resolved = resolve_one_digest(digests, short_digest)
            if resolved is None:
                error = True
            else:
                inner_result.extend(resolved)
        result.append(inner_result)
    return result, error
                

def do_list(args):
    import json, shlex
    image = ImageManifest.from_path(args.image)
    configuration = image.configuration
    for key in ['Created', 'Author', 'Architecture', 'OS', 'Variant']:
        if key.lower() in configuration:
            print(f"{key}: {configuration[key.lower()]}")

    print()
    print(f"{'Digest':65s} {'Size':12s} Media-Type")
    for layer in image.layers:
        print(f"{layer.digest.split(':',1)[1]:65s} {layer.size:12d} {layer.media_type}")

    if args.config:
        print()
        print("Configuration:")
        config = configuration['config']
        if config.get('Entrypoint'):
            entrypoint = ' '.join(map(shlex.quote, config['Entrypoint']))
            print(f"Entrypoint: {entrypoint}")
        if config.get('Cmd'):
            cmd = ' '.join(map(shlex.quote, config['Cmd']))
            print(f"Cmd: {cmd}")
        for key in ['User', 'ExposedPorts', 'WorkingDir', 'Labels', 'StopSignal']:
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
        for history in configuration['history']:
            print()
            if 'created' in history:
                print(f"Date: {history['created']}")
            if 'author' in history:
                print(f"Author: {history['author']}")
            if 'comment' in history:
                print(f"Comment: {history['comment']}")
            if 'created_by' in history:
                print(history['created_by'])


def do_copy(args):
    keys = load_encryption_keys(args.encryption)
    image = ImageManifest.from_path(getattr(args,'source-image'))
    if args.remove_layer or args.merge_layers:
        layers = {
            layer.digest.split(':',1)[1]: layer
            for layer in image.layers
        }
        to_be_removed, errors_remove = resolve_digests(layers, args.remove_layer)
        to_be_merged, errors_merged = resolve_digests(layers, args.merge_layers)
        counter = Counter()
        counter.update(chain.from_iterable(to_be_removed))
        counter.update(chain.from_iterable(to_be_merged))
        for digest, count in counter.items():
            if count > 1:
                print(f"{digest} appears more than once")
                errors_merged = True
        if errors_remove or errors_merged:
            return
        to_be_removed = set(chain.from_iterable(to_be_removed))
        all_to_be_merged = set(chain.from_iterable(to_be_merged))
        print(f"{'Digest':65s} {'Size':12s} Media-Type")
        for layer in image.layers:
            digest = layer.digest.split(':',1)[1]
            if digest in to_be_removed:
                print(f"{digest:65s} {layer.size:12d} {layer.media_type} removed.")
                layer.status = 'remove'
            elif digest in all_to_be_merged:
                print(f"{digest:65s} {layer.size:12d} {layer.media_type} merged.")
                others = next(m for m in to_be_merged if digest in m)
                if digest == others[0]:
                    layer.status = 'merge'
                    layer.merge_with = [layers[d] for d in others[1:]]
                else:
                    layer.status = 'remove'
            else:
                print(f"{digest:65s} {layer.size:12d} {layer.media_type} kept.")
    if args.add_layer:
        for filename in chain.from_iterable(args.add_layer):
            path = Path(filename)
            if path.suffix == '.sq':
                media_type = 'squashfs'
            elif path.suffix == '.tar':
                media_type = 'tar'
            elif path.suffix in ('.gz', '.tgz'):
                media_type = 'tar+gzip'
            elif path.is_dir():
                media_type = 'dir'
            else:
                raise RuntimeError("unsupported file type")
            layer = LayerDescriptor(path, media_type, None)
            layer.status = 'new'
            print(f"{layer.digest.split(':',1)[1]:65s} {layer.size:12d} {layer.media_type} added.")
            image.layers.append(layer)
    if args.squashfs:
        for layer in image.layers:
            layer.convert("squashfs")
    if args.tar:
        for layer in image.layers:
            layer.convert("tar+gzip")
    for layer in image.layers:
        layer.encryption_keys = keys
    config = image.configuration['config']
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
    if args.volumes:
        config["Volumes"] = {v:{} for vols in args.volumes for v in vols}
    if args.entrypoint is not None:
        import shlex
        config["Entrypoint"] = shlex.split(args.entrypoint)
        if "Cmd" in config:
            del config["Cmd"]
    if args.working_dir is not None:
        config["WorkingDir"] = args.working_dir
    image.export(getattr(args, 'destination-image'), image.MANIFEST_DOCKER_MEDIA_TYPE)

def do_shell(args):
    from .run import LocalConfig, run
    config = LocalConfig(args.image)
    config.config['Entrypoint'] = ['/bin/sh']
    config.config['Cmd'] = []
    config.check_volumes = False
    config.args = args.args
    config.volumes = args.volume
    sys.exit(run(config, args.overlay_dir))

def do_publish(args):
    image = ImageManifest.from_path(args.image)
    image.publish(getattr(args, 'docker-url'), oci_spec.MANIFEST_DOCKER_MEDIA_TYPE, args.root_certificate, args.cosign_key)


def store_concil_key(cosign_path, key_id, key, password):
    cosign_path.mkdir(parents=True, exist_ok=True)
    if key.has_private:
        print(f"Private key written to {key_id}.key")
        (cosign_path / f"{key_id}.key").write_bytes(
            key.export_to_pem(True, password.encode('utf8') or None))
    print(f"Public key written to {key_id}.pub")
    (cosign_path / f"{key_id}.pub").write_bytes(
        key.export_to_pem())


def do_config_cosign_generate_key(config, args):
    from jwcrypto import jwk
    key_id = getattr(args, 'key-id')
    key = jwk.JWK.generate(kty='EC', crv='P-256')
    password = getpass("Enter password for private key:")
    password_again = getpass("Enter password for private key again:")
    if password != password_again:
        print("passwords differ")
        sys.exit(1)
    store_concil_key(config.cosign_path, key_id, key, password)


def do_config_cosign_list_keys(config, args):
    cosign_path = config.cosign_path
    if not cosign_path.is_dir():
        print(f"no keys found")
        return
    public_keys = {
        path.stem for path in cosign_path.glob('*.pub')
    }
    private_keys = {
        path.stem for path in cosign_path.glob('*.key')
    }
    keys = sorted(public_keys | private_keys)
    max_length = max(6, max(map(len, keys)))
    print(f"{'Key-ID':{max_length}s} public private")
    for key in keys:
        public = "  x   " if key in public_keys else ""
        private = "   x" if key in private_keys else ""
        print(f"{key:{max_length}s} {public} {private}")


def do_config_cosign_export_key(config, args):
    cosign_path = config.cosign_path
    key_id = getattr(args, 'key-id')
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
    from jwcrypto import jwk
    key_id = getattr(args, 'key-id')
    data = Path(args.filename).read_bytes()
    try:
        key = jwk.JWK.from_pem(data)
        password = ""
    except TypeError:
        password = getpass("Enter password for private key:")
        key = jwk.JWK.from_pem(data, password.encode('utf8'))
    store_concil_key(config.cosign_path, key_id, key, password)


def do_config(args):
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


def main():
    warnings.simplefilter("default", urllib3.exceptions.SecurityWarning)
    store.TAR2SQFS[-1] = "level=19"
    parser = argparse.ArgumentParser(description='Convert container images.')
    subparsers = parser.add_subparsers(help='sub-command help', dest='cmd')
    parser_list = subparsers.add_parser('list', help='list layers of image')
    parser_list.add_argument('image', help='image directory')
    parser_list.add_argument('--config', action='store_true', help='show config')
    parser_list.add_argument('--history', action='store_true', help='show history')
    
    parser_copy = subparsers.add_parser('copy', help='modify the layers of image')
    parser_copy.add_argument('source-image', help='source directory')
    parser_copy.add_argument('destination-image', help='destination directory')
    parser_copy.add_argument('--squashfs', action='store_true',
        help='convert layers to squashfs')
    parser_copy.add_argument('--tar', action='store_true',
        help='convert layers to tar')
    parser_copy.add_argument('--encryption', metavar="key", nargs="+", action='append',
        help='encryption keys')
    parser_copy.add_argument('--remove-layer', metavar="layer", nargs="+", action='append',
        help='ID of layers to remove')
    parser_copy.add_argument('--add-layer', metavar="layer", nargs="+", action='append',
        help='filename of new layers appended')
    parser_copy.add_argument('--merge-layers', metavar="layers", nargs="+", action='append',
        help='filename of new layers appended')
    parser_copy.add_argument('--env', metavar="env", nargs="+", action='append',
        help='updates the environment: Key=Value')
    parser_copy.add_argument('--volumes', metavar="volumes", nargs="+", action='append',
        help='list of volumes')
    parser_copy.add_argument('--entrypoint', action='store', help='sets the entrypoint')
    parser_copy.add_argument('--working-dir', action='store', help='sets the working dir')

    parser_shell = subparsers.add_parser('shell', help='start a shell in the container')
    parser_shell.add_argument('image', help='image directory')
    parser_shell.add_argument('--overlay-dir', action='store', help='overlay directory')
    parser_shell.add_argument('-v', '--volume', action='append', help='volumes')
    parser_shell.add_argument('args', nargs=argparse.REMAINDER)

    parser_publish = subparsers.add_parser('publish', help='publish image to docker hub')
    parser_publish.add_argument('--root-certificate', action='store', help='root certificate for notary')
    parser_publish.add_argument('--cosign-key', action='store', help='signing key for cosign')
    parser_publish.add_argument('image', help='image directory')
    parser_publish.add_argument('docker-url', help='docker url of the form docker://host/repository:tag')

    parser_config = subparsers.add_parser('config', help='configuration commands')
    subparsers_config = parser_config.add_subparsers(help='config-command help', dest='config_cmd')
    parser_cosign_list_keys = subparsers_config.add_parser('cosign-list-keys', help='list all signing keys')
    parser_cosign_generate_key = subparsers_config.add_parser('cosign-generate-key', help='generates a signing key')
    parser_cosign_generate_key.add_argument('key-id', help='the key-id')
    parser_cosign_export_key = subparsers_config.add_parser('cosign-export-key', help='export a signing key')
    parser_cosign_export_key.add_argument('key-id', help='the key-id')
    parser_cosign_export_key.add_argument('filename', help='output filename')
    parser_cosign_export_key.add_argument('--private', action="store_true", help='export the private key')
    parser_cosign_import_key = subparsers_config.add_parser('cosign-import-key', help='import a private or public signing key')
    parser_cosign_import_key.add_argument('key-id', help='the key-id')
    parser_cosign_import_key.add_argument('filename', help='key filename')

    args = parser.parse_args()
    if args.cmd == 'list':
        do_list(args)
    elif args.cmd == 'copy':
        do_copy(args)
    elif args.cmd == 'shell':
        do_shell(args)
    elif args.cmd == 'publish':
        do_publish(args)
    elif args.cmd == 'config':
        do_config(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
