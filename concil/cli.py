import argparse
from itertools import chain
from collections import Counter
from pathlib import Path
from .image import ImageManifest, Descriptor
from . import store
from cryptography.hazmat.backends import default_backend
from jwcrypto import jwk
import urllib3.exceptions
import warnings

def generate_key(outputfilename, password):
    key = jwk.JWK.generate(kty='EC', crv='P-521')    
    with open(outputfilename + '.private.pem', 'wb') as output:
        output.write(key.export_to_pem(True, password.encode()))
    with open(outputfilename + '.pem', 'wb') as output:
        output.write(key.export_to_pem())

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
        if 'Entrypoint' in config:
            print(f"Entrypoint: {' '.join(map(shlex.quote, config['Entrypoint']))}")
        if 'Cmd' in config:
            print(f"Cmd: {' '.join(map(shlex.quote, config['Cmd']))}")
        for key in ['User', 'ExposedPorts', 'WorkingDir', 'Labels', 'StopSignal']:
            if key in config:
                print(f"{key}: {config[key]}")
        if "Env" in config:
            print()
            print("Environment:")
            for env in config["Env"]:
                print(env)
        if "Volumes" in config:
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
    keys = []
    for key in chain.from_iterable(args.encryption or []):
        with open(key, 'rb') as inp:
            keys.append(jwk.JWK.from_pem(inp.read()))
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
            layer = Descriptor(path, media_type, None)
            layer.status = 'new'
            print(f"{layer.digest.split(':',1)[1]:65s} {layer.size:12d} {layer.media_type} added.")
            image.layers.append(layer)
    if args.squashfs:
        for layer in image.layers:
            layer.convert("squashfs")
    for layer in image.layers:
        layer.encryption_keys = keys
    config = image.configuration['config']
    if args.env:
        print(args.env)
        env = dict(kv.split('=',1) for env in args.env for kv in env)
        environment = []
        if "Env" in config:
            for kv in config["Env"]:
                k, v = kv.split('=', 1)
                if k in env:
                    v = env.pop(k)
                    kv = f"{k}={v}"
                if v:
                    environment.append(kv)
        for k, v in env.items():
            environment.append(f"{k}={v}")
        config["Env"] = environment
    if args.volumes:
        config["Volume"] = {v:{} for vols in args.volumes for v in vols}
    if args.entrypoint is not None:
        import shlex
        config["Entrypoint"] = shlex.split(args.entrypoint)
    if args.working_dir is not None:
        config["WorkingDir"] = args.working_dir
    image.export(getattr(args, 'destination-image'), image.MANIFEST_DOCKER_MEDIA_TYPE)

def do_publish(args):
    image = ImageManifest.from_path(args.image)
    image.publish(getattr(args, 'docker-url'), image.MANIFEST_DOCKER_MEDIA_TYPE, args.root_certificate)

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
#
    parser_publish = subparsers.add_parser('publish', help='publish image to docker hub')
    parser_publish.add_argument('--root-certificate', action='store', help='root certificate')
    parser_publish.add_argument('image', help='image directory')
    parser_publish.add_argument('docker-url', help='docker url of the form docker://host/repository:tag')

    args = parser.parse_args()
    if args.cmd == 'list':
        do_list(args)
    elif args.cmd == 'copy':
        do_copy(args)
    elif args.cmd == 'publish':
        do_publish(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
