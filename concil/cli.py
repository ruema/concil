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


def resolve_digests(digests, short_digests):
    """ resolves a list of short_digests into full digests
    returns the list of list of digests and a error flag
    """
    result = []
    error = False
    for inner_short_digests in (short_digests or []):
        inner_result = []
        for short_digest in inner_short_digests:
            found = [d for d in digests if d.startswith(short_digest)]
            if len(found) != 1:
                if not found:
                    print(f"{short_digest} not found!")
                else:
                    print(f"{short_digest} amigous: {', '.join(found)}!")
                error = True
            else:
                inner_result.append(found[0])
        result.append(inner_result)
    return result, error
                

def do_list(args):
    image = ImageManifest.from_path(args.image)
    print(f"{'Digest':65s} {'Size':12s} Media-Type")
    for layer in image.layers:
        print(f"{layer.digest.split(':',1)[1]:65s} {layer.size:12d} {layer.media_type}")

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
                media_type = 'tar+gz'
            else:
                raise RuntimeError("unsupported file type")
            layer = Descriptor(path, media_type, None, path.stat().st_size)
            layer.status = 'new'
            print(f"{layer.digest.split(':',1)[1]:65s} {layer.size:12d} {layer.media_type} added.")
            image.layers.append(layer)
    if args.squashfs:
        for layer in image.layers:
            layer.convert("squashfs")
    for layer in image.layers:
        layer.encryption_keys = keys
    image.export(getattr(args, 'destination-image'), image.MANIFEST_DOCKER_MEDIA_TYPE)

def do_publish(args):
    image = ImageManifest.from_path(args.image)
    image.publish(getattr(args, 'docker-url'), image.MANIFEST_DOCKER_MEDIA_TYPE)

def main():
    warnings.simplefilter("default", urllib3.exceptions.SecurityWarning)
    store.TAR2SQFS = ["tar2sqfs", "-c", "zstd", "-X", "level=19"]
    parser = argparse.ArgumentParser(description='Convert container images.')
    subparsers = parser.add_subparsers(help='sub-command help', dest='cmd')
    parser_list = subparsers.add_parser('list', help='list layers of image')
    parser_list.add_argument('image', help='image directory')
    
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

    parser_publish = subparsers.add_parser('publish', help='publish image to docker hub')
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
        raise RuntimeError()

if __name__ == "__main__":
    main()
