import re
from jwcrypto import jwk
from jwcrypto.common import base64url_decode, base64url_encode
from base64 import standard_b64encode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def parse_outer_dict(data):
    parts = iter(re.findall(rb'"(?:[^"]|\\")*"|[{}\[\]]|[^{}\[\]"]+', data))
    if next(parts) != b'{':
        raise ValueError('"{" expected.')
    result = {}
    while True:
        key = next(parts)
        if not key.strip():
            continue
        if key[0] != 34: # b'"'
            raise ValueError('string expected')
        if next(parts).strip() != b':':
            raise ValueError('":" expected.')
        count = 0
        value = b""
        while True:
            token = next(parts)
            if token in (b'}', b']'):
                count -= 1
            elif token in (b'{', b'['):
                count += 1
            value += token
            if count == 0:
                break
        result[key] = value
        token = next(parts)
        if token == b'}':
            break
        if token.strip() != b',':
            raise ValueError('"}" expected.')
    if list(parts):
        raise ValueError("eom expected")
    return result


def verify_ecdsa(public_key, data, sig):
    key_size = (public_key.key_size + 7) // 8
    r = int.from_bytes(sig[:key_size], 'big')
    s = int.from_bytes(sig[key_size:], 'big')
    public_key.verify(encode_dss_signature(r,s), data, ec.ECDSA(hashes.SHA256()))

def sign_ecdsa(private_key, data):
    key_size = (private_key.key_size + 7) // 8
    sig = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r,s = decode_dss_signature(ss)
    return r.to_bytes(key_size, 'big') + s.to_bytes(key_size, 'big')

SIGNATURE_METHODS = {
    "ecdsa": verify_ecdsa,
}

def decode_signed_json(public_keys, data):
    result = parse_outer_dict(data)
    print(result[b'"signatures"'])
    signatures = json.loads(result[b'"signatures"'])
    signed = result[b'"signed"']
    print(signatures)
    for signature in signatures:
        key = public_keys[signature['keyid']]
        sig = base64url_decode(signature['sig'])
        method = signature['method']
        SIGNATURE_METHODS[method](key, signed, sig)
    return json.loads(signed)

def encode_signed_json(private_keys, data):
    data = json.dumps(data, separators=(':',',')).encode('utf8')
    signatures = []
    for key_id, key in private_keys.items():
        sig = sign_ecdsa(key, data)
        signatures.append({
            "keyid": key_id,
            "method": "ecdsa",
            "sig": standard_b64encode(sig).decode('utf8')
        })
    signatures = json.dumps(signatures, separators=(':',',')).encode('utf8')
    return b'{"signed":%s,"signatures"%s}' % (data, signatures)
