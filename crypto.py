#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from hashlib import new, sha256 as _sha256
from collections import deque
from utils import int_to_unknown_bytes

def sha256(bytestr):
    return _sha256(bytestr).digest()


def double_sha256(bytestr):
    return _sha256(_sha256(bytestr).digest()).digest()


def double_sha256_checksum(bytestr):
    return double_sha256(bytestr)[:4]


def ripemd160_sha256(bytestr):
    return new('ripemd160', sha256(bytestr)).digest()



BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BASE58_ALPHABET_LIST = list(BASE58_ALPHABET)
BASE58_ALPHABET_INDEX = {char: index for index, char in enumerate(BASE58_ALPHABET)}


def b58encode(bytestr):

    alphabet = BASE58_ALPHABET_LIST

    encoded = deque()
    append = encoded.appendleft
    _divmod = divmod

    num = int.from_bytes(bytestr, 'big')

    while num > 0:
        num, rem = _divmod(num, 58)
        append(alphabet[rem])

    encoded = ''.join(encoded)

    pad = 0
    for byte in bytestr:
        if byte == 0:
            pad += 1
        else:
            break

    return '1' * pad + encoded


def b58encode_check(bytestr):
    return b58encode(bytestr + double_sha256_checksum(bytestr))


def b58decode(string):

    alphabet_index = BASE58_ALPHABET_INDEX

    num = 0

    try:
        for char in string:
            num *= 58
            num += alphabet_index[char]
    except KeyError:
        raise ValueError('"{}" is an invalid base58 encoded '
                         'character.'.format(char)) from None

    bytestr = int_to_unknown_bytes(num)

    pad = 0
    for char in string:
        if char == '1':
            pad += 1
        else:
            break

    return b'\x00' * pad + bytestr


def b58decode_check(string):

    decoded = b58decode(string)
    shortened = decoded[:-4]
    decoded_checksum = decoded[-4:]
    hash_checksum = double_sha256_checksum(shortened)

    if decoded_checksum != hash_checksum:
        raise ValueError('Decoded checksum {} derived from "{}" is not equal to hash '
                         'checksum {}.'.format(decoded_checksum, string, hash_checksum))

    return shortened

MAIN_PUBKEY_HASH = b'\x00'
MAIN_SCRIPT_HASH = b'\x05'
MAIN_PRIVATE_KEY = b'\x80'
MAIN_BIP32_PUBKEY = b'\x04\x88\xb2\x1e'
MAIN_BIP32_PRIVKEY = b'\x04\x88\xad\xe4'
TEST_PUBKEY_HASH = b'\x6f'
TEST_SCRIPT_HASH = b'\xc4'
TEST_PRIVATE_KEY = b'\xef'
TEST_BIP32_PUBKEY = b'\x045\x87\xcf'
TEST_BIP32_PRIVKEY = b'\x045\x83\x94'
PUBLIC_KEY_UNCOMPRESSED = b'\x04'
PUBLIC_KEY_COMPRESSED_EVEN_Y = b'\x02'
PUBLIC_KEY_COMPRESSED_ODD_Y = b'\x03'
PRIVATE_KEY_COMPRESSED_PUBKEY = b'\x01'


def address_to_public_key_hash(address):
    get_prefix(address)
    return b58decode_check(address)[1:]


def get_prefix(address):
    prefix = b58decode_check(address)[:1]

    if prefix == MAIN_PUBKEY_HASH:
        return 'main'
    elif prefix == TEST_PUBKEY_HASH:
        return 'test'
    else:
        raise ValueError('{} does not correspond to a mainnet nor '
                         'testnet address.'.format(prefix))


def bytes_to_wif(private_key, prefix='main', compressed=False):

    if prefix == 'test':
        prefix = TEST_PRIVATE_KEY
    else:
        prefix = MAIN_PRIVATE_KEY

    if compressed:
        suffix = PRIVATE_KEY_COMPRESSED_PUBKEY
    else:
        suffix = b''

    private_key = prefix + private_key + suffix

    return b58encode_check(private_key)


def wif_to_bytes(wif):

    private_key = b58decode_check(wif)

    prefix = private_key[:1]

    if prefix == MAIN_PRIVATE_KEY:
        prefix = 'main'
    elif prefix == TEST_PRIVATE_KEY:
        prefix = 'test'
    else:
        raise ValueError('{} does not correspond to a mainnet nor '
                         'testnet address.'.format(prefix))

    # Remove prefix byte and, if present, compression flag.
    if len(wif) == 52 and private_key[-1] == 1:
        private_key, compressed = private_key[1:-1], True
    else:
        private_key, compressed = private_key[1:], False

    return private_key, compressed, prefix


def wif_checksum_check(wif):

    try:
        decoded = b58decode_check(wif)
    except ValueError:
        return False

    if decoded[:1] in (MAIN_PRIVATE_KEY, TEST_PRIVATE_KEY):
        return True

    return False


def public_key_to_address(public_key, prefix='main'):
    if prefix == 'test':
        prefix = TEST_PUBKEY_HASH
    elif prefix == 'main':
        prefix = MAIN_PUBKEY_HASH
    else:
        raise ValueError('Invalid prefix.')

    # 33 bytes compressed, 65 uncompressed.
    length = len(public_key)
    if length not in (33, 65):
        raise ValueError('{} is an invalid length for a public key.'.format(length))

    return b58encode_check(prefix + ripemd160_sha256(public_key))

