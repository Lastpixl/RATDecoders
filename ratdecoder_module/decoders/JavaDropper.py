#!/usr/bin/env python
import zlib
import string
import hashlib
from zipfile import ZipFile
from cStringIO import StringIO
from base64 import b64decode
import logging

# Non Standard Imports
from Crypto.Cipher import ARC4, AES, XOR

log = logging.getLogger("ratdecoder." + __name__)


# Helper Functions Go Here


def string_print(line):
    return filter(lambda x: x in string.printable, line)

# Ciphers


def decrypt_RC4(enckey, data):
    cipher = ARC4.new(enckey)
    return cipher.decrypt(data)


def decrypt_AES(enckey, data):
    cipher = AES.new(enckey)
    return cipher.decrypt(data)


def decrypt_XOR(enckey, data):
    cipher = XOR.new(enckey)
    return cipher.decrypt(data)


def parse_ek(key, drop):
    enc_key = key[:16]
    coded = drop
    drop_details = key[16:]
    decoded = decrypt_AES(enc_key, coded)
    for section in drop_details.split(','):
        log.info(b64decode(section).decode('hex'))
    return decoded


def parse_load(key, drop):
    raw_key = '{0}ALSKEOPQLFKJDUSIKSJAUIE'.format(key)
    enc_key = hashlib.sha256(raw_key).hexdigest()
    decoded = decrypt_RC4(enc_key, drop)
    return decoded


def parse_stub(drop):
    keys = ['0kwi38djuie8oq89', '0B4wCrd5N2OxG93h']

    for key in keys:
        decoded = decrypt_AES(key, drop)
        if 'META-INF' in decoded:
            log.info("Found Embedded Jar")
            return decoded
        if 'Program' in decoded:
            log.info("Found Embedded EXE")
            return decoded


def parse_xor(key, drop):
    key2 = 'FYj&w3bd"m/kSZjD'
    decoded = decrypt_XOR(key2, drop)
    decompressed = zlib.decompress(decoded, 16+zlib.MAX_WBITS)
    return decompressed


def run(raw_data):
    """
    Jar Parser
    """
    decoded = False
    jar_data = StringIO(raw_data)
    jar = ZipFile(jar_data, 'r')

    if 'e' and 'k' in jar.namelist():
        log.info("Found EK Dropper")
        key = jar.read('k')
        drop = jar.read('e')
        decoded = parse_ek(key, drop)

    if 'config.ini' and 'password.ini' in jar.namelist():
        log.info("Found LoadStub Dropper")
        key = jar.read('password.ini')
        drop = jar.read('config.ini')
        decoded = parse_load(key, drop)

    if 'stub/stub.dll' in jar.namelist():
        log.info("Found Stub Dropper")
        drop = jar.read('stub/stub.dll')
        decoded = parse_stub(drop)

    if 'c.dat' in jar.namelist():
        log.info("Found XOR Dropper")
        key_file = b64decode(jar.read('c.dat'))
        key_text = decrypt_XOR('\xdd', key_file)
        drop_file = key_text.split('\n')[1]
        key = key_text.split('\n')[5]
        log.info(key)
        decoded = parse_xor(key, jar.read(drop_file))

    if decoded:
        return decoded
    else:
        log.warning("Unable to decode")
