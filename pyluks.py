#!/usr/bin/env python3

import argparse
import hashlib

def createByteString(string, length):
    result = string.encode('ascii')
    result += b'\0' * (length - len(string))
    return result

def createByteInt(value):
    return value.to_bytes(4, 'big')


def getUUID():
    return "3dbc5803-20e4-4d8a-ace3-a034fa0d4a6"


def getmasterkey():
    iterations = 16
    salt = b'\0' * 32
    key = ""
    keyhash = hashlib.pbkdf2_hmac("sha256", key.encode("utf-8"), salt, iterations, 20)

    return (keyhash, salt, iterations)


def createHeader():
    magic = b"LUKS" + bytes.fromhex("BABE")
    version = bytes.fromhex("0001")
    chipher_name = createByteString("aes", 32)
    chipher_mode = createByteString("xts-plain64", 32)
    hash_spec = createByteString("sha256", 32)
    payload_offset = createByteInt(4096)
    key_bytes = createByteInt(64)
    mk_digest, mk_digest_salt, mk_iterations = getmasterkey()
    mk_digest_iter = createByteInt(mk_iterations)
    uuid = createByteString(getUUID(), 40)
    key_slot_0 = b'k' * 48
    key_slot_other = b'\0' * 48 * 7

    header = magic + version + chipher_name + chipher_mode + hash_spec + payload_offset + key_bytes + mk_digest + mk_digest_salt + mk_digest_iter + uuid + key_slot_0 + key_slot_other

    return header

parser = argparse.ArgumentParser(
    prog = 'PyLuks',
    description = 'Create a Luks filesystem image from python')
parser.add_argument('file', type = argparse.FileType('wb'))

args = parser.parse_args()

header = createHeader()
f = args.file
f.write(header)
f.close()
