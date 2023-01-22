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
    return "3dbc5803-20e4-4d8a-ace3-a034fa0d4a64"


def getmasterkey():
    iterations = 128754
    salt = bytes.fromhex("1924e8299633c0e0f2eb700d046f4836e3d644f7ad8836e7c5a73f05f88960b1")
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

    header = magic + version + chipher_name + chipher_mode + hash_spec + payload_offset + key_bytes + mk_digest + mk_digest_salt + mk_digest_iter + uuid

    disabled = bytes.fromhex("0000DEAD")
    enabled = bytes.fromhex("00AC71F3")
    status = enabled

    size_of_phdr = 592
    luks_sector_size = 512

    offset =  size_of_phdr // luks_sector_size + 1
    offset =  8
    stripes = 4000
    keyMaterialSectors = (stripes * 64) // luks_sector_size + 1
    keyMaterialSectors = 504


    for key_id in range(8):
        iterations = 2056030
        salt = bytes.fromhex("e98b34cc2157547c10c4e31d1bdf985555c2bf561488116f38dbd344a47a828f")
        header += status
        if status == disabled:
            header += b'\0' * 4
            header += b'\0' * 32
            header += createByteInt(offset)
            header += createByteInt(stripes)
            offset +=  keyMaterialSectors
            continue

        header += createByteInt(iterations)
        header += salt
        header += createByteInt(offset)
        header += createByteInt(stripes)
        status = disabled
        offset +=  keyMaterialSectors

    header += b'\0' * 16776624
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
