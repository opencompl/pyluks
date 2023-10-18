#!/usr/bin/env python3

import argparse
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def createByteString(string, length):
    result = string.encode('ascii')
    result += b'\0' * (length - len(string))
    return result

def createByteInt(value):
    return value.to_bytes(4, 'big')

def getUUID():
    return "abcdabcd-abcd-abcd-abcd-abcdabcdabcd"

def getRandom(length):
    return bytes.fromhex("01") * length

def getmasterkey():
    iterations = 1000
    salt = getRandom(32)
    key = bytes.fromhex(
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            )
    keyhash = hashlib.pbkdf2_hmac("sha256", key, salt, iterations, 20)

    return (key, keyhash, salt, iterations)

def xorbytes(var, key):
    return bytes(a ^ b for a, b in zip(var, key))

def hashval(val):
    width = 32
    blocks = math.ceil((len(val)/width))

    result = bytes()
    for i in range(blocks):
        data = val[i*width:(i+1)*width]
        iterator = i.to_bytes(4, "big")
        h = hashlib.sha256()
        h.update(iterator)
        h.update(data)
        hashedData = h.digest()
        hashedData = hashedData[0:len(data)]
        result += hashedData

    return result

import random, math

def afSplitter(unsplitMaterial, stripes):
    length = len(unsplitMaterial)

    d = bytes.fromhex("00") * length
    s = b''

    for stripe in range(stripes-1):
        s_k = getRandom(length)

        d = xorbytes(d, s_k)
        d = hashval(d)
        s += s_k

    s += xorbytes(d, unsplitMaterial)

    return s

def getSlotKey(mk, stripes, iterations, salt):
    split = afSplitter(mk, stripes)
    key = ""
    keyhash = hashlib.pbkdf2_hmac("sha256", key.encode("utf-8"), salt, iterations, 64)

    blocks = len(split)
    ct = bytes()
    for i in range(500):
        src = split[i * 512: (i+1)*512]
        iv = (i).to_bytes(16, 'little')
        cipher = Cipher(algorithms.AES(keyhash), modes.XTS(iv))
        encryptor = cipher.encryptor()
        ct += (encryptor.update(src) + encryptor.finalize())
    return ct

def createHeader():
    header = bytes()

    magic = b"LUKS" + bytes.fromhex("BABE")
    version = bytes.fromhex("0001")
    header += magic + version

    chipher_name = createByteString("aes", 32)
    chipher_mode = createByteString("xts-plain64", 32)
    hash_spec = createByteString("sha256", 32)
    header += chipher_name + chipher_mode + hash_spec

    conf_payload_offset = 4096
    payload_offset = createByteInt(conf_payload_offset)
    header += payload_offset

    key_bytes = createByteInt(64)
    mk, mk_digest, mk_digest_salt, mk_iterations = getmasterkey()
    mk_digest_iter = createByteInt(mk_iterations)
    header += key_bytes + mk_digest + mk_digest_salt + mk_digest_iter

    uuid = createByteString(getUUID(), 40)
    header += uuid

    disabled = bytes.fromhex("0000DEAD")
    enabled = bytes.fromhex("00AC71F3")
    status = enabled

    size_of_phdr = 592
    luks_sector_size = 512

    #offset =  size_of_phdr // luks_sector_size + 1
    offset = 8
    stripes = 4000
    #keyMaterialSectors = (stripes * 64) // luks_sector_size + 1
    keyMaterialSectors = 504

    for key_id in range(8):
        iterations = 124680
        salt = getRandom(32)
        header += status
        if status == enabled:
            header += createByteInt(iterations)
            header += salt
            status = disabled
        else:
            header += b'\0' * 4
            header += b'\0' * 32

        header += createByteInt(offset)
        header += createByteInt(stripes)
        offset += keyMaterialSectors

    header += b'\0' * (conf_payload_offset - len(header))

    slot1 = getSlotKey(mk, stripes, iterations, salt)
    header += slot1
    header += b'\0' * 512 * 4

    for id in range(1,8):
        header += getRandom(512 * 500)
        header += b'\0' * 512 * 4

    conf_filesize = pow(2, 24)
    header += b'\0' * (conf_filesize - len(header))

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
