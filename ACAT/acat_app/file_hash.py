# ACAT/ACAT/acat_app/file_hash.py

import hashlib
import logging
from configparser import ConfigParser
from .global_ import *

# todo: 1) implement previous hashlib algorithms MD4, MDC2, SM3, Whirlpool, RIPEMD-160, MD5-SHA1, SHA512_224, and SHA512_256
# todo: 2) option to display all hashes
# todo: 3) get Adler32 working
# todo: 4) implement zlib's CRC
# todo: 5) output hash values to screen
# todo: 6) debug blake2


logger = logging.getLogger(__name__)


def generate_File_Hash(file, fh_Alg_Selection, fh_shake_digest):
    logging.info("FUNCTION generateFileHash")
    if fh_Alg_Selection == "md5":
        hash_object = hashlib.md5()
    elif fh_Alg_Selection == "shake_128":
        hash_object = hashlib.shake_128()
    elif fh_Alg_Selection == "shake_256":
        hash_object = hashlib.shake_256()
    elif fh_Alg_Selection == "blake2s":
        hash_object = hashlib.blake2s()
    elif fh_Alg_Selection == "blake2b":
        hash_object = hashlib.blake2b()
    elif fh_Alg_Selection == "sha1":
        hash_object = hashlib.sha1()
    elif fh_Alg_Selection == "sha224":
        hash_object = hashlib.sha224()
    elif fh_Alg_Selection == "sha256":
        hash_object = hashlib.sha256()
    elif fh_Alg_Selection == "sha384":
        hash_object = hashlib.sha384()
    elif fh_Alg_Selection == "sha512":
        hash_object = hashlib.sha512()
    elif fh_Alg_Selection == "sha3_224":
        hash_object = hashlib.sha3_224()
    elif fh_Alg_Selection == "sha3_256":
        hash_object = hashlib.sha3_256()
    elif fh_Alg_Selection == "sha3_384":
        hash_object = hashlib.sha3_384()
    elif fh_Alg_Selection == "sha3_512":
        hash_object = hashlib.sha3_512()
    hash_block_size = 128 * hash_object.block_size
    file_name = open("media/" + file, "rb")
    chunk = file_name.read(hash_block_size)
    while chunk:
        hash_object.update(chunk)
        chunk = file_name.read(hash_block_size)
    if fh_Alg_Selection == "shake_128" or "shake_256":
        file_Hash_Value = hash_object.hexdigest(fh_shake_digest)
    else:
        file_Hash_Value = hash_object.hexdigest()
    print("Alg Selection    :  ", fh_Alg_Selection)
    print("Hash Value       :  ", file_Hash_Value)
    # $ write hash type and hash value to config file
    configP_Writer_Object = ConfigParser()
    configP_Writer_Object.read("settings.ini")
    configP_FILE_HASHING = configP_Writer_Object["FILE_HASHING"]
    configP_FILE_HASHING["hash_type"] = fh_Alg_Selection
    configP_FILE_HASHING["hash_value"] = file_Hash_Value
    with open("settings.ini", "w") as conf:
        configP_Writer_Object.write(conf)
