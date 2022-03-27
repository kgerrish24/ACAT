# ACAT/ACAT/acat_app/messaging.py

import logging
from cryptography.fernet import Fernet
from .app_settings import *


# todo: resolve leading and trailing character formatting


logger = logging.getLogger(__name__)


# Fernet Symmetric Authenticated Cryptography
def messageEncrypt_Fernet():
    logger.info("FUNCTION messageEncrypt_Fernet")
    global encryptionKey, encryptedMessage, decryptedMessage
    from .views import decryptionKey, enc_or_dec, plaintextMessage

    if enc_or_dec == 1:
        logger.info("FUNCTION messageEncrypt_Fernet IF enc_or_dec == 1")
        encryptionKey = Fernet.generate_key()
        fernet = Fernet(encryptionKey)
        encryptedMessage = fernet.encrypt(plaintextMessage.encode())
        decryptedMessage = fernet.decrypt(encryptedMessage).decode()
        # print("plaintext Message: ", plaintextMessage)
        # print("encryption key   : ", encryptionKey)
        # print("decryption key   : ", decryptionKey)
        # print("encrypted string : ", encryptedMessage)
        # print("decrypted string : ", decryptedMessage)
    elif enc_or_dec == 2:
        logger.info("FUNCTION messageEncrypt_Fernet IF enc_or_dec == 2")
        f = Fernet(decryptionKey)
        decryptedMessage = f.decrypt(plaintextMessage)
