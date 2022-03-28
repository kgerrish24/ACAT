# ACAT/ACAT/acat_app/views.py


import logging
import time
from django.core.files.storage import FileSystemStorage
from django.http import HttpResponse
from django.shortcuts import render
from django.utils.html import linebreaks
from .file_hash import *
from .genkeypair import *
from .app_settings import *
from .messaging import *


# todo: add ssh keypair generation
# todo: add a page of info on cryptographic standards and comparisons (constructor, digest, block, alg, enc purpose, rounds, bits, year implemented, been compromised?)
# todo: move the settings from Config Parser to a database
# todo: add activity audit logging database
# todo: store certificates in database


logger = logging.getLogger(__name__)


def about(request):
    logging.info("FUNCTION HTML about")
    return render(request, "about.html", {})


def app_settings(request):
    configParser_read_all_configFile()
    context = {"issuer_attributes": [issuer_CN, issuer_OU,
                                     issuer_O, issuer_L, issuer_S, issuer_C],
               "subject_attributes": [subject_CN, subject_OU, subject_O, subject_L, subject_S, subject_C],
               "private_key": [private_KeySize, private_SigAlg, private_Algorithm, private_Curve, private_Format],
               "hash_file": [hash_type, hash_value]
               }
    # return response with template and context
    return render(request, "app_settings.html", context)


def index(request):
    logging.info("FUNCTION HTML index")
    return render(request, "index.html", {})


def examine(request):
    logging.info("FUNCTION HTML examine")
    return render(request, "examine.html", {})


def file_hash(request):
    logging.info("file_hash")
    # accept post request with file request
    if request.method == "POST" and request.FILES["upload"]:
        logging.info("file_hash 2 + POST")
        # get webpage hash type selection
        fh_Alg_Selection = request.POST.get("algorithm")
        # get variable length digest if using shake128 or shake256
        fh_shake_digestStr = request.POST.get("fh_shake_digest")
        fh_shake_digest = int(fh_shake_digestStr)
        # get file stream from user input then save to media folder
        upload = request.FILES["upload"]
        fss = FileSystemStorage()
        file = fss.save(upload.name, upload)
        file_url = fss.url(file)
        # generate file hash
        generate_File_Hash(file, fh_Alg_Selection, fh_shake_digest)
        # read hash type and hash value from config for display
        configP_Writer_Object = ConfigParser()
        configP_Writer_Object.read("settings.ini")
        configP_FILE_HASHING = configP_Writer_Object["FILE_HASHING"]
        cp_hash_Type = format(configP_FILE_HASHING["hash_type"])
        cp_hash_Value = format(configP_FILE_HASHING["hash_value"])
        context = {
            "cp_hash_Type": cp_hash_Type,
            "cp_hash_Value": cp_hash_Value,
        }
        # return response with template and context
        return render(request, "acat_app/file_hash.html", context)
    return render(request, "acat_app/file_hash.html")
    # return render(request, "acat_app/file_hash.html", {"file_url": file_url})


def genkeypair(request):
    # uses the function generate_Certificate
    logging.info("FUNCTION HTML genkeypair")
    # return response with template
    return render(request, "genkeypair.html")


def generate_Certificate(request):
    logging.info("FUNCTION HTML generate_Certificate")
    global private_KeySize, private_SigAlg, private_Algorithm, private_Curve
    global subject_CN, subject_O, subject_OU, subject_L, subject_S, subject_C
    global issuer_CN, issuer_OU, issuer_O, issuer_L, issuer_S, issuer_C
    global no_subject_Address, no_issuer_Address, private_Format
    no_issuer_Address = None
    if request.method == "POST" and "run_script" in request.POST:
        # initialize config parser
        configP_Writer_Object = ConfigParser()
        configP_Writer_Object.read("settings.ini")
        configP_PRIVATE_KEY = configP_Writer_Object["PRIVATE_KEY"]
        configP_SUBJECT_ATTRIBUTES = configP_Writer_Object["SUBJECT_ATTRIBUTES"]
        configP_ISSUER_ATTRIBUTES = configP_Writer_Object["ISSUER_ATTRIBUTES"]
        configP_CERTIFICATE_DATA = configP_Writer_Object["CERTIFICATE_DATA"]
        # get user selected settings from web page
        private_KeySize = request.POST.get("KeySize")
        private_SigAlg = request.POST.get("SigAlg")
        private_Algorithm = request.POST.get("Algorithm")
        # Remove curve data if not using an Elliptic Curve in the cert
        if private_Algorithm == "EC":
            private_Curve = request.POST.get("Curve")
        private_Format = request.POST.get("Format")
        no_subject_Address = request.POST.get("no_Sub_Add")
        subject_CN = request.POST.get("Subject_CN")
        subject_O = request.POST.get("Subject_O")
        subject_OU = request.POST.get("Subject_OU")
        subject_L = request.POST.get("Subject_L")
        subject_S = request.POST.get("Subject_S")
        subject_C = request.POST.get("Subject_C")
        #! get key usage selections from web page -ONLY RESIDENT IN VARIABLE-
        key_usage = request.POST.getlist("KeyUsage")
        #! get extended key usage selections from web page -ONLY RESIDENT IN VARIABLE-
        extended_Key_Usage = request.POST.getlist("extendedKeyUsage")
        # read issuer attributes from config file
        issuer_CN = format(configP_ISSUER_ATTRIBUTES["Issuer_CN"])
        issuer_O = format(configP_ISSUER_ATTRIBUTES["Issuer_O"])
        issuer_OU = format(configP_ISSUER_ATTRIBUTES["Issuer_OU"])
        issuer_L = format(configP_ISSUER_ATTRIBUTES["Issuer_L"])
        issuer_S = format(configP_ISSUER_ATTRIBUTES["Issuer_S"])
        issuer_C = format(configP_ISSUER_ATTRIBUTES["Issuer_C"])
        # write private key settings and subject attribute settings to config file
        configP_PRIVATE_KEY["KeySize"] = private_KeySize
        configP_PRIVATE_KEY["SigAlg"] = private_SigAlg
        configP_PRIVATE_KEY["Algorithm"] = private_Algorithm
        configP_PRIVATE_KEY["Format"] = private_Format
        # Remove curve data if not using an Elliptic Curve in the cert
        if private_Algorithm == "EC":
            configP_PRIVATE_KEY["Curve"] = private_Curve
        else:
            configP_PRIVATE_KEY["Curve"] = ""
        # assign certificate data to configuration writer objects
        configP_SUBJECT_ATTRIBUTES["Subject_CN"] = subject_CN
        configP_SUBJECT_ATTRIBUTES["Subject_O"] = subject_O
        configP_SUBJECT_ATTRIBUTES["Subject_OU"] = subject_OU
        configP_SUBJECT_ATTRIBUTES["Subject_L"] = subject_L
        configP_SUBJECT_ATTRIBUTES["Subject_S"] = subject_S
        configP_SUBJECT_ATTRIBUTES["Subject_C"] = subject_C
        # commit configuration items to config file
        with open("settings.ini", "w") as conf:
            configP_Writer_Object.write(conf)
        fp_NewCert_TimeStamp = time.strftime("%y%m%d_%H%M%S_")
        if request.POST.get("Algorithm", "") == "EC":
            execute_Crypto_Engine_2()
            # read generated cert data into memory
            configP_Writer_Object.read("settings.ini")
            private_to_Webpage = linebreaks(
                format(configP_CERTIFICATE_DATA["PRIVATE2_DECODED"]))
            public_to_Webpage = linebreaks(
                format(configP_CERTIFICATE_DATA["PUBLIC2_DECODED"]))
        else:
            execute_Crypto_Engine_1()
            # read generated cert data into memory
            configP_Writer_Object.read("settings.ini")
            private_to_Webpage = linebreaks(
                format(configP_CERTIFICATE_DATA["PRIVATE1_DECODED"]))
            public_to_Webpage = linebreaks(
                format(configP_CERTIFICATE_DATA["PUBLIC1_DECODED"]))
        html = (
            "<html><body><a href=/genkeypair>Click to Return</a><p>Private Certificate Displayed First and Saved to PRIVATE.KEY.</p>Public Certificate Displayed Second and saved to PUBLIC.CRT.<p></p>Private Certificate Below<p></p> %s </body></html>"
            % private_to_Webpage
            + "<html><body>Public Certificate Below %s </body></html>" % public_to_Webpage
        )
        file_Processing(fp_NewCert_TimeStamp)
        # return response with html
        return HttpResponse(html)


def messaging(request):
    logging.info("FUNCTION HTML messaging")
    global plaintextMessage, decryptionKey, enc_or_dec
    # code for encryption
    if request.method == "POST" and "execute_encryption" in request.POST:
        # assign textbox data to variables
        plaintextMessage = request.POST.get("plaintextMessage")
        decryptionKey = request.POST.get("decryptionKey")
        # enc_or_dec = 1 for Encryption and 2 for Decryption
        enc_or_dec = 1
        messageEncrypt_Fernet()
        from .messaging import decryptedMessage, encryptedMessage, encryptionKey

        context = {
            "encryption_key": encryptionKey,
            # "decryption_key": decryptionKey,
            "encrypted_message": encryptedMessage,
            "decrypted_message": decryptedMessage,
        }
        # return response with template and context
        return render(request, "messaging.html", context)
    # code for decryption
    if request.method == "POST" and "execute_decryption" in request.POST:
        # assign textbox data to variables and convert to bytes encoded in utf-8
        plaintextMessage = request.POST.get("plaintextMessage")
        decryptionKey = request.POST.get("decryptionKey")
        plaintextMessage = bytes(plaintextMessage, "utf-8")
        decryptionKey = bytes(decryptionKey, "utf-8")
        enc_or_dec = 2
        messageEncrypt_Fernet()
        from .messaging import decryptedMessage

        encryptedMessage = plaintextMessage
        context = {
            # "encryption_key": encryptionKey,
            "decryption_key": decryptionKey,
            "encrypted_message": encryptedMessage,
            "decrypted_message": decryptedMessage,
        }
        # return response with template and context
        return render(request, "messaging.html", context)
    # return response with template
    return render(request, "messaging.html", {})


def upload(request):
    if request.method == "POST" and request.FILES["upload"]:
        upload = request.FILES["upload"]
        fss = FileSystemStorage()
        file = fss.save(upload.name, upload)
        file_url = fss.url(file)
        return render(request, "acat_app/upload.html", {"file_url": file_url})
    # return response with template
    return render(request, "acat_app/upload.html")
