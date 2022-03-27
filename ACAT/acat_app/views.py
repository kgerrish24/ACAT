# ACAT/ACAT/acat_app/views.py


import logging
import time

from django.core.files.storage import FileSystemStorage
from django.http import HttpResponse
from django.shortcuts import render
from django.utils.html import linebreaks
from configparser import ConfigParser
from .file_hash import *
from .genkeypair import *
from .global_ import *
from .messaging import *

# // todo: 3) consolidate views
# // todo: 5) organize request execution view into functions
# // todo: 7) move configuration to settings and functions
# todo: 2) encrypted messaging
# todo: 9) password hash extractor and identifier
# todo: 10) add abilities to about page
# todo: 11) add ssh ver-1 keypair generation
# todo: 12) add ssh ver-2 keypair generation
# todo: 13) activity audit database
# todo: 16) narrow module import
# // todo: 19) fix upper case starting variables, convert to camel case
# // todo: 20) tweak logging
# todo: 21) debug logging
# // todo: 22) break code out into individual files
# todo: 23) cleanup project url paterns and namespaces
# todo: 24) add brute force password cracking for apps like zip archiving
# todo: 25) add password salt/hash analysis and cracking Windows OS
# todo: 26) expand menu system
# todo: 27) add cryptographic standards and comparisons charts or datasets (constructor, digest, block, alg, purpose, rounds, bits, year, been compromised?)
# todo: 28) file hashing
# todo: 29) create a cryptography app for performance benchmarking. CPU and GPU and MultiThreaded
# todo: 30) document which crypto features come from which modules, populate about section
# todo: 31) verification and diagnostics process
# todo: 32) convert the config parser setup to an internal database


logger = logging.getLogger(__name__)


def about(request):
    logging.info("FUNCTION HTML about")
    return render(request, "about.html", {})


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
    global private_KeySize, private_SigAlg, private_Algorithm, private_Curve, private_Format
    global subject_CN, subject_O, subject_OU, subject_L, subject_S, subject_C
    global issuer_CN, issuer_O, issuer_OU, issuer_L, issuer_S, issuer_C
    global no_subject_Address, no_issuer_Address
    private_Curve = ""
    if request.method == "POST" and "run_script" in request.POST:
        # get private key selections
        private_KeySize = request.POST.get("KeySize")
        private_SigAlg = request.POST.get("SigAlg")
        private_Algorithm = request.POST.get("Algorithm")
        if private_Algorithm == "EC":
            private_Curve = request.POST.get("Curve")
        private_Format = request.POST.get("Format")
        # get subject attribute information
        no_subject_Address = request.POST.get("no_Sub_Add")
        subject_CN = request.POST.get("Subject_CN")
        subject_O = request.POST.get("Subject_O")
        subject_OU = request.POST.get("Subject_OU")
        subject_L = request.POST.get("Subject_L")
        subject_S = request.POST.get("Subject_S")
        subject_C = request.POST.get("Subject_C")
        # get issuer attribute information
        no_issuer_Address = request.POST.get("no_Iss_Add")
        issuer_CN = request.POST.get("Issuer_CN")
        issuer_O = request.POST.get("Issuer_O")
        issuer_OU = request.POST.get("Issuer_OU")
        issuer_L = request.POST.get("Issuer_L")
        issuer_S = request.POST.get("Issuer_S")
        issuer_C = request.POST.get("Issuer_C")
        # get key usage selections
        key_usage = request.POST.getlist("KeyUsage")
        # get extended key usage selections
        extended_Key_Usage = request.POST.getlist("extendedKeyUsage")
        configP_from_ConfigFile()
        configP_to_ConfigFile(request)
        fp_NewCert_TimeStamp = time.strftime("%y%m%d_%H%M%S_")
        if request.POST.get("Algorithm", "") == "EC":
            execute_Crypto_Engine_2()
            from .genkeypair import configP_Writer_Object

            configP_Writer_Object.read("settings.ini")
            from .genkeypair import configP_CERTIFICATE_DATA

            private_to_Webpage = linebreaks(
                format(configP_CERTIFICATE_DATA["PRIVATE2_DECODED"])
            )
            public_to_Webpage = linebreaks(format(configP_CERTIFICATE_DATA["PUBLIC2_DECODED"]))
        else:
            execute_Crypto_Engine_1()
            from .genkeypair import configP_Writer_Object

            configP_Writer_Object.read("settings.ini")
            from .genkeypair import configP_CERTIFICATE_DATA

            private_to_Webpage = linebreaks(
                format(configP_CERTIFICATE_DATA["PRIVATE1_DECODED"])
            )
            public_to_Webpage = linebreaks(format(configP_CERTIFICATE_DATA["PUBLIC1_DECODED"]))
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


def new_design(request):
    # create a dictionary to pass
    # data to the template
    context = {"data": "New design sandbox web page", "list": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]}
    # return response with template and context
    return render(request, "new_design.html", context)


def test_view(request):
    # create a dictionary to pass
    # data to the template
    context = {"data": "Gfg is the best", "list": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]}
    # return response with template and context
    return render(request, "test.html", context)


def upload(request):
    if request.method == "POST" and request.FILES["upload"]:
        upload = request.FILES["upload"]
        fss = FileSystemStorage()
        file = fss.save(upload.name, upload)
        file_url = fss.url(file)
        return render(request, "acat_app/upload.html", {"file_url": file_url})
    # return response with template
    return render(request, "acat_app/upload.html")
