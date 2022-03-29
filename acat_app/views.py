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
import acat_app.app_settings as appset
from .messaging import *

logger = logging.getLogger(__name__)


# todo: add ssh keypair generation
# todo: add a page of info on cryptographic standards and comparisons (constructor, digest, block, alg, enc purpose, rounds, bits, year implemented, been compromised?)
# todo: move the settings from Config Parser to a database
# todo: add activity audit logging database
# todo: store certificates in database


def about(request):
    logging.info("FUNCTION HTML about")
    return render(request, "about.html", {})


def app_settings(request):
    # initialize Config Parser
    configP_Writer_Object = ConfigParser()
    configP_Writer_Object.read("settings.ini")
    configP_ISSUER_ATTRIBUTES = configP_Writer_Object["ISSUER_ATTRIBUTES"]
    appset.issuer_CN = format(configP_ISSUER_ATTRIBUTES["issuer_cn"])
    appset.issuer_O = format(configP_ISSUER_ATTRIBUTES["issuer_o"])
    appset.issuer_OU = format(configP_ISSUER_ATTRIBUTES["issuer_ou"])
    appset.issuer_L = format(configP_ISSUER_ATTRIBUTES["issuer_l"])
    appset.issuer_S = format(configP_ISSUER_ATTRIBUTES["issuer_s"])
    appset.issuer_C = format(configP_ISSUER_ATTRIBUTES["issuer_c"])
    context = {"issuer_attributes": [appset.issuer_CN, appset.issuer_OU,
                                     appset.issuer_O, appset.issuer_L, appset.issuer_S, appset.issuer_C],
               "subject_attributes": [appset.subject_CN, appset.subject_OU, appset.subject_O, appset.subject_L, appset.subject_S, appset.subject_C],
               "private_key": [appset.private_KeySize, appset.private_SigAlg, appset.private_Algorithm, appset.private_Curve, appset.private_Format],
               "hash_file": [appset.hash_type, appset.hash_value],
               "html_Issuer_CN": appset.issuer_CN,
               "html_Issuer_O": appset.issuer_O,
               "html_Issuer_OU": appset.issuer_OU,
               "html_Issuer_L": appset.issuer_L,
               "html_Issuer_S": appset.issuer_S,
               "html_Issuer_C": appset.issuer_C,
               }
    if request.method == "POST" and "save_settings" in request.POST:
        appset.issuer_CN = request.POST.get("html_Issuer_CN")
        appset.issuer_O = request.POST.get("html_Issuer_O")
        appset.issuer_OU = request.POST.get("html_Issuer_OU")
        appset.issuer_L = request.POST.get("html_Issuer_L")
        appset.issuer_S = request.POST.get("html_Issuer_S")
        appset.issuer_C = request.POST.get("html_Issuer_C")
        configP_ISSUER_ATTRIBUTES["issuer_cn"] = appset.issuer_CN
        configP_ISSUER_ATTRIBUTES["issuer_o"] = appset.issuer_O
        configP_ISSUER_ATTRIBUTES["issuer_ou"] = appset.issuer_OU
        configP_ISSUER_ATTRIBUTES["issuer_l"] = appset.issuer_L
        configP_ISSUER_ATTRIBUTES["issuer_s"] = appset.issuer_S
        configP_ISSUER_ATTRIBUTES["issuer_c"] = appset.issuer_C
        # commit config settings to config file
        with open("settings.ini", "w") as conf:
            configP_Writer_Object.write(conf)
        # update the context display
        context = {"issuer_attributes": [appset.issuer_CN, appset.issuer_OU,
                                         appset.issuer_O, appset.issuer_L, appset.issuer_S, appset.issuer_C],
                   "subject_attributes": [appset.subject_CN, appset.subject_OU, appset.subject_O, appset.subject_L, appset.subject_S, appset.subject_C],
                   "private_key": [appset.private_KeySize, appset.private_SigAlg, appset.private_Algorithm, appset.private_Curve, appset.private_Format],
                   "hash_file": [appset.hash_type, appset.hash_value],
                   "html_Issuer_CN": appset.issuer_CN,
                   "html_Issuer_O": appset.issuer_O,
                   "html_Issuer_OU": appset.issuer_OU,
                   "html_Issuer_L": appset.issuer_L,
                   "html_Issuer_S": appset.issuer_S,
                   "html_Issuer_C": appset.issuer_C,
                   }
        # return response with template and context
        return render(request, "app_settings.html", context)
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
    appset.no_issuer_Address = None
    if request.method == "POST" and "run_script" in request.POST:
        # initialize config parser
        appset.configP_Writer_Object = ConfigParser()
        appset.configP_Writer_Object.read("settings.ini")
        appset.configP_PRIVATE_KEY = appset.configP_Writer_Object["PRIVATE_KEY"]
        appset.configP_SUBJECT_ATTRIBUTES = appset.configP_Writer_Object["SUBJECT_ATTRIBUTES"]
        configP_ISSUER_ATTRIBUTES = appset.configP_Writer_Object["ISSUER_ATTRIBUTES"]
        configP_CERTIFICATE_DATA = appset.configP_Writer_Object["CERTIFICATE_DATA"]
        # get user selected settings from web page
        appset.private_KeySize = request.POST.get("KeySize")
        appset.private_SigAlg = request.POST.get("SigAlg")
        appset.private_Algorithm = request.POST.get("Algorithm")
        # Remove curve data if not using an Elliptic Curve in the cert
        if appset.private_Algorithm == "EC":
            appset.private_Curve = request.POST.get("Curve")
        appset.private_Format = request.POST.get("Format")
        appset.no_subject_Address = request.POST.get("no_Sub_Add")
        appset.subject_CN = request.POST.get("Subject_CN")
        appset.subject_O = request.POST.get("Subject_O")
        appset.subject_OU = request.POST.get("Subject_OU")
        appset.subject_L = request.POST.get("Subject_L")
        appset.subject_S = request.POST.get("Subject_S")
        appset.subject_C = request.POST.get("Subject_C")
        #! get key usage selections from web page -ONLY RESIDENT IN VARIABLE-
        appset.key_usage = request.POST.getlist("KeyUsage")
        #! get extended key usage selections from web page -ONLY RESIDENT IN VARIABLE-
        appset.extended_Key_Usage = request.POST.getlist("extendedKeyUsage")
        # read issuer attributes from config file
        appset.issuer_CN = format(configP_ISSUER_ATTRIBUTES["Issuer_CN"])
        appset.issuer_O = format(configP_ISSUER_ATTRIBUTES["Issuer_O"])
        appset.issuer_OU = format(configP_ISSUER_ATTRIBUTES["Issuer_OU"])
        appset.issuer_L = format(configP_ISSUER_ATTRIBUTES["Issuer_L"])
        appset.issuer_S = format(configP_ISSUER_ATTRIBUTES["Issuer_S"])
        appset.issuer_C = format(configP_ISSUER_ATTRIBUTES["Issuer_C"])
        # write private key settings and subject attribute settings to config file
        appset.configP_PRIVATE_KEY["KeySize"] = appset.private_KeySize
        appset.configP_PRIVATE_KEY["SigAlg"] = appset.private_SigAlg
        appset.configP_PRIVATE_KEY["Algorithm"] = appset.private_Algorithm
        appset.configP_PRIVATE_KEY["Format"] = appset.private_Format
        # Remove curve data if not using an Elliptic Curve in the cert
        if appset.private_Algorithm == "EC":
            appset.configP_PRIVATE_KEY["Curve"] = appset.private_Curve
        else:
            appset.configP_PRIVATE_KEY["Curve"] = ""
        # assign certificate data to configuration writer objects
        appset.configP_SUBJECT_ATTRIBUTES["Subject_CN"] = appset.subject_CN
        appset.configP_SUBJECT_ATTRIBUTES["Subject_O"] = appset.subject_O
        appset.configP_SUBJECT_ATTRIBUTES["Subject_OU"] = appset.subject_OU
        appset.configP_SUBJECT_ATTRIBUTES["Subject_L"] = appset.subject_L
        appset.configP_SUBJECT_ATTRIBUTES["Subject_S"] = appset.subject_S
        appset.configP_SUBJECT_ATTRIBUTES["Subject_C"] = appset.subject_C
        # commit configuration items to config file
        with open("settings.ini", "w") as conf:
            appset.configP_Writer_Object.write(conf)
        fp_NewCert_TimeStamp = time.strftime("%y%m%d_%H%M%S_")
        if request.POST.get("Algorithm", "") == "EC":
            execute_Crypto_Engine_2()
            # read generated cert data into memory
            appset.configP_Writer_Object.read("settings.ini")
            private_to_Webpage = linebreaks(
                format(configP_CERTIFICATE_DATA["PRIVATE2_DECODED"]))
            public_to_Webpage = linebreaks(
                format(configP_CERTIFICATE_DATA["PUBLIC2_DECODED"]))
        else:
            execute_Crypto_Engine_1()
            # read generated cert data into memory
            appset.configP_Writer_Object.read("settings.ini")
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
