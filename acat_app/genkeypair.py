# ACAT/ACAT/acat_app/genkeypair.py


import datetime
import logging
import os
import shutil
from configparser import ConfigParser
import acat_app.app_settings as appset


logger = logging.getLogger(__name__)


# todo: pass args to TLS engines instead of using global variables?
# todo: add subject Alt Name logic
# todo: setup logic for key usage
# todo: setup logic for extended key usage


# crypto engine 1 OpenSSL used for RSA and DSA certs
# crypto engine 2 cryptography used for EC certs


def file_Processing(fp_NewCert_TimeStamp):
    logging.info("FUNCTION file_Processing")
    path_NewCerts = "acat_app/NewCerts/"
    fp_cert_Private = "private.key"
    fp_cert_Public = "public.crt"
    # Strip Period and At characters off Subject_CN so it can be safely added to filename
    Subject_CN_PrepFileName = appset.subject_CN
    Subject_CN_ForFileName = Subject_CN_PrepFileName.replace(
        ".", "-").replace("@", "-")
    # Check if directory exists, if not then create
    isExist = os.path.exists(path_NewCerts)
    if isExist == False:
        logging.info("FUNCTION file_Processing IF isExist == False ")
        os.mkdir(path_NewCerts)
    # Check for private cert, if found then copy to directory and append date, time, and subject
    if os.path.isfile(fp_cert_Private):
        logging.info(
            "FUNCTION file_Processing IF os.path.isfile(fp_cert_Private)")
        shutil.copy(fp_cert_Private, path_NewCerts)
        os.rename(path_NewCerts + fp_cert_Private, path_NewCerts +
                  fp_NewCert_TimeStamp + Subject_CN_ForFileName + "_" + fp_cert_Private,)
    # Check for public cert, if found then copy to directory and append date, time, and subject
    if os.path.isfile(fp_cert_Public):
        shutil.copy(fp_cert_Public, path_NewCerts)
        os.rename(path_NewCerts + fp_cert_Public, path_NewCerts +
                  fp_NewCert_TimeStamp + Subject_CN_ForFileName + "_" + fp_cert_Public,)


def crypto_Engine_1():
    logging.info("FUNCTION crypto_Engine_1")
    import random
    from OpenSSL import crypto
    appset.private_key = crypto.PKey()
    if appset.private_Algorithm == "RSA":
        appset.private_key.generate_key(
            crypto.TYPE_RSA, (int(appset.private_KeySize)))
    elif appset.private_Algorithm == "DSA":
        appset.private_key.generate_key(
            crypto.TYPE_DSA, (int(appset.private_KeySize)))
    x509 = crypto.X509()
    subject = x509.get_subject()
    # get variable to determine if adding subject address
    if appset.no_subject_Address == "no_Sub_Add":
        subject.organizationName = appset.subject_O
        subject.organizationalUnitName = appset.subject_OU
        subject.commonName = appset.subject_CN
    else:
        subject.countryName = appset.subject_C
        subject.stateOrProvinceName = appset.subject_S
        subject.localityName = appset.subject_L
        subject.organizationName = appset.subject_O
        subject.organizationalUnitName = appset.subject_OU
        subject.commonName = appset.subject_CN
    issuer = x509.get_issuer()
    # get variable to determine if adding issuer address
    if appset.no_issuer_Address == "no_Iss_Add":
        issuer.organizationName = appset.issuer_O
        issuer.organizationalUnitName = appset.issuer_OU
        issuer.commonName = appset.issuer_CN
    else:
        issuer.countryName = appset.issuer_C
        issuer.stateOrProvinceName = appset.issuer_S
        issuer.localityName = appset.issuer_L
        issuer.organizationName = appset.issuer_O
        issuer.organizationalUnitName = appset.issuer_OU
        issuer.commonName = appset.issuer_CN
    x509.gmtime_adj_notBefore(0)
    # Years * days * hours * minutes * seconds
    x509.gmtime_adj_notAfter(1 * 365 * 24 * 60 * 60)
    x509.set_pubkey(appset.private_key)
    x509.set_serial_number(random.randrange(100000))
    x509.set_version(2)
    x509.add_extensions(
        [
            crypto.X509Extension
            (b"subjectAltName", False,
             ",".join(["DNS:%s" % appset.subject_CN % (),
                       "DNS:*.%s" % appset.subject_CN % (),
                       "DNS:localhost",
                       "DNS:*.localhost",
                       ]
                      ).encode(),
             ),
            crypto.X509Extension(b"keyUsage", True,
                                 b"digitalSignature,keyEncipherment"),
            crypto.X509Extension(b"extendedKeyUsage", False,
                                 b"clientAuth,serverAuth"),
            crypto.X509Extension(b"basicConstraints", True,
                                 b"CA:false"), ])
    x509.sign(appset.private_key, (appset.private_SigAlg))
    return (crypto.dump_certificate(crypto.FILETYPE_PEM, x509), crypto.dump_privatekey(crypto.FILETYPE_PEM, appset.private_key),)


def crypto_Engine_2():
    logging.info("FUNCTION crypto_Engine_2")
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID
    one_day = datetime.timedelta(1, 0, 0)
    if appset.private_Algorithm == "RSA":
        logging.info("FUNCTION crypto_Engine_2 IF cert_Algorithm == RSA")
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=(int(appset.private_KeySize)), backend=default_backend())
    elif appset.private_Algorithm == "EC":
        logging.info("FUNCTION crypto_Engine_2 ELIF cert_Algorithm == EC")
        if appset.private_Curve == "secp521r1":
            private_key = ec.generate_private_key(ec.SECP521R1())
        elif appset.private_Curve == "secp384r1":
            private_key = ec.generate_private_key(ec.SECP384R1())
        elif appset.private_Curve == "secp256r1":
            private_key = ec.generate_private_key(ec.SECP256R1())
        elif appset.private_Curve == "secp256k1":
            private_key = ec.generate_private_key(ec.SECP256K1())
        elif appset.private_Curve == "secp224r1":
            private_key = ec.generate_private_key(ec.SECP224R1())
        elif appset.private_Curve == "secp192r1":
            private_key = ec.generate_private_key(ec.SECP192R1())
        elif appset.private_Curve == "BrainpoolP512R1":
            private_key = ec.generate_private_key(ec.BrainpoolP512R1())
        elif appset.private_Curve == "BrainpoolP384R1":
            private_key = ec.generate_private_key(ec.BrainpoolP384R1())
        elif appset.private_Curve == "BrainpoolP256R1":
            private_key = ec.generate_private_key(ec.BrainpoolP256R1())
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    # get variable to determine if adding subject address
    if appset.no_subject_Address == "no_Sub_Add":
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.ORGANIZATION_NAME, appset.subject_O),
                    x509.NameAttribute(
                        NameOID.ORGANIZATIONAL_UNIT_NAME, appset.subject_OU),
                    x509.NameAttribute(NameOID.COMMON_NAME, appset.subject_CN),
                ]
            )
        )
    else:
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, appset.subject_C),
                    x509.NameAttribute(
                        NameOID.STATE_OR_PROVINCE_NAME, appset.subject_S),
                    x509.NameAttribute(
                        NameOID.LOCALITY_NAME, appset.subject_L),
                    x509.NameAttribute(
                        NameOID.ORGANIZATION_NAME, appset.subject_O),
                    x509.NameAttribute(
                        NameOID.ORGANIZATIONAL_UNIT_NAME, appset.subject_OU),
                    x509.NameAttribute(NameOID.COMMON_NAME, appset.subject_CN),
                ]
            )
        )
    # get variable to determine if adding issuer address
    if appset.no_issuer_Address == "no_Iss_Add":
        builder = builder.issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.ORGANIZATION_NAME, appset.issuer_O),
                    x509.NameAttribute(
                        NameOID.ORGANIZATIONAL_UNIT_NAME, appset.issuer_OU),
                    x509.NameAttribute(NameOID.COMMON_NAME, appset.issuer_CN),
                ]
            )
        )
    else:
        builder = builder.issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, appset.issuer_C),
                    x509.NameAttribute(
                        NameOID.STATE_OR_PROVINCE_NAME, appset.issuer_S),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, appset.issuer_L),
                    x509.NameAttribute(
                        NameOID.ORGANIZATION_NAME, appset.issuer_O),
                    x509.NameAttribute(
                        NameOID.ORGANIZATIONAL_UNIT_NAME, appset.issuer_OU),
                    x509.NameAttribute(NameOID.COMMON_NAME, appset.issuer_CN),
                ]
            )
        )
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(
        datetime.datetime.today() + (one_day * 365 * 1))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.SubjectAlternativeName(
            [
                x509.DNSName(appset.subject_CN % ()),
                x509.DNSName("*.%s" % appset.subject_CN % ()),
                x509.DNSName("localhost"),
                x509.DNSName("*.localhost"),
            ]
        ),
        critical=False,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH, x509.OID_SERVER_AUTH]), critical=False
    )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    if appset.private_SigAlg == "sha1":
        certificate = builder.sign(
            private_key=private_key, algorithm=hashes.SHA1(), backend=default_backend()
        )
    elif appset.private_SigAlg == "sha256":
        logging.info("FUNCTION crypto_Engine_2 ELIF cert_SigAlg == sha256 ")
        certificate = builder.sign(
            private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend()
        )
    elif appset.private_SigAlg == "sha384":
        certificate = builder.sign(
            private_key=private_key, algorithm=hashes.SHA384(), backend=default_backend()
        )
    elif appset.private_SigAlg == "sha512":
        certificate = builder.sign(
            private_key=private_key, algorithm=hashes.SHA512(), backend=default_backend()
        )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def execute_Crypto_Engine_1():
    logging.info("FUNCTION execute_Crypto_Engine_1")
    # initialize configuration parser
    configP_Writer_Object = ConfigParser()
    configP_Writer_Object.read("settings.ini")
    raw_Certs1 = crypto_Engine_1()
    raw_Certs_Listed1 = list(raw_Certs1)
    private1 = raw_Certs_Listed1[1]
    public1 = raw_Certs_Listed1[0]
    private1_Decoded = private1.decode()
    public1_Decoded = public1.decode()
    # assign certificate data to configuration writer objects
    configP_CERTIFICATE_DATA = configP_Writer_Object["CERTIFICATE_DATA"]
    configP_CERTIFICATE_DATA["PRIVATE1_DECODED"] = private1_Decoded
    configP_CERTIFICATE_DATA["PUBLIC1_DECODED"] = public1_Decoded
    # commit certificate data to configuration file
    with open("settings.ini", "w") as conf:
        configP_Writer_Object.write(conf)
    fileA1 = open("private.key", "w")
    fileA1.write(private1_Decoded)
    fileA1.close()
    fileA2 = open("public.crt", "w")
    fileA2.write(public1_Decoded)
    fileA2.close()


def execute_Crypto_Engine_2():
    logging.info("FUNCTION execute_Crypto_Engine_2")
    # initialize configuration parser
    configP_Writer_Object = ConfigParser()
    configP_Writer_Object.read("settings.ini")
    raw_Certs2 = crypto_Engine_2()
    raw_Certs_Listed2 = list(raw_Certs2)
    private2 = raw_Certs_Listed2[1]
    public2 = raw_Certs_Listed2[0]
    private2_Decoded = private2.decode()
    public2_Decoded = public2.decode()
    # assign certificate data to config objects
    configP_CERTIFICATE_DATA = configP_Writer_Object["CERTIFICATE_DATA"]
    configP_CERTIFICATE_DATA["PRIVATE2_DECODED"] = private2_Decoded
    configP_CERTIFICATE_DATA["PUBLIC2_DECODED"] = public2_Decoded
    # commit certificate data to configuration file
    with open("settings.ini", "w") as conf:
        configP_Writer_Object.write(conf)
    fileB1 = open("private.key", "w")
    fileB1.write(private2_Decoded)
    fileB1.close()
    fileB2 = open("public.crt", "w")
    fileB2.write(public2_Decoded)
    fileB2.close()
