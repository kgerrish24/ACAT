# ACAT/ACAT/acat_app/app_settings.py


from configparser import ConfigParser


global private_KeySize, private_SigAlg, private_Algorithm, private_Curve, private_Format
global subject_CN, subject_O, subject_OU, subject_L, subject_S, subject_C
global issuer_CN, issuer_O, issuer_OU, issuer_L, issuer_S, issuer_C
global hash_type, hash_value, private1_decoded, public1_decoded, private2_decoded, public2_decoded
global no_issuer_Address, no_subject_Address


def configParser_read_all_configFile():
    global private_KeySize, private_SigAlg, private_Algorithm, private_Curve, private_Format
    global subject_CN, subject_O, subject_OU, subject_L, subject_S, subject_C
    global issuer_CN, issuer_O, issuer_OU, issuer_L, issuer_S, issuer_C
    global hash_type, hash_value, private1_decoded, public1_decoded, private2_decoded, public2_decoded
    # initialize Config Parser
    configP_Writer_Object = ConfigParser()
    configP_Writer_Object.read("settings.ini")
    # get configuration sections
    configP_PRIVATE_KEY = configP_Writer_Object["PRIVATE_KEY"]
    configP_SUBJECT_ATTRIBUTES = configP_Writer_Object["SUBJECT_ATTRIBUTES"]
    configP_ISSUER_ATTRIBUTES = configP_Writer_Object["ISSUER_ATTRIBUTES"]
    configP_FILE_HASHING = configP_Writer_Object["FILE_HASHING"]
    configP_CERTIFICATE_DATA = configP_Writer_Object["CERTIFICATE_DATA"]
    # get config settings from file and assign to variables
    private_KeySize = format(configP_PRIVATE_KEY["keysize"])
    private_SigAlg = format(configP_PRIVATE_KEY["sigalg"])
    private_Algorithm = format(configP_PRIVATE_KEY["algorithm"])
    private_Curve = format(configP_PRIVATE_KEY["curve"])
    private_Format = format(configP_PRIVATE_KEY["format"])
    subject_CN = format(configP_SUBJECT_ATTRIBUTES["subject_cn"])
    subject_O = format(configP_SUBJECT_ATTRIBUTES["subject_o"])
    subject_OU = format(configP_SUBJECT_ATTRIBUTES["subject_ou"])
    subject_L = format(configP_SUBJECT_ATTRIBUTES["subject_l"])
    subject_S = format(configP_SUBJECT_ATTRIBUTES["subject_s"])
    subject_C = format(configP_SUBJECT_ATTRIBUTES["subject_c"])
    issuer_CN = format(configP_ISSUER_ATTRIBUTES["issuer_cn"])
    issuer_O = format(configP_ISSUER_ATTRIBUTES["issuer_o"])
    issuer_OU = format(configP_ISSUER_ATTRIBUTES["issuer_ou"])
    issuer_L = format(configP_ISSUER_ATTRIBUTES["issuer_l"])
    issuer_S = format(configP_ISSUER_ATTRIBUTES["issuer_s"])
    issuer_C = format(configP_ISSUER_ATTRIBUTES["issuer_c"])
    hash_type = format(configP_FILE_HASHING["hash_type"])
    hash_value = format(configP_FILE_HASHING["hash_value"])
    private1_decoded = format(configP_CERTIFICATE_DATA["private1_decoded"])
    public1_decoded = format(configP_CERTIFICATE_DATA["public1_decoded"])
    private2_decoded = format(configP_CERTIFICATE_DATA["private2_decoded"])
    public2_decoded = format(configP_CERTIFICATE_DATA["public2_decoded"])


# initialize configuration
configParser_read_all_configFile()


def configParser_write_all_configFile():
    # initialize Config Parser
    configP_Writer_Object = ConfigParser()
    configP_Writer_Object.read("settings.ini")
    # Get configuration sections
    configP_PRIVATE_KEY = configP_Writer_Object["PRIVATE_KEY"]
    configP_SUBJECT_ATTRIBUTES = configP_Writer_Object["SUBJECT_ATTRIBUTES"]
    configP_ISSUER_ATTRIBUTES = configP_Writer_Object["ISSUER_ATTRIBUTES"]
    configP_FILE_HASHING = configP_Writer_Object["FILE_HASHING"]
    configP_CERTIFICATE_DATA = configP_Writer_Object["CERTIFICATE_DATA"]
    # assign config settings from variables to config objects
    configP_PRIVATE_KEY["keysize"] = private_KeySize
    configP_PRIVATE_KEY["sigalg"] = private_SigAlg
    configP_PRIVATE_KEY["algorithm"] = private_Algorithm
    configP_PRIVATE_KEY["format"] = private_Format
    configP_PRIVATE_KEY["curve"] = private_Curve
    configP_SUBJECT_ATTRIBUTES["subject_cn"] = subject_CN
    configP_SUBJECT_ATTRIBUTES["subject_o"] = subject_O
    configP_SUBJECT_ATTRIBUTES["subject_ou"] = subject_OU
    configP_SUBJECT_ATTRIBUTES["subject_l"] = subject_L
    configP_SUBJECT_ATTRIBUTES["subject_s"] = subject_S
    configP_SUBJECT_ATTRIBUTES["subject_c"] = subject_C
    configP_ISSUER_ATTRIBUTES["issuer_cn"] = issuer_CN
    configP_ISSUER_ATTRIBUTES["issuer_o"] = issuer_O
    configP_ISSUER_ATTRIBUTES["issuer_ou"] = issuer_OU
    configP_ISSUER_ATTRIBUTES["issuer_l"] = issuer_L
    configP_ISSUER_ATTRIBUTES["issuer_s"] = issuer_S
    configP_ISSUER_ATTRIBUTES["issuer_c"] = issuer_C
    configP_FILE_HASHING["hash_type"] = hash_type
    configP_FILE_HASHING["hash_value"] = hash_value
    configP_PRIVATE_KEY["private1_decoded"] = private1_decoded
    configP_PRIVATE_KEY["public1_decoded"] = public1_decoded
    configP_PRIVATE_KEY["private2_decoded"] = private2_decoded
    configP_PRIVATE_KEY["public2_decoded"] = public2_decoded
    # commit config settings to config file
    with open("settings.ini", "w") as conf:
        configP_Writer_Object.write(conf)
