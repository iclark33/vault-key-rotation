from datetime import datetime

from vault_key_rotation.gcp.key_rotation_config_class import KeyRotationConfig
import vault_key_rotation.gcp.key_rotation_constants as c

OPEN = "{\n"
CLOSE = "\n}\n"
NL = "\n"

"""
Contains a few helper functions related to configuration.    
"""

def get_log_file_name(script_dir: str) -> str:
    """
    Creates a log file name that gets passed to the logging initialisation.
    The file name is of the form: <script_directory>/logs/gcp_key_rotation_YYYY_MM_DD.log

    :param script_dir: The directory that the main key rotation script is located in.
    :type script_dir: str
    :return: The full path to the log file
    :rtype: str
    """
    now = datetime.now()
    year = now.strftime("%Y")
    month = now.strftime("%m")
    day = now.strftime("%d")
    file_name = f"gcp_key_rotation_{year}_{month}_{day}.log"
    log_file = script_dir + '/logs/' + file_name
    log_file = log_file.replace('\\', '\\\\')
    return log_file

def get_url_log_file_name(script_dir: str) -> str:
    """
    Creates a log file name that gets passed to the logging initialisation. This file logs the urllib events.
    The file name is of the form: <script_directory>/logs/urllib_YYYY_MM_DD.log

    :param script_dir: The directory that the main key rotation script is located in.
    :type script_dir: str
    :return: The full path to the log file
    :rtype: str
    """
    now = datetime.now()
    year = now.strftime("%Y")
    month = now.strftime("%m")
    day = now.strftime("%d")
    file_name = f"urllib_{year}_{month}_{day}.log"
    log_file = script_dir + '/logs/' + file_name
    log_file = log_file.replace('\\', '\\\\')
    return log_file

def create_vault_policy(config_file :str) -> str:
    """
    Returns a sample vault policy HCL that can be written to file and used as a starting point for configuring a vault policy to provide access to the key rotation endpoints.

    :param config_file: The config file with the Vault configuration.
    :type config_file: str
    :return: A string representing a vault HCL policy.
    :rtype: str
    """

    #load the config file
    config = KeyRotationConfig(config_file)
    config_map = config.get_config_dictionary()
    gcp_engines = config.get_gcp_secrets_engines()
    policy = ''

    policy += "############################################################\n"
    policy += f"# Vault policy auto generated for config file:\n"
    policy += f"'{config_file}'\n"
    policy += NL
    policy += NL

    #add generic permissions
    policy += "##############################\n"
    policy += "# Generic options\n"
    policy += NL

    #read key details
    #http://127.0.0.1:8200/v1/sys/leases/lookup
    policy += "#get key details\n"
    policy += "path \"sys/leases/lookup\"\n"
    policy += OPEN
    policy += '  capabilities = ["update","sudo"]'
    policy += CLOSE
    policy += NL

    #revoke key
    #http://127.0.0.1:8200/v1/sys/leases/revoke
    policy += "#revoke the keys\n"
    policy += "path \"sys/leases/revoke/*\"\n"
    policy += OPEN
    policy += '  capabilities = ["update","sudo"]'
    policy += CLOSE
    policy += NL


    for gcp_engine in gcp_engines:

        policy += "##############################\n"
        policy += f"# policies required for GCP secrets engine '{gcp_engine}'\n"
        policy += NL

        #rotate root key for the secrets engine
        #https://127.0.0.1:8200/v1/gcp/config/rotate-root
        policy += "# rotate root key\n"
        policy += f"path \"{gcp_engine}/config/rotate-root\"\n"
        policy += OPEN
        policy += '  capabilities = ["update"]'
        policy += CLOSE
        policy += NL

        #list keys
        #sys/leases/lookup/gcp
        policy += "# list keys\n"
        policy += f"path \"sys/leases/lookup/{gcp_engine}/*\"\n"
        policy += OPEN
        policy += '  capabilities = ["list","sudo"]'
        policy += CLOSE
        policy += NL

        #create key deprecated pre vault 1.8
        #http://192.168.0.37:61000/v1/gcp/key/roleset_name (deprecated)
        policy += "#create new key, deprecated path, Vault server prior to v1.8\n"
        policy += f"path \"{gcp_engine}/key/*\"\n"
        policy += OPEN
        policy += '  capabilities = ["read"]'
        policy += CLOSE
        policy += NL

        #create key for a roleset / static account, post Vault 1.8
        #https://127.0.0.1:8200/v1/gcp/roleset/my-key-roleset/key
        #https://127.0.0.1:8200/v1/gcp/static-account/my-key-roleset/key
        policy += "#create new key for a roleset / static account, Vault server from v1.8 on\n"
        policy += f"path \"{gcp_engine}/key/*\"\n"
        policy += OPEN
        policy += '  capabilities = ["read"]'
        policy += CLOSE
        policy += NL

        #vault gcp account types
        account_type = config_map[c.GCP_ENGINES]['vault_gcp_account_types'].lower()
        if account_type == c.ACCOUNT_TYPES.BOTH or account_type == c.ACCOUNT_TYPES.ROLESET:
            #set the roleset policies

            #list rolesets
            #https://127.0.0.1:8200/v1/gcp/rolesets
            policy += "# list rolesets\n"
            policy += f"path \"{gcp_engine}/rolesets\"\n"
            policy += OPEN
            policy += '  capabilities = ["list"]'
            policy += CLOSE
            policy += NL

            #read roleset details
            #https://127.0.0.1:8200/v1/gcp/roleset/my-token-roleset
            policy += "# Read roleset\n"
            policy += f"path \"{gcp_engine}/roleset/*\"\n"
            policy += OPEN
            policy += '  capabilities = ["read"]'
            policy += CLOSE
            policy += NL


        if account_type == c.ACCOUNT_TYPES.BOTH or account_type == c.ACCOUNT_TYPES.STATIC:
            #set the static account policies

            #list static accounts
            #https://127.0.0.1:8200/v1/gcp/static-accounts
            policy += "# list static accounts\n"
            policy += f"path \"{gcp_engine}/static-accounts\"\n"
            policy += OPEN
            policy += '  capabilities = ["list"]'
            policy += CLOSE
            policy += NL

            #read static account details
            #https://127.0.0.1:8200/v1/gcp/static-account/my-token-account
            policy += "# Read static account\n"
            policy += f"path \"{gcp_engine}/static-account/*\"\n"
            policy += OPEN
            policy += '  capabilities = ["read"]'
            policy += CLOSE
            policy += NL

        policy += f"# end of policies for GCP secrets engine '{gcp_engine}'\n"
        policy += "##############################\n"



    #is the child token creation requried
    if config_map[c.GCP_ENGINES]['use_child_token'].lower() == 'yes':
        #http://127.0.0.1:8200/v1/auth/token/create-orphan
        policy += NL
        policy += "#create an orphan token to use when creating GCP keys / leases\n"
        policy += "path \"auth/token/create\"\n"
        policy += OPEN
        policy += '  capabilities = ["create","update","sudo"]'
        policy += CLOSE

    #is kv required
    if config_map[c.KEY_FILES]['vault_kv_storage'].lower() == 'yes':
        kv_engine = config_map[c.KV_ENGINE]['kv_secrets_engine']
        kv_path = config_map[c.KV_ENGINE]['kv_path']
        kv_version = config_map[c.KV_ENGINE]['kv_engine_version']
        #V1 https://127.0.0.1:8200/v1/secret/my-secret
        #V2 https://127.0.0.1:8200/v1/secret/data/my-secret
        policy += NL
        policy += f"#write to a v{kv_version} kv engine\n"
        if kv_version == '1':
            policy += f"path \"{kv_engine}/{kv_path}/*\"\n"
        else:
            policy += f"path \"{kv_engine}/data/{kv_path}/*\"\n"
        policy += OPEN
        policy += '  capabilities = ["create","update"]'
        policy += CLOSE
        policy += NL

    #is transit required
    if config_map[c.KEY_FILES]['vault_kv_storage'].lower() == 'yes':
        transit_engine = config_map[c.TRANSIT_ENGINE]['transit_secrets_engine']
        transit_key = config_map[c.TRANSIT_ENGINE]['transit_key_name']
        #transit encrypt
        #http://127.0.0.1:8200/v1/transit/encrypt/my-key
        policy += "# encrypt via transit engine\n"
        policy += f"path \"{transit_engine}/encrypt/{transit_key}\"\n"
        policy += OPEN
        policy += '  capabilities = ["update"]'
        policy += CLOSE
        policy += NL

    #are snapshots required
    if config_map[c.SNAPSHOT]['save_snapshots'].lower() == 'yes':
        policy += "#save a snapshot\n"
        policy += "path \"sys/storage/raft/snapshot\"\n"
        policy += OPEN
        policy += '  capabilities = ["read","sudo"]'
        policy += CLOSE


    policy += NL

    return policy

def create_config_file_template() -> str:
    """
    Returns a sample config file that can be written to file and used as a starting point for configuring the script.

    :return: A string representing a config file.
    :rtype: str
    """

    return """# configuration file to drive the Vault GCP key rotation python program

[vault_gcp_engines]
# this section contans values needed by the script to connect to and interact
# with vault to lookup GCP secrets engines and rotate keys for configured
# GCP service accounts

# a comma separated list of GCP secrets engines to interrogate and rotate any configured keys
# defaults to 'gcp' if not set
gcp_secrets_engines = 

# GCP keys can be created under a new longer lived orphaned child token
# if this is not the desired behaviour then we can create GCP tokens under the token used to authenticate to vault initially
# yes / no
# defaults to yes meaning we will create a child token prior to creating a GCP key
use_child_token = 

# the policies to attach to the child token that creates the GCP keys /vault leases
# this can be a comma separated list
# defaults to 'gcp_key_rotation'
vault_key_policies = 

# the types of service accounts to rotate
# valid values are 'roleset', 'static', 'both'
# defaults to both if not set
vault_gcp_account_types = 

# 'approle' and 'token' are supported
# if other methods are required then the authentication can happen up front
# and the token received can be used
# defaults to token if not set
vault_authentication_type = 

# approle role for approle authentication
# the raw value can be provided here
# or the name of an environment variable can supplied in the form 'ENV:VARIABLE_NAME'
vault_approle =  

# role id for approle authentication
# the raw value can be provided here
# or the name of an environment variable can supplied in the form 'ENV:VARIABLE_NAME'
vault_role_id = 

# secret id for approle authentication
# the raw value can be provided here (not recommended)
# or the name of an environment variable can supplied in the form 'ENV:VARIABLE_NAME'
vault_secret_id = 

# the vault token to use for authetnication
# the raw value can be supplied (not recommended)
# an environment variable can be supplied in the form 'ENV:VARIABLE_NAME'
# defaults to using the VAULT_TOKEN environment variable if not set
vault_token = 

# the address of the vault server hosting the GCP secrets engine(s)
# the value can be specified
# an environment variable can be specified
# defaults to using the VAULT_ADDR environment variable if not set
vault_address = 

# the CA details if this is needed for the key rotation script to trust the vault certificate
# the path to the file which holds the CA cert
# will use the environment variable VAULT_CACERT if set
vault_ca_cert = 

# the proxy server details
# if HTTP_PROXY and / or HTTPS_PROXY are set then they will be used if the config values are left blank
vault_http_proxy = 
vault_https_proxy = 

# specify a namespace if being used by vault
# if left empty then the environment variable VAULT_NAMESPACE will be used if set
# defaults to empty
vault_namespace = 

# specifies the client certificate for connecting to vault servers which require
# client certificates to connect to the listener
# if left empty then the environment variable VAULT_CLIENT_CERT will be used if set
# defaults to empty
vault_client_cert = 

# specifies the client key for connecting to vault servers which require
# client certificates to connect to the listener
# if left empty then the environment variable VAULT_CLIENT_KEY will be used if set
# defaults to empty
vault_client_key = 

# skip TLS verification (not recommended)
# skips verification of the vault server certificate
# do not use in production
# picks up VAULT_SKIP_VERIFY environment variable if set
# yes / no
# defaults to no
vault_skip_tls_verify = 


[key_rotation]
# this section contains values that affect how the key rotation happens

# how close to key expiry before we trigger the renewal process within the program
# e.g. a threshold of 10d
# a key which expires in 11 days does not get rotated
# but a key which expires in 9 days will be rotated
# time can be specified in seconds (s) or no units
# days (d) or hours (h) can also be specified
# 
# e.g. 1d, 24h, 86400s, 86400 all refer to one day
key_expiry_threshold = 

# specifies whether to delete old keys as part of the rotation process
# during rotation a new key will be created, this option specifies how to deal with the old key
#
# values are 'now', 'never' or a time value, e.g. 12h or 1d
# now means delete the old key when the new key is created
# never means do not expire the old key as part of this process, let vault expire it automatically
# for time based values a check is made against the age of the newest key against the account
# e.g. the threshold is 12h
# if the newest key is 13 hours old then we delete the old keys
# if the newest key is 11 hours old then we retain the old keys
# 
# defaults to now
delete_old_key_threshold = 


[key_files]
# this section configures how to store the keyfiles for new keys
# that get created as part of the rotation process

# options are write to a file or store in a vault KV secrets engine
# there are additional options related to encrypting the key data prior to storage

# if storing the key to the file system, this is the directory to write the key files to
# any directories specified as relative directories will be relative to the python script location
key_output_directory = 

# what should the keyfile be named
# the file name can be built up from various pieces of information relating to the key
# {VAULT_ACCOUNT} - refers to the roleset name or static account name as configured in vault
# {GCP_KEY_ID} - refers to the GCP key id provided by GCP
# {GCP_EMAIL_ID} - refers to the GCP email id assocaited with the service account
# {VAULT_LEASE_ID} - refers to the vault lease id relating to the key
# 
# defaults to {VAULT_ACCOUNT}.json
key_file_name = 

# we can optionally encrypt the data using GPG
# gpg must be installed and the keyring already configured with the intended recipients
# the final encrypted filename will be of the form <key_file_name>.json.gpg based on the key file name config above
# if recipients is set below, then the keyfile will be encrypted
# only one of gpg encryption or transit encryption can be used
# multiple recipients can be specified by separating each recipient with a comma
gpg_recipients = 

# we can optionally encrypt the keyfile using a vault transit engine (EAAS)
# yes or no, the transit engine details are configured in another section
# only one of gpg encryption or transit encryption can be used
# defaults to no
vault_transit_encryption = 

# we can store the keyfile in a vault kv secrets engine
# this can be in addition to or instead of storing the key to the file system
# yes or no, the kv engine details are configured in another section
# defaults to no
vault_kv_storage = 


[vault_kv]
# the details for the vault kv secrets engine are configured here
# this section is only required if [key_files][vault_kv_storage] is set to 'yes'

# the name of the kv secrets engine to use
# this can be either a kv engine or a kv v2 engine
# defaults to kv
kv_secrets_engine = 

# the path within the kv engine where the keys are stored
kv_path = 

# the kv key name where will store each GCP key
# {VAULT_ACCOUNT} - refers to the roleset name or static account name as configured in vault
# {GCP_KEY_ID} - refers to the GCP key id provided by GCP
# {VAULT_LEASE_ID} - refers to the vault lease id relating to the key
# 
# defaults to {VAULT_ACCOUNT}
kv_key_name = 

# the KV engine version
# defaults to 1 (1 or 2)
kv_engine_version = 

# the remaining variables can be set if the vault server hosting the kv secrets engine 
# is different to the one that hosts the gcp secrets engines
# 
# leaving these values unset will cause the vault variables to be reused from the
# config section for the GCP secrets engines [vault_gcp_engines]
#
#vault_authentication_type = 
#vault_role_id = 
#vault_secret_id = 
#vault_token = 
#vault_address = 
#vault_ca_cert = 
#vault_http_proxy = 
#vault_https_proxy = 
#vault_namespace = 
#vault_client_cert = 
#vault_client_key = 
#vault_skip_tls_verify = 


[vault_transit]
# the details for the vault transit secrets engine are configured here
# this section is only required if [key_files][vault_transit_encryption] is set to 'yes'

# the transit engine to be used to encrypt the GCP key data
# defaults to 'transit'
transit_secrets_engine = 

# the key name within the transit engine to use for the encryption
transit_key_name = 

# the remaining variables can be set if the vault server hosting the kv secrets engine 
# is different to the one that hosts the gcp secrets engines
# 
# leaving these values unset will cause the vault variables to be reused from the
# config section for the GCP secrets engines [vault_gcp_engines]
#
#vault_authentication_type = 
#vault_role_id = 
#vault_secret_id = 
#vault_token = 
#vault_address = 
#vault_ca_cert = 
#vault_http_proxy = 
#vault_https_proxy = 
#vault_namespace = 
#vault_client_cert = 
#vault_client_key = 
#vault_skip_tls_verify = 


[snapshots]
# configures whether snapshots are taken before and after updates to vault's config
# only supported on clusters using raft intergated storage as the storage backend

# turn on snapshot saving
# yes / no
# defaults to no
save_snapshots = 

# directory to save the snapshots to
# any directories specified as relative directories will be relative to the python script location
snapshot_folder = 

"""

