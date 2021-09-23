import logging
import sys
import re
import base64
import traceback
import json
from typing import List
from datetime import datetime, timedelta, timezone
from subprocess import PIPE, Popen

from vault_key_rotation.gcp.key_rotation_config_class import KeyRotationConfig
from vault_key_rotation.vault_server_class import VaultServer
import vault_key_rotation.gcp.key_rotation_constants as c


class KeyRotation:
    """
    The key rotation class controls the logic for performing key rotation. 
    It loads the config file and then orchestrates the calls to the Vault server to manage teh key rotation process.
    After creating an instance of the class the entry point is the 'rotate_keys' method which controls all of the required logic.
    
    :param config_file: The path to the config file
    :type config_file: str
    :param reporting_only: Flag indicating whether we should only report. If True no updates will be amde to the Vault server.
    :type config_file: bool
    :param rotate_root: Flag indicating whether we should rotate the GCP secrets engine root key. 
    :type config_file: bool
    """
    def __init__(self, config_file: str, reporting_only: bool, rotate_root: bool) -> None:

        logger = logging.getLogger('vault_key_rotation.gcp.key_rotation_class')
        self.logger = logger

        #load the config file
        self.config = KeyRotationConfig(config_file)

        #extract the GCP engine config section
        self.config_map = self.config.get_config_dictionary()
        gcp_vault_values = self.config_map[c.GCP_ENGINES]

        #connect to vault, to interact with the gcp engines
        self.vault = VaultServer(gcp_vault_values)

        #add an uninitialised child vault class
        self.child_vault = None

        #set the reporting flag
        self.reporting_only = reporting_only

        #set the rotate_root flag
        self.rotate_root = rotate_root

        self.report = {}
        self.report['config_file'] = config_file
        #serialise the config file values
        config_string = ''
        for section in self.config_map.sections():
            config_string += f"[{section}]\n"
            for key in self.config_map[section]:
                value = self.config_map[section][key]
                if key.lower() == 'vault_token' or key.lower() == 'vault_secret_id':
                    config_string += f"{key} = ******************\n"
                else:
                    config_string += f"{key} = {value}\n"
        self.report['config_values'] = config_string


    def rotate_keys(self) -> None:
        """
        This is the entry method to control the key rotation process. 
        It processes each GCP secrets engine in turn and process all rolesets and / or static accounts.
        """
        logger = self.logger

        #get the list of GCP secrets engines to be processed
        ####################################################
        #remove this as it won't work on HCP for example
        #just use the list given and fail if anything is wrong
        #vault_gcp_engines = self.vault.get_gcp_secrets_engines()
        config_gcp_engines = self.config.get_gcp_secrets_engines()
        #common_engines = list(set(vault_gcp_engines) & set(config_gcp_engines))

        #find engines in the config file that are not present on the vault server
        #non_existent_engines = list(set(config_gcp_engines) - set(vault_gcp_engines))
        #logger.warning('The following secrets engine(s) are listed in the config file but are not present on the vault server: %s', non_existent_engines)

        #create a snapshot if required
        self.save_snapshot()

        gcp_engines_report_list = []

        for secrets_engine in config_gcp_engines:
            logger.info("Processing secrets engine '%s'", secrets_engine)
            self.current_gcp_engine_dict = {}

            #any errors should result in us going to the next secrets engine and processing that
            try:
                if self.rotate_root:
                    if self.vault.rotate_gcp_root(secrets_engine):
                        logger.info(f"Root key rotated for secrets engine '{secrets_engine}'")
                    else:
                        logger.error(f"Error while rotating root key for secrets engine '{secrets_engine}'")

                account_types = self.config_map[c.GCP_ENGINES]['vault_gcp_account_types']
                if account_types in (c.ACCOUNT_TYPES.ROLESET, c.ACCOUNT_TYPES.BOTH):
                    rolesets = self.vault.list_accounts(secrets_engine, c.ACCOUNT_TYPES.ROLESET)
                if account_types in (c.ACCOUNT_TYPES.STATIC, c.ACCOUNT_TYPES.BOTH):
                    if self.vault.static_accounts_supported():
                        static_accounts = self.vault.list_accounts(secrets_engine,
                                                                c.ACCOUNT_TYPES.STATIC)
                    else:
                        static_accounts = []

                self.current_gcp_engine_dict['name'] = secrets_engine
                self.current_gcp_engine_dict['roleset_list'] = rolesets
                self.current_gcp_engine_dict['static_account_list'] = static_accounts
                self.process_accounts(secrets_engine, rolesets, c.ACCOUNT_TYPES.ROLESET)
                self.process_accounts(secrets_engine, static_accounts, c.ACCOUNT_TYPES.STATIC)

            except Exception as err:
                logger.error(traceback.format_exc())
                logger.error("Error thrown when processing GCP engine '%s' : %s",
                            secrets_engine, err)

            #save snapshot after processing if required
            self.save_snapshot()

            gcp_engines_report_list.append(self.current_gcp_engine_dict)

        #write the report
        self.report['gcp_engines'] = gcp_engines_report_list
        self.write_vault_report()


    def process_accounts(self, secrets_engine: str,
                        account_list: List[str],
                        account_type: str) -> None:
        """
        Process the roleset / static account.
        Retrieves the keys and performs the logic to determine if they have expired and need to be rotated.

        :param secrets_engine: The name of the GCP secrets engine the account belongs to.
        :type secrets_engine: str
        :param account_list: a list of rolesets / static accounts to be processed.
        :type account_list: List[str]
        :param account_type: The type of account, either 'roleset' or 'static_account'
        :type account_type: str
        """

        logger = self.logger

        account_report_list = []
        for account in account_list:
            current_account = {}
            current_account['name'] = account
            current_account['type'] = account_type
            logger.info(f"Processing {account_type.lower()} '{account}'")
            if self.vault.read_account(secrets_engine, account_type, account):
                json_text = self.vault.get_last_response_json()
                bindings = json_text['data']['bindings']
                if account_type == c.ACCOUNT_TYPES.ROLESET:
                    project = json_text['data']['project']
                elif account_type == c.ACCOUNT_TYPES.STATIC:
                    project = json_text['data']['service_account_project']
                else:
                    project = ''
                email = json_text['data']['service_account_email']
                logger.debug(f"Project : {project}")
                logger.debug(f"Email   : {email}")
                logger.debug(f"Bindings: {bindings}")
                current_account['gcp_project'] = project
                current_account['gcp_email'] = email
                escaped_bindings = json.dumps(bindings)
                current_account['bindings'] = escaped_bindings

            keys = self.vault.list_account_keys(secrets_engine, account_type, account)
            at_least_one_good = False
            newest_key_date = None
            expired_keys = []
            current_account['key_list'] = keys
            if keys:
                key_dict_list = []
                for key in keys:
                    current_key = {}
                    current_key['id'] = key
                    logger.info(f"Processing key '{key}'")
                    if self.vault.static_accounts_supported():
                        lease_id = secrets_engine + '/' + account_type + '/' + account + '/key/' + key
                    else:
                        lease_id = secrets_engine + '/key/' + account + '/' + key
                    current_key['lease_id'] = lease_id
                    if self.vault.get_account_key_details(lease_id):
                        json_text = self.vault.get_last_response_json()
                        key_expiry = json_text['data']['expire_time']
                        key_creation = json_text['data']['issue_time']
                        lease_id = json_text['data']['id']

                        current_key['key_expiry'] = key_expiry
                        current_key['key_creation'] = key_creation
                        current_key['vault_retruned_lease_id'] = lease_id

                        creation_date_time = self.get_date_time_from_string(key_creation)

                        #set the newest key date for this account
                        if newest_key_date:
                            if newest_key_date < creation_date_time:
                                newest_key_date = creation_date_time
                                logger.info(f"Key '{key}' has replaced newest key creation date: '{newest_key_date}'")
                        else:
                            newest_key_date = creation_date_time
                            logger.info(f"Key '{key}' has newest key creation date: '{newest_key_date}'")

                        #check if expiry threshold has passed
                        time_period = self.config_map[c.KEY_ROTATION]['key_expiry_threshold']
                        current_key['key_expiry_threshold'] = time_period
                        threshold_delta = self.create_timedelta_object(time_period)
                        expiry_date_time = self.get_date_time_from_string(key_expiry)
                        threshold_date_time = expiry_date_time - threshold_delta
                        now = datetime.now(timezone.utc).astimezone()

                        if threshold_date_time < now:
                            expired_keys.append(lease_id)
                            logger.info(f"Key '{key}' has expired, threshold date: '{threshold_date_time}'")
                            current_key['key_expired'] = True
                        else:
                            logger.info(f"Key '{key}' has NOT expired, threshold date: '{threshold_date_time}'")
                            at_least_one_good = True
                            current_key['key_expired'] = False

                    key_dict_list.append(current_key)

                current_account['existing_keys'] = key_dict_list
                current_account['newest_key_date'] = str(newest_key_date)
                ##### - end for each key

            else:
                #no keys configured
                logger.info("No keys available for account '%s'", account)

            ###################################################
            #report from here
            create_key_success = True
            if not self.reporting_only:
                if not at_least_one_good:
                    new_key_report = {}
                    #we need to create a new key
                    #create a child token, then create a new vault instance authenticated with that token
                    if not self.child_vault:
                        if self.config_map[c.GCP_ENGINES]['use_child_token'] == 'yes':
                            vault_child_policies = self.config_map[c.GCP_ENGINES]['vault_key_policies']
                            if self.vault.create_child_token(vault_child_policies):
                                response_json = self.vault.get_last_response_json()
                                child_token = response_json['auth']['client_token']
                                key_create_vault_config = self.config_map[c.GCP_ENGINES]
                                key_create_vault_config['vault_authentication_type'] = 'token'
                                key_create_vault_config['vault_token'] = child_token
                                obfuscated_token = self.obfuscate_token(child_token)
                                logger.info(f"Child token created: {obfuscated_token}")
                                self.child_vault = VaultServer(key_create_vault_config)
                                new_key_report['created_by_child_token'] = True
                            else:
                                create_key_success = False
                                logger.error("Unable to create orphan token for key creation")
                        else:
                            #don't create a child token, just reuse the same token
                            self.child_vault = self.vault
                            new_key_report['created_by_child_token'] = False

                    if create_key_success:
                        if self.child_vault.create_account_key(secrets_engine, account_type, account):
                            response_json = self.child_vault.get_last_response_json()
                            new_lease_id = response_json['lease_id']
                            new_key_report['lease_id'] = new_lease_id
                            if self.store_key(account, response_json):
                                logger.info("Key successfully created and stored for '%s'", account)
                                vault_key_id = new_lease_id.split('/')[-1]
                                gcp_key_json_b64 = response_json['data']['private_key_data']
                                gcp_key_json_str = base64.b64decode(gcp_key_json_b64)
                                gcp_key_json = json.loads(gcp_key_json_str)
                                gcp_key_id = gcp_key_json['private_key_id']
                                new_key_report['vault_key_id'] = vault_key_id
                                new_key_report['gcp_key_id'] = gcp_key_id
                            else:
                                create_key_success = False
                                logger.error("Key storage failure")
                        else:
                            create_key_success = False
                            logger.error("Error creating new key for account '%s'", account)

                    current_account['new_key'] = new_key_report

 
            if create_key_success:
                if not self.reporting_only:
                    old_key_threshold = self.config_map[c.KEY_ROTATION]['delete_old_key_threshold']
                    if old_key_threshold.lower() == 'never':
                        #no key deletion required
                        logger.info("Old key deletion skipped, config set to 'never'")
                    elif old_key_threshold.lower() == 'now':
                        logger.info("Old key deletion, config set to 'now', all expired keys will be deleted")
                        self.revoke_old_keys(expired_keys)
                    else:
                        #parse the time value
                        threshold_delta = self.create_timedelta_object(old_key_threshold)
                        threshold_date_time = newest_key_date + threshold_delta
                        now = datetime.now(timezone.utc).astimezone()

                        if threshold_date_time < now:
                            logger.info(f"Old key threshold passed. Old key threshold date: {threshold_date_time}")
                            self.revoke_old_keys(expired_keys)
                        else:
                            logger.info(f"Old key threshold not passed, no old keys deleted. Old key threshold date: {threshold_date_time}")
            
            account_report_list.append(current_account)
        
        self.current_gcp_engine_dict[account_type + 's'] = account_report_list


    def obfuscate_token(self, token: str) -> str:
        """
        Helper method which generates an obfuscated token that can be safely logged to the log file.
        Simply takes the first 4 and last 4 characters separated by 9 periods.

        :param token: The full token to be obfuscated.
        :type token: str
        :return: The obfuscated value, safe to log to the log file.
        :rtype: str
        """
        logger = self.logger
        start = token[0:4]
        end = token[-4:]
        return start + '.........' + end


    def revoke_old_keys(self, lease_id_list: List[str]) -> None:
        """
        Revokes the old expired keys

        :param lease_id_list: The list of lease ids of expired keys.
        :type lease_id_list: List[str]
        """
        logger = self.logger

        #delete all the old keys
        for old_key in lease_id_list:
            if self.vault.revoke_account_key(old_key):
                logger.info("Key deleted: '%s'", old_key)
            else:
                logger.error("Unable to revoke key: '%s'", old_key)


    def store_key(self, account_name: str, key_json: str) -> bool:
        """
        This method takes care of storing the newly generated key.

        :param account_name: The roleset / static account name
        :type account_name: str
        :param key_json: The json string returned from the Vault create key operation
        :type key_json: str
        :raises RuntimeError: Raises an error if any thing goes wrong with the encryption or storage of the key.
        :return: True / False indicating if the key storage was successful or not.
        :rtype: bool
        """
        logger = self.logger

        ret_val = True

        #extract the values from the create key response json
        lease_id = key_json['lease_id']
        vault_key_id = lease_id.split('/')[-1]
        gcp_key_json_b64 = key_json['data']['private_key_data']
        gcp_key_json_str = base64.b64decode(gcp_key_json_b64)
        gcp_key_json = json.loads(gcp_key_json_str)
        gcp_key_id = gcp_key_json['private_key_id']
        gcp_email_id = gcp_key_json['client_email']

        #log the key ids that have been created
        logger.info("New key created:")
        logger.info(f"  lease_id     : {lease_id}")
        logger.info(f"  vault key id : {vault_key_id}")
        logger.info(f"  gcp key id   : {gcp_key_id}")
        logger.info(f"  gcp email id : {gcp_email_id}")

        #where are we storing the key
        key_directory = self.config_map[c.KEY_FILES]['key_output_directory']
        if len(key_directory) > 0:
            encryption_extension = ''
            try:
                #store the key to a file, check if we need to encrypt
                if self.config_map[c.KEY_FILES]['vault_transit_encryption'].lower() == 'yes':
                    #transit encrypt the json string
                    gcp_key_output = self.write_to_transit(gcp_key_json_str)
                    logger.info(f"Key data encrypted using vault transit engine")
                    encryption_extension = '.enc'
                elif self.config_map[c.KEY_FILES]['gpg_recipients']:
                    #GPG encrypt the json string
                    gcp_key_output = self.gpg_encrypt(gcp_key_json_str.decode())
                    logger.info(f"Key data encrypted using gpg")
                    encryption_extension = '.gpg'
                else:
                    #no encryption required
                    gcp_key_output = gcp_key_json_str.decode()
            except:
                logger.error("Something went wrong encrypting the key")
                raise RuntimeError("Error encrypting the key data")

            #store to file
            #create the file name
            key_file_name = self.get_key_file_name(account_name, vault_key_id, gcp_key_id, gcp_email_id)
            key_file_name += encryption_extension
            with open(key_file_name, 'w') as file_object:
                file_object.write(str(gcp_key_output))
                logger.info(f"Keyfile for key '{gcp_key_id}' written to '{key_file_name}'")

        #vault KV
        if self.config_map[c.KEY_FILES]['vault_kv_storage'].lower() == 'yes':
            #store to the kv engine
            key_name = self.get_key_name(account_name, vault_key_id, gcp_key_id)
            if self.store_to_kv_engine(account_name, gcp_key_json, key_name):
                #success
                logger.info(f"Key '{gcp_key_id}' written to vault KV engine")
            else:
                #store failed
                logger.error(f"Unable to store key '{gcp_key_id}' to Vault KV engine")
                ret_val = False

        return ret_val


    def store_to_kv_engine(self, account: str, value: str, key_name: str) -> bool:
        """
        Stores the key in a Vault KV engine.

        :param account: The roleset / static key name
        :type account: str
        :param value: The GCP JSON key data
        :type value: str
        :param key_name: The name of the key to be used when storing in the KV engine
        :type key_name: str
        :return: True / False indicating whether it was successful or not
        :rtype: bool
        """
        logger = self.logger

        kv_vault_values = self.config_map[c.KV_ENGINE]

        #connect to vault, to interact with the transit engine
        kv = VaultServer(kv_vault_values)

        #encrypt the plaintext
        kv_engine = kv_vault_values['kv_secrets_engine']
        kv_path = kv_vault_values['kv_path']
        logger.info(f"Going to store key for '{account}' into KV engine '{kv_engine}/{kv_path}'")
        return kv.write_kv_key(kv_vault_values['kv_engine_version'], 
                                kv_engine,
                                kv_path,
                                key_name, 
                                value)


    def get_key_file_name(self, account: str, vault_id: str, gcp_id: str, gcp_email_id: str) -> str:
        """
        Creates the required keyfile name based on the config values in the 'key_files' section of the config file.
        It will generate teh full path taking into account the directory and filename template that has been configured.

        :param account: Roleset or static account name
        :type account: str
        :param vault_id: The vault key id
        :type vault_id: str
        :param gcp_id: The GCP key id
        :type gcp_id: str
        :param gcp_email_id: The GCP key email id
        :type gcp_email_id: str
        :return: The full path and filename to save the key data to
        :rtype: str
        """
        logger = self.logger

        gcp_email_id = gcp_email_id.replace('@', '_at_')
        key_directory = self.config_map[c.KEY_FILES]['key_output_directory']
        key_file_template = self.config_map[c.KEY_FILES]['key_file_name']
        #replace the values in the filename
        key_file_template = key_file_template.replace('{VAULT_ACCOUNT}', account)
        key_file_template = key_file_template.replace('{VAULT_LEASE_ID}', vault_id)
        key_file_template = key_file_template.replace('{GCP_KEY_ID}', gcp_id)
        key_file_template = key_file_template.replace('{GCP_EMAIL_ID}', gcp_email_id)
        return key_directory + '/' + key_file_template


    def get_key_name(self, account: str, vault_id: str, gcp_id: str) -> str:
        """
        Generates the KV key name to save the key data to.
        Uses the config values in the 'vault_kv' section of the config file. 

        :param account: Roleset or static account name
        :type account: str
        :param vault_id: The vault key id
        :type vault_id: str
        :param gcp_id: The GCP key_id
        :type gcp_id: str
        :return: The name of the kv key to store the key against
        :rtype: str
        """
        logger = self.logger

        key_template = self.config_map[c.KV_ENGINE]['kv_key_name']
        #replace the values in the name
        key_template = key_template.replace('{VAULT_ACCOUNT}', account)
        key_template = key_template.replace('{VAULT_LEASE_ID}', vault_id)
        key_template = key_template.replace('{GCP_KEY_ID}', gcp_id)
        return key_template


    def write_to_transit(self, plain_text: str) -> str:
        """
        Controls the encryption of the key using the Vault transit engine.

        :param plain_text: The plain text key data
        :type plain_text: str
        :raises RuntimeError: aises an error if anything goes wrong during encryption
        :return: The encrypted text.
        :rtype: str
        """
        logger = self.logger

        transit_vault_values = self.config_map[c.TRANSIT_ENGINE]

        #connect to vault, to interact with the transit engine
        transit = VaultServer(transit_vault_values)

        #encrypt the plaintext
        transit_engine = self.config_map[c.TRANSIT_ENGINE]['transit_secrets_engine']
        transit_key = self.config_map[c.TRANSIT_ENGINE]['transit_key_name']

        logger.info(f"Key data being encrypted to transit engine '{transit_engine}' and transit key '{transit_key}'")
        if transit.transit_encrypt(transit_engine, transit_key, plain_text):
            cipher_text_json = transit.get_last_response_json()
            cipher_text = cipher_text_json['data']['ciphertext']
            return cipher_text
        else:
            raise RuntimeError("Transit encryption failed")


    def gpg_encrypt(self, plain_text: str) -> str:
        """
        Encrypts the key data by calling GPG.

        :param plain_text: The plain text key data.
        :type plain_text: str
        :raises RuntimeError: Raises an exception if anything goes worng during the encryption process.
        :return: The encrypted text.
        :rtype: str
        """
        logger = self.logger

        gpg_recipient_list = self.config_map[c.KEY_FILES]['gpg_recipients']
        for recipient in gpg_recipient_list.split(','):
            recipient_string = f"--recipient {recipient.strip()} "

        command_string = f"gpg --status-fd 2 --no-tty --batch --yes --always-trust {recipient_string} --armor --output - --encrypt"
        logger.info(f"Data being GPG encrypted to recipients: '{recipient_string}'")
        logger.debug(f"GPG command line: '{command_string}'")
        proc = Popen(command_string, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE, universal_newlines=True)
        #proc.stdin.write(plain_text.encode('utf-8'))
        proc.stdin.write(plain_text)
        proc.stdin.flush()
        proc.stdin.close()
        proc.wait()

        if proc.returncode != 0:
            #something went wrong, throw an error
            raise RuntimeError("GPG encryption failed")
        else:
            #return proc.stdout.read().decode()
            return proc.stdout.read()


    def get_date_time_from_string(self, date_string: str) -> datetime:
        """
        Parses a Vault date time string and converts it to a python datetime.
        This is requried becasue Vault returns a date time string which includes nanoseconds.
        Python doesn't support nanoseconds and throws an error if we try to convert directly.
        The string needs to be parsed and the partial seconds are discarded before converting to a python datetime.

        :param date_string: The Vault date time string.
        :type date_string: str
        :return: The Vault date time as a python datetime.
        :rtype: datetime
        """
        logger = self.logger
        #'2021-09-18T22:05:11.978541659+01:00'
        #vault returns nano seconds, python datetime only supports micro seconds
        #need to remove the partial seconds and then parse into a date time

        #                 2021     - 09   - 18   T 22   : 05   : 11    . 978541659+01:00
        #                 2021     - 09   - 13   T 21   : 07   : 58    . 927139239Z
        p = re.compile('^(\d\d\d\d)-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)\.(\d+)(\+\d\d:\d\d|Z)$')
        m = p.match(date_string)
        reformatted_date_string = ''
        if m:
            year = m.group(1)
            month = m.group(2)
            day = m.group(3)
            hour = m.group(4)
            minute = m.group(5)
            second = m.group(6)
            partial_second = m.group(7)
            tz = m.group(8)
            if tz.lower() == 'z':
                tz = '+00:00'

            reformatted_date_string = (
                                        year + '-' + month + '-' + day +
                                        'T' + hour + ':' + minute + ':' + second +
                                        tz
            )

        return datetime.fromisoformat(reformatted_date_string)


    def create_timedelta_object(self, time_period: str) -> timedelta:
        """
        Creates a python timedelta object from a time period item retrieved from the config file.
        The time period values can have no units which equates to seconds.
        It can also have seconds explicitly configured or hours or days can be configured.

        :param time_period: A config time value, e.g. 3600s, 12h 30d
        :type time_period: str
        :return: A python timedelta that corresponds to the config value time period.
        :rtype: timedelta
        """
        p = re.compile('^(\d+)\s*([shd])$')
        m = p.match(time_period)
        number = ''
        unit = ''
        match = False
        delta = None
        if m:
            number = m.group(1)
            unit = m.group(2).lower()
            match = True
        else:
            #no match, check for digits only
            p = re.compile('^(\d+)$')
            m = p.match(time_period)
            if m:
                number = m.group(1)
                unit = 's'
                match = True

        if match:
            if unit == 's':
                delta = timedelta(
                    seconds=int(number),
                )
            elif unit == 'h':
                delta = timedelta(
                    hours=int(number),
                )
            elif unit == 'd':
                delta = timedelta(
                    days=int(number),
                )
        
        return delta

    def save_snapshot(self) -> None:
        """
        Takes a Vault snapshot and saves it to disk.
        """
        logger = self.logger

        try:
            snapshots_required = self.config_map[c.SNAPSHOT]['save_snapshots'].lower()
            if snapshots_required == 'yes':
                snapshots_directory = self.config_map[c.SNAPSHOT]['snapshot_folder']
                date = datetime.now().strftime("%Y%m%d-%I%M%S")
                full_filename = snapshots_directory + '/' + 'vault_snapshot_' + date
                if self.vault.save_snapshot(full_filename):
                    logger.info(f"Snapshot successfully saved to '{full_filename}'")
            else:
                logger.debug("Snapshot saving turned off")

            return
        except:
            #don't interupt program execution, log and move on
            logger.error("Unable to save snapshot")
            return

    def write_vault_report(self) -> None:
        """
        Writes a JSON representation of the current Vault configuration to a file.
        This can be used by other applications wishing to provide a report of what is currently configured on Vault.
        """
        logger = self.logger

        try:
            report_file_name = 'vault_gcp_report.json'
            json_str = json.dumps(self.report, indent=2, skipkeys=True)
            with open(report_file_name, 'w') as file_object:
                file_object.write(str(json_str))
                logger.info(f"Vault report written to '{report_file_name}'")
            logger.debug(json_str)
        except:
            type, value, traceback = sys.exc_info()
            logger.error("Unable to save vault report")
            logger.error(f"ExceptionType  : '{type}'")
            logger.error(f"ExceptionValue : '{value}'")
