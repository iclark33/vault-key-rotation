import configparser
import os
import logging
import sys
import re
from subprocess import PIPE, Popen
from typing import List

import vault_key_rotation.gcp.key_rotation_constants as c
 
class KeyRotationConfig:
    """
    Class that manages the loading, processing and validation of a config file.

    :param configfile: The path to the config file
    :type configfile: str
    :raises RuntimeError: Raises an exception if anything goes wrong with the file load or the parameter validation.
    """

    def __init__(self, configfile: str) -> None:        
        logger = logging.getLogger('vault_key_rotation.gcp.config_class')
        self.logger = logger

        #load the config file
        try:
            config = configparser.ConfigParser()
            config.read(configfile)
        except:
            logger.warn(f"Unexpected error parsing config file : {sys.exc_info()[0]}")
            raise

        else:
            self.config = config
            #populate the default values
            self.expand_config_defaults()
            #validate the config
            config_valid = self.validate_config_values()
            if not config_valid:
                raise RuntimeError(f"Config file validation failed ({configfile}) - see logfile for details")


    def set_default(self, section: str, key: str, default_value: str) -> None:
        """
        Checks the value that is set in the config file and then sets a default value of requried.
        If the section and key can't be retrieved (e.g. doesn't exist) then it is set with the provided default.
        If the value is empty it gets set to the default value.
        If a value is already set then it is left untouched.

        :param section: The section name in the config file
        :type section: str
        :param key: The key of the config value
        :type key: str
        :param default_value: The default value to set the config item to if required.
        :type default_value: str
        """

        logger = self.logger

        if default_value.startswith('ENV:'):
            env_variable = default_value[4:]
            default_value = os.getenv(env_variable, '')

        try:
            #retrive the current value
            value = self.config[section][key]
        except KeyError:
            #section or key don't exist, add it with the default
            logger.debug(f"[{section}][{key}] - added with default value '{default_value}' ")
            self.config[section][key] = default_value
        except:
            #something else went wrong, try adding the default
            logger.warn(f"Unexpected error setting default value : {sys.exc_info()[0]}")
            logger.debug(f"[{section}][{key}] - added with default value '{default_value}' ")
            self.config[section][key] = default_value
        else:
            #if there isn't a current value, set the default
            if len(value) == 0:
                logger.debug(f"[{section}][{key}] - updated with default value '{default_value}' ")
                self.config[section][key] = default_value


    def populate_environment_variables(self) -> None:
        """
        Iterates through the entire config file and replaces any values prefixed with value 'ENV:'
        e.g. a value of 'ENV:MY_VALUE' will be replaced with the value held in the environment variable 'MY_VALUE'
        """

        logger = self.logger

        #for each key determine if the key should be set from the environment
        for section in self.config.sections():
            for key in self.config[section]:
                value = self.config[section][key]
                if value.startswith('ENV:'):
                    env_variable = value[4:]
                    env_value = os.getenv(env_variable, '')
                    logger.debug(f"[{section}][{key}] - updated with value '{env_value}' from environment variable {env_variable} ")
                    self.config[section][key] = env_value


    def expand_config_defaults(self) -> None:
        """
        Sets the default value for each value in the config file.
        """

        #check if the skip verify environment variable is set
        vault_skip_verify = 'no'
        env_value = os.getenv('VAULT_SKIP_VERIFY', None)
        if env_value:
            vault_skip_verify = 'yes'

        self.set_default(c.GCP_ENGINES, 'gcp_secrets_engines',       'gcp')
        self.set_default(c.GCP_ENGINES, 'use_child_token',           'yes')
        self.set_default(c.GCP_ENGINES, 'vault_key_policies',        'gcp_key_rotation')
        self.set_default(c.GCP_ENGINES, 'vault_gcp_account_types',   'both')
        self.set_default(c.GCP_ENGINES, 'vault_authentication_type', 'token')
        self.set_default(c.GCP_ENGINES, 'vault_approle',             '')
        self.set_default(c.GCP_ENGINES, 'vault_role_id',             '')
        self.set_default(c.GCP_ENGINES, 'vault_secret_id',           '')
        self.set_default(c.GCP_ENGINES, 'vault_token',               'ENV:VAULT_TOKEN')
        self.set_default(c.GCP_ENGINES, 'vault_address',             'ENV:VAULT_ADDR')
        self.set_default(c.GCP_ENGINES, 'vault_ca_cert',             'ENV:VAULT_CACERT')
        self.set_default(c.GCP_ENGINES, 'vault_http_proxy',          'ENV:HTTP_PROXY')
        self.set_default(c.GCP_ENGINES, 'vault_https_proxy',         'ENV:HTTPS_PROXY')
        self.set_default(c.GCP_ENGINES, 'vault_http_proxy',          'ENV:http_proxy')
        self.set_default(c.GCP_ENGINES, 'vault_https_proxy',         'ENV:https_proxy')
        self.set_default(c.GCP_ENGINES, 'vault_namespace',           'ENV:VAULT_NAMESPACE')
        self.set_default(c.GCP_ENGINES, 'vault_client_cert',         'ENV:VAULT_CLIENT_CERT')
        self.set_default(c.GCP_ENGINES, 'vault_client_key',          'ENV:VAULT_CLIENT_KEY')        
        self.set_default(c.GCP_ENGINES, 'vault_skip_tls_verify',     vault_skip_verify)

        self.set_default(c.KV_ENGINE, 'kv_secrets_engine',         'kv')
        self.set_default(c.KV_ENGINE, 'kv_path',                   '')
        self.set_default(c.KV_ENGINE, 'kv_key_name',               '{VAULT_ACCOUNT}')
        self.set_default(c.KV_ENGINE, 'vault_address',             self.config[c.GCP_ENGINES]['vault_address'])
        #only copy if the vault addresses are the same, otherwise don't overwrite if blank
        if self.config[c.KV_ENGINE]['vault_address'] == self.config[c.GCP_ENGINES]['vault_address']:
            self.set_default(c.KV_ENGINE, 'vault_authentication_type', self.config[c.GCP_ENGINES]['vault_authentication_type'])
            self.set_default(c.KV_ENGINE, 'vault_token',               self.config[c.GCP_ENGINES]['vault_token'])
            self.set_default(c.KV_ENGINE, 'vault_approle',             self.config[c.GCP_ENGINES]['vault_approle'])
            self.set_default(c.KV_ENGINE, 'vault_role_id',             self.config[c.GCP_ENGINES]['vault_role_id'])
            self.set_default(c.KV_ENGINE, 'vault_secret_id',           self.config[c.GCP_ENGINES]['vault_secret_id'])
            self.set_default(c.KV_ENGINE, 'vault_namespace',           self.config[c.GCP_ENGINES]['vault_namespace'])
            self.set_default(c.KV_ENGINE, 'vault_ca_cert',             self.config[c.GCP_ENGINES]['vault_ca_cert'])
            self.set_default(c.KV_ENGINE, 'vault_http_proxy',          self.config[c.GCP_ENGINES]['vault_http_proxy'])
            self.set_default(c.KV_ENGINE, 'vault_https_proxy',         self.config[c.GCP_ENGINES]['vault_https_proxy'])
            self.set_default(c.KV_ENGINE, 'vault_client_cert',         self.config[c.GCP_ENGINES]['vault_client_cert'])
            self.set_default(c.KV_ENGINE, 'vault_client_key',          self.config[c.GCP_ENGINES]['vault_client_key'])
            self.set_default(c.KV_ENGINE, 'vault_skip_tls_verify',     self.config[c.GCP_ENGINES]['vault_skip_tls_verify'])

        self.set_default(c.TRANSIT_ENGINE, 'transit_secrets_engine',    'transit')
        self.set_default(c.TRANSIT_ENGINE, 'transit_key_name',          '')
        self.set_default(c.TRANSIT_ENGINE, 'vault_address',             self.config[c.GCP_ENGINES]['vault_address'])
        #only if the addresses are the same
        if self.config[c.TRANSIT_ENGINE]['vault_address'] == self.config[c.GCP_ENGINES]['vault_address']:
            self.set_default(c.TRANSIT_ENGINE, 'vault_authentication_type', self.config[c.GCP_ENGINES]['vault_authentication_type'])
            self.set_default(c.TRANSIT_ENGINE, 'vault_token',               self.config[c.GCP_ENGINES]['vault_token'])
            self.set_default(c.TRANSIT_ENGINE, 'vault_approle',             self.config[c.GCP_ENGINES]['vault_approle'])
            self.set_default(c.TRANSIT_ENGINE, 'vault_role_id',             self.config[c.GCP_ENGINES]['vault_role_id'])
            self.set_default(c.TRANSIT_ENGINE, 'vault_secret_id',           self.config[c.GCP_ENGINES]['vault_secret_id'])
            self.set_default(c.TRANSIT_ENGINE, 'vault_namespace',           self.config[c.GCP_ENGINES]['vault_namespace'])
            self.set_default(c.TRANSIT_ENGINE, 'vault_ca_cert',             self.config[c.GCP_ENGINES]['vault_ca_cert'])
            self.set_default(c.TRANSIT_ENGINE, 'vault_http_proxy',          self.config[c.GCP_ENGINES]['vault_http_proxy'])
            self.set_default(c.TRANSIT_ENGINE, 'vault_https_proxy',         self.config[c.GCP_ENGINES]['vault_https_proxy'])
            self.set_default(c.TRANSIT_ENGINE, 'vault_client_cert',         self.config[c.GCP_ENGINES]['vault_client_cert'])
            self.set_default(c.TRANSIT_ENGINE, 'vault_client_key',          self.config[c.GCP_ENGINES]['vault_client_key'])
            self.set_default(c.TRANSIT_ENGINE, 'vault_skip_tls_verify',     self.config[c.GCP_ENGINES]['vault_skip_tls_verify'])

        self.set_default(c.KEY_ROTATION, 'key_expiry_threshold',     '')
        self.set_default(c.KEY_ROTATION, 'delete_old_key_threshold', 'now')

        self.set_default(c.KEY_FILES, 'key_output_directory',        '')
        self.set_default(c.KEY_FILES, 'key_file_name',               '{VAULT_ACCOUNT}.json')
        self.set_default(c.KEY_FILES, 'gpg_recipients',              '')
        self.set_default(c.KEY_FILES, 'vault_transit_encryption',    'no')
        self.set_default(c.KEY_FILES, 'vault_kv_storage',            'no')

        self.set_default(c.SNAPSHOT, 'save_snapshots',  'no')
        self.set_default(c.SNAPSHOT, 'snapshot_folder', '')

        #convert any environemnt variable values to actual values
        self.populate_environment_variables()


    def get_config_dictionary(self) -> configparser.ConfigParser:
        """
        Returns the config object associated with this class.

        :return: The config object that represents the currently loaded config file.
        :rtype: configparser.ConfigParser
        """
        return self.config


    def validate_config_values(self) -> bool:
        """
        Performs basic validation on the values held in the config file.
        Any config errors detected are logged as ERROR log events.

        :return: True if config is valid, False otherwise.
        :rtype: bool
        """
        
        #self.config[section][key]
        gcp_engines_errors = []
        key_rotation_errors = []
        key_files_errors = []
        kv_errors = []
        transit_errors = []
        report_errors = []
        snapshot_errors = []

        #GCP ENGINES section validation
        if len(self.config[c.GCP_ENGINES]['gcp_secrets_engines']) == 0:
            gcp_engines_errors.append("'gcp_secrets_engines' must be set")

        use_child_token = self.config[c.GCP_ENGINES]['use_child_token'].lower()
        if use_child_token != 'yes':
            if use_child_token != 'no':
                key_files_errors.append("'use_child_token' must be 'yes' or 'no'")

        if use_child_token == 'yes':
            if len(self.config[c.GCP_ENGINES]['vault_key_policies']) == 0:
                gcp_engines_errors.append("'vault_key_policies' must be set")

        acct_type = self.config[c.GCP_ENGINES]['vault_gcp_account_types'].lower()
        if acct_type != 'both':
            if acct_type != 'static':
                if acct_type != 'roleset':
                    gcp_engines_errors.append("'vault_gcp_account_types' must be one of 'both', 'static' or 'roleset'")

        #validate the vault server parameters
        gcp_engines_errors = self.validate_vault_server_parameters(c.GCP_ENGINES, gcp_engines_errors)


        #KEY ROTATION section validation
        key_expiry = self.config[c.KEY_ROTATION]['key_expiry_threshold'].lower()
        if not self.validate_time_period(key_expiry):
            key_rotation_errors.append("'key_expiry_threshold' not a valid time period value")

        delete_threshold = self.config[c.KEY_ROTATION]['delete_old_key_threshold'].lower()
        if delete_threshold != 'now':
            if delete_threshold != 'never':
                if not self.validate_time_period(delete_threshold):
                    key_rotation_errors.append("'delete_old_key_threshold' must be 'now', 'never' or valid time period value")

        
        #KEY FILES section validation
        use_kv = self.config[c.KEY_FILES]['vault_kv_storage'].lower()
        if use_kv != 'yes':
            if use_kv != 'no':
                key_files_errors.append("'vault_kv_storage' must be 'yes' or 'no'")

        key_directory = self.config[c.KEY_FILES]['key_output_directory']
        if (use_kv != 'yes') and (len(key_directory) == 0):
            key_files_errors.append("At least one of 'key_output_directory' and 'vault_kv_storage' must be set'. ")

        if len(key_directory) > 0:
            if not os.path.isdir(key_directory):
                key_files_errors.append(f"'key_output_directory' directory must exist. '{key_directory}' cannot be found ")

        #key_name must contain something unique
        key_file_name = self.config[c.KEY_FILES]['key_file_name'].lower()
        if '{vault_account}' in key_file_name:
            if '{gcp_key_id}' in key_file_name:
                if '{vault_lease_id}' in key_file_name:
                    key_files_errors.append("'key_file_name' must contain '{VAULT_ACCOUNT}', '{GCP_KEY_ID}' or '{VAULT_LEASE_ID}' ")


        gpg_recipient_list = self.config[c.KEY_FILES]['gpg_recipients']
        if len(gpg_recipient_list) > 0:

            for recipient in gpg_recipient_list.split(','):
                recipient_string = f"--recipient {recipient.strip()} "
                command_string = f"gpg --status-fd 2 --no-tty --batch --yes --always-trust {recipient_string} --armor --output - --encrypt"
                p = Popen(command_string, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
                p.stdin.write('abc'.encode('utf-8'))
                p.stdin.flush()
                p.stdin.close()
                
                p.wait()

                if p.returncode != 0:
                    key_files_errors.append(f"'gpg_recipients' recipient '{recipient}' not configured / or gpg not available ")


        use_transit = self.config[c.KEY_FILES]['vault_transit_encryption'].lower()
        if use_transit != 'yes':
            if use_transit != 'no':
                key_files_errors.append("'vault_transit_encryption' must be 'yes' or 'no'")
        
        if gpg_recipient_list and (use_transit == 'yes'):
            key_files_errors.append("'gpg_recipients' and 'use_transit' cannot both be set")


        #KV section validation
        if use_kv == 'yes':
            #validate the KV section
            if len(self.config[c.KV_ENGINE]['kv_secrets_engine']) == 0:
                kv_errors.append("'kv_secrets_engine' must be set")

            if len(self.config[c.KV_ENGINE]['kv_path']) == 0:
                kv_errors.append("'kv_path' must be set")

            #kv_key_name must contain something unique to the generated key
            kv_name = self.config[c.KV_ENGINE]['kv_key_name'].lower()
            if '{vault_account}' in kv_name:
                if '{gcp_key_id}' in kv_name:
                    if '{vault_lease_id}' in kv_name:
                        kv_errors.append("'kv_key_name' must contain '{VAULT_ACCOUNT}', '{GCP_KEY_ID}' or '{VAULT_LEASE_ID}' ")

            #validate the vault server parameters
            kv_errors = self.validate_vault_server_parameters(c.KV_ENGINE, kv_errors)


        #TRANSIT section validation
        if use_transit == 'yes':
            #validate the TRANSIT section
            if len(self.config[c.TRANSIT_ENGINE]['transit_secrets_engine']) == 0:
                transit_errors.append("'transit_secrets_engine' must be set")

            if len(self.config[c.TRANSIT_ENGINE]['transit_key_name']) == 0:
                transit_errors.append("'transit_key_name' must be set")

            #validate the vault server parameters
            transit_errors = self.validate_vault_server_parameters(c.TRANSIT_ENGINE, transit_errors)


        #SNAPSHOT section validation
        save_snapshots = self.config[c.SNAPSHOT]['save_snapshots'].lower()
        if save_snapshots != 'yes':
            if save_snapshots != 'no':
                snapshot_errors.append(f"'save_snapshots' must be 'yes' or 'no'")

        if save_snapshots == 'yes':
            #validate the folder
            snapshot_folder = self.config[c.SNAPSHOT]['snapshot_folder']
            if len(snapshot_folder) == 0:
                snapshot_errors.append("'snapshot_folder' must be set")
            else:
                if not os.path.isdir(snapshot_folder):
                    key_files_errors.append(f"'snapshot_folder' directory must exist. '{snapshot_folder}' cannot be found ")


        #go through each section and report on any errors
        error_occurred = False
        error_occurred = self.log_errors(error_occurred, c.GCP_ENGINES,    gcp_engines_errors)
        error_occurred = self.log_errors(error_occurred, c.KEY_ROTATION,   key_rotation_errors)
        error_occurred = self.log_errors(error_occurred, c.KEY_FILES,      key_files_errors)
        error_occurred = self.log_errors(error_occurred, c.KV_ENGINE,      kv_errors)
        error_occurred = self.log_errors(error_occurred, c.TRANSIT_ENGINE, transit_errors)
        error_occurred = self.log_errors(error_occurred, c.SNAPSHOT,       snapshot_errors)

        if error_occurred:
            return False

        return True


    def log_errors(self, error_occurred: bool, section_name: str, error_list: List[str]) -> bool:
        """
        Logs the errors detected by the validation routine.
        It logs errors for a specific config section and is called multiple times to log errors for different sections.

        :param error_occurred: A boolean indicating if errors have already occurred.
        :type error_occurred: bool
        :param section_name: The section name that the errors relate to.
        :type section_name: str
        :param error_list: The list of error messages for the given section.
        :type error_list: List[str]
        :return: True if there were errors to log, False if there were none.
        :rtype: bool
        """
        logger = self.logger

        if error_list:
            error_occurred = True
            logger.error(f"Validation errors in config section [{section_name}]")
            logger.error(f"[{section_name}]")
            for error in error_list:
                logger.error(f"  - {error}")
        return error_occurred


    def validate_time_period(self, time_period: str) -> bool:
        """
        Validates the time period config values.
        Time periods are specified as a number followed by a unit.
        No units represents seconds.
        's' represents seconds, 'h' represents hours and 'd' represents days.
        e.g. 3600, 3600s, 12h, 30d

        :param time_period: The time preiod config value.
        :type time_period: str
        :return: True if its a valid value, False if not.
        :rtype: bool
        """
        #check for number and unit, e.g. '10d' or '10 d'
        p = re.compile('^(\d+)\s*([shd])$')
        m = p.match(time_period)
        if m:
            number = m.group(1)
            unit = m.group(2).lower()
            result = True
        else:
            #no match, check for digits only
            p = re.compile('^(\d+)$')
            m = p.match(time_period)
            if m:
                number = m.group(1)
                unit = 's'
                result = True
            else:
                #no match
                result = False

        return result

        
    def validate_vault_server_parameters(self, config_section: str, error_list: List[str]) -> List[str]:
        """
        Validates the set of parameters requried for a Vault server.  This is repeated for the GCP engones, KV engne and transit engine.

        :param config_section: The name of the config file section
        :type config_section: str
        :param error_list: The list of errors that have already been recorded for this config section. Any Vault validation errors will be appended to this list.
        :type error_list: List[str]
        :return: The complete list of errors for this section, including any errors appended while validating the vault parameters.
        :rtype: List[str]
        """
        
        auth_type = self.config[config_section]['vault_authentication_type'].lower()
        if auth_type != 'approle':
            if auth_type != 'token':
                error_list.append(f"'vault_authentication_type' must be one of 'approle' or 'token'")

        if auth_type == 'approle':
            if len(self.config[config_section]['vault_approle']) == 0:
                error_list.append(f"'vault_approle' must be set when 'vault_authentication_type' is set to 'approle' ")
            if len(self.config[config_section]['vault_role_id']) == 0:
                error_list.append(f"'vault_role_id' must be set when 'vault_authentication_type' is set to 'approle' ")
            if len(self.config[config_section]['vault_secret_id']) == 0:
                error_list.append(f"'vault_secret_id' must be set when 'vault_authentication_type' is set to 'approle' ")

        if auth_type == 'token':
            vault_token = self.config[config_section]['vault_token']
            if len(vault_token) == 0:
                error_list.append(f"'vault_token' must be set when 'vault_authentication_type' is set to 'token' ")

        if len(self.config[config_section]['vault_address']) == 0:
            error_list.append(f"'vault_address' must be set")

        ca_cert_file = self.config[config_section]['vault_ca_cert']
        if ca_cert_file:
            if not os.path.isfile(ca_cert_file):
                error_list.append(f"'vault_ca_cert' must exist. '{ca_cert_file}' cannot be found ")

        client_cert_file = self.config[config_section]['vault_client_cert']
        if client_cert_file:
            if not os.path.isfile(client_cert_file):
                error_list.append(f"'vault_client_cert' must exist. '{client_cert_file}' cannot be found ")

        client_key_file = self.config[config_section]['vault_client_key']
        if client_key_file:
            if not os.path.isfile(client_key_file):
                error_list.append(f"'vault_client_key' must exist. '{client_key_file}' cannot be found ")

        skip_verify = self.config[config_section]['vault_skip_tls_verify'].lower()
        if skip_verify != 'yes':
            if skip_verify != 'no':
                error_list.append(f"'vault_skip_tls_verify' must be 'yes' or 'no'")

        return error_list


    def get_gcp_secrets_engines(self) -> List[str]:
        """
        Takes the configured comma delimited list of GCP secrets engines configured in the config file and returns a python list of strings

        :return: The python list of strings of the GCP secrets engines to process.
        :rtype: List[str]
        """
        config_engines = self.config[c.GCP_ENGINES]['gcp_secrets_engines']
        config_engines_list = [engine.strip() for engine in config_engines.split(',')]
        return config_engines_list
