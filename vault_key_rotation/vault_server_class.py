""" Module to call the Vault server """
import sys
import logging
import base64
from typing import List
import requests

import vault_key_rotation.gcp.key_rotation_constants as c

class VaultServer:
    """
    This class manages the calls to the Vault server API.
    For each high level Vault operation the methods construct the data payload and the API URL,
    makes the HTTP call and verifies the response.
    Uses the requests module to manage the HTTP interactions.

    :param config_dict: A dictionary corresponding to a section of the config file. Contains all of the config parameters needed to connect to a Vault server.
    :type config_dict: dict
    :raises RuntimeError: Raises an exception if there are errors calling the vault server.
    """

    vault_api_version = 'v1'

    def __init__(self, config_dict: dict) -> None:
        logger = logging.getLogger('vault_key_rotation.vault_server_class')
        self.logger = logger

        ######################
        #we need all of the vault server config values to initiate a connection
        #pass in a dictionary of the following

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

        #set up the http client
        session = requests.Session()

        self.last_status_code = None
        self.text             = None
        self.content          = None
        self.json             = None

        self.config_dict = config_dict

        self.vault_address = config_dict['vault_address']
        #client cert and client key is configured
        if config_dict['vault_client_cert'] and config_dict['vault_client_key']:
            session.cert = config_dict['vault_client_cert'], config_dict['vault_client_key']

        #http and https proxy
        if config_dict['vault_http_proxy'] and config_dict['vault_https_proxy']:
            proxies = {
                        'http': config_dict['vault_http_proxy'],
                        'https': config_dict['vault_https_proxy'],
            }
            session.proxies.update(proxies)
        elif config_dict['vault_http_proxy']:
            proxies = {
                        'http': config_dict['vault_http_proxy'],
            }
            session.proxies.update(proxies)
        elif config_dict['vault_http_proxy']:
            proxies = {
                        'https': config_dict['vault_https_proxy'],
            }
            session.proxies.update(proxies)

        #ca cert config
        if config_dict['vault_ca_cert']:
            session.verify = config_dict['vault_ca_cert']

        #skip tls verification
        if config_dict['vault_skip_tls_verify'] == 'yes':
            session.verify = False

        #create namespace header if required
        if config_dict['vault_namespace']:
            session.headers.update({'X-Vault-Namespace': config_dict['vault_namespace']})

        #store the session against the class
        self.session = session

        vault_ok = False

        #call the status endpoint
        try:
            if self.status():
                #server is running and unsealed
                #check the authentication type
                #if its token add to the headers
                if config_dict['vault_authentication_type'] == 'token':
                    session.headers.update({'X-Vault-Token': config_dict['vault_token']})
                    vault_ok = True
                elif config_dict['vault_authentication_type'] == 'approle':
                    #log in and retrive the token
                    if self.authenticate_via_approle(config_dict['vault_approle'],
                                                    config_dict['vault_role_id'],
                                                    config_dict['vault_secret_id']):
                        #add token to the headers
                        session.headers.update({'X-Vault-Token': self.vault_token})
                        vault_ok = True
                    else:
                        logger.error("Cannot authenticate to vault server - approle login error")
            else:
                logger.error("Cannot connect to vault server - status error")
                raise RuntimeError("Cannot verify vault seal status")

        except requests.exceptions.ConnectionError:
            raise RuntimeError("HTTP Connection error")
        except:
            raise RuntimeError("Unknown HTTP error")

        if vault_ok:
            logger.info(f"Connected to vault server : {self.vault_address}")


    def http_call(self, url: str,
                        verb: str ='get',
                        data_payload: str =None,
                        skip_request_log: bool =False,
                        skip_response_log: bool =False) -> int:
        """
        Makes the HTTP call to the Vault server.

        :param url: The URL endpint to call
        :type url: str
        :param verb: The HTTP verb, defaults to 'get'
        :type verb: str, optional
        :param data_payload: The payload required by a POST operation, defaults to None
        :type data_payload: str, optional
        :param skip_request_log: If True the request payload will not be logged, e.g. if it contains secrets, defaults to False
        :type skip_request_log: bool, optional
        :param skip_response_log: If True the response payload will not be logged, e.g. if it contains secrets, defaults to False
        :type skip_response_log: bool, optional
        :return: The HTTP response code is returned
        :rtype: int
        """
        logger = self.logger

        urllib_logger = logging.getLogger("urllib3.vault_server_class")
        try:
            if data_payload:
                if not skip_request_log:
                    urllib_logger.debug(f"HTTP data payload:\n{data_payload}")
            verb = verb.lower()
            self.reset_last_values()
            if verb == 'get':
                response = self.session.get(url)
            elif verb == 'post':
                if data_payload:
                    response = self.session.post(url, data=data_payload)
                else:
                    response = self.session.post(url)
            elif verb == 'list':
                response = self.session.request('LIST', url)
            elif verb == 'put':
                if data_payload:
                    response = self.session.put(url, data=data_payload)
                else:
                    response = self.session.put(url)

            self.last_status_code = response.status_code
            self.text = response.text
            self.content = response.content
            try:
                self.json = response.json()
            except:
                self.json = '{}'

            if not skip_response_log:
                urllib_logger.debug(self.text.strip())
            return self.last_status_code
        except:
            type, value, traceback = sys.exc_info()
            logger.error("Vault HTTP call failed: HTTP exception")
            logger.error(f"ExceptionType  : '{type}'")
            logger.error(f"ExceptionValue : '{value}'")
            return 999


    def status(self) -> bool:
        """
        Calls the 'Seal status' endpoint

        :return: True if the call is successful (Vault is up and unsealed), False otherwise
        :rtype: bool
        """
        #curl \
        #http://127.0.0.1:8200/v1/sys/seal-status

        logger = self.logger
        endpoint = self.build_url('sys/seal-status')

        status_code = self.http_call(endpoint)
        if status_code <= 299:
            #parse the json and check the seal status
            sealed = self.json['sealed']
            self.version = self.json['version']
            logger.debug(f"Vault server version is '{self.version}'")
            if sealed:
                logger.error(f"Vault getstatus check seal status: HTTP status code '{str(self.last_status_code)}'")
                logger.error(f"HTTP response: {self.text}")
                return False
            else:
                #status ok
                return True
        else:
            #the http call failed
            logger.error(f"Vault call failed to '{endpoint}': HTTP status code '{str(self.last_status_code)}'")
            logger.error(f"HTTP response: {self.text}")
            return False


    def authenticate_via_approle(self, approle: str, role_id: str, secret_id: str) -> bool:
        """
        Authenticates via the approle auth method. If successful it stores the Vault token which will be added to all subsequent requests.

        :param approle: The approle value
        :type approle: str
        :param role_id: The role-id for this role
        :type role_id: str
        :param secret_id: The secret-id to authenticate with this role
        :type secret_id: str
        :return: True if successful, False otherwise.
        :rtype: bool
        """
        #{
            #"role_id": "59d6d1ca-47bb-4e7e-a40b-8be3bc5a0ba8",
            #"secret_id": "84896a0c-1347-aa90-a4f6-aca8b7558780"
        #}
        #curl \
        #--request POST \
        #--data @payload.json \
        #http://127.0.0.1:8200/v1/auth/approle/login

        logger = self.logger

        data_payload = '{ "role_id": "' + role_id + '", '
        data_payload += '"secret_id": "' + secret_id + '" }'
        endpoint = self.build_url('auth/' + approle + '/login')

        status_code = self.http_call(endpoint, 'POST', data_payload, False, True)
        if status_code <=299:
            #extract the token
            logger.info(f"Successfully logged using approle: '{approle}'")
            self.vault_token = self.json['auth']['client_token']
            return True
        else:
            #the http call failed
            logger.error(f"Vault call failed to '{endpoint}': HTTP status code '{str(self.last_status_code)}'")
            logger.error(f"HTTP response: {self.text}")
            return False


    def get_gcp_secrets_engines(self) -> List[str]:
        """
        Retrieves the list of secrets engines of type 'GCP'

        :return: A list of GCP secrets engines
        :rtype: List[str]
        """
        #curl \
        #--header "X-Vault-Token: ..." \
        #http://127.0.0.1:8200/v1/sys/mounts

        logger = self.logger
        endpoint = self.build_url('sys/mounts')

        status_code = self.http_call(endpoint)
        if status_code <= 299:
            gcp_engines = []
            #parse the json and parse the secrets engine list
            for engine in self.json['data']:
                if self.json['data'][engine]['type'] == 'gcp':
                    #remove the trailing slash
                    engine = engine.rstrip("/")
                    gcp_engines.append(engine)

            return gcp_engines

        else:
            #the http call failed
            logger.error(f"Vault call failed to '{endpoint}': HTTP status code '{str(self.last_status_code)}'")
            logger.error(f"HTTP response: {self.text}")
            return []


    def rotate_gcp_root(self, gcp_engine: str) -> bool:
        """
        Rotates the root key for the GCP engine

        :param gcp_engine: The GCP engine to rotate the root for.
        :type gcp_engine: str
        :return: True if successful, False otherwise.
        :rtype: bool
        """
        #curl \
        #--header "X-Vault-Token: ..." \
        #--request POST \
        #https://127.0.0.1:8200/v1/gcp/config/rotate-root

        logger = self.logger
        endpoint = self.build_url( gcp_engine + '/config/rotate-root')

        status_code = self.http_call(endpoint, 'POST')
        if status_code <= 299:
            return True
        else:
            #the http call failed
            logger.error(f"Vault call failed to '{endpoint}': HTTP status code '{str(self.last_status_code)}'")
            logger.error(f"HTTP response: {self.text}")
            return False


    def list_accounts(self, gcp_engine: str, account_type: str) -> List[str]:
        """
        List the rolesets / static accounts for the GCP secrets engine.

        :param gcp_engine: The GCP secrets engine to list
        :type gcp_engine: str
        :param account_type: The type of account to list, 'roleset' or 'static account'
        :type account_type: str
        :return: A list of roleset / static account names
        :rtype: List[str]
        """
        #curl \
        #--header "X-Vault-Token: ..." \
        #--request LIST \
        #https://127.0.0.1:8200/v1/gcp/rolesets
        #https://127.0.0.1:8200/v1/gcp/static-accounts

        logger = self.logger
        account_type = account_type.lower()

        #validate the type is one of the allowed values
        #throws error if not
        self.validate_account_type(account_type)

        endpoint = self.build_url(gcp_engine + '/' + account_type + 's')

        rolesets = []
        status_code = self.http_call(endpoint, 'LIST')
        if status_code <= 299:
            for key in self.json['data']['keys']:
                rolesets.append(key)

            return rolesets

        elif status_code == 404:
            #this could mean there are no accounts
            #i.e. not an error but an empty list
            error_string = str(self.json['errors'])
            if error_string == '[]':
                #no accounts returned but the call was valid
                return rolesets
            else:
                #the http call failed
                logger.error(f"Vault call failed to '{endpoint}': HTTP status code '{str(self.last_status_code)}'")
                logger.error(f"HTTP response: {self.text}")
                return []
        else:
            #the http call failed
            logger.error(f"Vault call failed to '{endpoint}': HTTP status code '{str(self.last_status_code)}'")
            logger.error(f"HTTP response: {self.text}")
            return []


    def read_account(self, gcp_engine: str, account_type: str, account_name: str) -> bool:
        """
        Read the details of the roleset / static account.

        :param gcp_engine: Name of the GCP secrets engine
        :type gcp_engine: str
        :param account_type: The account type, roleset or static account
        :type account_type: str
        :param account_name: The name of the roleset / static account
        :type account_name: str
        :return: True is successful, False if there were any errors.
        :rtype: bool
        """
        #curl \
        #--header "X-Vault-Token: ..." \
        #--request GET \
        #https://127.0.0.1:8200/v1/gcp/roleset/my-token-roleset
        #https://127.0.0.1:8200/v1/gcp/static-account/my-token-account

        logger = self.logger
        account_type = account_type.lower()

        #validate the type is one of the allowed values
        #throws error if not
        self.validate_account_type(account_type)

        endpoint = self.build_url(gcp_engine + '/' + account_type + '/' + account_name)

        status_code = self.http_call(endpoint)
        if status_code <= 299:
            return True

        else:
            #the http call failed
            logger.error(f"Vault call failed to '{endpoint}': HTTP status code '{str(self.last_status_code)}'")
            logger.error(f"HTTP response: {self.text}")
            return False


    def list_account_keys(self, gcp_engine: str, account_type:str, account_name: str) -> List[str]:
        """
        List the keys for the given account.
        Checks the version of Vault to determine if static accounts are supported.
        The path is different depending on the version of Vault.

        :param gcp_engine: The name of the GCP secrets engine
        :type gcp_engine: str
        :param account_type: The account type, roleset or static account
        :type account_type: str
        :param account_name: The roleset / static account name
        :type account_name: str
        :return: A list of key ids for the account.
        :rtype: List[str]
        """
        #curl \
        #--header "X-Vault-Token: ..." \
        #--request LIST \
        #http://127.0.0.1:8200/v1/sys/leases/lookup/aws/creds/deploy/
        #http://127.0.0.1:8200/v1/sys/leases/lookup/gcp/key/roleset/
        #http://127.0.0.1:8200/v1/sys/leases/lookup/gcp/key/static-account/

        #on v1.8 there are separate paths for rolesets and static accounts
        #vault list /sys/leases/lookup/gcp/roleset/ian-clark-bucket4/key
        #vault list /sys/leases/lookup/gcp/static-account/my-key-account/key

        logger = self.logger

        #endpoint = self.build_url('sys/leases/lookup/' + gcp_engine + '/key/' + account_name)

        #validate the type is one of the allowed values
        #throws error if not
        self.validate_account_type(account_type)

        if self.static_accounts_supported():
            endpoint = self.build_url('sys/leases/lookup/' + gcp_engine + '/' + account_type + '/' + account_name + '/key')
        else:
            #use the deprecated path as the new path isn't supported on older versions
            endpoint = self.build_url('sys/leases/lookup/' + gcp_engine + '/key/' + account_name)

        keys = []
        status_code = self.http_call(endpoint, 'LIST')
        if status_code <= 299:
            for key in self.json['data']['keys']:
                keys.append(key)

            return keys

        elif status_code == 404:
            #this could mean there are no accounts
            #i.e. not an error but an empty list
            error_string = str(self.json['errors'])
            if error_string == '[]':
                #no accounts returned but the call was valid
                return keys
            else:
                #the http call failed
                logger.error(f"Vault call failed to '{endpoint}': HTTP status code '{str(self.last_status_code)}'")
                logger.error(f"HTTP response: {self.text}")
                return []

        else:
            #the http call failed
            logger.error(f"Vault call failed to '{endpoint}': HTTP status code '{str(self.last_status_code)}'")
            logger.error(f"HTTP response: {self.text}")
            return []


    def get_account_key_details(self, lease_id: str) -> bool:
        """
        Retrive the key details for the given lease id.

        :param lease_id: The lease id
        :type lease_id: str
        :return: True if successful, False if there are any errors.
        :rtype: bool
        """
        #{
        #  "lease_id": "aws/creds/deploy/abcd-1234..."
        #}
        #curl \
        #--header "X-Vault-Token: ..." \
        #--request PUT \
        #--data @payload.json \
        #http://127.0.0.1:8200/v1/sys/leases/lookup

        logger = self.logger

        data_payload = '{ "lease_id": "' + lease_id + '" }'

        endpoint = self.build_url('sys/leases/lookup')

        status_code = self.http_call(endpoint, 'PUT', data_payload)
        if status_code <= 299:
            return True

        else:
            #the http call failed
            logger.error(f"Vault call failed to '{endpoint}': HTTP status code '{str(self.last_status_code)}'")
            logger.error(f"HTTP response: {self.text}")
            return False


    def create_account_key(self,
                         gcp_engine: str,
                         account_type: str,
                         account_name: str,
                         ttl: str =None) -> bool:
        """
        Creates a new key on GCP.
        This method checks whether the Vault version supports static accounts or not.
        The Vault paths are different for the different version.

        :param gcp_engine: The name of the GCP secrets engine.
        :type gcp_engine: str
        :param account_type: The account type, roleset or static account
        :type account_type: str
        :param account_name: The name of the roleset / static account
        :type account_name: str
        :param ttl: The ttl for the Vault lease, defaults to None
        :type ttl: str, optional
        :return: True if successful, False if there were any errors
        :rtype: bool
        """
        #curl \
        #--header "X-Vault-Token: ..." \
        #--request GET \
        #https://127.0.0.1:8200/v1/gcp/roleset/my-key-roleset/key
        #https://127.0.0.1:8200/v1/gcp/static-account/my-key-roleset/key
        #http://192.168.0.37:61000/v1/gcp/key/roleset_name (deprecated)

        logger = self.logger
        account_type = account_type.lower()

        if ttl:
            method = 'post'
            data_payload = '{ "ttl": "' + ttl + '" }'
        else:
            data_payload = ''
            method = 'get'

        #validate the type is one of the allowed values
        #throws error if not
        self.validate_account_type(account_type)

        if self.static_accounts_supported():
            endpoint = self.build_url(gcp_engine + '/' + account_type + '/' + account_name + '/key')
        else:
            #use the deprecated path as the new path isn't supported on older versions
            endpoint = self.build_url(gcp_engine + '/key/' + account_name )

        status_code = self.http_call(endpoint, method, data_payload, False, True)
        if status_code <= 299:
            return True

        else:
            #the http call failed
            logger.error(f"Vault call failed to '{endpoint}': HTTP status code '{str(self.last_status_code)}'")
            logger.error(f"HTTP response: {self.text}")
            return False


    def revoke_account_key(self, lease_id: str) -> bool:
        """
        Revokes a Vault lease and the associated GCP key.

        :param lease_id: The Vault lease id to revoke
        :type lease_id: str
        :return: True if successful, False if there were any errors
        :rtype: bool
        """
        #{
        #  "lease_id": "postgresql/creds/readonly/abcd-1234..."
        #}
        #curl \
        #--header "X-Vault-Token: ..." \
        #--request PUT \
        #--data @payload.json \
        #http://127.0.0.1:8200/v1/sys/leases/revoke

        logger = self.logger

        data_payload = '{ "lease_id": "' + lease_id + '" }'

        endpoint = self.build_url('sys/leases/revoke')

        status_code = self.http_call(endpoint, 'PUT', data_payload)
        if status_code <= 299:
            return True

        else:
            #the http call failed
            logger.error(f"Vault call failed to '{endpoint}': HTTP status code '{str(self.last_status_code)}'")
            logger.error(f"HTTP response: {self.text}")
            return False


    def save_snapshot(self, save_filename: str) -> bool:
        """
        Creates a Vault snapshot and saves it to disk.

        :param save_filename: The filename to save the snapshot to
        :type save_filename: str
        :return: True if successful, False if there are any errors.
        :rtype: bool
        """
        #GET	/sys/storage/raft/snapshot

        logger = self.logger

        endpoint = self.build_url('sys/storage/raft/snapshot')

        status_code = self.http_call(endpoint, 'GET', None, False, True)
        if status_code <= 299:
            try:
                with open(save_filename, 'wb') as file_object:
                    file_object.write(self.content)

                return True

            except:
                type, value, traceback = sys.exc_info()
                logger.error(f"Error saving snapshot to disk - {type} : {value}")
                return False

        else:
            #the http call failed
            logger.error(f"Vault call failed to '{endpoint}': HTTP status code '{str(self.last_status_code)}'")
            logger.error(f"HTTP response: {self.text}")
            return False


    def transit_encrypt(self, transit_engine: str, transit_key: str, plain_text: str) -> bool:
        """
        Encrypt data using the Vault transit engine.

        :param transit_engine: The transit engine name
        :type transit_engine: str
        :param transit_key: The transit engine key name
        :type transit_key: str
        :param plain_text: The plain text to encrypt.
        :type plain_text: str
        :return: True if successful, False if there are any errors.
        :rtype: bool
        """
        #{
        #  "plaintext": "dGhlIHF1aWNrIGJyb3duIGZveAo="
        #}
        #curl \
        #--header "X-Vault-Token: ..." \
        #--request POST \
        #--data @payload.json \
        #http://127.0.0.1:8200/v1/transit/encrypt/my-key

        logger = self.logger

        b64_plain_text = base64.b64encode(plain_text).decode()

        data_payload = '{ "plaintext": "' + b64_plain_text + '" }'

        endpoint = self.build_url(transit_engine + '/encrypt/' + transit_key)

        status_code = self.http_call(endpoint, 'POST', data_payload, True)
        if status_code <= 299:
            return True

        else:
            #the http call failed
            logger.error(f"Vault call failed to '{endpoint}': HTTP status code '{str(self.last_status_code)}'")
            logger.error(f"HTTP response: {self.text}")
            return False


    def write_kv_key(self,
                kv_version: str,
                kv_engine: str,
                kv_path: str,
                kv_key: str,
                data: str) -> bool:
        """
        Write data to a Vault KV engine.

        :param kv_version: The KV engine version, '1' or '2'
        :type kv_version: str
        :param kv_engine: The KV engine name
        :type kv_engine: str
        :param kv_path: The KV engine path
        :type kv_path: str
        :param kv_key: The KV key
        :type kv_key: str
        :param data: The data to write
        :type data: str
        :return: True if successful, False if there were any errors
        :rtype: bool
        """
        #KV V1
        #{
        #  "foo": "bar",
        #}
        #curl \
        #--header "X-Vault-Token: ..." \
        #--request POST \
        #--data @payload.json \
        #https://127.0.0.1:8200/v1/secret/my-secret

        #KV V2
        #{
        #  "data": {
        #    "foo": "bar",
        #    "zip": "zap"
        #  }
        #}
        #curl \
        #--header "X-Vault-Token: ..." \
        #--request POST \
        #--data @payload.json \
        #https://127.0.0.1:8200/v1/secret/data/my-secret

        logger = self.logger

        if kv_version == '1':
            #create a v1 payload
            data_payload = "{\n" + '  "' + kv_key + '": "' + str(data) + '"' + "\n}"
            endpoint = self.build_url(kv_engine + '/' + kv_path)
        elif kv_version == '2':
            #create a v2 payload
            data_payload = "{\n"
            data_payload += '  "data": {' + "\n" + '    "'
            data_payload += kv_key + '": "' + str(data) + '"' + "\n  }\n"
            data_payload += '}'
            endpoint = self.build_url(kv_engine + '/data/' + kv_path)

        status_code = self.http_call(endpoint, 'POST', data_payload)
        if status_code <= 299:
            return True

        else:
            #the http call failed
            logger.error(f"Vault call failed to '{endpoint}': HTTP status code '{str(self.last_status_code)}'")
            logger.error(f"HTTP response: {self.text}")
            return False


    def create_child_token(self, policies_list_str: str, ttl: str ='') -> bool:
        """
        Create an orphan child token.

        :param policies_list_str: A comma separated list of policies to apply to the child token.
        :type policies_list_str: str
        :param ttl: TTL of the token, optional, defaults to ''
        :type ttl: str, optional
        :return: True if successful, False if there are any errors
        :rtype: bool
        """
        #{
        #  "policies": ["web", "stage"],
        #  "ttl": "1h",
        #  "renewable": false,
        #}
        #curl \
        #--header "X-Vault-Token: ..." \
        #--request POST \
        #--data @payload.json \
        #http://127.0.0.1:8200/v1/auth/token/create-orphan
        logger = self.logger

        #policies list is a comma separated list
        #split and recombine into the right format
        policies_list = [policy.strip() for policy in policies_list_str.split(',')]
        policies = '['
        for policy in policies_list:
            if policies != '[':
                policies += ', "' + policy + '"'
            else:
                policies += '"' + policy + '"'
        policies += ']'

        data_payload  = "{\n"
        data_payload += '  "policies": ' + policies
        if ttl:
            data_payload += ",\n  " + '"ttl": "' + ttl + '"'
        data_payload += "\n}"

        endpoint = self.build_url('auth/token/create-orphan')

        status_code = self.http_call(endpoint, 'POST', data_payload)
        if status_code <= 299:
            return True

        else:
            #the http call failed
            logger.error(f"Vault call failed to '{endpoint}': HTTP status code '{str(self.last_status_code)}'")
            logger.error(f"HTTP response: {self.text}")
            return False


    def static_accounts_supported(self) -> bool:
        """
        Checks the Vault server version and verfies if its greater than v1.8.
        GCP static accounts were first supported in Vault 1.8

        :return: True if version is greater or equal 1.8 and GCP static accounts are supported. False otherwise.
        :rtype: bool
        """
        logger = self.logger
        supported = False
        version = self.version
        version_numbers = version.split('.')
        if int(version_numbers[0]) == 1:
            if int(version_numbers[1]) >= 8:
                supported = True
        elif int(version_numbers[0]) > 1:
            supported = True

        if not supported:
            logger.warning("This version of vault does not support the use of GCP static accounts : v%s",
                        version)

        return supported


    def validate_account_type(self, account_type: str) -> None:
        """
        Validate that the account type is either roleset or static account

        :param account_type: The account type to check
        :type account_type: str
        :raises RuntimeError: Exception gets rasied if the account type is not valid
        """
        if account_type != c.ACCOUNT_TYPES.ROLESET:
            if account_type != c.ACCOUNT_TYPES.STATIC:
                raise RuntimeError(f"'account_type' must be one of '{c.ACCOUNT_TYPES.ROLESET}' or '{c.ACCOUNT_TYPES.STATIC}' ")


    def build_url(self, endpoint: str) -> str:
        """
        Build the Vault URL prior to calling the API

        :param endpoint: The API end point
        :type endpoint: str
        :return: The full URL, server address, api version and api endpoint
        :rtype: str
        """
        return self.vault_address + '/' + self.vault_api_version + '/' + endpoint

    def get_last_status_code(self) -> int:
        """
        Returns the last HTTP status code returned by this instance

        :return: The HTTP status code
        :rtype: int
        """
        return self.last_status_code

    def get_last_response_text(self) -> str:
        """
        Returns the last HTTP text response returned by this instance

        :return: The response text
        :rtype: str
        """
        return self.text

    def get_last_response_json(self) -> str:
        """
        Returns the last HTTP response JSON returned by this instance

        :return: the response JSON
        :rtype: str
        """
        return self.json

    def get_vault_version(self) -> str:
        """
        Returns the Vault server version represented by this instance

        :return: The Vault server version
        :rtype: str
        """
        return self.version

    def reset_last_values(self) -> None:
        """
        Clear the last returned values
        """
        self.last_status_code = None
        self.text = None
        self.json = None
