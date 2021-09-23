import unittest
import os
import sys
import configparser

#get script directory
script_dir = os.path.dirname(os.path.realpath(__file__))

from vault_key_rotation.gcp.key_rotation_config_class import *
from vault_key_rotation.gcp.key_rotation_config import create_config_file_template
import vault_key_rotation.gcp.key_rotation_constants as c


class TestConfigClass(unittest.TestCase):

    config_file_name = script_dir + '/test_config_class.ini'

    def reload_config_file(self):

        tmp_config = configparser.ConfigParser()
        with open(self.config_file_name, 'w') as file_object:
            file_object.write(self.returned_config_file)

        tmp_config.read(self.config_file_name)

        tmp_config[c.GCP_ENGINES]['vault_token'] = 's.jadhfjadhflkadfh'
        tmp_config[c.GCP_ENGINES]['vault_address'] = 'http://127.0.0.1:6100'
        tmp_config[c.KEY_ROTATION]['key_expiry_threshold'] = '5d'
        tmp_config[c.KEY_FILES]['key_output_directory'] = script_dir

        with open(self.config_file_name, 'w') as configfile:
            tmp_config.write(configfile)

        config_class = KeyRotationConfig(self.config_file_name)
        self.config_class = config_class


    def setUp(self) -> None:
        #create config file to use for testing
        returned_config_file = create_config_file_template()
        self.returned_config_file = returned_config_file
        self.reload_config_file()
        return super().setUp()

    def tearDown(self) -> None:
        #delete config file
        os.remove(self.config_file_name)
        return super().tearDown()


    def test_populate_environment_variable(self):
        os.environ['POP_VAR_TEST'] = 'POP_VAR_TEST_VAL'
        self.config_class.config[c.SNAPSHOT]['save_snapshots'] = 'ENV:POP_VAR_TEST'
        self.config_class.populate_environment_variables()
        self.assertEqual('POP_VAR_TEST_VAL', self.config_class.config[c.SNAPSHOT]['save_snapshots'])
        self.config_class.config[c.SNAPSHOT]['save_snapshots'] = ''


    def test_set_static_default_values(self):
        self.reload_config_file()

        self.assertEqual('gcp', self.config_class.config[c.GCP_ENGINES]['gcp_secrets_engines'])
        self.assertEqual('both', self.config_class.config[c.GCP_ENGINES]['vault_gcp_account_types'])
        self.assertEqual('token', self.config_class.config[c.GCP_ENGINES]['vault_authentication_type'])
        self.assertEqual('no', self.config_class.config[c.GCP_ENGINES]['vault_skip_tls_verify'])

        self.assertEqual('kv', self.config_class.config[c.KV_ENGINE]['kv_secrets_engine'])
        self.assertEqual('{VAULT_ACCOUNT}', self.config_class.config[c.KV_ENGINE]['kv_key_name'])

        self.assertEqual('transit', self.config_class.config[c.TRANSIT_ENGINE]['transit_secrets_engine'])

        self.assertEqual('now', self.config_class.config[c.KEY_ROTATION]['delete_old_key_threshold'])

        self.assertEqual('{VAULT_ACCOUNT}.json', self.config_class.config[c.KEY_FILES]['key_file_name'])
        self.assertEqual('no', self.config_class.config[c.KEY_FILES]['vault_transit_encryption'])
        self.assertEqual('no', self.config_class.config[c.KEY_FILES]['vault_kv_storage'])

        self.assertEqual('no', self.config_class.config[c.SNAPSHOT]['save_snapshots'])


    def test_set_dont_copy_default_values(self):

        self.reload_config_file()
        self.populate_gcp_engines()
                
        #set KV and TRANSIT vault address to different value
        self.config_class.config[c.KV_ENGINE]['vault_address'] = 'http://127.0.0.1:6200'
        self.config_class.config[c.TRANSIT_ENGINE]['vault_address'] = 'http://127.0.0.1:6300'

        self.config_class.expand_config_defaults()

        #verify the GCP namespace does NOT get copied
        self.assertEqual('', self.config_class.config[c.KV_ENGINE]['vault_namespace'])
        self.assertEqual('', self.config_class.config[c.TRANSIT_ENGINE]['vault_namespace'])


    def test_set_copy_default_values(self):

        self.reload_config_file()
        self.populate_gcp_engines()

        #clear all values for each section
        self.clear_vault_values(c.KV_ENGINE)
        self.clear_vault_values(c.TRANSIT_ENGINE)

        self.config_class.expand_config_defaults()

        #verify the GCP vault values get copied to the KV and TRANSIT engines
        self.assertEqual('http://127.0.0.1:6100', self.config_class.config[c.KV_ENGINE]['vault_address'])
        self.assertEqual('token', self.config_class.config[c.KV_ENGINE]['vault_authentication_type'])
        self.assertEqual('role', self.config_class.config[c.KV_ENGINE]['vault_role_id'])
        self.assertEqual('secret', self.config_class.config[c.KV_ENGINE]['vault_secret_id'])
        self.assertEqual('tokenval', self.config_class.config[c.KV_ENGINE]['vault_token'])
        self.assertEqual('ca_cert_file', self.config_class.config[c.KV_ENGINE]['vault_ca_cert'])
        self.assertEqual('http_proxy', self.config_class.config[c.KV_ENGINE]['vault_http_proxy'])
        self.assertEqual('https_proxy', self.config_class.config[c.KV_ENGINE]['vault_https_proxy'])
        self.assertEqual('NS1', self.config_class.config[c.KV_ENGINE]['vault_namespace'])
        self.assertEqual('client_cert_file', self.config_class.config[c.KV_ENGINE]['vault_client_cert'])
        self.assertEqual('client_key_file', self.config_class.config[c.KV_ENGINE]['vault_client_key'])
        self.assertEqual('tls_verify', self.config_class.config[c.KV_ENGINE]['vault_skip_tls_verify'])

        self.assertEqual('http://127.0.0.1:6100', self.config_class.config[c.TRANSIT_ENGINE]['vault_address'])
        self.assertEqual('token', self.config_class.config[c.TRANSIT_ENGINE]['vault_authentication_type'])
        self.assertEqual('role', self.config_class.config[c.TRANSIT_ENGINE]['vault_role_id'])
        self.assertEqual('secret', self.config_class.config[c.TRANSIT_ENGINE]['vault_secret_id'])
        self.assertEqual('tokenval', self.config_class.config[c.TRANSIT_ENGINE]['vault_token'])
        self.assertEqual('ca_cert_file', self.config_class.config[c.TRANSIT_ENGINE]['vault_ca_cert'])
        self.assertEqual('http_proxy', self.config_class.config[c.TRANSIT_ENGINE]['vault_http_proxy'])
        self.assertEqual('https_proxy', self.config_class.config[c.TRANSIT_ENGINE]['vault_https_proxy'])
        self.assertEqual('NS1', self.config_class.config[c.TRANSIT_ENGINE]['vault_namespace'])
        self.assertEqual('client_cert_file', self.config_class.config[c.TRANSIT_ENGINE]['vault_client_cert'])
        self.assertEqual('client_key_file', self.config_class.config[c.TRANSIT_ENGINE]['vault_client_key'])
        self.assertEqual('tls_verify', self.config_class.config[c.TRANSIT_ENGINE]['vault_skip_tls_verify'])


    def populate_gcp_engines(self):
        self.config_class.config[c.GCP_ENGINES]['vault_address'] = 'http://127.0.0.1:6100'
        self.config_class.config[c.GCP_ENGINES]['vault_authentication_type'] = 'token'
        self.config_class.config[c.GCP_ENGINES]['vault_role_id'] = 'role'
        self.config_class.config[c.GCP_ENGINES]['vault_secret_id'] = 'secret'
        self.config_class.config[c.GCP_ENGINES]['vault_token'] = 'tokenval'
        self.config_class.config[c.GCP_ENGINES]['vault_ca_cert'] = 'ca_cert_file'
        self.config_class.config[c.GCP_ENGINES]['vault_http_proxy'] = 'http_proxy'
        self.config_class.config[c.GCP_ENGINES]['vault_https_proxy'] = 'https_proxy'
        self.config_class.config[c.GCP_ENGINES]['vault_namespace'] = 'NS1'
        self.config_class.config[c.GCP_ENGINES]['vault_client_cert'] = 'client_cert_file'
        self.config_class.config[c.GCP_ENGINES]['vault_client_key'] = 'client_key_file'
        self.config_class.config[c.GCP_ENGINES]['vault_skip_tls_verify'] = 'tls_verify'


    def clear_vault_values(self, section):
        self.config_class.config[section]['vault_address'] = ''
        self.config_class.config[section]['vault_authentication_type'] = ''
        self.config_class.config[section]['vault_role_id'] = ''
        self.config_class.config[section]['vault_secret_id'] = ''
        self.config_class.config[section]['vault_token'] = ''
        self.config_class.config[section]['vault_ca_cert'] = ''
        self.config_class.config[section]['vault_http_proxy'] = ''
        self.config_class.config[section]['vault_https_proxy'] = ''
        self.config_class.config[section]['vault_namespace'] = ''
        self.config_class.config[section]['vault_client_cert'] = ''
        self.config_class.config[section]['vault_client_key'] = ''
        self.config_class.config[section]['vault_skip_tls_verify'] = ''


    def test_validate_time_period(self):
        self.reload_config_file()

        self.assertTrue(self.config_class.validate_time_period('84000'))
        self.assertTrue(self.config_class.validate_time_period('84000s'))
        self.assertTrue(self.config_class.validate_time_period('36h'))
        self.assertTrue(self.config_class.validate_time_period('2d'))
        self.assertTrue(self.config_class.validate_time_period('84000 s'))
        self.assertTrue(self.config_class.validate_time_period('24 h'))
        self.assertTrue(self.config_class.validate_time_period('5 d'))

        self.assertFalse(self.config_class.validate_time_period('5 y'))
        self.assertFalse(self.config_class.validate_time_period('five days'))
        self.assertFalse(self.config_class.validate_time_period('5 days'))


    def test_validate_values(self):
        self.reload_config_file()

        #################################
        #manipulate different values
        #run the validation and check the return
        #so many validations to check
        
        #####################
        #we can also set up logging verification

        #####################################



if __name__ == '__main__':
    unittest.main()
