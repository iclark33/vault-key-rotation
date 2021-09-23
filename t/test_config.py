import unittest
import os
import sys
import hashlib

#get script directory
script_dir = os.path.dirname(os.path.realpath(__file__))

from vault_key_rotation.gcp.key_rotation_config import *

class TestConfig(unittest.TestCase):

    def setUp(self) -> None:
        return super().setUp()

    def tearDown(self) -> None:
        return super().tearDown()


    def test_logfile_name(self):

        returned_log_file = get_log_file_name(script_dir)

        now = datetime.now()
        year = now.strftime("%Y")
        month = now.strftime("%m")
        day = now.strftime("%d")
        file_name = f"gcp_key_rotation_{year}_{month}_{day}.log"
        log_file = script_dir + '/logs/' + file_name
        log_file = log_file.replace('\\', '\\\\')
        
        self.assertEqual(log_file, returned_log_file)


    def test_default_config_file(self):
        returned_config_file = create_config_file_template()
        # we test the hash for simplicity, but this will make debugging harder in the 
        # event of an assertion failure
        hex = hashlib.sha256(returned_config_file.strip().encode('utf-8')).hexdigest()
        self.assertEqual(hex, 'fd74acc551f997954784009cebf6b6b3f8ef82f4a16c61594eb92f4b2ffbcee5')


if __name__ == '__main__':
    unittest.main()

