"""This package will manage the key rotation of GCP secrets engines configured on Hashicorp Vault"""

import logging
import logging.config
import os
import sys

import vault_key_rotation.gcp.key_rotation_constants as c
import vault_key_rotation.gcp.key_rotation_functions as krf
import vault_key_rotation.gcp.key_rotation_config as krc
from vault_key_rotation.gcp.key_rotation_class import KeyRotation


# get script directory
script_dir = os.path.dirname(os.path.realpath(__file__))


def display_version():
    """Display the program version."""
    print(f"\nVault GCP key rotation : Version {c.VERSION}\n\n")


##############################################################################

# parse command line parameters
parser = krf.parse_command_line_parameters()
args = parser.parse_args()

if args.version:
    display_version()
    sys.exit(0)

#validate parameters
valid_args = krf.validate_command_line_parameters(parser, script_dir)

if valid_args.create_config_file:
    CONFIG_TEXT = krc.create_config_file_template()
    print(CONFIG_TEXT)
    sys.exit(0)


#change working dir, all relative paths in the config file are from the script directory
os.chdir(script_dir)


#initialise logging
log_file_name = krc.get_log_file_name(script_dir)
urllib_log_file = krc.get_url_log_file_name(script_dir)
logging.config.fileConfig(  valid_args.log_config,
                            disable_existing_loggers=True,
                            defaults={ 'logfilename' : log_file_name,
                                       'urlliblogfilename' : urllib_log_file } )
logger = logging.getLogger('vault_key_rotation')

if valid_args.generate_vault_policies:
    POLICY_TEXT = krc.create_vault_policy(valid_args.config)
    print(POLICY_TEXT)
    sys.exit(0)

logger.info("")
logger.info("----------------------------")
logger.info("Key rotation process started")

#verify we have the rotate keys flag
if not valid_args.rotate_keys:
    valid_args.report = True

#rotate the keys
kr = KeyRotation(valid_args.config, valid_args.report, valid_args.rotate_root)
kr.rotate_keys()

logger.info("Key rotation process stopped")
logger.info("----------------------------")
logger.info("")
