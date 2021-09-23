"""
A module with some general functions to mange command line parameters.
"""

import argparse
import sys
import os

import vault_key_rotation.gcp.key_rotation_constants as c


def parse_command_line_parameters() -> argparse.ArgumentParser:
    """
    Parse the command line parameters.

    :return: A argparse.ArgumentParser object representing teh requried command line parameters.
    :rtype: argparse.ArgumentParser
    """
    
    #parse command line parameters
    parser = argparse.ArgumentParser(description="Rotate GCP keys in Vault.",
                                    epilog=".")
    parser.add_argument("-v", "--version", help="display version",
                        action="store_true")
    parser.add_argument("-g", "--generate_vault_policies", help="generate the vault policy giving access to all paths",
                        action="store_true")
    parser.add_argument("-k", "--rotate_keys", help="rotate any keys reaching expiry",
                        action="store_true")
    parser.add_argument("-r", "--rotate_root", help="rotate the secret engines root keys",
                        action="store_true")
    parser.add_argument("--report", help="report on what is configured in Vault",
                        action="store_true")
    parser.add_argument("--create_config_file", help="generate an empty config file and print to console",
                        action="store_true")
    parser.add_argument("-c", "--config", help="path to config file")
    parser.add_argument("-l", "--log_config", help="path to the logging config file")

    return parser


def validate_command_line_parameters(parser: argparse.ArgumentParser,
                                     script_dir: str):
    """
    Validates the comamnd line parameters.

    :param parser: The argparser args passed on the command line.
    :type parser: argparse.ArgumentParser
    :param script_dir: The directory where the script is located.
    :type script_dir: str
    :return: The updated args value.
    :rtype: argparse.ArgumentParser.parse_args
    """

    errors = []

    if not len(sys.argv) > 1:
        #nothing has been passed
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.create_config_file and args.rotate_keys:
        errors.append("Command line args 'generate_config_file' and 'rotate_keys' cannot both be specified")

    if args.create_config_file and args.rotate_root:
        errors.append("Command line args 'generate_config_file' and 'rotate_root' cannot both be specified")

    if args.create_config_file and args.report:
        errors.append("Command line args 'generate_config_file' and 'report' cannot both be specified")

    if args.create_config_file and args.generate_vault_policies:
        errors.append("Command line args 'generate_config_file' and 'generate_vault_policies' cannot both be specified")

    if args.report and args.rotate_keys:
        errors.append("Command line args 'report' and 'rotate_keys' cannot both be specified")

    if args.report and args.rotate_root:
        errors.append("Command line args 'report' and 'rotate_root' cannot both be specified")

    if args.generate_vault_policies and args.rotate_keys:
        errors.append("Command line args 'generate_vault_policies' and 'rotate_keys' cannot both be specified")

    if args.generate_vault_policies and args.rotate_root:
        errors.append("Command line args 'generate_vault_policies' and 'rotate_root' cannot both be specified")

    if args.generate_vault_policies and args.report:
        errors.append("Command line args 'generate_vault_policies' and 'report' cannot both be specified")

    if not args.create_config_file:
        if not args.config:
            errors.append("Command line arg 'config' must be specified")
        elif not os.path.isfile(args.config):
            errors.append(f"Config file '{args.config}' does not exist")

    if args.log_config:
        if not os.path.isfile(args.log_config):
            errors.append(f"Logging config file '{args.log_config}' does not exist")

    if errors:
        #report errors
        print("\nErrors in command line parameters:")
        for error in errors:
            print(f"  {error}")
        print("\n")
        sys.exit(1)

    #get the absolute path to the logging config
    if args.log_config:
        args.log_config = os.path.realpath(args.log_config)
    else:
        args.log_config = script_dir + '/' + c.DEFAULT_LOG_CONFIG

    #get the absolute path to the config file
    if args.config:
        args.config = os.path.realpath(args.config)

    return args
