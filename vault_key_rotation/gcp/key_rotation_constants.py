"""
A module to define various constants that are used throughout the package.    
"""

VERSION: str = '0.0.1'

DEFAULT_LOG_CONFIG: str = 'logging.cfg'

#config section headers
GCP_ENGINES: str    = 'vault_gcp_engines'
KEY_ROTATION: str   = 'key_rotation'
KEY_FILES: str      = 'key_files'
KV_ENGINE: str      = 'vault_kv'
TRANSIT_ENGINE: str = 'vault_transit'
SNAPSHOT: str       = 'snapshots'

class ACCOUNT_TYPES:
    ROLESET: str = 'roleset'
    STATIC : str = 'static-account'
    BOTH: str    = 'both'

