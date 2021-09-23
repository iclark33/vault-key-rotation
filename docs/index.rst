.. Vault GCP Key Rotation documentation master file, created by
   sphinx-quickstart on Sun Sep 12 13:54:52 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Vault Key Rotation's documentation!
==================================================

.. toctree::
   :maxdepth: 4
   :caption: Contents:

   config
   logging
   script_code

Code
----

The code is hosted on github.

`Download the code <https://github.com/iclark33/vault-key-rotation>`_

Pre-requisites
++++++++++++++

The code requires python 3.7 to run. 

The following modules need to be installed:

* `requests <https://docs.python-requests.org/en/latest/>`_


Introduction
------------

`Hashicorp Vault <https://www.vaultproject.io/>`_ is an open source secrets manager that can be used in many scenarios wherever secrets are being used by an application.  One common use case is for Vault to manage dynamic secrets used in Cloud deployments such as GCP and AWS. Many organisations have security policies which mandate that the rotation of cloud credentials is carried out regularly. There are very few options to perform the key rotation and this package aims to make this an easy configuration driven process.

The ideal approach to using Vault and Cloud is to generate dynamic short lived credentials that get generated when they are needed and expire shortly after they are no longer required.  For legacy applications it may be difficult to shift to this pattern and this package can hopefully help these legacy applications manage key rotation while still getting the benefit of using Vault to manage their cloud keys.

The specific scenario that led to this package being developed is a legacy application which puts a framework around the Google gsutil command line tool to manage numerous transfers to and from Google Cloud Storage.  The application itself has no awareness of Vault or even the GCP service account keys.  The keys are created outside of the application and are referenced from the `BOTO config file <https://cloud.google.com/storage/docs/boto-gsutil>`_ which is used to configure the gsutil tool. As the keys are managed outside of the application it isn't practical to generate short term keys just as they are needed therefore the keys used are used for a longer term. Any rotation of the keys also has to happen outside of the application.  There are no tools readily available to perform this rotation so the decision was to manage the keys via Vault and use the Vault API to perform the rotation.

The code currently only supports GCP secrets engines.

This package can be used to interrogate Vault and determine what is configured. The key details are looked up and checked to verify if the key is nearing expiry.  If required a new key is generated and is then stored using a number of storage options from where the legacy application can retrieve the key.  The old keys nearing expiry can then be explicitly revoked or they can be left to allow Vault to auto revoke them.  The high level process is:

.. code-block::
 
   foreach configured Vault GCP secrets engine
      foreach roleset
         foreach key
            if all keys are within the expiry threshold
               create a new key
            endif
         endfor
                              
         if new key created
            delete old keys within the deletion threshold
         endif
      endfor
   endfor

The behaviour of the script can be controlled via the ":ref:`config`".

View the package logging information in ":ref:`logging`".

GCP Key TTL
-----------

The expected scenario is that short lived Vault credentials will be used to authenticate to Vault. The code then interrogates Vault and determines whether new keys need to be generated.  When generating new keys, this can be done under the same Vault logon but is probably not desirable as any GCP keys created would have the same short term lease as the authentication token. To get round this issue the code can create an orphan child token which will then be used to create the new keys.  This child token can have a longer TTL meaning that the GCP keys it creates also have a longer lease.

How to invoke the code
----------------------

A sample script [link to code file source] is provided showing how to set up and call the package. The following command line parameters are available:

::
   -h, --help            show this help message and exit
   -v, --version         display version
   -g, --generate_vault_policies
                        generate the vault policy giving access to all paths
   -k, --rotate_keys     rotate any keys reaching expiry
   -r, --rotate_root     rotate the secret engines root keys
   --report              report on what is configured in Vault
   --create_config_file  generate an empty config file and print to console
   -c CONFIG, --config CONFIG
                        path to config file
   -l LOG_CONFIG, --log_config LOG_CONFIG
                        path to the logging config file



The sample script shows how to do the following:

* Set up logging
* How to generate a sample config file
* How to generate the required vault policies
* How to report on what is configured in Vault
* How to perform the key rotation

The script code can be viewed here ":ref:`scriptcode`".


Features:
---------

* Standalone key rotation script
* Supports Vault approle authentication
* Supports Vault token authentication
   * additional auth types can be supported by authenticating outside of this package and using the token
* Supports Vault GCP secrets engine rolesets and static accounts
* Can store the generated key on the filesystem
   * Can be encrypted using GPG
   * Can be encrypted with a Vault transit engine
* Can store the generated key in a Vault KV store
* Can optionally create an orphan child token to generate the new GCP keys so the GCP key lifetime is not tied to the authentication token for the script
   * The key rotation process can have a short lifetime Vault token
   * The GCP key can have a much longer lease and doesn't expire when the Vault authentication token expires
* Can report on what is currently configured in the Vault GCP secrets engines
   * Rolesets
      * GCP account details
      * GCP permission bindings
   * Static accounts
   * Keys
   * key creation and expiry dates
* Supports taking snapshots before and after the rotation process runs if Raft integrated storage is the storage backend used on Vault
* Supports Vault namespaces
* Supports HTTP proxies
* Supports specifying a CA to trust Vault connections with a custom CA
* Supports specifying a client cert
* Supports Python logging



.. include:: modules.rst

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
