# CryptoConf
Support library for cryptographically storing files in source control

## Features
1. Verified encryption content using hmac signatures and [Elliptic Curve Cryptography](https://en.wikipedia.org/wiki/Elliptic_curve_cryptography)
2. Create symmetric private and public keys for production ( read only ) and development ( read and write ) use
3. integrate reading of encrypted file contents directly with a python app
4. supports multiple secrets in a .cryptoconf manifest
5. easy cli integration for updating content

## Installation
```
$ # I use virtualenvwrapper
$ mkvirtualenv cryptoconf --python=`which python3`
(cryptoconf)$ pip install -r requirements.txt -e .
```

## Configuration
1. Create a `.cryptoconf` file for your project ( [its content is yaml](https://raw.githubusercontent.com/josephcopenhaver/CryptoConf/master/sample.cryptoconf) )
2. list the files you wish to secure under the `raw_files` attribute using either relative or absolute paths
3. [optional] set an application development policy for these files using the `dev_policy` attribute (e.g. `PREFER_RAW`)
 
 > (default) NONE: prefer encrypted, use raw only if ecrypted does not exist
 
 > PREFER_RAW: prefer raw, use encrypted only if raw does not exist
 
 > ENCRYPTED_ONLY: scrictest setting, raw files never utilized
 
4. Choose a name for the secret key you wish to store in your environment using the `env_pkey` attribute (e.g. `MY_SECRET_ENV_KEY`)
5. Generate your dev and prod keys using `crypto-conf create-keys`
6. Store the keys used in step 5 someplace trusted
7. Update the environment settings in your production and dev boxes to have `MY_SECRET_ENV_KEY=<DEV_OR_PROD_KEY>`
8. before you push to git, run `crypto-conf encrypt` to create `.cryptoconf` files that can be securely published. This will also remove the original raw files if and only if all files are encrypted properly

## Usage
```
(cryptoconf)$ crypto-conf --help
usage: crypto-conf [-h] [-f] [-p]
                   {create-keys,encrypt,decrypt,delete-raw,delete-sec}
                   [target]

Creates configuration files which can be read on production systems, but only
written on dev systems

positional arguments:
  {create-keys,encrypt,decrypt,delete-raw,delete-sec}
                        create-keys: create dev/prod key pairs encrypt:
                        obsfucate raw config files decrypt: recreate raw
                        config files
  target                directory path containing main .cryptoconf file or
                        file path of a .cryptoconf file

optional arguments:
  -h, --help            show this help message and exit
  -f                    ignore previously existing destination files or
                        missing source files for an encryption/decryption
                        action
  -p                    preserve raw files when encrypting; or secured files
                        when decrypting
(cryptoconf)$
```