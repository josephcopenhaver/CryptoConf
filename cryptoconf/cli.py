from argparse import ArgumentParser
from os import path

from cryptoconf.keygen import generate_keys, read_env_keys
from cryptoconf.cryptofiles import encrypt, decrypt, delete_files


def create_keys():
	prodkey, devkey = generate_keys()
	print("\n\nPROD KEY:\n{}\n\nDEV  KEY:\n{}\n\n".format(
		prodkey.decode(),
		devkey.decode()
	))


def main():
	parser = ArgumentParser(
		prog="crypto-conf",
		description=""
		"Creates configuration files which can be read on production systems, "
		"but only written on dev systems"
	)
	parser.add_argument(
		"cmd",
		choices=("create-keys", "encrypt", "decrypt", "delete-raw", "delete-sec"),
		default="create-keys",
		help=""
		"create-keys: create dev/prod key pairs\n"
		"encrypt: obsfucate raw config files\n"
		"decrypt: recreate raw config files"
	)
	parser.add_argument(
		"target",
		nargs="?",
		default=".",
		help="directory path containing main .cryptoconf file or file path of a .cryptoconf file"
	)
	parser.add_argument(
		'-f',
		action='store_true',
		default=False,
		help="overwrite existing destination files for an encryption/decryption action"
	)
	parser.add_argument(
		'-p',
		action='store_true',
		default=False,
		help="preserve raw files when encrypting; or secured files when decrypting"
	)
	args = parser.parse_args()
	cmd = args.cmd
	if cmd == "create-keys":
		create_keys()
	else:
		target = args.target
		force = args.f
		preserve_src = args.p
		if not path.isfile(target) and not path.isdir(target):
			raise Exception("Not a file or directory: {}".format(target))
		if cmd == "encrypt":
			encrypt(target, force, preserve_src)
		elif cmd == "decrypt":
			decrypt(target, force, preserve_src)
		elif cmd == "delete-raw":
			delete_files(target, True)
		elif cmd == "delete-sec":
			delete_files(target, False)


if __name__ == "__main__":
	main()

