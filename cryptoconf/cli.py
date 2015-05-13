from argparse import ArgumentParser
from os import path

from cryptoconf.keygen import generate_keys, read_env_keys
from cryptoconf.cryptofiles import encrypt, decrypt


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
		choices=("create-keys", "encrypt", "decrypt"),
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
	args = parser.parse_args()
	cmd = args.cmd
	if cmd == "create-keys":
		create_keys()
	else:
		target = args.target
		if not path.isfile(target) and not path.isdir(target):
			raise Exception("Not a file or directory: {}".format(target))
		if cmd == "encrypt":
			encrypt(target)
		elif cmd == "decrypt":
			decrypt(target)


if __name__ == "__main__":
	main()

