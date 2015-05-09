from argparse import ArgumentParser

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
		choices=("create_keys", "encrypt", "decrypt"),
		default="create_keys",
		help=""
		"create_keys: create dev/prod key pairs\n"
		"encrypt: obsfucate raw config files\n"
		"decrypt: recreate raw config files"
	)
	args = parser.parse_args()
	cmd = args.cmd
	if cmd == "create_keys":
		create_keys()
	elif cmd == "encrypt":
		encrypt()
	elif cmd == "decrypt":
		decrypt()


if __name__ == "__main__":
	main()

