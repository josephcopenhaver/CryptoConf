from argparse import ArgumentParser
from os import environ, path, unlink
from io import BytesIO
import pickle
import shutil
from yaml import load
from pyelliptic.ecc import ECC
from base64 import b64encode, b64decode


DEFAULT_CURVE_TYPE = 'sect571r1'


class Keys(object):

	__slots__ = ("prod", "dev")

	def __init__(self, prod_privkey, prod_pubkey, dev_privkey, dev_pubkey):
		self.prod = ECC(curve=DEFAULT_CURVE_TYPE, privkey=prod_privkey, pubkey=prod_pubkey)
		self.dev = ECC(curve=DEFAULT_CURVE_TYPE, privkey=dev_privkey, pubkey=dev_pubkey)


def crypto_fpath(raw_fpath):
	return "{}.cryptoconf".format(raw_fpath)


def crypto_tempfpath(raw_fpath):
	fpath = "{}.tmp.cryptoconf".format(raw_fpath)
	return path.join(
		path.dirname(fpath),
		".{}".format(path.basename(fpath))
	)


def getkeys(pkey):
	keydata = BytesIO(b64decode(environ[pkey]))
	priv_prod = pickle.load(keydata)
	pub_prod = pickle.load(keydata)
	priv_dev = pickle.load(keydata)
	priv_prod = keydata.read(priv_prod)
	if pub_prod > 0:
		pub_prod = keydata.read(pub_prod)
	else:
		pub_prod = None
	if priv_dev > 0:
		priv_dev = keydata.read(priv_dev)
	else:
		priv_dev = None
	return Keys(priv_prod, pub_prod, priv_dev, keydata.read())


def genkeys():
	"""
	Create a randomly generated application key pair
	"""
	prodkey = ECC(curve=DEFAULT_CURVE_TYPE)
	devkey = ECC(curve=DEFAULT_CURVE_TYPE)
	priv_prod = prodkey.get_privkey()
	pub_prod = prodkey.get_pubkey()
	plen_pub_prod = pickle.dumps(len(pub_prod))
	priv_dev = devkey.get_privkey()
	while priv_dev == priv_prod:
		devkey = ECC(curve=DEFAULT_CURVE_TYPE)
		priv_dev = devkey.get_privkey()
	pub_dev = devkey.get_pubkey()
	print("\n\nPROD KEY:\n{}\n\nDEV  KEY:\n{}\n\n".format(
		b64encode(
			pickle.dumps(len(priv_prod))
			+ plen_pub_prod
			+ pickle.dumps(0)
			+ priv_prod
			+ pub_prod
			+ pub_dev
		).decode(),
		b64encode(
			pickle.dumps(len(priv_prod))
			+ plen_pub_prod
			+ pickle.dumps(len(priv_dev))
			+ priv_prod
			+ pub_prod
			+ priv_dev
			+ pub_dev
		).decode(),
	))


def encrypt():
	"""
	"""
	with open("./.cryptoconf", "r") as ch:
		settings = load(ch)
		raw_fpath = settings["raw"]
		pkey = settings["env_pkey"]
		del settings

	ckeys = getkeys(pkey)
	del pkey

	with open(raw_fpath, "rb") as rh:
		raw = rh.read()
		signature = ckeys.dev.sign(raw)
		with open(crypto_fpath(raw_fpath), "wb") as wh:
			cdata = ECC.encrypt(raw, ckeys.prod.get_pubkey())
			pickle.dump(len(cdata), wh, pickle.HIGHEST_PROTOCOL)
			wh.flush()
			wh.write(cdata)
			wh.write(signature)



def decrypt():
	"""
	"""
	with open("./.cryptoconf", "r") as ch:
		settings = load(ch)
		raw_fpath = settings["raw"]
		pkey = settings["env_pkey"]
		del settings

	ckeys = getkeys(pkey)
	del pkey
	tmpfpath = crypto_tempfpath(raw_fpath)

	try:
		with open(tmpfpath, "wb") as wh:
			with open(crypto_fpath(raw_fpath), "rb") as rh:
				size = pickle.load(rh)
				raw = ckeys.prod.decrypt(rh.read(size))
				wh.write(raw)
				signature = rh.read()

		ckeys.dev.verify(signature, raw)
	except:
		if path.isfile(tmpfpath):
			unlink(tmpfpath)
		raise
	del ckeys
	del raw

	shutil.move(tmpfpath, raw_fpath)


def main():
	parser = ArgumentParser(
		prog="crypto-conf",
		description=""
		"Creates configuration files which can be read on production systems, "
		"but only written on dev systems"
	)
	parser.add_argument(
		"cmd",
		choices=("genkeys", "encrypt", "decrypt"),
		default="genkeys",
		help=""
		"genkeys: create dev/prod key pairs\n"
		"encrypt: obsfucate raw config files\n"
		"decrypt: recreate raw config files"
	)
	args = parser.parse_args()
	cmd = args.cmd
	if cmd == "genkeys":
		genkeys()
	elif cmd == "encrypt":
		encrypt()
	elif cmd == "decrypt":
		decrypt()


if __name__ == "__main__":
	main()

