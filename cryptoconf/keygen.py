import pickle
from os import environ
from io import BytesIO
from base64 import b64encode, b64decode

from pyelliptic.ecc import ECC


DEFAULT_CURVE_TYPE = 'sect571r1'


class Keys(object):

	__slots__ = ("prod", "dev")

	def __init__(self, prod_privkey, prod_pubkey, dev_privkey, dev_pubkey):
		self.prod = ECC(curve=DEFAULT_CURVE_TYPE, privkey=prod_privkey, pubkey=prod_pubkey)
		self.dev = ECC(curve=DEFAULT_CURVE_TYPE, privkey=dev_privkey, pubkey=dev_pubkey)


def generate_keys():
	"""
	Create a randomly generated application key pair
	"""
	prodkey = ECC(curve=DEFAULT_CURVE_TYPE)
	devkey = ECC(curve=DEFAULT_CURVE_TYPE)
	priv_prod = prodkey.get_privkey()
	pub_prod = prodkey.get_pubkey()
	priv_dev = devkey.get_privkey()

	while priv_dev == priv_prod:
		devkey = ECC(curve=DEFAULT_CURVE_TYPE)
		priv_dev = devkey.get_privkey()
	pub_dev = devkey.get_pubkey()

	plen_pub_prod = pickle.dumps(len(pub_prod))

	prodkey = b64encode(
		pickle.dumps(len(priv_prod))
		+ plen_pub_prod
		+ pickle.dumps(0)
		+ priv_prod
		+ pub_prod
		+ pub_dev
	)
	devkey = b64encode(
		pickle.dumps(len(priv_prod))
		+ plen_pub_prod
		+ pickle.dumps(len(priv_dev))
		+ priv_prod
		+ pub_prod
		+ priv_dev
		+ pub_dev
	)
	return prodkey, devkey


def read_env_keys(pkey):
	keydata = BytesIO(b64decode(environ[pkey]))
	priv_prod = pickle.load(keydata)
	pub_prod = pickle.load(keydata)
	priv_dev = pickle.load(keydata)
	priv_prod = keydata.read(priv_prod)
	pub_prod = keydata.read(pub_prod)
	if priv_dev > 0:
		priv_dev = keydata.read(priv_dev)
	else:
		priv_dev = None
	return Keys(priv_prod, pub_prod, priv_dev, keydata.read())
