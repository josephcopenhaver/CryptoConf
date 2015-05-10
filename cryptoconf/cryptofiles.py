import pickle
import shutil
from os import path, unlink

from pyelliptic.ecc import ECC

from cryptoconf.settings import Settings
from cryptoconf.keygen import read_env_keys


CRYPT_EXTENSION = "cryptoconf"


def crypto_fpath(raw_fpath):
	return "{}.{}".format(raw_fpath, CRYPT_EXTENSION)


def crypto_tempfpath(raw_fpath):
	return path.join(
		path.dirname(raw_fpath),
		".{}.tmp.{}".format(path.basename(raw_fpath), CRYPT_EXTENSION)
	)


def encrypt(settings_fpath=None):
	"""
	"""
	for setting in Settings(settings_fpath):
		raw_fpath = setting.raw_fpath

		ckeys = read_env_keys(setting.pkey)
		del setting

		with open(raw_fpath, "rb") as rh:
			raw = rh.read()
			signature = ckeys.dev.sign(raw)
			with open(crypto_fpath(raw_fpath), "wb") as wh:
				cdata = ECC.encrypt(raw, ckeys.prod.get_pubkey())
				pickle.dump(len(cdata), wh, pickle.HIGHEST_PROTOCOL)
				wh.flush()
				wh.write(cdata)
				wh.write(signature)


def read_to(ckeys, raw_fpath, wh):
	with open(crypto_fpath(raw_fpath), "rb") as rh:
		size = pickle.load(rh)
		raw = ckeys.prod.decrypt(rh.read(size))
		wh.write(raw)
		signature = rh.read()
		return raw, signature


def decrypt_single(env_pkey, raw_fpath, fp_out=None):
	ckeys = read_env_keys(env_pkey)
	if fp_out is not None:
		tmpfpath = None
	else:
		tmpfpath = crypto_tempfpath(raw_fpath)

	try:
		if tmpfpath is not None:
			with open(tmpfpath, "wb") as wh:
				raw, signature = read_to(ckeys, raw_fpath, wh)
		else:
			raw, signature = read_to(ckeys, raw_fpath, fp_out)
			

		ckeys.dev.verify(signature, raw)
		if tmpfpath is not None:
			shutil.move(tmpfpath, raw_fpath)
	except:
		if tmpfpath is not None and path.isfile(tmpfpath):
			unlink(tmpfpath)
		raise


def decrypt(settings_fpath=None):
	"""
	"""
	for setting in Settings(settings_fpath):
		decrypt_single(setting.pkey, setting.raw_fpath)
