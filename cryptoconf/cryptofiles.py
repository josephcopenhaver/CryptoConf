import pickle
import shutil
from os import path, unlink

from pyelliptic.ecc import ECC

from cryptoconf.settings import settings
from cryptoconf.keygen import read_env_keys


CRYPT_EXTENSION = "cryptoconf"


def _crypto_fpath_pdir(fpath):
	if not path.isdir(fpath):
		fpath = path.dirname(fpath)
	return path.abspath(fpath)


def crypto_fpath(raw_fpath):
	return "{}.{}".format(raw_fpath, CRYPT_EXTENSION)


def _crypto_tempfpath(raw_fpath):
	return path.join(
		path.dirname(raw_fpath),
		".{}.tmp.{}".format(path.basename(raw_fpath), CRYPT_EXTENSION)
	)


def _before_bulk_crypt_verify(settings_fpath, force, encrypt_flag):
	pdir = _crypto_fpath_pdir(settings_fpath)

	if encrypt_flag:
		action = "encryption"
	else:
		action = "decryption"

	for setting in settings(settings_fpath):

		src_fpath = setting.raw_fpath
		del setting

		if not path.isabs(src_fpath):
			src_fpath = path.join(pdir, src_fpath)

		src_fpath = path.abspath(src_fpath)
		dst_fpath = crypto_fpath(src_fpath)
		dst_fpath = path.abspath(dst_fpath)

		if not encrypt_flag:
			src_fpath, dst_fpath = dst_fpath, src_fpath

		if (
			not path.isfile(src_fpath)
			and (not force or path.exists(src_fpath))
		):
			raise Exception("{} not possible, file does not exist: {}".format(
				action,
				src_fpath
			))

		try:
			with open(src_fpath, "rb"):
				pass
		except:
			raise Exception("{} not possible, cannot read from file: {}".format(
				action,
				src_fpath
			))

		if path.isfile(dst_fpath):
			test_action = "write to"
			if not force:
				raise Exception("{} not possible, file already exists {}\n\nPlease backup the file's contents and use the -f (force) option".format(
					action,
					dst_fpath
				))
		else:
			test_action = "create"
		try:
			with open(dst_fpath, "a"):
				pass
		except:
			raise Exception("{} not possible, cannot {} file: {}".format(
				action,
				test_action,
				dst_fpath
			))

	return pdir


def encrypt(settings_fpath, force, preserve_src):
	"""
	"""
	pdir = _before_bulk_crypt_verify(settings_fpath, force, True)

	last_pkey = None

	for setting in settings(settings_fpath):
		raw_fpath = setting.raw_fpath

		if not path.isabs(raw_fpath):
			raw_fpath = path.join(pdir, raw_fpath)

		if force and not path.exists(raw_fpath):
			continue

		if setting.pkey != last_pkey:
			last_pkey = setting.pkey
			ckeys = read_env_keys(last_pkey)

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
		if preserve_src:
			continue
		unlink(raw_fpath)


def decrypt_single(ckeys, raw_fpath, wh):
	cfpath = crypto_fpath(raw_fpath)
	with open(cfpath, "rb") as rh:
		size = pickle.load(rh)
		raw = ckeys.prod.decrypt(rh.read(size))
		wh.write(raw)
		signature = rh.read()
	ckeys.dev.verify(signature, raw)
	return cfpath


def decrypt(settings_fpath, force, preserve_src):
	"""
	"""
	pdir = _before_bulk_crypt_verify(settings_fpath, force, False)

	last_pkey = None

	for setting in settings(settings_fpath):
		raw_fpath = setting.raw_fpath

		if not path.isabs(raw_fpath):
			raw_fpath = path.join(pdir, raw_fpath)

		if force and not path.exists(crypto_fpath(raw_fpath)):
			continue

		if setting.pkey != last_pkey:
			last_pkey = setting.pkey
			ckeys = read_env_keys(last_pkey)

		del setting

		tmpfpath = _crypto_tempfpath(raw_fpath)
		try:
			with open(tmpfpath, "wb") as wh:
				cfpath = decrypt_single(ckeys, raw_fpath, wh)
			shutil.move(tmpfpath, raw_fpath)
		except:
			if path.isfile(tmpfpath):
				unlink(tmpfpath)
			raise
		if preserve_src:
			continue
		unlink(cfpath)


def delete_files(settings_fpath, target_raw_files):
	pdir = _crypto_fpath_pdir(settings_fpath)
	for setting in settings(settings_fpath):
		fpath = setting.raw_fpath
		del setting
		if not path.isabs(fpath):
			fpath = path.join(pdir, fpath)
		if not target_raw_files:
			fpath = crypto_fpath(fpath)
		if not path.exists(fpath):
			continue
		unlink(fpath)

