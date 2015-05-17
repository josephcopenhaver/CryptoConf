import sys
from threading import local, Lock
from io import BytesIO
from os import path

from cryptoconf.cryptofiles import read_env_keys, crypto_fpath, decrypt_single
from cryptoconf.settings import settings


_g_file_store = None
_g_pdir = None
_threading_lock = Lock()

_threading = local()
_threading.file_store = None
_threading.pdir = None


def _init_threading():
	global _g_file_store
	global _g_pdir

	if _g_file_store is not None and _g_pdir is not None:
		_threading.file_store = _g_file_store
		_threading.pdir = _g_pdir
		return _g_file_store, _g_pdir

	with _threading_lock:
		if _g_file_store is not None and _g_pdir is not None:
			_threading.file_store = _g_file_store
			_threading.pdir = _g_pdir
			return _g_file_store, _g_pdir
		file_store = {}
		pdir = sys.argv[0]
		pdir = path.dirname(pdir)
		pdir = path.abspath(pdir)
		pdir = path.normpath(pdir)

		for setting in settings(pdir):
			fpath = setting.raw_fpath
			if not path.isabs(fpath):
				fpath = path.join(pdir, fpath)
			fpath = path.abspath(fpath)
			fpath = path.normpath(fpath)
			assert file_store.get(fpath, None) is None
			file_store[fpath] = (setting.pkey, setting.dev_policy)
			del fpath

		_g_file_store = file_store
		_g_pdir = pdir
		_threading.file_store = file_store
		_threading.pdir = pdir
		return file_store, pdir


def get_file_contents(fpath):
	"""
	Read from a cryptographically secure config file
	returns bytes in the raw file
	"""
	file_store = _threading.file_store
	pdir = _threading.pdir
	if file_store is None or pdir is None:
		file_store, pdir = _init_threading()
	if not path.isabs(fpath):
		fpath = path.join(pdir, fpath)
	fpath = path.abspath(fpath)
	fpath = path.normpath(fpath)

	pkey_devstrat = file_store.get(fpath, None)
	
	if pkey_devstrat is None:
		return None

	devstrat = pkey_devstrat[1]

	ckeys = read_env_keys(pkey_devstrat[0])

	del pkey_devstrat

	if (
		ckeys.can_create and
		(
			(devstrat == DevPolicy.PREFER_RAW and path.isfile(fpath))
			|| devstrat == DevPolicy.NONE and not path.isfile(crypto_fpath(fpath))
		)
	):
		with open(fpath, "rb") as fh:
			return fh.read()

	bytes_buffer = BytesIO()
	decrypt_single(ckeys, fpath, bytes_buffer)
	bytes_buffer.seek(0)

	return bytes_buffer.read()
