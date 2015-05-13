import sys
from threading import local, Lock
from io import BytesIO
from os import path

from cryptoconf.cryptofiles import decrypt_single
from cryptoconf.settings import settings


_g_file_store = None
_file_store_lock = Lock()

_threading = local()
_threading.file_store = None


def _fill_file_store():
	global _g_file_store

	fpath = sys.argv[0]
	pdir = path.dirname(fpath)
	pdir = path.abspath(pdir)
	pdir = path.normpath(pdir)

	for setting in settings(pdir):
		fpath = setting.raw_fpath
		if not path.isabs(fpath):
			path.join(pdir, fpath)
		fpath = path.abspath(fpath)
		fpath = path.normpath(fpath)
		assert _g_file_store.get(fpath, None) is None
		_g_file_store[fpath] = setting.pkey


def _init_threading():
	global _g_file_store

	with _file_store_lock:
		file_store = _threading.file_store
		if file_store is not None:
			return file_store
		if _g_file_store is not None:
			_threading.file_store = _g_file_store
			return _g_file_store
		_g_file_store = {}
		_threading.file_store = _g_file_store
		_fill_file_store()
		return _g_file_store


def get_file_contents(fpath):
	"""
	Read from a cryptographically secure config file
	returns bytes in the raw file
	"""
	abs_fpath = path.abspath(fpath)
	abs_fpath = path.normpath(abs_fpath)
	file_store = _threading.file_store
	if file_store is None:
		file_store = _init_threading()

	pkey = file_store.get(abs_fpath, None)
	
	if pkey is None:
		return None

	bytes_buffer = BytesIO()
	decrypt_single(pkey, abs_fpath, bytes_buffer)
	bytes_buffer.seek(0)

	return bytes_buffer.read()
