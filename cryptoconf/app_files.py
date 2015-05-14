import sys
from threading import local, Lock
from io import BytesIO
from os import path

from cryptoconf.cryptofiles import decrypt_single
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
				path.join(pdir, fpath)
			fpath = path.abspath(fpath)
			fpath = path.normpath(fpath)
			assert file_store.get(fpath, None) is None
			file_store[fpath] = setting.pkey
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

	pkey = file_store.get(fpath, None)
	
	if pkey is None:
		return None

	bytes_buffer = BytesIO()
	decrypt_single(pkey, fpath, bytes_buffer)
	bytes_buffer.seek(0)

	return bytes_buffer.read()
