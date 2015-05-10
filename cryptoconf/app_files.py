from threading import local, Lock
from io import BytesIO
from os import path

from cryptoconf.cryptofiles import decrypt_single
from cryptoconf.settings import Settings


_g_file_store = None
_file_store_lock = Lock()

_threading = local()
_threading.file_store = None


def _fill_file_store():
	global _g_file_store

	settings = Settings()
	for setting in settings:
		fpath = path.abspath(setting.raw_fpath)
		assert _g_file_store.get(fpath, None) is None
		_g_file_store[fpath] = setting.pkey


def _init_threading():
	global _g_file_store

	with _file_store_lock:
		if _g_file_store is not None:
			_threading.file_store = _g_file_store
			return _g_file_store
		_g_file_store = {}
		_fill_file_store()
		return _g_file_store


def get_file_contents(fpath):
	abs_fpath = path.abspath(fpath)
	file_store = _threading.file_store
	if file_store is None:
		file_store = _init_threading()

	pkey = file_store.get(abs_fpath, None)
	
	if pkey is None:
		return None

	file_io_bytes = BytesIO()
	decrypt_single(pkey, abs_fpath, file_io_bytes)
	file_io_bytes.seek(0)

	return file_io_bytes
