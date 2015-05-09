from yaml import load


DEFAULT_SETTINGS_FPATH = "./.cryptoconf"


class Settings():

	__slots__ = (
		"raw_fpath",
		"pkey",
	)

	def __init__(self, fpath=None):
		if fpath is None:
			fpath = DEFAULT_SETTINGS_FPATH
		with open(fpath, "r") as ch:
			settings = load(ch)
			self.raw_fpath = settings["raw"]
			self.pkey = settings["env_pkey"]
