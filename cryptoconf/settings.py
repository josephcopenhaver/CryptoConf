from yaml import load


DEFAULT_SETTINGS_FPATH = "./.cryptoconf"


class Setting():
	__slots__ = (
		"raw_fpath",
		"pkey",
	)

	def __init__(self, pkey, raw_fpath):
		self.pkey = pkey
		self.raw_fpath = raw_fpath


class Settings():

	__slots__ = (
		"_yaml",
	)

	def __init__(self, fpath=None):
		if fpath is None:
			fpath = DEFAULT_SETTINGS_FPATH
		with open(fpath, "r") as ch:
			self._yaml = load(ch)

	def __iter__(self):
		yaml = self._yaml
		if yaml is None:
			return
		self._yaml = None
		for confgroup in yaml:
			pkey = confgroup["env_pkey"]
			for raw in confgroup["raw_files"]:
				yield Setting(pkey, raw)
