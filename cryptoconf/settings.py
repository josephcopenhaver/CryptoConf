from os import path
from yaml import load


DEFAULT_SETTINGS_FNAME = ".cryptoconf"


class Setting():
	__slots__ = (
		"raw_fpath",
		"pkey",
	)

	def __init__(self, pkey, raw_fpath):
		self.pkey = pkey
		self.raw_fpath = raw_fpath


def settings(fpath):
	"""
	iterator/provider of various Setting objects
	"""
	if path.isdir(fpath):
		fpath = path.join(fpath, DEFAULT_SETTINGS_FNAME)
	with open(fpath, "r") as ch:
		for confgroup in load(ch):
			pkey = confgroup["env_pkey"]
			for raw in confgroup["raw_files"]:
				yield Setting(pkey, raw)
