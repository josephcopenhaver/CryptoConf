from os import path
from yaml import load
from enum import Enum


DEFAULT_SETTINGS_FNAME = ".cryptoconf"


class DevPolicy(Enum):
	NONE = 0
	PREFER_RAW = 1
	ENCRYPTED_ONLY = 2


def _str_to_policy(pstr):
	if pstr is None:
		return DevPolicy.NONE
	return DevPolicy[pstr.upper()]


class Setting():
	__slots__ = (
		"raw_fpath",
		"pkey",
		"dev_policy",
	)

	def __init__(self, pkey, raw_fpath, dev_policy):
		self.pkey = pkey
		self.raw_fpath = raw_fpath
		self.dev_policy = dev_policy


def settings(fpath):
	"""
	iterator/provider of various Setting objects
	"""
	if path.isdir(fpath):
		fpath = path.join(fpath, DEFAULT_SETTINGS_FNAME)
	with open(fpath, "r") as ch:
		for confgroup in load(ch):
			pkey = confgroup["env_pkey"]
			dev_policy = confgroup.get("dev_policy", None)
			dev_policy = _str_to_policy(dev_policy)
			for raw in confgroup["raw_files"]:
				yield Setting(pkey, raw, dev_policy)
