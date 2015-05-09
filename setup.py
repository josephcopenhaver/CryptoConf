from setuptools import find_packages, setup

setup(
    name="CryptoConf",
    packages=find_packages(),
    entry_points = {
    	"console_scripts": [
    		"crypto-conf=cryptoconf.cli:main",
    	],
    },
)

