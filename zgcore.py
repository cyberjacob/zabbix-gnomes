#!/usr/bin/env python2.7
#
# import needed modules.
# pyzabbix is needed, see https://github.com/lukecyca/pyzabbix
#
import argparse
import ConfigParser
import os
import os.path
import distutils.util
import traceback
import logging
import sys
import cmd
import urlparse
from getpass import getpass
from pyzabbix import ZabbixAPI


def setup():
	global username
	global password
	global api
	global noverify
	logging.debug('Loading global variables')
	username = None
	password = None
	api = None
	noverify = None
	
	try:
		defconf = os.getenv("HOME") + "/.zbx.conf"
	except:
		defconf = None
	if not defconf:
		logging.warning('Could not set default config file path. Is $HOME set?')

	cfg=zgconfig(defconf)


class zgconfig:
	#
	# This class will load settings from a config file
	#

	def __init__(self, cfgfile):

		#
		# define a helper function to load individual settings from config sections
		#
		def loadsetting(section, setting):
			try:
				result = settings.get(section, setting)
				if result:
					if setting == "password":
						logging.debug(" - [%s] Found password", section)
					else:
						logging.debug(" - [%s] Found %s \"%s\"",section, setting, result)
					return result
			except:
				return None
	
	
		# First define empty settings...
		self.username=None
		self.password=None
		self.api=None
		self.noverify=None
	

		# ...Then try to override them from the specified config file.
		logging.debug("Trying to access config file \"%s\"", cfgfile)
		if os.path.isfile(cfgfile) and os.access(cfgfile, os.R_OK):
			logging.debug("Loading config from \"%s\"", cfgfile)
 			settings=ConfigParser.ConfigParser()
			settings.read(cfgfile)
		
			self.username=loadsetting('Zabbix API','username')
			self.password=loadsetting('Zabbix API','password')
			self.api=loadsetting('Zabbix API','api')
			self.noverify=loadsetting('Zabbix API','no_verify')
		
			logging.info("Config file \"%s\" is loaded", cfgfile)
		else:
			logging.info("Config file \"%s\" is not loadable", cfgfile)
		return





def verifyconfig():
#                                        apiurl=urlparse.urlsplit(settings.get('Zabbix API','api'))
#                                        if (apiurl.scheme == "http") or (apiurl.scheme == "https"):
#                                                self.api=apiurl.geturl()
#                                                logging.debug(" - Found Zabbix API URL: \"%s\"", self.api)
#                                except:
#                                        self.api=None
#
#                                try:
#                                        self.noverify=bool(distutils.util.strtobool(settings.get('Zabbix API','no_verify')))
#                                        if self.noverify:
#                                                logging.debug(" - Found \"no_verify\" setting (%s)", str(self.noverify))
#
#
#
	return	

def apilogin():
	return

def main(argv=None):
	if argv is None:
		argv = sys.argv
	logging.basicConfig(format='%(levelname)s: %(message)s',level=logging.DEBUG)
	setup()



if __name__ == "__main__":
	sys.exit(main())
