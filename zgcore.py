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
	logging.debug('Preloading global variables')
	username = None
	password = None
	api = None
	noverify = None

	
	### Load command args here first! ###
	### If CFG is specified, load it here...else use default config
	
	try:
		defconf = os.getenv("HOME") + "/.zbx.conf"
	except:
		defconf = None
	if not defconf:
		logging.warning('Could not set default config file path. Is $HOME set?')

	cfg=zgconfig(defconf)

	### CMD args should override config file settings ###

	logging.debug("Verifying configured settings:")
	
	verifyconfig("username", cfg.username)
	verifyconfig("password", cfg.password)
	verifyconfig("api", cfg.api)
	verifyconfig("noverify", cfg.noverify)
	verifyconfig("patat", "mayo")
	
	


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
						logging.debug(" - [%s] Found %s", section, setting)
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
		self.delimiter=None
		self.enclose=None	

		# ...Then try to override them from the specified config file.
		logging.debug("Trying to access config file \"%s\"", cfgfile)
		try:
			if os.path.isfile(cfgfile) and os.access(cfgfile, os.R_OK):
				logging.debug("Loading config from \"%s\"", cfgfile)
 				settings=ConfigParser.ConfigParser()
				settings.read(cfgfile)
			
				self.username=loadsetting('Zabbix API','username')
				self.password=loadsetting('Zabbix API','password')
				self.api=loadsetting('Zabbix API','api')
				self.noverify=loadsetting('Zabbix API','no_verify')

				self.delimiter=loadsetting('Output','delimiter')
				self.enclose=loadsetting('Output','enclose')
		
				logging.info("Loaded config file \"%s\"", cfgfile)
			else:
				logging.info("Could not load config file \"%s\"", cfgfile)
		
		except:
			logging.info("Could not load config file \"%s\"", cfgfile)
		return
		




def verifyconfig(setting, var):
	def returntrue():	
		logging.debug(" - \"%s\" is valid", setting)
		return True

	def returnfalse(reason):
		logging.debug(" - \"%s\" is %s", setting, reason)
		return False

	# Test input for validity. 	
	if (setting == "username") or (setting == "password") or (setting == "api") or (setting == "noverify") :
		if (setting == "username"):
			try:
				if (len(var)>0) and (len(var)<65):
					returntrue()
				else:
					returnfalse("invalid")
			except:
				returnfalse("invalid")
		elif (setting == "password"):
			try:
				if (len(var)>0):
					returntrue()
				else:
					returnfalse("invalid")
			except:
				returnfalse("invalid")
		elif (setting == "api"):
			try:
				apiurl=urlparse.urlsplit(var)
				if (apiurl.scheme == "http") or (apiurl.scheme == "https"):
					returntrue()
				else:
					returnfalse("invalid")
			except:
				returnfalse("invalid")
		elif (setting == "noverify"):
			try:
				if bool(distutils.util.strtobool(var)):
					returntrue()
				else:
					returnfalse("invalid")
			except:
				returnfalse("invalid")
		else:
			# The var is not valid.
			returnfalse("invalid")
	else:
		# The var is unknown.
		returnfalse("unknown")
		


def apilogin():
	return

def main(argv=None):
	if argv is None:
		argv = sys.argv
	logging.basicConfig(format='%(levelname)s: %(message)s',level=logging.DEBUG)
	setup()



if __name__ == "__main__":
	sys.exit(main())
