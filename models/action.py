from core.models import action, webui
from core import auth, helpers

from plugins.sslscan.models import sslscan
from plugins.sslscan.models.includes import sslHelper
#SSL Scan
from time import sleep
from collections import defaultdict
import logging
import requests
import json
import sys
import datetime
import validators

import re
import subprocess
import socket
import time
import os 


'''
Added incase the installation does not have remote installed additional func wont work
'''
CAN_IMPORT_REMOTE=True
try:
	from plugins.remote.includes import helpers as remoteHelpers
except ImportError as e:
	print("Please install the remote plugin")
	CAN_IMPORT_REMOTE=False


class SSLException(Exception):
	pass

class _sslscan(action._action):
	class _properties(webui._properties):
		def generate(self,classObject):
			formData = []
			formData.append({"type" : "input", "schemaitem" : "name", "textbox" : classObject.name})
			formData.append({"type" : "input", "schemaitem" : "scanHost", "textbox" : classObject.scanHost})
			formData.append({"type" : "input", "schemaitem" : "webServer_port", "textbox" : classObject.webServer_port})
			formData.append({"type" : "checkbox", "schemaitem" : "scanCache", "checked" : classObject.scanCache,"tooltip" : "Use previous results; turning off scans host again"})
			formData.append({"type" : "checkbox", "schemaitem" : "scan_publish", "checked" : classObject.scan_publish,"tooltip" : "Scan results will be published on SSL Labs - default is off"})	
			formData.append({"type" : "checkbox", "schemaitem" : "scan_ignoreMismatch", "checked" : classObject.scan_ignoreMismatch,"tooltip" : "Scan if hostname does not match cert (recommend to put on)"})	
			formData.append({"type" : "checkbox", "schemaitem" : "useProxy", "checked" : classObject.useProxy,"tooltip" : "Use a proxy configuration supplied below"})	
			formData.append({"type" : "input", "schemaitem" : "proxyConf", "textbox" : classObject.proxyConf})
			formData.append({"type" : "checkbox", "schemaitem" : "runRemote", "checked" : classObject.runRemote,"tooltip" : "Query API using external host (requires remote plugin"})
			formData.append({"type" : "checkbox", "schemaitem" : "enabled", "checked" : classObject.enabled })
			return formData
			
	scanHost 			= str()
	scan_publish 		= bool()			#supports on /off - have results stored on ssllabs
	scan_ignoreMismatch = bool() 	#supports on /off - continues if cert does not match host name
	webServer_port 		= int()			#Webserver port

	scanCache 			= bool()	#supports on /off - used recently cached results

	useProxy			= bool()
	proxyConf			= str()
	runRemote			= bool()
	enabled				= bool()

	def isValidDomain(self,observable):
		if validators.domain(observable):
			return True
		else:
			return False

	# # # # # # # # # # # # # #
	# 	Qeury API
	# # # # # # # # # # # # # #  
	# Loops until scan complete
	def run(self,data,persistentData,actionResult):


		host 			= helpers.evalString(self.scanHost,{"data" : data})
		# port			= helpers.evalString(self.webServer_port,{"data" : data})

		if host != "":
			if not self.isValidDomain(host):			
				actionResult["result"] 	= False
				actionResult["rc"]		= 400
				actionResult["data"]["message"]	= "Please supply a valid domain"
				return actionResult				

			scanResults = sslscan._sslscan().query(query={ "scanHost" : self.scanHost })["results"]

			# In the case you perform a query and it resturns an empty list 
			if not scanResults:
				sslscan._sslscan().new(self.scanHost)


			if self.scan_publish == True:
				publish = "on"
			else:
				publish = "off"

			if self.scan_ignoreMismatch == True:
				ignoreMismatch = "on"
			else:
				ignoreMismatch = "off"
			
			if self.scanCache == True:
				scan_cache = "on"
			else:
				scan_cache = "off"
			

			proxy = {"http": "http://", "https": "http://"}			
			
			if self.useProxy == True:
				sslLabsClient    =  sslHelper._sslassist(host,proxy)			
			else:
				sslLabsClient    =  sslHelper._sslassist(host)			
		
			if self.runRemote == True:
				#If persistent data found
				if "remote" in persistentData:
					#If Remote module can be imported
					if CAN_IMPORT_REMOTE:		
						while True:
							try:
								remote = remoteHelpers.runRemoteFunction(True,persistentData,sslHelper.runIPfunction,{"host" : host, "publish": publish,"ignoreMismatch": ignoreMismatch,"scan_cache": scan_cache },elevate=False)						
								_blob = remote["response"]
								if remote["statusCode"] == 200:
									if _blob["status"] == "DNS":
										print("DNS") 
										sleep(10)
										continue

									elif _blob["status"] == "IN_PROGRESS":
										print("IN PRO") 			
										sleep(10)
										continue

									elif _blob["status"] == "READY":
										break

									elif _blob["status"] == "ERROR":
										break
								# if statuscode not 200 (err has ouccred prevent null keys from erroring)
								else:
									actionResult["result"] 	= False
									actionResult["rc"]		= -1
									actionResult["data"]["message"]	= "ERROR connecting to API please investigate"									
							except SSLException as msg:

								actionResult["result"] 	= False
								actionResult["rc"]		= -1
								actionResult["data"]["message"] = msg	
						# response = remote["response"]["status"]
				else:
					actionResult["result"] 	= False
					actionResult["rc"]		= -1
					actionResult["data"]["message"]	= "Remote Config supplied, client data not found exiting"
					return actionResult
			# 
			# Scan Locally
			# 
			else:
				while True:
					try:
						_blob 		= sslLabsClient.apiCall(publish=publish,ignoreMismatch=ignoreMismatch,scan_cache=scan_cache,all="on")

						if _blob["status"] == "DNS":
							print("DNS") 
							sleep(10)
							continue

						elif _blob["status"] == "IN_PROGRESS":
							print("IN PRO") 			
							sleep(10)
							continue

						elif _blob["status"] == "READY":
							break

						elif _blob["status"] == "ERROR":
							break
					except Exception as msg:

						actionResult["result"] 	= False
						actionResult["rc"]		= -1
						actionResult["data"]["message"] = msg	


			# # # # # # # # # # # # # #
			# # Parse Cert Info
			# # # # # # # # # # # # # #
			ipAddress 	= _blob["endpoints"][0]["ipAddress"]
			ssl_grade	= _blob["endpoints"][0]["grade"]
			tls_ciphers = sslLabsClient.get_cipher_suites(_blob["endpoints"][0]["details"]["suites"])
			cert_info 	= sslLabsClient.get_cert(_blob)
			
			vulns 		= sslLabsClient.get_vulns(_blob["endpoints"][0]["details"])			
			try:
				server_sig 	= _blob["endpoints"][0]["details"]["serverSignature"]
			except KeyError as e:
				server_sig 	= "Server sig not found"			

			sslscan._sslscan().api_update(query={ "scanHost" : f"{self.scanHost}" },update={ "$set" : { "supportedTLSCiphers" : tls_ciphers, "cert_info": cert_info, "vulnerableCiphers": vulns, "SSL_grade": f"{ssl_grade}", "ipAddress" : f"{ipAddress}", "serverSignature": f"{server_sig}" } })


			actionResult["data"]["ipAddress"]					= ipAddress
			actionResult["data"]["serverSignature"]				= server_sig
			actionResult["data"]["serverScore"]	 				= ssl_grade
			actionResult["data"]["supportedTLSCiphers"]			= tls_ciphers
			actionResult["data"]["certificateInfo"]				= cert_info
			actionResult["data"]["vulnerabilityResults"]		= vulns


			actionResult["result"] 								= True
			actionResult["rc"]									= 200
			actionResult["data"]["message"]						= "Host was successfully scanned"			


			# #**** look for the header where the response code is 200 not 302 ****
			# headers = _blob["endpoints"][0]["details"]["httpTransactions"] #, responseHeadersRaw			

		else:
			actionResult["result"] 	= False
			actionResult["rc"]		= -1
			actionResult["data"]["message"]	= "Please specify a host to scan"


		return actionResult


