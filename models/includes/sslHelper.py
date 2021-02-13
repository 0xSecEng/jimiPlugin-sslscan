#SSL Scan
from time import sleep
from collections import defaultdict
import logging
import requests
import json
import sys
import datetime

def runIPfunction(functionInputDict):
    '''
        Function allows you to run the scan on a remote host
        useful in cases where there are outbound restrictions
    '''
    import requests

    host            = functionInputDict["host"]

    publish         = functionInputDict["publish"]
    ignoreMismatch  = functionInputDict["ignoreMismatch"]
    scan_cache      = functionInputDict["scan_cache"]
    #publish=publish,ignoreMismatch=ignoreMismatch,scan_cache=scan_cache,all="on"
    
    url           = f"https://api.ssllabs.com/api/v3/analyze?host={host}&publish={publish}&ignoreMismatch={ignoreMismatch}&scan_cache={scan_cache}&all=on"
    response      = requests.get(url, timeout=20) 
    _status_code  = response.status_code
    _blob         = response.json()

    if _status_code == 200:

        return {"url": url, "statusCode": _status_code, "response": _blob}
    else:
        return {"url": url, "statusCode": _status_code, "response": response}

class SSLException(Exception):
    pass

class _sslassist():

    api_url 	 = "https://api.ssllabs.com/api/v3/"       
    API_Endpoint = "api.ssllabs.com/api/v3"
    def __init__(self,host,proxy={ "http": None, "https": None}):
        self.host          = host
        self.proxies       = proxy




    def _handle_http_codes(self,response):
        '''
            # # # # # # #-# # # # # # #
            # Handle HTTP Status Codes
            # # # # # # #-# # # # # # #
        '''
        _status_code = response.status_code		

        if _status_code == 200:
            msg = f"API has returned: {response.status_code}"
            return _status_code, response
            
        if _status_code == 401:
            msg = (f"Token is not authorized to perform this function: {response.status_code}")
            return _status_code,msg

        if _status_code == 404:
            msg = (f"The resource was not found: {response.status_code}")
            return _status_code,msg

        if _status_code == 429:
            msg = (f"Too many requests have been sent to the service: {response.status_code}")
            return _status_code,msg


        if _status_code == 441:
            msg = (f"Incorrectly parsed request: {response.status_code}")
            return _status_code,msg

        if _status_code == 500:
            msg = (f"Internal Server Error: {response.status_code}")
            return _status_code,msg

        if _status_code == 503:
            msg = (f"Server Is unavailable at this time: {response.status_code}")
            return _status_code,msg
        if _status_code == 529:
            msg = (f"Server overloaded: {response.status_code}")
            return _status_code,msg        
        else:
            msg = "Unhandled Error Code"
            return _status_code,msg	


    def apiCall(self,**kwargs):
        params = ""
        for key,value in kwargs.items():
            params += f"&{key}={value}"
        
        # can also do __class__.DOMAIN
        url                         = f"https://{self.API_Endpoint}/analyze?host={self.host}{params}"

        if self.proxies["http"] != None:
            _status_code, response      = self._handle_http_codes(requests.get(url, timeout=20,proxies=self.proxies,verify=False)) #turned off verify Upart
        else:
            _status_code, response      = self._handle_http_codes(requests.get(url, timeout=20)) #turned off verify Upart

        _blob = response.json()

        if _status_code == 200:
            return _blob
        else:
            # will switch this to the action result which will be passed back to user
            REQException(response)

    # # # # # # # # # # # # # #
    # 	Cipher Suites
    # # # # # # # # # # # # # #  
    def get_cipher_suites(self,ciphers):
        '''
            Parses Codes into readable format / scraps data we're not interested in
        '''
        # Does not like fullstops so used underscores instead 
        tlsDict = { 768: "SSL3_0", 769: "1_0", 770: "1_1", 771: "1_2", 772: "1_3" }

        supported_ciphers =  defaultdict(list)

        for tls in ciphers:
            result = {}
            tlsV   = {}

            tls_version = tls["protocol"]


            for cipher in tls["list"]:
                cipher_name = cipher["name"]
                cipher_strength = cipher["cipherStrength"]
                
                try:
                    if cipher["q"] == "1":
                        cipher_status = "WEAK"
                    else:
                        cipher_status = "INSECURE"
                except KeyError:
                    cipher_status = "Unable to check"

                finding = {
                "Cipher Name": cipher_name,
                "Cipher Strength": cipher_strength,
                "Cipher Status": cipher_status 
                }

                # Maps the TLS name to human readble name listed in dict 
                # 
                supported_ciphers[tlsDict[tls_version]].append(finding)

        # Converted from collections dict as Jimi reports Key error? - Ask
        supported_ciphers = dict(supported_ciphers)
                
        # print(json.dumps(supported_ciphers, indent=3))
        return supported_ciphers

    # # # # # # # # # # # # # #
    # 		Vuln Info
    # # # # # # # # # # # # # #  
    def get_vulns(self,vulns):
        '''
            Get vulnerability Information associated with ssl
            parses to readable format
        '''
        #  some keys have 5 Options / so I've just captured the ones where host is vuln/not vuln - happy to update dict if required
        vuln_dict = { 
        "zombiePoodleVulnerable": { 1: "Not Vulnerable", 2: "Vulnerable", 3: "Vulnerable and Exploitable" },
        "sleepingPoodle": { 1: "Not Vulnerable", 10: "Vulnerable", 11: "Vulnerable and Exploitable" }, 
        "goldenDoodleVulnerable": { 1: "Not Vulnerable", 4: "Vulnerable", 5: "Vulnerable and Exploitable" },
        "openSSLLuckyMinus20": { 1: "Not Vulnerable",2: "Vulnerable and Insecure"},
        "openSslCcs": { 1: "Not Vulnerable", 2: "Possibly Vulnerable, Not Exploitable", 3:"Vulnerable and Exploitable" },
        "ticketbleed": { 1: "Not Vulnerable", 2: "Vulnerable and Insecure", 3: "Not Vulnerable; bug detected" },
        "zeroLengthPaddingOracle": { 1: "Not Vulnerable", 6: "Vulnerable", 7: "Vulnerable and Exploitable" },
        "bleichenbacher": { 1: "Not Vulnerable", 2: "Vulnerable (Weak Oracle)", 3: "Vulnerable (Strong Oracle)", 4: "Inconsistent Results" }
        }

        try:
            sleepingPoodle			= vuln_dict["zombiePoodleVulnerable"][vulns["sleepingPoodle"]]
            zombiePoodleVulnerable  = vuln_dict["zombiePoodleVulnerable"][vulns["zombiePoodle"]]
            goldenDoodleVulnerable 	= vuln_dict["goldenDoodleVulnerable"][vulns["goldenDoodle"]]
            openSSLLuckyMinus20  	= vuln_dict["openSSLLuckyMinus20"][vulns["openSSLLuckyMinus20"]]
            openSslCcs  			= vuln_dict["openSslCcs"][vulns["openSslCcs"]]
            ticketbleed  			= vuln_dict["ticketbleed"][vulns["ticketbleed"]]
            bleichenbacher  		= vuln_dict["bleichenbacher"][vulns["bleichenbacher"]]
            zeroLengthPaddingOracle = vuln_dict["bleichenbacher"][vulns["zeroLengthPaddingOracle"]]  

        # Captures the options I intentionally left out of the dictionary
        except KeyError:

            sleepingPoodle			= "Error Occured - Unable to scan"
            zombiePoodleVulnerable 	= "Error Occured - Unable to scan"
            goldenDoodleVulnerable 	= "Error Occured - Unable to scan"
            openSSLLuckyMinus20  	= "Error Occured - Unable to scan"
            openSslCcs  			= "Error Occured - Unable to scan"
            ticketbleed  			= "Error Occured - Unable to scan"
            bleichenbacher  		= "Error Occured - Unable to scan"
            zeroLengthPaddingOracle = "Error Occured - Unable to scan"

        finding = {
            "vulnDrown": vulns["drownVulnerable"],
            "vulnBeast": vulns["vulnBeast"],
            "vulnPoodle": vulns["poodle"],
            "vulnHeartBleed": vulns["heartbleed"],
            "vulnFreak": vulns["freak"], 
            "vulnLogJam": vulns["logjam"],
            "vulnSleepingPoodle": sleepingPoodle,
            "vulnZombiePoodle": zombiePoodleVulnerable,
            "vulnGoldenDoodle": goldenDoodleVulnerable,
            "vulnPpenSSLLuckyMinus20": openSSLLuckyMinus20,
            "vulnOpenSSLCcs": openSslCcs,
            "vulnTicketBleed": ticketbleed,
            "vulnBleichenbacher": bleichenbacher,
            "vulnZeroLengthPaddingOracle": zeroLengthPaddingOracle
        }

        # print(json.dumps(finding, indent=3))
        return finding

    # # # # # # # # # # # # # #
    # 	Certificate Info
    # # # # # # # # # # # # # #  
    def get_cert(self,host):
        '''
            As the name suggests it parses cert info using various lookup dicts
        '''
        finding = {}
        StatusDict = {"0": "Unable to check", "1": "Certificate REVOKED" ,"2": "Certificate not revoked", "3": "Revocation check error", "4": "No revocation information","5": "Internal Error"}
        cert = host["certs"][0]

        
        # convert Valid from/to to readible format
        notBefore	= int(cert["notBefore"]) / 1000
        notAfter	= int(cert["notAfter"]) / 1000
        validFrom 	= datetime.datetime.fromtimestamp(notBefore).strftime("%Y-%m-%d %H:%M:%S")
        validUntil 	= datetime.datetime.fromtimestamp(notAfter).strftime("%Y-%m-%d %H:%M:%S")

        try:
            revocationStatus 		= StatusDict[str(cert["revocationStatus"])]
            crlrevocationStatus 	= StatusDict[str(cert["crlRevocationStatus"])]
            ocsprevocationStatus 	= StatusDict[str(cert["ocspRevocationStatus"])]
        except KeyError:
            revocationStatus 		= "Unable to check"
            crlrevocationStatus 	= "Unable to check"
            ocsprevocationStatus 	= "Unable to check"	

        finding = {
            "commonNames": cert["commonNames"],
            "altNames": cert["altNames"],
            "certSubject": cert["subject"],
            "issuerSubject": cert["issuerSubject"],
            "validFrom": validFrom,
            "validUntil": validUntil,
            "keyHash": cert["sha256Hash"],
            "keyAlgorithm": cert["keyAlg"],
            "keyStrength": cert["keyStrength"],
            "revocationStatus": revocationStatus,
            "crlrevocationStatus": crlrevocationStatus,
            "ocsprevocationStatus": ocsprevocationStatus,
            "cert": cert["raw"] 				
        }
        # print output if desired for debug
        # print(json.dumps(finding, indent=3))
        return finding