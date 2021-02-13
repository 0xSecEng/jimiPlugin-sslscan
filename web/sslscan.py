import requests

import urllib.parse, urllib.request 
from flask import request
from markupsafe import Markup

from flask import Blueprint, render_template,jsonify,Response
from flask import current_app as app

from core import api

from datetime import datetime
from dateutil import relativedelta #Time difference

from json import loads,dumps

# from flask import make_response
from io import BytesIO 
from plugins.sslscan.models import sslscan
# from plugins.sslscan.models.includes import determine_score, calc_average

pluginPages = Blueprint('sslPages', __name__, template_folder="ssltemplates",static_folder="sslstatic",static_url_path="sslstatic")

@pluginPages.app_template_filter('urlencode')
def urlencode_filter(s):
    if type(s) == 'Markup':
        s = s.unescape()
    s = s.encode('utf8')
    s = urllib.parse.quote_plus(s)
    return Markup(s)

# # # # # # # #
# GET REQUESTS
# # # # # # # #
@pluginPages.route("/sslscan/")
def sslmainPage():

    allScans = sslscan._sslscan()._dbCollection.distinct("scanHost")
    
    threeMonths,sixMonths,oneYear = 0,0,0
    SSLV2,SSLV3, TLS1_0,TLS1_1,TLS1_2,TLS1_3 = False,False,False,False,False,False
    expringSoonList = []

    for scan in allScans:
        #Picked a random key to ensure only fully populated results are added to dashboard
        scanResults                 = sslscan._sslscan().query(api.g.sessionData,query={ "scanHost" : scan })["results"][0]
        if "supportedTLSCiphers" in scanResults:
            
            grade = scanResults["SSL_grade"]
            IP    = scanResults["ipAddress"]
            host  = scanResults["scanHost"]

            
            sslVersions = scanResults["supportedTLSCiphers"] 
            validFrom   = scanResults["cert_info"]["validFrom"]
            validUntil  = scanResults["cert_info"]["validUntil"]
            
            now = datetime.now()
            date2 = datetime.strptime(str(validUntil), '%Y-%m-%d %H:%M:%S')
            #relativedelta(months=+11, days=+26, hours=+8, minutes=+7, seconds=+2, microseconds=+519424)
            timeLeft = relativedelta.relativedelta(date2, now)
            

            if timeLeft.months < 3:
                threeMonths += 1
                expringSoonList.append(host)
            elif timeLeft.months <= 6 <= 12:
                sixMonths   += 1
                expringSoonList.append(host)
            elif timeLeft.months <= 12:
                oneYear     += 1

            if "1_0" in sslVersions:
                TLS1_0 = True
            if "1_1" in sslVersions:
                TLS1_1 = True    
            if "1_2" in sslVersions:
                TLS1_2 = True
            if "1_3" in sslVersions:
                TLS1_3 = True   

            if "2_0" in sslVersions:
                SSLV2 = True   
            if "3_0" in sslVersions:
                SSLV3 = True   

            # algorithmInUse
            # Algorithm
            tableResults.append({"host": f"{host}" , "IP": f"{IP}", "sslScore": f"{grade}","validUntil": validUntil})
        
    supportedSSLVersions = { "SSLV2": SSLV3, "SSLV3": SSLV3, "TLS1_0": TLS1_0, "TLS1_1": TLS1_1, "TLS1_2": TLS1_2, "TLS1_3":  TLS1_0}
    sslPieChart = {"threeMonths": threeMonths,"oneYear": oneYear, "sixMonths": sixMonths}

    return render_template("sslHomePageMin.html",tableResults=tableResults,sslPieChart=sslPieChart,expringSoonList=expringSoonList,supportedSSLVersions=supportedSSLVersions)


@pluginPages.route("/sslscan/scan/")
def getScan():
    scanName = urllib.parse.unquote_plus(request.args.get("scanName"))

    
    results = sslscan._sslscan().query(api.g.sessionData,query={ "scanHost" : scanName})["results"][0]


    grade       = results["SSL_grade"]
    IP          = results["ipAddress"]
    host        = results["scanHost"]
    validFrom   = results["cert_info"]["validFrom"]
    validUntil      = results["cert_info"]["validUntil"]
    serverSignature = results["serverSignature"]
    
    keyStrength     = results["cert_info"]["keyStrength"]
    keyAlgorithm    = results["cert_info"]["keyAlgorithm"]
    keyStrength     = results["cert_info"]["keyStrength"]

    revocationStatus     = results["cert_info"]["revocationStatus"]
    crlrevocationStatus  = results["cert_info"]["crlrevocationStatus"]
    ocsprevocationStatus = results["cert_info"]["ocsprevocationStatus"]

    commonNames         = results["cert_info"]["commonNames"]
    altNames            = results["cert_info"]["altNames"]

    vulnerableCiphers   = results["vulnerableCiphers"]

    # Icons
    if revocationStatus == "Certificate not revoked":
        revocationStatus = "fa-check"
    else:
        revocationStatus = "fa-exclamation"

    if crlrevocationStatus == "Certificate not revoked":
        crlStatus = "fa-check"
    else:
        crlStatus = "fa-exclamation"

    if ocsprevocationStatus == "Certificate not revoked":
        ocsptatus = "fa-check"
    else:
        ocsptatus = "fa-exclamation"
    

    # add common Name
    # Alternative Name
    tableResults = { "ocsptatus": ocsptatus,"crlStatus": crlStatus, "revocationStatus": revocationStatus ,"keyAlgorithm": keyAlgorithm, "keyStrength": keyStrength, "host": f"{host}" , "IP": f"{IP}", "sslScore": f"{grade}","validFrom": validFrom, "validUntil": validUntil, "serverSignature": serverSignature}

    return render_template("sslReport.html", tableResults=tableResults,commonNames=commonNames,altNames=altNames,vulnerableCiphers=vulnerableCiphers)
