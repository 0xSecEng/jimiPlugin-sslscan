import time

from core import db, audit

# Initialize
dbCollectionName = "sslscan"

class _sslscan(db._document):
    scanHost                = str()
    ipAddress               = str()
    serverSignature         = str()
    SSL_grade               = str()
    supportedTLSCiphers     = dict()
    cert_info               = dict()
    vulnerableCiphers       = dict()

    _dbCollection = db.db[dbCollectionName]

    def new(self, scanHost):

        self.scanHost = scanHost
        return super(_sslscan, self).new()

    def updateRecord(self, scanHost):
        audit._audit().add("sslscan","history",{ "lastUpdate" : self.lastUpdateTime, "endDate" : int(time.time()), "scanHost" : self.scanHost }) 


        self.lastScan = int(time.time())
        self.scanHost = scanHost
        self.update(["lastScan","scanHost"])

