from core import plugin, model

class _sslscan(plugin._plugin):
    version = 0.4

    def install(self):
        # Register models
        model.registerModel("sslscan","_sslscan","_action","plugins.sslscan.models.action")
        return True



    def uninstall(self):
        # deregister models
        model.deregisterModel("sslscan","_sslscan","_action","plugins.sslscan.models.action")
        model.deregisterModel("niktoScan","_niktoScan","_action","plugins.sslscan.models.action")
        return True

    def upgrade(self,LatestPluginVersion): 
        if self.version < 0.5:        
            model.deregisterModel("niktoScan","_niktoScan","_action","plugins.sslscan.models.action")
        model.registerModel("sslscan","_sslscan","_action","plugins.sslscan.models.action")

