from .smb import smblog


class SmbConfig(object):
    """
    This class helps to access the config values.
    """

    def __init__(self, config=None):
        """
        :param config: The config dict from dionaea
        :type config: Dict

        """
        if config is None:
            config = {}

        self.native_os = "Windows 5.1"
        self.native_lan_manager = "Windows 2000 LAN Manager"
        self.oem_domain_name = "WORKGROUP"
        self.primary_domain = "WORKGROUP"
        self.server_name = "HOMEUSER-3AF6FE"

        value_names = [
            "native_lan_manager",
            "native_os",
            "oem_domain_name",
            "primary_domain",
            "server_name"
        ]
        for name in value_names:
            value = config.get(name)
            if value is None:
                continue
            smblog.debug("Set '%s' to '%s'" % (name, value))
            setattr(self, name, value)
