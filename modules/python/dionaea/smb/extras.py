from . import rpcservices
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
        self.os_type = 2
        self.primary_domain = "WORKGROUP"
        self.server_name = "HOMEUSER-3AF6FE"
        self.shares = {}

        default_shares = {
            "ADMIN$" : {
                "comment" : "Remote Admin",
                "path": "C:\\Windows",
                "type": "disktree"
            },
            "C$" : {
                "comment" : "Default Share",
                "path": "C:\\",
                "type": ["disktree", "special"]
            },
            "IPC$" : {
                "comment" : "Remote IPC",
                "path": "",
                "type": "ipc",
            },
            "Printer" : {
                "comment" : "Microsoft XPS Document Writer",
                "path": "",
                "type": "printq",
            }
        }

        value_names = [
            "native_lan_manager",
            "native_os",
            "oem_domain_name",
            "os_type",
            "primary_domain",
            "server_name"
        ]
        for name in value_names:
            value = config.get(name)
            if value is None:
                continue
            smblog.debug("Set '%s' to '%s'" % (name, value))
            setattr(self, name, value)

        shares = config.get("shares")
        if shares is None:
            shares = default_shares
        for name, options in shares.items():
            cfg_share_types = options["type"]
            if not isinstance(cfg_share_types, list):
                cfg_share_types = [cfg_share_types]
            share_type = 0x00000000
            for cfg_share_type in cfg_share_types:
                if cfg_share_type.lower() == "disktree":
                    share_type |= rpcservices.STYPE_DISKTREE
                elif cfg_share_type.lower() == "ipc":
                    share_type |= rpcservices.STYPE_IPC
                elif cfg_share_type.lower() == "printq":
                    share_type |= rpcservices.STYPE_PRINTQ
                elif cfg_share_type.lower() == "special":
                    share_type |= rpcservices.STYPE_SPECIAL

            self.shares[name] = {
                "comment": options.get("comment", ""),
                "path": options.get("path", ""),
                "type": share_type
            }
