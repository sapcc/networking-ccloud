Search.setIndex({"docnames": ["architecture/driver", "architecture/index", "architecture/overview", "architecture/switch-config", "cli/index", "configuration/config-driver", "configuration/config-input", "configuration/config-oslo", "configuration/index", "contributor/contributing", "contributor/index", "index", "install/get-started", "install/index", "install/install", "install/next-steps", "install/verify", "intro", "reference/index"], "filenames": ["architecture/driver.rst", "architecture/index.rst", "architecture/overview.rst", "architecture/switch-config.rst", "cli/index.rst", "configuration/config-driver.rst", "configuration/config-input.rst", "configuration/config-oslo.rst", "configuration/index.rst", "contributor/contributing.rst", "contributor/index.rst", "index.rst", "install/get-started.rst", "install/index.rst", "install/install.rst", "install/next-steps.rst", "install/verify.rst", "intro.rst", "reference/index.rst"], "titles": ["CC-Fabric ML2 Driver Internals", "Driver Architecutre", "Overview", "Device Config", "Command line interface reference", "Driver Configuration", "Generator Input", "Oslo Config", "Configuration", "So You Want to Contribute\u2026", "Contributor Documentation", "Welcome to the documentation of networking_ccloud", "Networking CCloud VXLAN Fabric service overview", "Networking CCloud VXLAN Fabric service installation guide", "Install and configure", "Next steps", "Verify operation", "Introduction", "References"], "terms": {"note": [0, 9, 14], "ar": [0, 3, 6, 9, 14], "draft": 0, "thought": 0, "have": [0, 3, 6, 9, 14], "been": 0, "record": [0, 3], "over": [0, 3], "cours": 0, "project": [0, 9, 15, 16], "some": [0, 3, 9, 14], "written": 0, "befor": 0, "implement": [0, 3], "while": 0, "wa": 0, "being": [0, 3], "done": [0, 3], "therefor": 0, "might": [0, 9, 14], "100": [0, 3, 6], "accur": 0, "need": [0, 3, 6, 9, 14], "review": [0, 9], "The": [0, 3, 6, 12, 13, 14], "follow": [0, 3, 6, 12, 13], "relev": 0, "configur": [0, 6, 7, 11, 13, 17], "id": [0, 3, 6], "us": [0, 3, 6, 9, 14, 17], "name": [0, 3, 6, 14], "refer": [0, 11], "thi": [0, 3, 6, 9, 13, 14, 17], "availability_zone_hint": [0, 3], "decid": 0, "port": [0, 1, 8], "can": [0, 3, 6, 7, 9, 14], "bound": [0, 6], "admin_state_up": [0, 3], "fixm": [0, 5, 7], "should": [0, 3, 6, 17], "we": [0, 6, 7, 9], "respect": [0, 3], "flag": 0, "router": [0, 3], "extern": [0, 6], "subnet": [0, 1, 6], "belong": [0, 3], "singl": [0, 6], "onli": [0, 3, 6, 14, 16], "gateway_ip": [0, 3], "binding_host": [0, 3], "host": [0, 2, 3, 6], "which": [0, 3, 6, 14], "map": [0, 3, 14], "hostgroup": [0, 3, 5, 14], "binding_profil": [0, 3], "altern": 0, "sourc": [0, 16], "bind": [0, 3, 6], "baremet": [0, 2], "tabl": [0, 3], "networkseg": 0, "network_typ": [0, 3], "vxlan": [0, 9, 11, 14, 16], "vlan": 0, "manag": [0, 3, 6], "segment": [0, 2, 3, 6], "neutron": [0, 13, 17], "network_id": [0, 3], "physical_network": [0, 3], "physnet": 0, "defin": [0, 3, 6], "segmentation_id": [0, 3], "vni": [0, 3], "segment_index": 0, "level": [0, 3, 17], "0": [0, 3, 6], "top": [0, 3, 17], "1": [0, 3, 6, 14], "ml2_port_bind": 0, "see": [0, 15], "profil": 0, "vif_detail": 0, "extra": 0, "ml2_port_binding_level": 0, "each": [0, 3, 6, 16], "ha": [0, 3], "entri": [0, 3], "again": 0, "isn": 0, "t": 0, "duplic": 0, "our": [0, 6, 9], "pool": [0, 1, 6], "multipl": [0, 2, 3], "same": [0, 3, 14], "physnet_nam": 0, "list": [0, 3, 6, 16], "interfac": [0, 3, 8, 11], "A": [0, 3, 6], "consist": [0, 12], "hold": 0, "physic": [0, 6], "question": [0, 3], "well": [0, 3], "els": [0, 14], "cannot": 0, "so": [0, 6, 10, 11, 14], "gener": [0, 3, 7, 8, 9, 11, 14], "full": [0, 6], "look": 0, "thing": [0, 7], "all": [0, 3, 6, 9, 14], "specifi": 0, "found": [0, 6], "queri": [0, 6], "re": [0, 6], "carri": [0, 6], "There": [0, 3, 6], "three": 0, "hostgroupin": 0, "one": [0, 2, 3, 6, 14], "delet": [0, 3], "snyc": 0, "get": [0, 6, 10, 14], "find": [0, 6], "creat": [0, 3, 6], "hosgroup": 0, "check": [0, 9], "ani": [0, 6], "remain": 0, "stop": 0, "other": [0, 3, 14], "still": 0, "mayb": 0, "rpc": 0, "call": [0, 3, 12], "remov": [0, 3], "from": [0, 3, 6, 9], "unus": 0, "help": 0, "could": [0, 3, 6], "necessari": [0, 3, 6], "send": 0, "tell": 0, "complet": [0, 14], "clean": 0, "add": [0, 3, 5, 15], "replac": 0, "For": [0, 3, 6, 9], "chang": [0, 3], "an": [0, 3, 6, 9, 17], "includ": [0, 3, 6, 14, 15], "inform": [0, 3, 9, 14], "per": [0, 2, 3, 6, 14], "identifi": [0, 3, 6], "mappin": 0, "local": [0, 3, 6], "descript": [0, 3, 6, 7, 14], "uuid": 0, "translat": [0, 3], "channel": [0, 3, 6], "option": [0, 3, 6], "member": [0, 3, 6], "subinterfac": 0, "overriden": 0, "moment": 0, "idea": 0, "would": [0, 3], "case": [0, 3, 6], "direct": 0, "stuff": [0, 14], "e": [0, 6, 9], "g": [0, 9], "nativ": [0, 3], "both": [0, 3, 6], "maximum": 0, "capac": 0, "x": [0, 6], "2000": [0, 6], "arista": [0, 3, 6, 14], "1750": 0, "directli": 0, "insid": [0, 17], "openstack": [0, 3, 9, 13, 15, 16], "authent": 0, "facil": 0, "provid": [0, 3, 12, 13], "command": [0, 11, 16], "mode": [0, 2, 3, 6], "show": 0, "given": [0, 3], "pull": [0, 9], "enricht": 0, "knowledg": 0, "leaf": [0, 8], "etc": [0, 3, 6, 9], "basic": [0, 9], "data": 0, "hand": [0, 3], "out": [0, 3, 9], "its": [0, 3, 6], "state": 0, "ask": 0, "devic": [0, 1, 6, 11, 14], "off": [0, 3], "return": 0, "between": [0, 2, 3], "those": [0, 3], "two": [0, 3, 6, 14], "user": [0, 3, 12], "dictionari": 0, "reappli": 0, "mai": [0, 6], "want": [0, 10, 11], "leftov": 0, "though": 0, "also": [0, 3, 6], "handl": [0, 3], "separ": 0, "cleanup": 0, "loop": [0, 3], "brainstorm": 0, "phase": 0, "test": 0, "connect": [0, 3, 6], "dump": [0, 7], "version": 0, "uptim": 0, "resync": 0, "paus": 0, "avocado": [0, 2], "architectur": 1, "network": [1, 4, 8, 9, 11, 14, 16, 17, 18], "ccloud": [1, 3, 4, 8, 9, 11, 14, 16, 17, 18], "overview": [1, 11, 13], "featur": [1, 3], "agent": [1, 13], "design": 1, "cc": [1, 3, 6, 11, 14], "fabric": [1, 6, 9, 11, 14, 16], "ml2": [1, 2, 9, 11, 14, 17], "intern": [1, 3, 11], "structur": 1, "db": 1, "api": [1, 3, 6, 12], "config": [1, 5, 6, 8, 11, 14], "object": [1, 3, 6], "how": [1, 9, 14], "thei": [1, 3], "match": [1, 3, 6], "togeth": 1, "sync": 1, "oper": [1, 3, 11, 13], "commun": [1, 6, 9], "syncloop": 1, "schedul": [1, 3], "borderleaf": 1, "aci": [1, 14], "transit": [1, 6], "In": [1, 3, 6], "debug": 1, "mainten": 1, "float": 1, "ip": [1, 6], "scale": 1, "limit": 1, "hierarch": [2, 3, 14], "portbind": [2, 14], "switch": [2, 3, 5, 6, 14], "infra": [2, 3, 6], "lend": 2, "magic": 2, "One": 2, "vendor": [2, 6, 14], "alloc": [2, 3, 6], "foo": 2, "document": [3, 17], "describ": [3, 6, 14], "support": [3, 6], "combin": 3, "basi": 3, "assum": [3, 13], "l2": [3, 8], "broadcast": 3, "domain": 3, "wai": [3, 6], "establish": 3, "server": [3, 6], "specif": [3, 6, 9], "demand": 3, "sub": 3, "whenev": 3, "requir": [3, 6], "group": 3, "type": 3, "within": 3, "inter": 3, "traffic": 3, "rout": [3, 6], "l3": [3, 8], "span": [3, 6], "extend": 3, "site": [3, 6], "function": 3, "when": [3, 6], "first": [3, 6], "go": 3, "through": 3, "last": [3, 6], "trigger": 3, "request": [3, 9], "depend": 3, "set": [3, 6], "below": [3, 6, 9], "determin": 3, "scope": 3, "anoth": 3, "environ": [3, 15], "trunk": 3, "differ": [3, 6, 9], "share": 3, "respons": [3, 6], "work": [3, 13], "mean": 3, "present": [3, 6], "side": 3, "point": 3, "notifi": 3, "own": 3, "signal": 3, "bind_port": 3, "updat": 3, "_port_postcommit": 3, "hook": 3, "associ": [3, 6], "servic": [3, 6, 11, 14, 15, 16], "potenti": 3, "pick": 3, "allow": 3, "least": 3, "guarante": 3, "free": 3, "forward": 3, "outsid": 3, "solv": 3, "underli": 3, "base": [3, 6], "pair": [3, 8], "back": 3, "hierarchi": 3, "If": [3, 6, 9, 14], "more": [3, 6, 9], "than": [3, 6], "avail": [3, 14], "avoid": 3, "migrat": [3, 6], "flow": 3, "expect": 3, "via": [3, 6, 14], "static": [3, 6], "non": [3, 6], "control": [3, 6, 14, 16], "topolog": 3, "variat": 3, "scenario": 3, "alreadi": 3, "exist": 3, "addit": [3, 9, 15], "aza": 3, "ad": [3, 6], "deploy": 3, "b": [3, 6], "bgw": 3, "No": 3, "action": 3, "c": 3, "AND": [3, 6], "azb": 3, "ml2_cc_fabric": 3, "regional_l3": 3, "fals": [3, 6], "az_l3": 3, "qa": [3, 6], "de": [3, 6], "1d": [3, 6], "global": 3, "asn_region": 3, "65130": 3, "infra_network_default_vrf": 3, "mgmt": [3, 6], "vrf": [3, 6], "rd": 3, "900": 3, "node001": 3, "bb301": 3, "ethernet1": 3, "3": [3, 6], "sw1103a": 3, "sw1103b": 3, "node002": 3, "ethernet2": 3, "201": 3, "lacp": 3, "true": 3, "ethernet3": 3, "nova": 3, "comput": [3, 12], "infra_network": 3, "10301100": 3, "untag": 3, "10": [3, 6], "246": 3, "24": 3, "dhcp_relai": 3, "147": 3, "204": 3, "45": 3, "247": 3, "122": 3, "10301101": 3, "101": [3, 6], "metagroup": 3, "switchgroup": [3, 5, 6, 14], "asn": [3, 6], "1103": 3, "availability_zon": 3, "1a": 3, "bgp_source_ip": 3, "03": 3, "114": 3, "203": 3, "password": 3, "nope": 3, "admin2": 3, "platform": [3, 6], "eo": [3, 6], "2": [3, 6, 14], "role": [3, 6], "vtep_ip": 3, "1b": 3, "aeec9fd4": 3, "30f7": 3, "4398": 3, "8554": 3, "34acb36b7712": 3, "ipv4_address_scop": 3, "24908a2d": 3, "55e8": 3, "4c03": 3, "87a9": 3, "e1493cd0d995": 3, "mtu": 3, "8950": 3, "floatingip": 3, "sfh03": 3, "eude1": 3, "project_id": 3, "07ed7aa018584972b40d94697b70a37b": 3, "null": 3, "10394": 3, "3150": 3, "2300": 3, "2340": 3, "statu": [3, 6], "activ": [3, 6], "14b7b745": 3, "8d5d": 3, "4667": 3, "a3e3": 3, "2be0facbb23d": 3, "72f96182": 3, "d93d": 3, "4aa7": 3, "a987": 3, "edb315875c9": 3, "bbe371a": 3, "341b": 3, "4f86": 3, "931a": 3, "e9c808cb312": 3, "size": 3, "hint": 3, "reject": 3, "fce02a86": 3, "525c": 3, "49c9": 3, "a6cd": 3, "bf472881a83f": 3, "10400": 3, "3200": 3, "f77d7403": 3, "c46a": 3, "42d0": 3, "a20b": 3, "d104b8bc203f": 3, "n": 3, "possibl": 3, "region": [3, 6], "vxlan1": 3, "bgp": 3, "1112": 3, "target": 3, "export": 3, "import": [3, 6], "redistribut": 3, "nx": 3, "os": 3, "nve1": 3, "ingress": 3, "replic": 3, "protocol": 3, "suppress": 3, "arp": 3, "2420": 3, "vn": 3, "applic": [3, 6], "999": [3, 6], "remot": 3, "convent": 3, "vs": 3, "tag": [3, 6], "prefix": [3, 6], "supernet": [3, 6], "announc": 3, "toward": 3, "upstream": 3, "azc": 3, "azd": 3, "cloudxx": 3, "ext": 3, "region_asn": 3, "1xx": 3, "peraz": 3, "4": [3, 6], "aggreg": 3, "core": [3, 6], "std": 3, "address": [3, 6], "hcp03": 3, "public": 3, "export_rt_suffix": 3, "102": 3, "import_rt_suffix": 3, "cloud02": 3, "exampl": 3, "f2fd984c": 3, "45b1": 3, "4465": 3, "9f99": 3, "e72f86b896fa": 3, "address_scope_id": 3, "e6df3de0": 3, "16dd": 3, "46e3": 3, "850f": 3, "5418fd6dd820": 3, "47": 3, "8": 3, "fbc4b555": 3, "4266": 3, "46a0": 3, "916b": 3, "3863c649223a": 3, "20": 3, "cidr": 3, "192": 3, "27": [3, 6], "193": 3, "host_rout": 3, "ip_vers": 3, "sap": 3, "01": 3, "subnetpool_id": 3, "e8556528": 3, "01e6": 3, "4ccd": 3, "9286": 3, "0145ac7a75f4": 3, "25": 3, "rm": 3, "extcommun": 3, "65101": 3, "1102": 3, "instanc": [3, 14], "virtual": [3, 6], "secondari": 3, "2102": 3, "4102": 3, "attribut": 3, "shutdown": 3, "context": [3, 6], "famili": [3, 6], "ipv4": 3, "unicast": 3, "tenant": 3, "default": 3, "gw": 3, "exempt": 3, "nat": 3, "compar": 3, "sinc": 3, "current": [3, 6, 14], "assign": 3, "them": 3, "must": [3, 6], "next": [3, 6, 11, 13], "hop": 3, "binding_vif_typ": 3, "asr1k": 3, "device_own": 3, "router_gatewai": 3, "fixed_ip": 3, "subnet_id": 3, "ip_address": [3, 6], "197": 3, "8a307448": 3, "ef2a": 3, "4cae": 3, "9b2a": 3, "2edf0287e194": 3, "ab16807f": 3, "9c82": 3, "45e8": 3, "8e8d": 3, "da615eb8505a": 3, "floatdapnet": 3, "criteria": 3, "section": [3, 6, 14], "summar": [3, 6], "across": [3, 6], "summari": 3, "maintain": 3, "pod": 3, "filter": [3, 6], "undesir": 3, "It": [3, 6, 9], "polici": 3, "peer": [3, 6], "do": [3, 6, 9], "collect": 3, "continu": 3, "process": [3, 16], "individu": 3, "compress": 3, "merg": [3, 10], "adjac": 3, "where": [3, 6, 17], "equal": 3, "conflict": [3, 6], "appropri": 3, "ccloudxx": 3, "remaind": 3, "bs": 3, "10c48c80": 3, "b250": 3, "4452": 3, "a253": 3, "7f88b7a0deec": 3, "ff3452d0": 3, "c968": 3, "49c6": 3, "b1c7": 3, "152e5ffb11a": 3, "130": 3, "214": 3, "202": 3, "188": 3, "16": 3, "21": 3, "236": 3, "22": 3, "438157b9": 3, "3ce3": 3, "4370": 3, "8bb5": 3, "59131ff105f9": 3, "internet": 3, "215": 3, "26": [3, 6], "64": 3, "5051685d": 3, "37c5": 3, "4bab": 3, "98bf": 3, "8e797453ab03": 3, "ccloud02": 3, "high": 3, "churn": 3, "rate": 3, "mac": 3, "mobil": 3, "caus": [3, 14], "signific": 3, "otherwis": 3, "mitig": 3, "To": [3, 6, 15], "reduc": [3, 6], "number": [3, 6], "packet": 3, "significantli": 3, "instantan": 3, "everi": 3, "certain": [3, 6], "fip": 3, "locat": 3, "destin": 3, "endpoint": 3, "until": 3, "becom": 3, "serv": 3, "mac_address": 3, "fa": 3, "3e": 3, "6d": 3, "d3": 3, "33": 3, "fixed_ip_address": 3, "180": 3, "7": 3, "floating_ip_address": 3, "104": 3, "75": 3, "floating_network_id": 3, "fb8a5ddd": 3, "611b": 3, "415a": 3, "8bd7": 3, "64d3033ab840": 3, "router_id": 3, "260c2d26": 3, "2904": 3, "4073": 3, "8407": 3, "7f94ed1e88b8": 3, "fa16": 3, "3e6d": 3, "d333": 3, "creation": 3, "hpb": 3, "front": [3, 6, 14], "attach": 3, "equip": [3, 6], "further": 3, "down": [3, 5], "chain": 3, "execut": 3, "final": 3, "subsequ": 3, "most": [3, 7, 9], "commonli": 3, "up": 3, "partial": 3, "accordingli": 3, "afterward": 3, "binding_host_id": 3, "binding_vif_detail": 3, "eu": [3, 6], "7574c44b": 3, "a3d7": 3, "471f": 3, "89e5": 3, "f3a450181f9a": 3, "switchport": 3, "storm": 3, "tree": 3, "portfast": 3, "errdis": 3, "recoveri": 3, "bpduguard": 3, "interv": 3, "300": 3, "channel201": 3, "min": 3, "link": [3, 7], "fallback": 3, "timeout": [3, 7], "tbd": 3, "resourc": 3, "1800": 3, "4000": 3, "500": 3, "fx3": 3, "24000": 3, "6000": 3, "cli": [4, 16], "write": 5, "er": 5, "driver": [6, 7, 8, 9, 11, 13, 17], "tool": 6, "netbox": [6, 14], "spine": 6, "compliant": 6, "regex": 6, "p": 6, "w": 6, "d": 6, "sw": 6, "az": 6, "ab": 6, "z": 6, "bb_no": 6, "9": 6, "Or": 6, "readabl": 6, "i": 6, "sw4223a": 6, "bb147": 6, "condit": 6, "appli": 6, "variabl": 6, "fashion": 6, "like": [6, 7, 9], "mlag": 6, "vpc": 6, "uniqu": 6, "digit": 6, "indic": 6, "zero": 6, "fist": 6, "second": 6, "sequenc": 6, "lower": 6, "charact": 6, "leaf_id": 6, "leaf_a_b": 6, "exactli": 6, "subrol": 6, "apod": 6, "bpod": 6, "netpod": 6, "stpod": 6, "vpod": 6, "push": 6, "net": 6, "bl": 6, "border": 6, "tl": 6, "legaci": 6, "purpos": 6, "bg": 6, "interconnect": 6, "s": [6, 9], "multi": 6, "3750": 6, "effect": 6, "express": 6, "valu": 6, "2100": 6, "3000": 6, "deliv": 6, "plane": 6, "These": 6, "hypervisor": 6, "access": [6, 14, 16], "provis": 6, "pure": 6, "layer": 6, "model": 6, "enabl": 6, "portion": 6, "accord": 6, "exemplari": 6, "python": 6, "code": [6, 9, 14], "illustr": 6, "pynetbox": 6, "nb": 6, "dcim": 6, "slug": 6, "bb": 6, "271": 6, "pod_typ": 6, "vgroup": 6, "ipam": 6, "vlan_group": 6, "f": 6, "03d": 6, "pod_numb": 6, "pad": 6, "correspond": 6, "correct": 6, "mgmt_role": 6, "cc_tenant": 6, "tenanc": 6, "converg": [6, 9], "cloud": [6, 9], "mgmt_vlan": 6, "vid": 6, "build": 6, "block": 6, "precreat": 6, "retreiv": 6, "cc_mgmt_vrf": 6, "candidate_net": 6, "site_id": 6, "vrf_id": 6, "startswith": 6, "len": 6, "rais": 6, "valueerror": 6, "bb_net": 6, "ip_network": 6, "prefixes_26": 6, "mgmt_net": 6, "new_prefix": 6, "prefixes_27": 6, "mgmt_prefix": 6, "str": 6, "is_pool": 6, "shall": 6, "svi": 6, "order": 6, "reflect": 6, "unatagged_vlan": 6, "detail": 6, "snippet": 6, "prefixlen": 6, "alwai": 6, "assigned_object_typ": 6, "assigned_object_id": 6, "form": 6, "11": 6, "doe": 6, "yet": 6, "overlai": 6, "wide": 6, "800": 6, "100800": 6, "200800": 6, "mani": 6, "1ppppvvv": 6, "lead": 6, "v": 6, "371": 6, "10371100": 6, "10000": 6, "99999": 6, "bundl": 6, "logic": 6, "mark": 6, "instal": [6, 11, 15], "diagnost": 6, "dynam": 6, "self": 6, "ensur": 6, "definit": 6, "distinct": 6, "usag": 6, "reserv": 6, "admin": [6, 16], "futur": 6, "99": 6, "new": [6, 17], "exact": 6, "cisco": 6, "nxo": [6, 14], "made": 6, "either": 6, "distinguish": 6, "variant": 6, "channel100": 6, "1110a": 6, "regular": 6, "1110b": 6, "tagged_vlan": 6, "untagged_vlan": 6, "deriv": 6, "server_interfac": 6, "infra_vlan": 6, "vlan_consol": 6, "vlan_mgmt": 6, "vlan_vmot": 6, "vlan_backdoor": 6, "save": 6, "autogener": 7, "part": [7, 14], "importantli": 7, "actual": 7, "oslo": [8, 11, 14], "input": [8, 11], "pleas": 9, "contributor": [9, 11], "guid": [9, 11, 15], "start": [9, 14], "cover": 9, "common": 9, "account": 9, "interact": 9, "gerrit": 9, "system": [9, 14], "tailor": 9, "think": 9, "organ": 9, "welcom": [9, 17], "style": 9, "normal": 9, "max": 9, "line": [9, 11], "length": 9, "120": 9, "pep8": 9, "except": 9, "issu": 9, "github": [9, 14], "page": [9, 11], "http": [9, 14, 15], "com": [9, 14], "sapcc": [9, 14], "open": 9, "you": [10, 11, 14, 17], "contribut": [10, 11], "task": 10, "track": 10, "report": 10, "bug": 10, "your": [10, 14, 15], "patch": 10, "content": 11, "introduct": 11, "architecutr": 11, "verifi": [11, 13], "step": [11, 13], "index": 11, "modul": 11, "search": 11, "compon": [12, 16], "networking_ccloud": [12, 13, 14, 15], "accept": 12, "respond": 12, "end": 12, "chapter": 13, "setup": 13, "tutori": 13, "node": [14, 16], "pip": 14, "mechanism_driv": 14, "make": 14, "sure": 14, "begin": 14, "problem": 14, "put": 14, "now": [14, 15, 17], "split": 14, "contain": 14, "path": 14, "infrastructur": 14, "bindinghost": 14, "amongst": 14, "gen": 14, "take": 14, "care": 14, "file": 14, "suppli": 14, "ignor": 14, "doc": 15, "org": 15, "ocata": 15, "perform": 16, "credenti": 16, "gain": 16, "openrc": 16, "success": 16, "launch": 16, "registr": 16, "hello": 17, "ll": 17, "bne": 17, "train": 17, "piec": 17, "softwar": 17, "explain": 17, "run": 17}, "objects": {}, "objtypes": {}, "objnames": {}, "titleterms": {"cc": 0, "fabric": [0, 3, 12, 13], "ml2": [0, 3], "driver": [0, 1, 2, 3, 5, 14], "intern": 0, "structur": 0, "overview": [0, 2, 3, 12], "db": 0, "api": 0, "config": [0, 3, 7], "object": 0, "how": 0, "thei": 0, "match": 0, "togeth": 0, "sync": 0, "oper": [0, 16], "agent": [0, 2, 3, 14], "design": [0, 2], "commun": [0, 3], "network": [0, 3, 6, 12, 13], "syncloop": 0, "schedul": 0, "borderleaf": 0, "aci": 0, "transit": [0, 3], "In": 0, "debug": 0, "mainten": 0, "relat": 0, "action": 0, "current": 0, "statu": 0, "diff": 0, "switch": 0, "leafpair": 0, "architecutr": 1, "featur": 2, "devic": 3, "singl": 3, "az": 3, "multi": 3, "workflow": 3, "legaci": 3, "integr": 3, "coordin": 3, "interconnect": 3, "dual": 3, "sampl": 3, "configur": [3, 5, 8, 14], "definit": 3, "On": 3, "apod": 3, "vpod": 3, "stpod": 3, "netpod": 3, "bpod": 3, "leaf": [3, 6], "border": 3, "gatewai": [3, 6], "subnet": 3, "rt": 3, "schema": 3, "extern": 3, "dapnet": 3, "directli": 3, "access": 3, "privat": 3, "pool": 3, "float": 3, "ip": 3, "port": [3, 6], "vlan": [3, 6], "handoff": 3, "vmware": 3, "nsx": 3, "t": 3, "neutron": [3, 14], "octavia": 3, "f5": 3, "netapp": 3, "iron": 3, "uc": 3, "asr": 3, "bare": 3, "metal": 3, "vxlan": [3, 12, 13], "evpn": [3, 6], "flood": 3, "learn": 3, "scale": 3, "limit": 3, "relev": 3, "command": 4, "line": 4, "interfac": [4, 6], "refer": [4, 18], "gener": 6, "input": 6, "pair": 6, "hostnam": 6, "convent": 6, "type": 6, "ccloud": [6, 12, 13], "pod": 6, "leav": 6, "cnd": 6, "l2": 6, "l3": 6, "tenant": 6, "rang": 6, "infrastructur": 6, "anycast": 6, "dhcp": 6, "relai": 6, "vni": 6, "map": 6, "cabl": 6, "link": 6, "aggreg": 6, "group": 6, "lag": 6, "assign": 6, "oslo": 7, "so": 9, "you": 9, "want": 9, "contribut": 9, "task": 9, "track": 9, "report": 9, "bug": 9, "get": 9, "your": 9, "patch": 9, "merg": 9, "contributor": 10, "document": [10, 11], "welcom": 11, "networking_ccloud": 11, "indic": 11, "tabl": 11, "servic": [12, 13], "instal": [13, 14], "guid": 13, "next": 15, "step": 15, "verifi": 16, "introduct": 17}, "envversion": {"sphinx.domains.c": 2, "sphinx.domains.changeset": 1, "sphinx.domains.citation": 1, "sphinx.domains.cpp": 6, "sphinx.domains.index": 1, "sphinx.domains.javascript": 2, "sphinx.domains.math": 2, "sphinx.domains.python": 3, "sphinx.domains.rst": 2, "sphinx.domains.std": 2, "sphinx": 56}})