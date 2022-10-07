Search.setIndex({"docnames": ["architecture/driver", "architecture/index", "architecture/numerical-attributes", "architecture/overview", "architecture/switch-config", "cli/index", "configuration/config-driver", "configuration/config-input", "configuration/config-oslo", "configuration/index", "contributor/contributing", "contributor/index", "index", "install/get-started", "install/index", "install/install", "install/next-steps", "install/verify", "intro", "reference/index"], "filenames": ["architecture/driver.rst", "architecture/index.rst", "architecture/numerical-attributes.rst", "architecture/overview.rst", "architecture/switch-config.rst", "cli/index.rst", "configuration/config-driver.rst", "configuration/config-input.rst", "configuration/config-oslo.rst", "configuration/index.rst", "contributor/contributing.rst", "contributor/index.rst", "index.rst", "install/get-started.rst", "install/index.rst", "install/install.rst", "install/next-steps.rst", "install/verify.rst", "intro.rst", "reference/index.rst"], "titles": ["CC-Fabric ML2 Driver Internals", "Driver Architecutre", "Numerical Attributes", "Overview", "Device Config", "Command line interface reference", "Driver Configuration", "Generator Input", "Oslo Config", "Configuration", "So You Want to Contribute\u2026", "Contributor Documentation", "Welcome to the documentation of networking_ccloud", "Networking CCloud VXLAN Fabric service overview", "Networking CCloud VXLAN Fabric service installation guide", "Install and configure", "Next steps", "Verify operation", "Introduction", "References"], "terms": {"note": [0, 10, 15], "ar": [0, 2, 4, 7, 10, 15], "draft": 0, "thought": 0, "have": [0, 4, 7, 10, 15], "been": 0, "record": [0, 4], "over": [0, 4, 7], "cours": 0, "project": [0, 10, 16, 17], "some": [0, 4, 10, 15], "written": 0, "befor": 0, "implement": [0, 4], "while": 0, "wa": 0, "being": [0, 4], "done": [0, 4], "therefor": 0, "might": [0, 10, 15], "100": [0, 4, 7], "accur": 0, "need": [0, 2, 4, 7, 10, 15], "review": [0, 10], "The": [0, 4, 7, 13, 14, 15], "follow": [0, 2, 4, 7, 13, 14], "relev": 0, "configur": [0, 2, 7, 8, 12, 14, 18], "id": [0, 2, 4], "us": [0, 2, 4, 7, 10, 15, 18], "name": [0, 4, 7, 15], "refer": [0, 2, 7, 12], "thi": [0, 2, 4, 7, 10, 14, 15, 18], "availability_zone_hint": [0, 4], "decid": 0, "port": [0, 1, 2, 9], "can": [0, 4, 7, 8, 10, 15], "bound": [0, 2, 7], "admin_state_up": [0, 4], "fixm": [0, 6, 8], "should": [0, 4, 7, 18], "we": [0, 4, 7, 8, 10], "respect": [0, 4], "flag": 0, "router": [0, 4], "extern": [0, 2, 7], "subnet": [0, 1, 2, 7], "belong": [0, 4], "singl": [0, 7], "onli": [0, 4, 7, 15, 17], "gateway_ip": [0, 4], "binding_host": [0, 2, 4], "host": [0, 3, 4, 7], "which": [0, 4, 7, 15], "map": [0, 2, 4, 15], "hostgroup": [0, 2, 4, 6, 15], "binding_profil": [0, 4], "altern": 0, "sourc": [0, 17], "bind": [0, 4, 7], "baremet": [0, 3], "tabl": [0, 4], "networkseg": 0, "network_typ": [0, 4], "vxlan": [0, 2, 10, 12, 15, 17], "vlan": [0, 2], "manag": [0, 2, 4, 7], "segment": [0, 2, 3, 4, 7], "neutron": [0, 14, 18], "u": 0, "network_id": [0, 4], "i": [0, 4, 7, 10, 15], "physical_network": [0, 4], "physnet": 0, "defin": [0, 4, 7], "segmentation_id": [0, 4], "vni": [0, 2, 4], "segment_index": 0, "level": [0, 4, 18], "0": [0, 2, 4, 7], "top": [0, 4, 18], "1": [0, 2, 4, 7, 15], "ml2_port_bind": 0, "see": [0, 2, 16], "profil": 0, "vif_detail": 0, "extra": 0, "ml2_port_binding_level": 0, "each": [0, 4, 7, 17], "ha": [0, 2, 4], "entri": [0, 4], "again": 0, "isn": 0, "t": 0, "duplic": 0, "our": [0, 7, 10], "pool": [0, 1, 7], "multipl": [0, 3, 4, 7], "same": [0, 4, 15], "physnet_nam": 0, "list": [0, 4, 7, 17], "interfac": [0, 2, 4, 9, 12], "A": [0, 4, 7], "consist": [0, 13], "hold": 0, "physic": [0, 7], "question": [0, 4], "well": [0, 4], "els": [0, 2, 15], "cannot": 0, "so": [0, 7, 11, 12, 15], "gener": [0, 2, 4, 8, 9, 10, 12, 15], "full": [0, 4, 7], "look": 0, "thing": [0, 8], "all": [0, 2, 4, 7, 10, 15], "specifi": 0, "found": [0, 7], "queri": [0, 7], "re": [0, 7], "carri": [0, 7], "There": [0, 2, 4], "three": 0, "hostgroupin": 0, "one": [0, 3, 4, 7, 15], "delet": [0, 4], "snyc": 0, "get": [0, 7, 11, 15], "find": [0, 7], "creat": [0, 4, 7], "hosgroup": 0, "check": [0, 10], "ani": [0, 2, 4, 7], "remain": 0, "stop": 0, "other": [0, 4, 15], "still": 0, "mayb": 0, "rpc": 0, "call": [0, 4, 13], "remov": [0, 4], "from": [0, 4, 7, 10], "unus": 0, "help": 0, "could": [0, 4, 7], "necessari": [0, 4, 7], "send": 0, "tell": 0, "complet": [0, 15], "clean": 0, "add": [0, 4, 6, 16], "replac": 0, "For": [0, 4, 7, 10], "chang": [0, 4], "an": [0, 2, 4, 7, 10, 18], "includ": [0, 4, 7, 15, 16], "inform": [0, 4, 10, 15], "per": [0, 3, 4, 7, 15], "identifi": [0, 4, 7], "mappin": 0, "local": [0, 4, 7], "descript": [0, 4, 7, 8, 15], "uuid": 0, "translat": [0, 4], "channel": [0, 4, 7], "option": [0, 4, 7], "member": [0, 4, 7], "subinterfac": 0, "overriden": 0, "moment": [0, 7], "idea": 0, "would": [0, 4], "case": [0, 4, 7], "direct": 0, "stuff": [0, 15], "e": [0, 7, 10], "g": [0, 10], "nativ": [0, 4], "both": [0, 4, 7], "maximum": 0, "capac": 0, "x": [0, 7], "2000": [0, 2, 7], "arista": [0, 4, 7, 15], "1750": 0, "directli": 0, "insid": [0, 18], "openstack": [0, 2, 4, 10, 14, 16, 17], "authent": 0, "facil": 0, "provid": [0, 4, 13, 14], "command": [0, 12, 17], "mode": [0, 3, 4, 7], "show": 0, "given": [0, 4], "pull": [0, 10], "enricht": 0, "knowledg": 0, "leaf": [0, 9], "etc": [0, 4, 7, 10], "basic": [0, 10], "data": [0, 2], "hand": [0, 4], "out": [0, 4, 7, 10], "its": [0, 4, 7], "state": 0, "ask": 0, "devic": [0, 1, 7, 12, 15], "off": [0, 4], "return": 0, "between": [0, 2, 3, 4], "those": [0, 4], "two": [0, 4, 7, 15], "user": [0, 4, 13], "dictionari": 0, "reappli": 0, "mai": [0, 7], "want": [0, 11, 12], "leftov": 0, "though": 0, "also": [0, 4, 7], "handl": [0, 4], "separ": 0, "cleanup": 0, "loop": [0, 4], "brainstorm": 0, "phase": 0, "test": 0, "connect": [0, 4, 7], "dump": [0, 8], "version": 0, "uptim": 0, "resync": 0, "paus": 0, "avocado": [0, 3], "architectur": 1, "network": [1, 2, 5, 9, 10, 12, 15, 17, 18, 19], "ccloud": [1, 4, 5, 9, 10, 12, 15, 17, 18, 19], "overview": [1, 12, 14], "featur": [1, 4], "agent": [1, 14], "design": 1, "cc": [1, 4, 7, 12, 15], "fabric": [1, 7, 10, 12, 15, 17], "ml2": [1, 3, 10, 12, 15, 18], "intern": [1, 4, 12], "structur": 1, "db": 1, "api": [1, 4, 7, 13], "config": [1, 2, 6, 7, 9, 12, 15], "object": [1, 2, 4, 7], "how": [1, 10, 15], "thei": [1, 4], "match": [1, 4, 7], "togeth": 1, "sync": 1, "oper": [1, 4, 12, 14], "commun": [1, 7, 10], "syncloop": 1, "schedul": [1, 4], "borderleaf": 1, "aci": [1, 15], "transit": [1, 2, 7], "In": [1, 4, 7], "debug": 1, "mainten": 1, "float": 1, "ip": [1, 7], "scale": 1, "limit": 1, "numer": [1, 12], "attribut": [1, 4, 12], "respons": [1, 4, 7], "rang": 1, "varieti": 2, "plane": [2, 7], "control": [2, 4, 7, 15, 17], "protocol": [2, 4], "resourc": [2, 4], "share": [2, 4], "entiti": 2, "backbon": 2, "page": [2, 10, 12], "gather": 2, "explain": [2, 18], "signific": [2, 4], "correpsond": 2, "eg": 2, "ethernet1": [2, 4], "switch": [2, 3, 4, 6, 7, 15], "metagroup": [2, 4], "appear": 2, "lag": 2, "channel101": 2, "assign": [2, 4], "number": [2, 4, 7], "alloc": [2, 3, 4, 7], "netbox": [2, 15], "model": 2, "switchgroup": [2, 4, 6, 7, 15], "infra_network": [2, 4], "3750": [2, 7], "region": [2, 4, 7], "10000": [2, 7], "65535": [2, 7], "through": [2, 4], "must": [2, 4, 7], "l2": [2, 4, 9], "evpn": 2, "rd": [2, 4], "depend": [2, 4], "type": [2, 4], "format": 2, "administr": 2, "subfield": 2, "f": [2, 4, 7], "switchgroup_id": 2, "vni_id": 2, "result": 2, "12666": 2, "1112": [2, 4], "az": [2, 7], "d": [2, 7], "rt": 2, "az_numb": 2, "4": [2, 4, 7], "l3": [2, 4, 9], "maintain": [2, 4], "preconfigur": [2, 4], "vrf": [2, 4, 7], "affin": 2, "2": [2, 4, 7, 15], "switch_asn": 2, "az_hint": 2, "vrf_id": [2, 7], "02d": 2, "hint": [2, 4], "76": 2, "65130": [2, 4], "4122": 2, "4176": 2, "23": 2, "176": 2, "hierarch": [3, 4, 15], "portbind": [3, 15], "infra": [3, 4, 7], "lend": 3, "magic": 3, "One": 3, "vendor": [3, 7, 15], "foo": 3, "document": [4, 18], "describ": [4, 7, 15], "support": [4, 7], "combin": 4, "basi": 4, "assum": [4, 14], "broadcast": 4, "domain": 4, "wai": [4, 7], "establish": 4, "server": [4, 7], "specif": [4, 7, 10], "demand": 4, "sub": 4, "whenev": 4, "requir": [4, 7], "group": 4, "within": [4, 7], "inter": 4, "traffic": 4, "rout": [4, 7], "span": [4, 7], "extend": 4, "site": [4, 7], "function": 4, "when": [4, 7], "first": [4, 7], "go": 4, "last": [4, 7], "trigger": 4, "request": [4, 10], "set": [4, 7], "below": [4, 7, 10], "determin": 4, "scope": 4, "anoth": 4, "environ": [4, 16], "trunk": 4, "differ": [4, 7, 10], "work": [4, 14], "mean": 4, "present": [4, 7], "side": 4, "point": 4, "notifi": 4, "own": 4, "signal": 4, "bind_port": 4, "updat": 4, "_port_postcommit": 4, "hook": 4, "associ": [4, 7], "servic": [4, 12, 15, 16, 17], "potenti": 4, "pick": 4, "allow": 4, "least": 4, "guarante": 4, "free": 4, "forward": 4, "outsid": 4, "solv": 4, "underli": 4, "base": [4, 7], "pair": [4, 9], "back": 4, "hierarchi": 4, "If": [4, 7, 10, 15], "more": [4, 7, 10], "than": [4, 7], "avail": [4, 15], "avoid": 4, "migrat": [4, 7], "flow": 4, "expect": 4, "via": [4, 15], "static": 4, "non": [4, 7], "topologi": 4, "variat": 4, "scenario": 4, "alreadi": 4, "exist": 4, "addit": [4, 10, 16], "aza": 4, "ad": [4, 7], "deploy": 4, "b": [4, 7], "bgw": 4, "No": 4, "action": 4, "c": 4, "AND": [4, 7], "azb": 4, "ml2_cc_fabric": 4, "regional_l3": 4, "fals": [4, 7], "az_l3": 4, "qa": [4, 7], "de": [4, 7], "1d": [4, 7], "global": 4, "asn_region": 4, "infra_network_default_vrf": 4, "mgmt": [4, 7], "900": 4, "node001": 4, "bb301": 4, "3": [4, 7], "sw1103a": 4, "sw1103b": 4, "node002": 4, "ethernet2": 4, "201": 4, "lacp": 4, "true": 4, "ethernet3": 4, "nova": 4, "comput": [4, 13], "10301100": 4, "untag": 4, "10": [4, 7], "246": 4, "24": 4, "dhcp_relai": 4, "147": 4, "204": 4, "45": 4, "247": 4, "122": 4, "10301101": 4, "101": [4, 7], "asn": [4, 7], "1103": 4, "availability_zon": 4, "1a": 4, "bgp_source_ip": 4, "03": 4, "114": 4, "203": 4, "password": 4, "nope": 4, "admin2": 4, "platform": [4, 7], "eo": [4, 7], "role": [4, 7], "vtep_ip": 4, "1b": 4, "aeec9fd4": 4, "30f7": 4, "4398": 4, "8554": 4, "34acb36b7712": 4, "ipv4_address_scop": 4, "24908a2d": 4, "55e8": 4, "4c03": 4, "87a9": 4, "e1493cd0d995": 4, "mtu": 4, "8950": 4, "floatingip": 4, "sfh03": 4, "eude1": 4, "project_id": 4, "07ed7aa018584972b40d94697b70a37b": 4, "null": 4, "10394": 4, "3150": 4, "2300": 4, "2340": 4, "statu": [4, 7], "activ": [4, 7], "14b7b745": 4, "8d5d": 4, "4667": 4, "a3e3": 4, "2be0facbb23d": 4, "72f96182": 4, "d93d": 4, "4aa7": 4, "a987": 4, "edb315875c9": 4, "bbe371a": 4, "341b": 4, "4f86": 4, "931a": 4, "e9c808cb312": 4, "size": 4, "reject": 4, "fce02a86": 4, "525c": 4, "49c9": 4, "a6cd": 4, "bf472881a83f": 4, "10400": 4, "3200": 4, "f77d7403": 4, "c46a": 4, "42d0": 4, "a20b": 4, "d104b8bc203f": 4, "n": 4, "possibl": 4, "vxlan1": 4, "target": 4, "export": 4, "import": [4, 7], "redistribut": 4, "nx": 4, "o": 4, "nve1": 4, "ingress": 4, "replic": 4, "suppress": 4, "arp": 4, "2420": 4, "vn": 4, "applic": [4, 7], "999": [4, 7], "remot": 4, "convent": 4, "v": [4, 7], "tag": [4, 7], "supernet": [4, 7], "announc": 4, "toward": 4, "upstream": 4, "azc": 4, "azd": 4, "cloudxx": 4, "ext": 4, "region_asn": 4, "1xx": 4, "peraz": 4, "11xx": 4, "21xx": 4, "31xx": 4, "41xx": 4, "aggreg": 4, "core": [4, 7], "std": 4, "address": [4, 7], "hcp03": 4, "public": 4, "export_rt_suffix": 4, "102": 4, "import_rt_suffix": 4, "cloud02": 4, "exampl": 4, "f2fd984c": 4, "45b1": 4, "4465": 4, "9f99": 4, "e72f86b896fa": 4, "address_scope_id": 4, "e6df3de0": 4, "16dd": 4, "46e3": 4, "850f": 4, "5418fd6dd820": 4, "47": 4, "8": 4, "fbc4b555": 4, "4266": 4, "46a0": 4, "916b": 4, "3863c649223a": 4, "20": 4, "cidr": 4, "192": 4, "27": [4, 7], "193": 4, "host_rout": 4, "ip_vers": 4, "sap": 4, "01": 4, "subnetpool_id": 4, "e8556528": 4, "01e6": 4, "4ccd": 4, "9286": 4, "0145ac7a75f4": 4, "25": 4, "zone": 4, "net": [4, 7], "nxo": [4, 7, 15], "pl": 4, "rm": 4, "maprm": 4, "relat": 4, "instanc": [4, 15], "redist": 4, "permit": 4, "extcommun": 4, "1102": 4, "30": 4, "40": 4, "2102": 4, "4102": 4, "unknown": 4, "seq": 4, "eq": 4, "vlan3150": 4, "virtual": [4, 7], "secondari": 4, "vlan3200": 4, "statement": 4, "compli": 4, "known": [4, 7], "shutdown": 4, "context": [4, 7], "famili": [4, 7], "ipv4": 4, "unicast": 4, "tenant": 4, "default": 4, "gw": 4, "exempt": 4, "nat": 4, "compar": 4, "sinc": 4, "current": [4, 7, 15], "them": 4, "next": [4, 7, 12, 14], "hop": 4, "binding_vif_typ": 4, "asr1k": 4, "device_own": 4, "router_gatewai": 4, "fixed_ip": 4, "subnet_id": 4, "ip_address": [4, 7], "197": 4, "8a307448": 4, "ef2a": 4, "4cae": 4, "9b2a": 4, "2edf0287e194": 4, "ab16807f": 4, "9c82": 4, "45e8": 4, "8e8d": 4, "da615eb8505a": 4, "floatdapnet": 4, "criteria": 4, "section": [4, 7, 15], "summar": [4, 7], "across": [4, 7], "summari": 4, "pod": 4, "filter": [4, 7], "undesir": 4, "It": [4, 7, 10], "polici": [4, 7], "peer": [4, 7], "do": [4, 10], "collect": 4, "continu": 4, "process": [4, 17], "individu": 4, "compress": 4, "merg": [4, 11], "adjac": 4, "where": [4, 7, 18], "equal": 4, "conflict": 4, "appropri": 4, "ccloudxx": 4, "remaind": 4, "10c48c80": 4, "b250": 4, "4452": 4, "a253": 4, "7f88b7a0deec": 4, "ff3452d0": 4, "c968": 4, "49c6": 4, "b1c7": 4, "152e5ffb11a": 4, "130": 4, "214": 4, "202": 4, "188": 4, "16": 4, "21": 4, "236": 4, "22": 4, "438157b9": 4, "3ce3": 4, "4370": 4, "8bb5": 4, "59131ff105f9": 4, "internet": 4, "215": 4, "26": [4, 7], "64": 4, "5051685d": 4, "37c5": 4, "4bab": 4, "98bf": 4, "8e797453ab03": 4, "ccloud02": 4, "high": 4, "churn": 4, "rate": 4, "mac": 4, "mobil": 4, "caus": [4, 15], "otherwis": 4, "mitig": 4, "To": [4, 16], "reduc": [4, 7], "packet": 4, "significantli": 4, "instantan": 4, "everi": 4, "certain": [4, 7], "fip": 4, "locat": 4, "destin": 4, "endpoint": 4, "until": 4, "becom": 4, "serv": 4, "mac_address": 4, "fa": 4, "3e": 4, "6d": 4, "d3": 4, "33": 4, "fixed_ip_address": 4, "180": 4, "7": 4, "floating_ip_address": 4, "104": 4, "75": 4, "floating_network_id": 4, "fb8a5ddd": 4, "611b": 4, "415a": 4, "8bd7": 4, "64d3033ab840": 4, "router_id": 4, "260c2d26": 4, "2904": 4, "4073": 4, "8407": 4, "7f94ed1e88b8": 4, "fa16": 4, "3e6d": 4, "d333": 4, "creation": 4, "hpb": 4, "front": [4, 7, 15], "attach": 4, "equip": [4, 7], "further": 4, "down": [4, 6], "chain": 4, "execut": 4, "final": 4, "subsequ": 4, "most": [4, 8, 10], "commonli": 4, "up": 4, "partial": 4, "accordingli": 4, "afterward": 4, "binding_host_id": 4, "binding_vif_detail": 4, "eu": [4, 7], "7574c44b": 4, "a3d7": 4, "471f": 4, "89e5": 4, "f3a450181f9a": 4, "switchport": 4, "storm": 4, "tree": 4, "portfast": 4, "errdis": 4, "recoveri": 4, "bpduguard": 4, "interv": 4, "300": 4, "channel201": 4, "min": 4, "link": [4, 8], "fallback": 4, "timeout": [4, 8], "tbd": 4, "800": [4, 7], "128": 4, "000": 4, "500": 4, "fx3": 4, "6": 4, "cli": [5, 17], "write": 6, "er": 6, "driver": [7, 8, 9, 10, 12, 14, 18], "tool": 7, "spine": 7, "compliant": 7, "regex": 7, "p": 7, "w": 7, "sw": 7, "ab": 7, "z": 7, "bb_no": 7, "9": 7, "Or": 7, "readabl": 7, "sw4223a": 7, "bb147": 7, "condit": 7, "appli": 7, "variabl": 7, "fashion": 7, "like": [7, 8, 10], "mlag": 7, "vpc": 7, "uniqu": 7, "digit": 7, "indic": 7, "zero": 7, "fist": 7, "second": 7, "sequenc": 7, "lower": 7, "charact": 7, "leaf_id": 7, "leaf_a_b": 7, "exactli": 7, "subrol": 7, "apod": 7, "bpod": 7, "netpod": 7, "stpod": 7, "vpod": 7, "push": 7, "bl": 7, "border": 7, "tl": 7, "legaci": 7, "purpos": 7, "bg": 7, "interconnect": 7, "": [7, 10], "multi": 7, "effect": 7, "express": 7, "valu": 7, "2100": 7, "3000": 7, "deliv": 7, "These": 7, "hypervisor": 7, "access": [7, 15, 17], "provis": 7, "pure": 7, "layer": 7, "enabl": 7, "prefix": 7, "portion": 7, "accord": 7, "exemplari": 7, "python": 7, "code": [7, 10, 15], "illustr": 7, "pynetbox": 7, "nb": 7, "dcim": 7, "slug": 7, "bb": 7, "271": 7, "pod_typ": 7, "vgroup": 7, "ipam": 7, "vlan_group": 7, "03d": 7, "pod_numb": 7, "pad": 7, "correspond": 7, "correct": 7, "mgmt_role": 7, "cc_tenant": 7, "tenanc": 7, "converg": [7, 10], "cloud": [7, 10], "mgmt_vlan": 7, "vid": 7, "build": 7, "block": 7, "precreat": 7, "retreiv": 7, "cc_mgmt_vrf": 7, "candidate_net": 7, "site_id": 7, "startswith": 7, "len": 7, "rais": 7, "valueerror": 7, "bb_net": 7, "ip_network": 7, "prefixes_26": 7, "mgmt_net": 7, "new_prefix": 7, "prefixes_27": 7, "mgmt_prefix": 7, "str": 7, "is_pool": 7, "shall": 7, "svi": 7, "order": 7, "reflect": 7, "unatagged_vlan": 7, "detail": 7, "snippet": 7, "prefixlen": 7, "alwai": 7, "assigned_object_typ": 7, "assigned_object_id": 7, "form": 7, "11": 7, "doe": 7, "yet": 7, "overlai": 7, "wide": 7, "100800": 7, "200800": 7, "mani": 7, "1ppppvvv": 7, "lead": 7, "371": 7, "10371100": 7, "bundl": 7, "logic": 7, "mark": 7, "instal": [7, 12, 16], "diagnost": 7, "new": [7, 18], "exact": 7, "cisco": 7, "made": 7, "assembl": 7, "enforc": 7, "howev": 7, "either": 7, "distinguish": 7, "variant": 7, "channel100": 7, "1110a": 7, "regular": 7, "1110b": 7, "usag": 7, "reserv": 7, "admin": [7, 17], "futur": 7, "99": 7, "henc": 7, "space": 7, "index": [7, 12], "slot": 7, "linecard": 7, "broken": 7, "breakout": 7, "never": 7, "lowest": 7, "calcul": 7, "slot_numb": 7, "interface_index": 7, "tagged_vlan": 7, "untagged_vlan": 7, "deriv": 7, "server_interfac": 7, "infra_vlan": 7, "vlan_consol": 7, "vlan_mgmt": 7, "vlan_vmot": 7, "vlan_backdoor": 7, "save": 7, "autogener": 8, "part": [8, 15], "importantli": 8, "actual": 8, "oslo": [9, 12, 15], "input": [9, 12], "pleas": 10, "contributor": [10, 12], "guid": [10, 12, 16], "start": [10, 15], "cover": 10, "common": 10, "account": 10, "interact": 10, "gerrit": 10, "system": [10, 15], "tailor": 10, "think": 10, "organ": 10, "welcom": [10, 18], "style": 10, "normal": 10, "max": 10, "line": [10, 12], "length": 10, "120": 10, "pep8": 10, "except": 10, "issu": 10, "github": [10, 15], "http": [10, 15, 16], "com": [10, 15], "sapcc": [10, 15], "open": 10, "you": [11, 12, 15, 18], "contribut": [11, 12], "task": 11, "track": 11, "report": 11, "bug": 11, "your": [11, 15, 16], "patch": 11, "content": 12, "introduct": 12, "architecutr": 12, "verifi": [12, 14], "step": [12, 14], "modul": 12, "search": 12, "compon": [13, 17], "networking_ccloud": [13, 14, 15, 16], "accept": 13, "respond": 13, "end": 13, "chapter": 14, "setup": 14, "tutori": 14, "node": [15, 17], "pip": 15, "mechanism_driv": 15, "make": 15, "sure": 15, "begin": 15, "problem": 15, "put": 15, "now": [15, 16, 18], "split": 15, "contain": 15, "path": 15, "infrastructur": 15, "bindinghost": 15, "amongst": 15, "gen": 15, "take": 15, "care": 15, "file": 15, "suppli": 15, "ignor": 15, "doc": 16, "org": 16, "ocata": 16, "perform": 17, "credenti": 17, "gain": 17, "openrc": 17, "success": 17, "launch": 17, "registr": 17, "hello": 18, "ll": 18, "bne": 18, "train": 18, "piec": 18, "softwar": 18, "run": 18}, "objects": {}, "objtypes": {}, "objnames": {}, "titleterms": {"cc": 0, "fabric": [0, 4, 13, 14], "ml2": [0, 4], "driver": [0, 1, 2, 3, 4, 6, 15], "intern": 0, "structur": 0, "overview": [0, 3, 4, 13], "db": 0, "api": 0, "config": [0, 4, 8], "object": 0, "how": 0, "thei": 0, "match": 0, "togeth": 0, "sync": 0, "oper": [0, 17], "agent": [0, 3, 4, 15], "design": [0, 3], "commun": [0, 4], "network": [0, 4, 7, 13, 14], "syncloop": 0, "schedul": 0, "borderleaf": 0, "aci": 0, "transit": [0, 4], "In": 0, "debug": 0, "mainten": 0, "relat": 0, "action": 0, "current": 0, "statu": 0, "diff": 0, "switch": 0, "leafpair": 0, "architecutr": 1, "numer": 2, "attribut": 2, "respons": 2, "rang": [2, 7], "featur": 3, "devic": 4, "singl": 4, "az": 4, "multi": 4, "workflow": 4, "legaci": 4, "integr": 4, "coordin": 4, "interconnect": 4, "dual": 4, "sampl": 4, "configur": [4, 6, 9, 15], "definit": 4, "On": 4, "apod": 4, "vpod": 4, "stpod": 4, "netpod": 4, "bpod": 4, "leaf": [4, 7], "border": 4, "gatewai": [4, 7], "subnet": 4, "rt": 4, "schema": 4, "extern": 4, "bgp": 4, "prefix": 4, "properti": 4, "dapnet": 4, "directli": 4, "access": 4, "privat": 4, "pool": 4, "float": 4, "ip": 4, "port": [4, 7], "vlan": [4, 7], "handoff": 4, "vmware": 4, "nsx": 4, "t": 4, "neutron": [4, 15], "octavia": 4, "f5": 4, "netapp": 4, "iron": 4, "uc": 4, "asr": 4, "bare": 4, "metal": 4, "vxlan": [4, 13, 14], "evpn": [4, 7], "flood": 4, "learn": 4, "scale": 4, "limit": 4, "relev": 4, "command": 5, "line": 5, "interfac": [5, 7], "refer": [5, 19], "gener": 7, "input": 7, "pair": 7, "hostnam": 7, "convent": 7, "type": 7, "ccloud": [7, 13, 14], "pod": 7, "leav": 7, "cnd": 7, "l2": 7, "l3": 7, "tenant": 7, "infrastructur": 7, "anycast": 7, "dhcp": 7, "relai": 7, "vni": 7, "map": 7, "cabl": 7, "link": 7, "aggreg": 7, "group": 7, "lag": 7, "netbox": 7, "model": 7, "id": 7, "assign": 7, "oslo": 8, "so": 10, "you": 10, "want": 10, "contribut": 10, "task": 10, "track": 10, "report": 10, "bug": 10, "get": 10, "your": 10, "patch": 10, "merg": 10, "contributor": 11, "document": [11, 12], "welcom": 12, "networking_ccloud": 12, "indic": 12, "tabl": 12, "servic": [13, 14], "instal": [14, 15], "guid": 14, "next": 16, "step": 16, "verifi": 17, "introduct": 18}, "envversion": {"sphinx.domains.c": 2, "sphinx.domains.changeset": 1, "sphinx.domains.citation": 1, "sphinx.domains.cpp": 8, "sphinx.domains.index": 1, "sphinx.domains.javascript": 2, "sphinx.domains.math": 2, "sphinx.domains.python": 3, "sphinx.domains.rst": 2, "sphinx.domains.std": 2, "sphinx": 57}, "alltitles": {"CC-Fabric ML2 Driver Internals": [[0, "cc-fabric-ml2-driver-internals"]], "Structural Overview": [[0, "structural-overview"]], "DB, API and Config Objects & How They Match Together": [[0, "db-api-and-config-objects-how-they-match-together"]], "Sync Operations": [[0, "sync-operations"]], "Agent Design": [[0, "agent-design"]], "Agent Communication": [[0, "agent-communication"]], "Network Syncloop (in Agent)": [[0, "network-syncloop-in-agent"]], "Network Scheduling on Borderleafs and ACI Transits": [[0, "network-scheduling-on-borderleafs-and-aci-transits"]], "In-Driver API for Debugging and Maintenance": [[0, "in-driver-api-for-debugging-and-maintenance"]], "Network-Related Actions": [[0, "network-related-actions"]], "Current Network Status": [[0, "current-network-status"]], "Network Diff": [[0, "network-diff"]], "Network Sync": [[0, "network-sync"]], "Switch / Leafpair Related Actions": [[0, "switch-leafpair-related-actions"]], "Driver Related Actions": [[0, "driver-related-actions"]], "Driver Architecutre": [[1, "driver-architecutre"]], "Numerical Attributes": [[2, "numerical-attributes"]], "Driver Responsible Ranges": [[2, "driver-responsible-ranges"]], "Ranges": [[2, "id4"]], "Overview": [[3, "overview"], [4, "overview"]], "Features": [[3, "features"]], "Driver-Agent Design": [[3, "driver-agent-design"]], "Device Config": [[4, "device-config"]], "Network": [[4, "network"]], "Single AZ": [[4, "single-az"], [4, "id1"]], "Multi AZ": [[4, "multi-az"]], "Workflow": [[4, "workflow"]], "Legacy Fabric Integration": [[4, "legacy-fabric-integration"]], "Legacy driver coordination": [[4, "legacy-driver-coordination"]], "Legacy fabric interconnection": [[4, "legacy-fabric-interconnection"]], "Dual AZ with Dual Legacy AZ": [[4, "dual-az-with-dual-legacy-az"]], "Dual AZ with Single Legacy AZ": [[4, "dual-az-with-single-legacy-az"]], "Multi AZ with Multi Legacy AZ": [[4, "multi-az-with-multi-legacy-az"]], "Multi AZ with Dual Legacy AZ": [[4, "multi-az-with-dual-legacy-az"]], "Sample Driver Configuration": [[4, "sample-driver-configuration"], [4, "id2"]], "Sample Network Definition": [[4, "sample-network-definition"]], "Single AZ Network": [[4, "single-az-network"]], "Multi AZ Network": [[4, "multi-az-network"]], "On Device configuration": [[4, "on-device-configuration"], [4, "id3"], [4, "id4"]], "aPOD/vPOD/stPOD/netPOD/bPOD/Transit leafs": [[4, "apod-vpod-stpod-netpod-bpod-transit-leafs"], [4, "id6"]], "Border Gateway": [[4, "border-gateway"]], "Subnet": [[4, "subnet"]], "RT and Community Schema": [[4, "id8"]], "External Network": [[4, "external-network"]], "Sample Subnet Definition": [[4, "sample-subnet-definition"]], "BGP prefix properties": [[4, "id9"]], "DAPnet Directly Accessible Private Network": [[4, "dapnet-directly-accessible-private-network"]], "Sample DAPnet Definition": [[4, "sample-dapnet-definition"]], "Subnet Pool": [[4, "subnet-pool"]], "Driver Configuration": [[4, "driver-configuration"], [6, "driver-configuration"], [15, "driver-configuration"]], "Sample Subnet Pool Definition": [[4, "sample-subnet-pool-definition"]], "On Device Configuration": [[4, "id5"], [4, "id7"]], "Floating IP": [[4, "floating-ip"]], "Sample Floating IP Definition": [[4, "sample-floating-ip-definition"]], "netPOD leafs": [[4, "netpod-leafs"]], "Port": [[4, "port"]], "VLAN Handoff": [[4, "vlan-handoff"]], "Sample Driver Config": [[4, "sample-driver-config"]], "Sample Port Definition": [[4, "sample-port-definition"]], "VMware NSX-t, Neutron Network Agent, Octavia F5, Netapp, Ironic UCS, Neutron ASR ml2": [[4, "vmware-nsx-t-neutron-network-agent-octavia-f5-netapp-ironic-ucs-neutron-asr-ml2"]], "Ironic Bare Metal Ports": [[4, "ironic-bare-metal-ports"]], "VXLAN EVPN Handoff": [[4, "vxlan-evpn-handoff"]], "VXLAN Flood and Learn Handoff": [[4, "vxlan-flood-and-learn-handoff"]], "Scaling Limits": [[4, "scaling-limits"]], "Relevant Device Scaling Limits": [[4, "id10"]], "Command line interface reference": [[5, "command-line-interface-reference"]], "Generator Input": [[7, "generator-input"]], "Leaf Pair": [[7, "leaf-pair"]], "Hostname Convention": [[7, "hostname-convention"]], "Leaf Types": [[7, "leaf-types"]], "CCloud Pod Leaves": [[7, "ccloud-pod-leaves"]], "CND EVPN Leaf Types:": [[7, "cnd-evpn-leaf-types"]], "L2/L3 Networks": [[7, "l2-l3-networks"]], "Tenant Network VLAN range": [[7, "tenant-network-vlan-range"]], "Infrastructure Networks": [[7, "infrastructure-networks"]], "Anycast Gateway": [[7, "anycast-gateway"]], "DHCP Relay": [[7, "dhcp-relay"]], "L2 Networks VLAN to VNI mapping": [[7, "l2-networks-vlan-to-vni-mapping"]], "Ports and Interfaces": [[7, "ports-and-interfaces"]], "Cables": [[7, "cables"]], "Link Aggregation Groups": [[7, "link-aggregation-groups"]], "LAG Ranges": [[7, "id1"]], "Netbox Modeller LAG ID Generation": [[7, "netbox-modeller-lag-id-generation"]], "Infrastructure Network Assignment": [[7, "infrastructure-network-assignment"]], "Oslo Config": [[8, "oslo-config"]], "Configuration": [[9, "configuration"]], "So You Want to Contribute\u2026": [[10, "so-you-want-to-contribute"]], "Task Tracking": [[10, "task-tracking"]], "Reporting a Bug": [[10, "reporting-a-bug"]], "Getting Your Patch Merged": [[10, "getting-your-patch-merged"]], "Contributor Documentation": [[11, "contributor-documentation"]], "Welcome to the documentation of networking_ccloud": [[12, "welcome-to-the-documentation-of-networking-ccloud"]], "Indices and tables": [[12, "indices-and-tables"]], "Networking CCloud VXLAN Fabric service overview": [[13, "networking-ccloud-vxlan-fabric-service-overview"]], "Networking CCloud VXLAN Fabric service installation guide": [[14, "networking-ccloud-vxlan-fabric-service-installation-guide"]], "Install and configure": [[15, "install-and-configure"]], "Installation": [[15, "installation"]], "Neutron Configuration": [[15, "neutron-configuration"]], "Agent Configuration": [[15, "agent-configuration"]], "Next steps": [[16, "next-steps"]], "Verify operation": [[17, "verify-operation"]], "Introduction": [[18, "introduction"]], "References": [[19, "references"]]}, "indexentries": {}})