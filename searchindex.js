Search.setIndex({"docnames": ["architecture/driver", "architecture/index", "architecture/numerical-attributes", "architecture/overview", "architecture/switch-config", "cli/index", "configuration/config-driver", "configuration/config-gen", "configuration/config-oslo", "configuration/index", "contributor/contributing", "contributor/index", "index", "install/get-started", "install/index", "install/install", "install/next-steps", "install/verify", "intro", "reference/index"], "filenames": ["architecture/driver.rst", "architecture/index.rst", "architecture/numerical-attributes.rst", "architecture/overview.rst", "architecture/switch-config.rst", "cli/index.rst", "configuration/config-driver.rst", "configuration/config-gen.rst", "configuration/config-oslo.rst", "configuration/index.rst", "contributor/contributing.rst", "contributor/index.rst", "index.rst", "install/get-started.rst", "install/index.rst", "install/install.rst", "install/next-steps.rst", "install/verify.rst", "intro.rst", "reference/index.rst"], "titles": ["CC-Fabric ML2 Driver Internals", "Driver Architecutre", "Numerical Attributes", "Overview", "Device Config", "Command line interface reference", "Driver Configuration", "Netbox Config Generator", "Oslo Config", "Configuration", "So You Want to Contribute\u2026", "Contributor Documentation", "Welcome to the documentation of networking_ccloud", "Networking CCloud VXLAN Fabric service overview", "Networking CCloud VXLAN Fabric service installation guide", "Install and configure", "Next steps", "Verify operation", "Introduction", "References"], "terms": {"note": [0, 10, 15], "ar": [0, 2, 4, 6, 7, 9, 10, 15], "draft": 0, "thought": 0, "have": [0, 4, 6, 7, 10, 15], "been": [0, 6], "record": [0, 4], "over": [0, 4, 6, 7], "cours": 0, "project": [0, 10, 16, 17], "some": [0, 4, 10, 15], "written": 0, "befor": 0, "implement": [0, 4], "while": [0, 9], "wa": 0, "being": [0, 4], "done": [0, 4], "therefor": 0, "might": [0, 10, 15], "100": [0, 4, 6, 7], "accur": 0, "need": [0, 2, 4, 6, 7, 10, 15], "review": [0, 10], "The": [0, 2, 4, 6, 7, 9, 13, 14, 15], "follow": [0, 2, 4, 6, 7, 13, 14], "relev": 0, "configur": [0, 2, 7, 8, 12, 14, 18], "id": [0, 2, 4], "us": [0, 2, 4, 6, 7, 9, 10, 15, 18], "name": [0, 2, 4, 6, 7, 15], "refer": [0, 2, 6, 7, 12], "thi": [0, 2, 4, 6, 7, 9, 10, 14, 15, 18], "availability_zone_hint": [0, 4], "decid": 0, "port": [0, 1, 2, 6, 9], "can": [0, 4, 6, 7, 8, 10, 15], "bound": [0, 2, 6, 7], "admin_state_up": [0, 4], "fixm": [0, 8], "should": [0, 4, 7, 18], "we": [0, 4, 7, 8, 9, 10], "respect": [0, 4], "flag": 0, "router": [0, 4, 7], "extern": [0, 2, 7], "subnet": [0, 1, 2, 7], "belong": [0, 4, 7], "singl": [0, 7], "onli": [0, 4, 7, 15, 17], "gateway_ip": [0, 4], "binding_host": [0, 2, 4, 6], "host": [0, 3, 4, 6], "which": [0, 2, 4, 6, 7, 15], "map": [0, 2, 4, 6, 15], "hostgroup": [0, 2, 4, 7, 9, 15], "binding_profil": [0, 4], "altern": 0, "sourc": [0, 6, 17], "bind": [0, 4, 6], "baremet": [0, 3], "tabl": [0, 4], "networkseg": 0, "network_typ": [0, 4], "vxlan": [0, 2, 10, 12, 15, 17], "vlan": [0, 2, 6], "manag": [0, 1, 4, 6, 9], "segment": [0, 2, 3, 4], "neutron": [0, 7, 14, 18], "u": [0, 4, 7], "network_id": [0, 4], "i": [0, 2, 4, 6, 7, 10, 15], "physical_network": [0, 4], "physnet": [0, 7], "defin": [0, 4, 6, 7], "segmentation_id": [0, 4], "vni": [0, 2, 4, 6], "segment_index": 0, "level": [0, 4, 6, 7, 18], "0": [0, 2, 4, 6, 7], "top": [0, 4, 6, 7, 18], "1": [0, 2, 4, 6, 7, 15], "ml2_port_bind": 0, "see": [0, 2, 7, 16], "profil": 0, "vif_detail": 0, "extra": [0, 2, 6], "ml2_port_binding_level": 0, "each": [0, 4, 7, 17], "ha": [0, 2, 4, 7], "entri": [0, 4], "again": [0, 6], "isn": 0, "t": 0, "duplic": 0, "our": [0, 2, 7, 10], "pool": [0, 1, 7], "multipl": [0, 3, 4, 6, 7], "same": [0, 4, 15], "physnet_nam": 0, "list": [0, 2, 4, 6, 7, 17], "interfac": [0, 2, 4, 6, 9, 12], "A": [0, 4, 6, 7], "consist": [0, 9, 13], "hold": 0, "physic": [0, 6, 7], "question": [0, 4], "well": [0, 4], "els": [0, 2, 15], "cannot": 0, "so": [0, 11, 12, 15], "gener": [0, 2, 4, 8, 9, 10, 12, 15], "full": [0, 4, 6, 7], "look": [0, 6, 7], "thing": [0, 8], "all": [0, 2, 4, 6, 7, 10, 15], "specifi": 0, "found": [0, 2, 7], "queri": 0, "re": [0, 7], "carri": 0, "There": [0, 2, 4, 7], "three": 0, "hostgroupin": 0, "one": [0, 3, 4, 7, 15], "delet": [0, 4], "snyc": 0, "get": [0, 11, 15], "find": 0, "creat": [0, 4, 7], "hosgroup": 0, "check": [0, 7, 10], "ani": [0, 2, 4, 6, 7], "remain": 0, "stop": 0, "other": [0, 4, 15], "still": [0, 6], "mayb": 0, "rpc": 0, "call": [0, 4, 6, 13], "remov": [0, 4, 6], "from": [0, 4, 6, 7, 9, 10], "unus": 0, "help": 0, "could": [0, 4], "necessari": [0, 4, 7], "send": 0, "tell": 0, "complet": [0, 2, 15], "clean": 0, "add": [0, 4, 16], "replac": 0, "For": [0, 4, 7, 10], "chang": [0, 4], "an": [0, 2, 4, 6, 7, 10, 18], "includ": [0, 4, 7, 15, 16], "inform": [0, 4, 10, 15], "per": [0, 3, 4, 7, 15], "identifi": [0, 2, 4, 7], "mappin": 0, "local": [0, 4, 7], "descript": [0, 4, 8, 15], "uuid": 0, "translat": [0, 4], "channel": [0, 4, 7], "option": [0, 4, 7], "member": [0, 4, 6, 7], "subinterfac": 0, "overriden": 0, "moment": [0, 7], "idea": 0, "would": [0, 4, 6, 9], "case": [0, 4, 6, 7], "direct": 0, "stuff": [0, 15], "e": [0, 7, 10], "g": [0, 10], "nativ": [0, 4], "both": [0, 4, 7], "maximum": 0, "capac": 0, "x": [0, 7], "2000": [0, 2, 7], "arista": [0, 4, 6, 7, 15], "1750": 0, "directli": 0, "insid": [0, 18], "openstack": [0, 2, 4, 6, 7, 10, 14, 16, 17], "authent": 0, "facil": 0, "provid": [0, 2, 4, 6, 13, 14], "command": [0, 12, 17], "mode": [0, 3, 4, 7], "show": 0, "given": [0, 4], "pull": [0, 10], "enricht": 0, "knowledg": 0, "leaf": [0, 6], "etc": [0, 4, 7, 10], "basic": [0, 10], "data": [0, 2], "hand": [0, 4, 9], "out": [0, 4, 7, 10], "its": [0, 4, 6, 7], "state": [0, 7], "ask": 0, "devic": [0, 1, 9, 12, 15], "off": [0, 4], "return": 0, "between": [0, 2, 3, 4], "those": [0, 4, 7], "two": [0, 4, 7, 15], "user": [0, 4, 6, 13], "dictionari": 0, "reappli": 0, "mai": [0, 6], "want": [0, 11, 12], "leftov": 0, "though": 0, "also": [0, 4, 6, 7], "handl": [0, 4], "separ": 0, "cleanup": 0, "loop": [0, 4], "brainstorm": 0, "phase": 0, "test": 0, "connect": [0, 4, 7], "dump": [0, 8], "version": [0, 7], "uptim": 0, "resync": 0, "paus": 0, "avocado": [0, 3], "architectur": 1, "network": [1, 5, 6, 9, 10, 12, 15, 17, 18, 19], "ccloud": [1, 4, 5, 10, 12, 15, 17, 18, 19], "overview": [1, 2, 12, 14], "featur": [1, 4], "agent": [1, 14], "design": 1, "cc": [1, 4, 6, 7, 12, 15], "fabric": [1, 7, 10, 12, 15, 17], "ml2": [1, 3, 10, 12, 15, 18], "intern": [1, 4, 12], "structur": [1, 9], "db": 1, "api": [1, 4, 13], "config": [1, 2, 6, 9, 12, 15], "object": [1, 2, 4, 6, 7], "how": [1, 7, 9, 10, 15], "thei": [1, 4, 6, 7], "match": [1, 4, 7], "togeth": 1, "sync": 1, "oper": [1, 4, 12, 14], "commun": [1, 6, 10], "syncloop": 1, "schedul": [1, 4], "borderleaf": 1, "aci": [1, 15], "transit": [1, 2, 7], "In": [1, 4, 6, 7, 9], "debug": 1, "mainten": 1, "float": 1, "ip": [1, 7], "scale": 1, "limit": 1, "numer": [1, 12], "attribut": [1, 4, 12], "respons": [1, 4, 7], "rang": [1, 4], "varieti": 2, "plane": [2, 6], "control": [2, 4, 6, 7, 15, 17], "protocol": [2, 4], "resourc": [2, 4], "share": [2, 4], "entiti": 2, "backbon": 2, "page": [2, 10, 12], "gather": [2, 7], "explain": [2, 18], "signific": [2, 4], "correpsond": 2, "eg": 2, "ethernet1": [2, 4, 6], "switch": [2, 3, 4, 6, 7, 15], "metagroup": [2, 4, 6, 7], "appear": 2, "lag": 2, "channel101": [2, 6], "assign": [2, 4, 7], "number": [2, 4, 6, 7], "alloc": [2, 3, 4, 7], "netbox": [2, 9, 12, 15], "model": 2, "switchgroup": [2, 4, 7, 9, 15], "infra_network": [2, 4, 7, 9], "3750": [2, 7], "region": [2, 4, 7], "10000": [2, 7], "65535": [2, 7], "through": [2, 4], "must": [2, 4, 6, 7], "l2": [2, 4, 9], "evpn": 2, "rd": [2, 4], "depend": [2, 4], "type": [2, 4], "format": 2, "administr": 2, "subfield": 2, "f": [2, 4, 7], "switchgroup_id": 2, "vni_id": 2, "result": 2, "12666": 2, "1112": [2, 4], "az": [2, 7], "d": [2, 6, 7], "rt": 2, "az_numb": 2, "4": [2, 4, 6, 7], "l3": [2, 4, 9], "maintain": [2, 4], "preconfigur": [2, 4, 6], "vrf": [2, 4, 6, 7], "affin": 2, "2": [2, 4, 6, 7, 9, 15], "switch_asn": 2, "az_hint": 2, "vrf_id": 2, "02d": 2, "hint": [2, 4], "76": 2, "65130": [2, 4, 6], "4122": 2, "4176": 2, "23": 2, "176": 2, "wai": [2, 4, 7], "either": [2, 7], "wholist": 2, "just": 2, "allow": [2, 4, 6], "pleas": [2, 10], "extra_vlan": [2, 7, 9], "detail": 2, "infrastructur": [2, 6, 15], "It": [2, 4, 7, 10], "doe": [2, 7], "aim": 2, "up": [2, 4, 7], "date": 2, "authorit": 2, "pod": [2, 4], "role": [2, 4, 7], "vpod": [2, 7], "infra": [2, 3, 4, 7], "vid": 2, "101": [2, 4, 6], "107": 2, "everi": [2, 4], "swift": 2, "node": [2, 15, 17], "mtu": [2, 4], "replic": [2, 4], "group": [2, 4, 6], "stpod": [2, 7], "754": 2, "756": 2, "cp": [2, 7], "k8": [2, 7], "peer": [2, 4, 7], "901": 2, "manila": [2, 7], "global": [2, 4, 6, 7], "981": 2, "hierarch": [3, 4, 15], "portbind": [3, 15], "lend": 3, "magic": 3, "One": 3, "vendor": [3, 7, 15], "foo": 3, "document": [4, 9, 18], "describ": [4, 7, 15], "support": [4, 7], "combin": 4, "basi": 4, "assum": [4, 6, 7, 14], "broadcast": 4, "domain": 4, "establish": 4, "server": [4, 7], "specif": [4, 6, 7, 10], "demand": 4, "sub": 4, "whenev": [4, 7], "requir": [4, 6, 7], "within": [4, 7], "inter": 4, "traffic": 4, "rout": [4, 6, 7], "span": [4, 7], "extend": 4, "site": 4, "function": 4, "when": [4, 7], "first": [4, 7], "go": 4, "last": [4, 7], "trigger": 4, "request": [4, 10], "set": [4, 6, 7], "below": [4, 7, 10], "determin": 4, "scope": [4, 7], "anoth": 4, "environ": [4, 7, 16], "trunk": 4, "differ": [4, 7, 10], "work": [4, 7, 14], "mean": 4, "present": 4, "side": [4, 6], "point": 4, "notifi": 4, "own": 4, "signal": 4, "bind_port": 4, "updat": 4, "_port_postcommit": 4, "hook": 4, "associ": [4, 6, 7], "servic": [4, 12, 15, 16, 17], "potenti": 4, "pick": [4, 7], "least": 4, "guarante": 4, "free": 4, "forward": 4, "outsid": 4, "solv": 4, "underli": 4, "base": [4, 7], "pair": [4, 7], "back": 4, "hierarchi": 4, "If": [4, 6, 7, 10, 15], "more": [4, 7, 9, 10], "than": 4, "avail": [4, 7, 15], "avoid": 4, "migrat": [4, 7], "flow": 4, "expect": [4, 7, 9], "via": [4, 15], "static": 4, "non": [4, 7], "topologi": [4, 9], "variat": 4, "scenario": 4, "alreadi": 4, "exist": [4, 7], "addit": [4, 7, 10, 16], "aza": 4, "ad": [4, 7], "deploy": 4, "b": [4, 7], "bgw": 4, "No": 4, "action": 4, "c": 4, "AND": [4, 7], "azb": 4, "ml2_cc_fabric": 4, "regional_l3": 4, "fals": [4, 6], "az_l3": 4, "qa": [4, 6], "de": [4, 6, 7], "1d": [4, 6], "asn_region": [4, 6], "infra_network_default_vrf": 4, "mgmt": [4, 6], "900": 4, "node001": [4, 6], "bb301": 4, "3": [4, 6, 7], "sw1103a": 4, "sw1103b": 4, "node002": [4, 6], "ethernet2": [4, 6], "201": 4, "lacp": [4, 6], "true": [4, 6], "ethernet3": 4, "nova": [4, 6], "comput": [4, 6, 13], "10301100": 4, "untag": 4, "10": [4, 6, 7], "246": 4, "24": [4, 6], "dhcp_relai": 4, "147": [4, 6], "204": 4, "45": 4, "247": 4, "122": 4, "10301101": 4, "asn": [4, 6, 7], "1103": 4, "availability_zon": [4, 6], "1a": 4, "bgp_source_ip": [4, 6], "03": 4, "114": 4, "203": 4, "password": [4, 6, 7], "nope": 4, "admin2": 4, "platform": [4, 6, 7], "eo": [4, 6, 7], "vtep_ip": [4, 6], "1b": 4, "aeec9fd4": 4, "30f7": 4, "4398": 4, "8554": 4, "34acb36b7712": 4, "ipv4_address_scop": 4, "24908a2d": 4, "55e8": 4, "4c03": 4, "87a9": 4, "e1493cd0d995": 4, "8950": 4, "floatingip": 4, "sfh03": 4, "eude1": 4, "project_id": 4, "07ed7aa018584972b40d94697b70a37b": 4, "null": 4, "10394": 4, "3150": 4, "2300": 4, "2340": 4, "statu": 4, "activ": [4, 7], "14b7b745": 4, "8d5d": 4, "4667": 4, "a3e3": 4, "2be0facbb23d": 4, "72f96182": 4, "d93d": 4, "4aa7": 4, "a987": 4, "edb315875c9": 4, "bbe371a": 4, "341b": 4, "4f86": 4, "931a": 4, "e9c808cb312": 4, "size": 4, "reject": 4, "fce02a86": 4, "525c": 4, "49c9": 4, "a6cd": 4, "bf472881a83f": 4, "10400": 4, "3200": 4, "f77d7403": 4, "c46a": 4, "42d0": 4, "a20b": 4, "d104b8bc203f": 4, "n": 4, "possibl": 4, "vxlan1": 4, "target": 4, "export": 4, "import": 4, "redistribut": 4, "nx": 4, "o": [4, 7], "nve1": 4, "ingress": 4, "suppress": 4, "arp": 4, "2420": 4, "vn": 4, "applic": [4, 7], "999": [4, 7], "remot": 4, "convent": [4, 7], "v": [4, 7], "tag": [4, 7], "supernet": [4, 7], "announc": 4, "toward": 4, "upstream": 4, "azc": 4, "azd": 4, "cloudxx": 4, "ext": 4, "region_asn": 4, "1xx": 4, "peraz": 4, "11xx": 4, "21xx": 4, "31xx": 4, "41xx": 4, "aggreg": [4, 6], "core": [4, 7], "std": 4, "address": [4, 7], "hcp03": 4, "public": 4, "export_rt_suffix": 4, "102": [4, 6], "import_rt_suffix": 4, "cloud02": [4, 6], "exampl": [4, 9], "f2fd984c": 4, "45b1": 4, "4465": 4, "9f99": 4, "e72f86b896fa": 4, "address_scope_id": 4, "e6df3de0": 4, "16dd": 4, "46e3": 4, "850f": 4, "5418fd6dd820": 4, "47": 4, "8": 4, "fbc4b555": 4, "4266": 4, "46a0": 4, "916b": 4, "3863c649223a": 4, "20": 4, "cidr": 4, "192": [4, 6], "27": [4, 6], "193": [4, 6], "host_rout": 4, "ip_vers": 4, "sap": 4, "01": 4, "subnetpool_id": 4, "e8556528": 4, "01e6": 4, "4ccd": 4, "9286": 4, "0145ac7a75f4": 4, "25": 4, "zone": 4, "nxo": [4, 7, 15], "pl": 4, "rm": 4, "relat": 4, "instanc": [4, 15], "redist": 4, "permit": 4, "extcommun": 4, "1102": 4, "30": 4, "40": 4, "These": [4, 7], "otherwis": 4, "octa": 4, "fail": 4, "build": 4, "valid": 4, "tree": 4, "2102": 4, "4102": 4, "crash": 4, "let": 4, "dummi": 4, "zeroconf": 4, "hackaround": 4, "problem": [4, 15], "169": 4, "254": 4, "255": 4, "null0": 4, "unknown": 4, "seq": 4, "vlan3150": 4, "virtual": 4, "secondari": 4, "vlan3200": 4, "statement": 4, "compli": 4, "known": [4, 6, 7], "shutdown": 4, "context": [4, 7], "famili": 4, "ipv4": 4, "unicast": 4, "tenant": 4, "default": [4, 6, 7], "gw": 4, "exempt": 4, "nat": 4, "compar": 4, "sinc": 4, "current": [4, 7, 15], "them": 4, "next": [4, 12, 14], "hop": 4, "binding_vif_typ": 4, "asr1k": 4, "device_own": 4, "router_gatewai": 4, "fixed_ip": 4, "subnet_id": 4, "ip_address": 4, "197": 4, "8a307448": 4, "ef2a": 4, "4cae": 4, "9b2a": 4, "2edf0287e194": 4, "ab16807f": 4, "9c82": 4, "45e8": 4, "8e8d": 4, "da615eb8505a": 4, "floatdapnet": 4, "criteria": 4, "section": [4, 7, 9, 15], "summar": [4, 7], "across": [4, 7], "summari": 4, "filter": 4, "undesir": 4, "polici": [4, 7], "do": [4, 10], "collect": 4, "continu": 4, "process": [4, 17], "individu": 4, "compress": 4, "merg": [4, 11], "adjac": 4, "where": [4, 7, 18], "equal": 4, "conflict": 4, "appropri": 4, "ccloudxx": 4, "remaind": 4, "10c48c80": 4, "b250": 4, "4452": 4, "a253": 4, "7f88b7a0deec": 4, "ff3452d0": 4, "c968": 4, "49c6": 4, "b1c7": 4, "152e5ffb11a": 4, "130": 4, "214": 4, "202": [4, 6], "188": 4, "16": 4, "21": 4, "236": 4, "22": 4, "438157b9": 4, "3ce3": 4, "4370": 4, "8bb5": 4, "59131ff105f9": 4, "internet": 4, "215": 4, "26": [4, 6], "64": 4, "5051685d": 4, "37c5": 4, "4bab": 4, "98bf": 4, "8e797453ab03": 4, "ccloud02": 4, "high": 4, "churn": 4, "rate": 4, "mac": 4, "mobil": 4, "caus": [4, 6, 15], "mitig": 4, "To": [4, 16], "reduc": [4, 7], "packet": 4, "significantli": 4, "instantan": 4, "certain": [4, 7], "fip": 4, "locat": 4, "destin": 4, "endpoint": 4, "until": 4, "becom": 4, "serv": 4, "mac_address": 4, "fa": 4, "3e": 4, "6d": 4, "d3": 4, "33": 4, "fixed_ip_address": 4, "180": 4, "7": 4, "floating_ip_address": 4, "104": [4, 6], "75": 4, "floating_network_id": 4, "fb8a5ddd": 4, "611b": 4, "415a": 4, "8bd7": 4, "64d3033ab840": 4, "router_id": 4, "260c2d26": 4, "2904": 4, "4073": 4, "8407": 4, "7f94ed1e88b8": 4, "fa16": 4, "3e6d": 4, "d333": 4, "creation": 4, "hpb": 4, "front": [4, 7, 15], "attach": 4, "equip": [4, 7], "further": [4, 6], "down": 4, "chain": 4, "execut": 4, "final": 4, "subsequ": 4, "most": [4, 8, 10], "commonli": 4, "partial": 4, "accordingli": 4, "afterward": 4, "binding_host_id": 4, "binding_vif_detail": 4, "eu": [4, 7], "7574c44b": 4, "a3d7": 4, "471f": 4, "89e5": 4, "f3a450181f9a": 4, "switchport": [4, 6], "storm": 4, "portfast": 4, "errdis": 4, "recoveri": 4, "bpduguard": 4, "interv": 4, "300": 4, "channel201": 4, "min": 4, "link": [4, 8], "fallback": 4, "timeout": [4, 8], "tbd": 4, "800": [4, 7], "128": 4, "000": 4, "500": 4, "fx3": 4, "6": 4, "cli": [5, 17], "suffix": 6, "direct_bind": 6, "properti": 6, "": [6, 7, 9, 10], "bb271": 6, "sw4113a": 6, "sw4113b": 6, "channel102": 6, "deliv": 6, "hypervisor": 6, "purpos": [6, 7], "access": [6, 15, 17], "provis": 6, "pure": [6, 7], "layer": [6, 7], "anycast": [6, 7], "gatewai": [6, 7], "suppos": 6, "bgp": [6, 7], "addition": [6, 7], "without": 6, "presenc": 6, "bb": 6, "consol": 6, "10271100": 6, "11": [6, 7], "12": 6, "65": 6, "10271101": 6, "vmotion": 6, "10271104": 6, "backdoor": 6, "225": 6, "106": 6, "10271106": 6, "henc": [6, 7], "unwant": 6, "effect": [6, 7], "unfortun": 6, "come": 6, "plai": 6, "program": 6, "memeb": 6, "406": 6, "4113": 6, "group_id": 6, "13": 6, "168": 6, "146": 6, "iv": 6, "the_hoff": 6, "fetch": 7, "cluster": 7, "input": 7, "tool": 7, "netbox_model": 7, "py": 7, "under": 7, "networking_ccloud": [7, 13, 14, 15, 16], "netbox_config_gen": 7, "entrypoint": 7, "gen": [7, 15], "nest": 7, "yaml": 7, "kei": 7, "helm": 7, "wrap": 7, "paramet": 7, "vault": 7, "inject": 7, "instead": 7, "plain": 7, "text": 7, "ref": 7, "routabl": 7, "suppli": [7, 15], "file": [7, 15], "address_scop": 7, "local_address_scop": 7, "global_address_scop": 7, "try": 7, "pars": 7, "item": 7, "r": 7, "os_region_nam": 7, "myapius": 7, "my": 7, "path": [7, 15], "pyccloud_secrets_repo_path": 7, "valu": 7, "w": 7, "cc_fabric": 7, "driver_config": 7, "path_to_helm_valu": 7, "spine": 7, "explicitli": 7, "ignor": [7, 15], "net": 7, "stage": 7, "compliant": 7, "regex": 7, "p": 7, "sw": 7, "ab": 7, "z": 7, "bb_no": 7, "9": 7, "Or": 7, "readabl": 7, "sw4223a": 7, "bb147": 7, "condit": 7, "appli": 7, "variabl": 7, "mlag": 7, "vpc": 7, "uniqu": 7, "digit": 7, "fashion": 7, "like": [7, 8, 10], "indic": 7, "zero": 7, "fist": 7, "second": 7, "sequenc": 7, "lower": 7, "charact": 7, "exactli": 7, "subrol": 7, "apod": 7, "bpod": 7, "netpod": 7, "push": 7, "bl": 7, "border": 7, "tl": 7, "legaci": 7, "bg": 7, "interconnect": 7, "multi": 7, "express": 7, "2100": 7, "3000": 7, "order": 7, "correspond": 7, "logic": 7, "scheme": 7, "derive_vlan_vni": 7, "shall": 7, "enabl": 7, "met": 7, "get_infra_network_l3_data": 7, "prefix": 7, "correct": 7, "parent": 7, "As": 7, "live": 7, "tor": 7, "moddel": 7, "svi": 7, "unatagged_vlan": 7, "form": 7, "yet": 7, "consid": 7, "long": 7, "upgrad": 7, "start": [7, 10, 15], "end": [7, 13], "overlai": 7, "wide": 7, "100800": 7, "200800": 7, "mani": 7, "1ppppvvv": 7, "lead": 7, "371": 7, "10371100": 7, "bundl": 7, "accord": 7, "mark": 7, "instal": [7, 12, 16], "diagnost": 7, "endpooint": 7, "satisfi": 7, "loadbalanc": 7, "converg": [7, 10], "cloud": [7, 10], "filer": 7, "chassi": 7, "resid": 7, "vsphere": 7, "prod": 7, "controlplan": 7, "f5": 7, "vcmp": 7, "new": [7, 18], "exact": 7, "cisco": 7, "made": 7, "assembl": 7, "enforc": 7, "howev": 7, "distinguish": 7, "variant": 7, "channel100": 7, "1110a": 7, "regular": 7, "1110b": 7, "usag": 7, "reserv": 7, "admin": [7, 17], "futur": 7, "99": 7, "space": 7, "index": [7, 12], "slot": 7, "linecard": 7, "broken": 7, "breakout": 7, "never": 7, "lowest": 7, "calcul": 7, "slot_numb": 7, "interface_index": 7, "autogener": 8, "part": [8, 15], "importantli": 8, "actual": 8, "driver": [8, 9, 10, 12, 14, 18], "oslo": [9, 12, 15], "focuss": 9, "around": 9, "runtim": 9, "becaus": 9, "cumbersom": 9, "larg": 9, "what": 9, "prerequisit": 9, "run": [9, 18], "global_config": 9, "contributor": [10, 12], "guid": [10, 12, 16], "cover": 10, "common": 10, "account": 10, "interact": 10, "gerrit": 10, "system": [10, 15], "tailor": 10, "think": 10, "organ": 10, "welcom": [10, 18], "code": [10, 15], "style": 10, "normal": 10, "max": 10, "line": [10, 12], "length": 10, "120": 10, "pep8": 10, "except": 10, "issu": 10, "github": [10, 15], "http": [10, 15, 16], "com": [10, 15], "sapcc": [10, 15], "open": 10, "you": [11, 12, 15, 18], "contribut": [11, 12], "task": 11, "track": 11, "report": 11, "bug": 11, "your": [11, 15, 16], "patch": 11, "content": 12, "introduct": 12, "architecutr": 12, "verifi": [12, 14], "step": [12, 14], "modul": 12, "search": 12, "compon": [13, 17], "accept": 13, "respond": 13, "chapter": 14, "setup": 14, "tutori": 14, "pip": 15, "mechanism_driv": 15, "make": 15, "sure": 15, "begin": 15, "put": 15, "now": [15, 16, 18], "split": 15, "contain": 15, "bindinghost": 15, "amongst": 15, "take": 15, "care": 15, "doc": 16, "org": 16, "ocata": 16, "perform": 17, "credenti": 17, "gain": 17, "openrc": 17, "success": 17, "launch": 17, "registr": 17, "hello": 18, "ll": 18, "bne": 18, "train": 18, "piec": 18, "softwar": 18}, "objects": {}, "objtypes": {}, "objnames": {}, "titleterms": {"cc": 0, "fabric": [0, 4, 13, 14], "ml2": [0, 4], "driver": [0, 1, 2, 3, 4, 6, 7, 15], "intern": 0, "structur": 0, "overview": [0, 3, 4, 13], "db": 0, "api": 0, "config": [0, 4, 7, 8], "object": 0, "how": 0, "thei": 0, "match": 0, "togeth": 0, "sync": 0, "oper": [0, 17], "agent": [0, 3, 4, 15], "design": [0, 3], "commun": [0, 4], "network": [0, 2, 4, 7, 13, 14], "syncloop": 0, "schedul": 0, "borderleaf": 0, "aci": 0, "transit": [0, 4], "In": 0, "debug": 0, "mainten": 0, "relat": 0, "action": 0, "current": 0, "statu": 0, "diff": 0, "switch": 0, "leafpair": 0, "architecutr": 1, "numer": 2, "attribut": 2, "respons": 2, "rang": [2, 7], "manag": [2, 7], "featur": 3, "devic": [4, 7], "singl": 4, "az": 4, "multi": 4, "workflow": 4, "legaci": 4, "integr": 4, "coordin": 4, "interconnect": 4, "dual": 4, "sampl": 4, "configur": [4, 6, 9, 15], "definit": 4, "On": 4, "apod": 4, "vpod": 4, "stpod": 4, "netpod": 4, "bpod": 4, "leaf": [4, 7], "border": 4, "gatewai": 4, "subnet": 4, "rt": 4, "schema": 4, "extern": 4, "bgp": 4, "prefix": 4, "properti": 4, "dapnet": 4, "directli": 4, "access": 4, "privat": 4, "pool": 4, "float": 4, "ip": 4, "port": [4, 7], "vlan": [4, 7], "handoff": 4, "vmware": 4, "nsx": 4, "t": 4, "neutron": [4, 15], "octavia": 4, "f5": 4, "netapp": 4, "iron": 4, "uc": 4, "asr": 4, "bare": 4, "metal": 4, "vxlan": [4, 13, 14], "evpn": [4, 7], "flood": 4, "learn": 4, "scale": 4, "limit": 4, "relev": 4, "command": 5, "line": 5, "interfac": [5, 7], "refer": [5, 19], "exampl": [6, 7], "global_config": 6, "hostgroup": 6, "infra_network": 6, "extra_vlan": 6, "switchgroup": 6, "netbox": 7, "gener": 7, "run": 7, "hostnam": 7, "type": 7, "ccloud": [7, 13, 14], "pod": 7, "leav": 7, "cnd": 7, "l2": 7, "l3": 7, "tenant": 7, "infrastructur": 7, "dhcp": 7, "relai": 7, "implement": 7, "so": [7, 10], "far": 7, "extra": 7, "vni": 7, "map": 7, "cabl": 7, "rule": 7, "link": 7, "aggreg": 7, "group": 7, "lag": 7, "model": 7, "id": 7, "oslo": 8, "you": 10, "want": 10, "contribut": 10, "task": 10, "track": 10, "report": 10, "bug": 10, "get": 10, "your": 10, "patch": 10, "merg": 10, "contributor": 11, "document": [11, 12], "welcom": 12, "networking_ccloud": 12, "indic": 12, "tabl": 12, "servic": [13, 14], "instal": [14, 15], "guid": 14, "next": 16, "step": 16, "verifi": 17, "introduct": 18}, "envversion": {"sphinx.domains.c": 2, "sphinx.domains.changeset": 1, "sphinx.domains.citation": 1, "sphinx.domains.cpp": 8, "sphinx.domains.index": 1, "sphinx.domains.javascript": 2, "sphinx.domains.math": 2, "sphinx.domains.python": 3, "sphinx.domains.rst": 2, "sphinx.domains.std": 2, "sphinx": 57}, "alltitles": {"CC-Fabric ML2 Driver Internals": [[0, "cc-fabric-ml2-driver-internals"]], "Structural Overview": [[0, "structural-overview"]], "DB, API and Config Objects & How They Match Together": [[0, "db-api-and-config-objects-how-they-match-together"]], "Sync Operations": [[0, "sync-operations"]], "Agent Design": [[0, "agent-design"]], "Agent Communication": [[0, "agent-communication"]], "Network Syncloop (in Agent)": [[0, "network-syncloop-in-agent"]], "Network Scheduling on Borderleafs and ACI Transits": [[0, "network-scheduling-on-borderleafs-and-aci-transits"]], "In-Driver API for Debugging and Maintenance": [[0, "in-driver-api-for-debugging-and-maintenance"]], "Network-Related Actions": [[0, "network-related-actions"]], "Current Network Status": [[0, "current-network-status"]], "Network Diff": [[0, "network-diff"]], "Network Sync": [[0, "network-sync"]], "Switch / Leafpair Related Actions": [[0, "switch-leafpair-related-actions"]], "Driver Related Actions": [[0, "driver-related-actions"]], "Driver Architecutre": [[1, "driver-architecutre"]], "Numerical Attributes": [[2, "numerical-attributes"]], "Driver Responsible Ranges": [[2, "driver-responsible-ranges"]], "Ranges": [[2, "id4"]], "Driver Managed Networks": [[2, "driver-managed-networks"], [2, "id5"]], "Overview": [[3, "overview"], [4, "overview"]], "Features": [[3, "features"]], "Driver-Agent Design": [[3, "driver-agent-design"]], "Device Config": [[4, "device-config"]], "Network": [[4, "network"]], "Single AZ": [[4, "single-az"], [4, "id1"]], "Multi AZ": [[4, "multi-az"]], "Workflow": [[4, "workflow"]], "Legacy Fabric Integration": [[4, "legacy-fabric-integration"]], "Legacy driver coordination": [[4, "legacy-driver-coordination"]], "Legacy fabric interconnection": [[4, "legacy-fabric-interconnection"]], "Dual AZ with Dual Legacy AZ": [[4, "dual-az-with-dual-legacy-az"]], "Dual AZ with Single Legacy AZ": [[4, "dual-az-with-single-legacy-az"]], "Multi AZ with Multi Legacy AZ": [[4, "multi-az-with-multi-legacy-az"]], "Multi AZ with Dual Legacy AZ": [[4, "multi-az-with-dual-legacy-az"]], "Sample Driver Configuration": [[4, "sample-driver-configuration"], [4, "id2"]], "Sample Network Definition": [[4, "sample-network-definition"]], "Single AZ Network": [[4, "single-az-network"]], "Multi AZ Network": [[4, "multi-az-network"]], "On Device configuration": [[4, "on-device-configuration"], [4, "id3"], [4, "id4"]], "aPOD/vPOD/stPOD/netPOD/bPOD/Transit leafs": [[4, "apod-vpod-stpod-netpod-bpod-transit-leafs"], [4, "id6"]], "Border Gateway": [[4, "border-gateway"]], "Subnet": [[4, "subnet"]], "RT and Community Schema": [[4, "id8"]], "External Network": [[4, "external-network"]], "Sample Subnet Definition": [[4, "sample-subnet-definition"]], "BGP prefix properties": [[4, "id9"]], "DAPnet Directly Accessible Private Network": [[4, "dapnet-directly-accessible-private-network"]], "Sample DAPnet Definition": [[4, "sample-dapnet-definition"]], "Subnet Pool": [[4, "subnet-pool"]], "Driver Configuration": [[4, "driver-configuration"], [6, "driver-configuration"], [15, "driver-configuration"]], "Sample Subnet Pool Definition": [[4, "sample-subnet-pool-definition"]], "On Device Configuration": [[4, "id5"], [4, "id7"]], "Floating IP": [[4, "floating-ip"]], "Sample Floating IP Definition": [[4, "sample-floating-ip-definition"]], "netPOD leafs": [[4, "netpod-leafs"]], "Port": [[4, "port"]], "VLAN Handoff": [[4, "vlan-handoff"]], "Sample Driver Config": [[4, "sample-driver-config"]], "Sample Port Definition": [[4, "sample-port-definition"]], "VMware NSX-t, Neutron Network Agent, Octavia F5, Netapp, Ironic UCS, Neutron ASR ml2": [[4, "vmware-nsx-t-neutron-network-agent-octavia-f5-netapp-ironic-ucs-neutron-asr-ml2"]], "Ironic Bare Metal Ports": [[4, "ironic-bare-metal-ports"]], "VXLAN EVPN Handoff": [[4, "vxlan-evpn-handoff"]], "VXLAN Flood and Learn Handoff": [[4, "vxlan-flood-and-learn-handoff"]], "Scaling Limits": [[4, "scaling-limits"]], "Relevant Device Scaling Limits": [[4, "id10"]], "Command line interface reference": [[5, "command-line-interface-reference"]], "Example Configuration": [[6, "example-configuration"]], "global_config": [[6, "global-config"]], "hostgroups": [[6, "hostgroups"]], "infra_networks": [[6, "infra-networks"]], "extra_vlans": [[6, "extra-vlans"]], "switchgroups": [[6, "switchgroups"]], "Netbox Config Generator": [[7, "netbox-config-generator"]], "Run": [[7, "run"]], "Example": [[7, "example"]], "Managed Devices": [[7, "managed-devices"]], "Hostnames": [[7, "hostnames"]], "Leaf Types": [[7, "leaf-types"]], "CCloud Pod Leaves": [[7, "ccloud-pod-leaves"]], "CND EVPN Leaf Types:": [[7, "cnd-evpn-leaf-types"]], "L2/L3 Networks": [[7, "l2-l3-networks"]], "Tenant Network VLAN range": [[7, "tenant-network-vlan-range"]], "Infrastructure Networks": [[7, "infrastructure-networks"]], "DHCP Relay (not implemented so far)": [[7, "dhcp-relay-not-implemented-so-far"]], "Extra VLANs": [[7, "extra-vlans"]], "L2 Networks VLAN to VNI mapping": [[7, "l2-networks-vlan-to-vni-mapping"]], "Ports and Interfaces": [[7, "ports-and-interfaces"]], "Cables": [[7, "cables"]], "Rules for Driver Managed Interfaces": [[7, "rules-for-driver-managed-interfaces"]], "Link Aggregation Groups": [[7, "link-aggregation-groups"]], "LAG Ranges": [[7, "id1"]], "Netbox Modeller LAG ID Generation": [[7, "netbox-modeller-lag-id-generation"]], "Oslo Config": [[8, "oslo-config"]], "Configuration": [[9, "configuration"]], "So You Want to Contribute\u2026": [[10, "so-you-want-to-contribute"]], "Task Tracking": [[10, "task-tracking"]], "Reporting a Bug": [[10, "reporting-a-bug"]], "Getting Your Patch Merged": [[10, "getting-your-patch-merged"]], "Contributor Documentation": [[11, "contributor-documentation"]], "Welcome to the documentation of networking_ccloud": [[12, "welcome-to-the-documentation-of-networking-ccloud"]], "Indices and tables": [[12, "indices-and-tables"]], "Networking CCloud VXLAN Fabric service overview": [[13, "networking-ccloud-vxlan-fabric-service-overview"]], "Networking CCloud VXLAN Fabric service installation guide": [[14, "networking-ccloud-vxlan-fabric-service-installation-guide"]], "Install and configure": [[15, "install-and-configure"]], "Installation": [[15, "installation"]], "Neutron Configuration": [[15, "neutron-configuration"]], "Agent Configuration": [[15, "agent-configuration"]], "Next steps": [[16, "next-steps"]], "Verify operation": [[17, "verify-operation"]], "Introduction": [[18, "introduction"]], "References": [[19, "references"]]}, "indexentries": {}})