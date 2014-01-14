import iptables
import pprint
pprint.pprint(iptables.get_entries("filter"))
pprint.pprint(dir(iptables))
