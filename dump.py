import pprint
import iptables
t = iptables.get_table("filter")
pprint.pprint(t)

