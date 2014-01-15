import iptables
import pprint
from cStringIO import StringIO

ctstate_dict = {
        iptables.CT_ESTABLISHED: "ESTABLISHED",
        iptables.CT_INVALID: "INVALID",
        iptables.CT_NEW: "NEW",
        iptables.CT_RELATED: "RELATED",
        iptables.CT_UNTRACKED: "UNTRACKED",
        iptables.CT_DNAT: "DNAT",
        iptables.CT_SNAT: "SNAT"
        }

tcp_flags_dict = {
        iptables.TCP_FLAG_ALL: "ALL",
        iptables.TCP_FLAG_ACK: "ACK",
        iptables.TCP_FLAG_FIN: "FIN",
        iptables.TCP_FLAG_NONE: "NONE",
        iptables.TCP_FLAG_PSH: "PSH",
        iptables.TCP_FLAG_RST: "RST",
        iptables.TCP_FLAG_SYN: "SYN",
        iptables.TCP_FLAG_URG: "URG"
        }

icmp_code_dict = {
        0xff: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "any"
                } 
            ],
        iptables.ICMP_ECHOREPLY: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "echo-reply"
                }
            ],
        iptables.ICMP_DEST_UNREACH: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "dest-unreach"
                },
            {
                "min": 0x0,
                "max": 0x0,
                "name": "network-unreach"
                },
            {
                "min": 0x1,
                "max": 0x1,
                "name": "host-unreach"
                },
            {
                "min": 0x2,
                "max": 0x2,
                "name": "protocol-unreach"
                }
            ] 
        }

t = iptables.get_entries("filter") 
print "table: %s" % t["tablename"]
print "chains: ", " ".join(t["chains"].keys())

def handle_matches(rule_buffer, match_tuple):
    match, value = match_tuple
    if match == "conntrack": 
        rule_buffer.write("-m conntrack ")
        if "state" in value:
            state_buffer = StringIO() 
            state_buffer.write("--ctstate ")
            state = value["state"] 
            state_buffer.write(" ".join([x for x in ctstate_dict if x & state])+" ")
            rule_buffer.write(state_buffer.getvalue())
            state_buffer.close()
    if match == "tcp":
        rule_buffer.write("-m tcp ") 
        tcp_buffer = StringIO()
        invflags = value["invflags"]
        if value["dpts"] != (0, 65535):
            ft = "--dports: %s " % "-".join(value["dpts"])
            if invflags & iptables.XT_TCP_INV_DSTPT:
                ft = "not " + ft
            tcp_buffer.write(ft)
        if value["spts"] != (0, 65535):
            ft = "--sports: %s " % "-".join(value["spts"])
            if invflags & iptables.XT_TCP_INV_SRCPT:
                ft = "not " + ft
            tcp_buffer.write(ft)
        if value["flag_cmp"]: 
            ft = "--tcp-flags %s " % " ".join([x for x in tcp_flags_dict if x & flags])
            if invflags & iptables.XT_TCP_INV_FLAGS: 
                ft = "not " + ft
            tcp_buffer.write(ft) 
        if value["options"]:
            ft = "--tcp-option %s " % value["options"]
            if invflags & iptables.XT_TCP_INV_OPTION:
                ft = "not " + ft
            tcp_buffer.write(ft)
        rule_buffer.write(tcp_buffer.getvalue())
        tcp_buffer.close()
    if match == "icmp":
        rule_buffer.write("-m icmp ")
        icmp_buffer = StringIO()



def handle_rule(rule_dict):
    rule_buffer = StringIO() 
    if "matches" in rule:
        #matches 
        for match_tuple in rule["matches"].items(): 
            #match plugins
            handle_matches(rule_buffer, match_tuple) 
                        
     

def handle_chains(table):
    for chain in t["chains"]: 
        for rule in rules:
            handle_rule(rule_dict)                      

pprint.pprint(dir(iptables))
