import iptables
import pprint
import pdb
from cStringIO import StringIO

protocol_dict = {
        iptables.IPPROTO_IP: "IP",
        iptables.IPPROTO_ICMP: "ICMP",
        iptables.IPPROTO_IGMP: "IGMP",
        iptables.IPPROTO_IPIP: "IPIP",
        iptables.IPPROTO_TCP: "TCP",
        iptables.IPPROTO_EGP: "EGP",
        iptables.IPPROTO_PUP: "PUP",
        iptables.IPPROTO_UDP: "UDP",
        iptables.IPPROTO_IDP: "IDP",
        iptables.IPPROTO_DCCP: "DCCP",
        iptables.IPPROTO_RSVP: "RSVP",
        iptables.IPPROTO_GRE: "GRE",
        iptables.IPPROTO_IPV6: "IPV6",
        iptables.IPPROTO_ESP: "ESP",
        iptables.IPPROTO_AH: "AH",
        iptables.IPPROTO_PIM: "PIM",
        iptables.IPPROTO_COMP: "COMP",
        iptables.IPPROTO_SCTP: "SCTP",
        iptables.IPPROTO_UDPLITE: "UDPLITE",
        iptables.IPPROTO_RAW: "RAW"
        }

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

pkttype_dict = {
        iptables.PACKET_HOST: "host",
        iptables.PACKET_BROADCAST: "broadcast",
        iptables.PACKET_MULTICAST: "multicast",
        iptables.PACKET_OTHERHOST: "othercast",
        iptables.PACKET_OUTGOING: "outgoing"
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
                },
            {
                "min": 0x3,
                "max": 0x3,
                "name": "port-unreach"
                },
            {
                "min": 0x4,
                "max": 0x4,
                "name": "frag-needed"
                },
            {
                "min": 0x5,
                "max": 0x5,
                "name": "source-route-failed"
                },
            {
                "min": 0x6,
                "max": 0x6,
                "name": "network-unknown"
                },
            {
                "min": 0x7,
                "max": 0x7,
                "name": "host-unknown"
                },
            {
                "min": 0x9,
                "max": 0x9,
                "name": "network-prohibited"
                },
            {
                "min": 0xa,
                "max": 0xa,
                "name": "host-prohibited"
                },
            {
                "min": 0xb,
                "max": 0xb,
                "name": "tos-network-unreach"
                },
            {
                "min": 0xc,
                "max": 0xc,
                "name": "tos-host-unreach"
                    },
            {
                "min": 0xd,
                "max": 0xd,
                "name": "comm-prohibited"
                },
            {
                "min": 0xe,
                "max": 0xe,
                "name": "host-precedence-violation"
                },
            {
                "min": 0xf,
                "max": 0xf,
                "name": "precedence-cutoff"
                } 
            ], 
        iptables.ICMP_SOURCE_QUENCH: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "source-quench"
                }
            ],
        iptables.ICMP_REDIRECT: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "redirect"
                },
            {
                "min": 0x0,
                "max": 0x0,
                "name": "network-redirect"
                },
            {
                "min": 0x1,
                "max": 0x1,
                "name": "host-redirect"
                },
            {
                "min": 0x2,
                "max": 0x2,
                "name": "tos-network-redirect"
                },
            {
                "min": 0x3,
                "max": 0x3,
                "name": "tos-host-rediect"
                }
            ],
        iptables.ICMP_ECHO: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "echo-request"
                }
            ],
        iptables.ICMP_TIME_EXCEEDED: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "time-exceeded"
                },
            {
                "min": 0x0,
                "max": 0x0,
                "name": "ttl-zero-during-transit"
                },
            {
                "min": 0x1,
                "max": 0x1,
                "name": "ttl-zero-during-reassembly"
                }
            ], 
        iptables.ICMP_PARAMETERPROB: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "parameter-problem"
                },
            {
                "min": 0x0,
                "max": 0x0,
                "name": "ip-header-bad"
                },
            {
                "min": 0x1,
                "max": 0x1,
                "name": "required-option-missing"
                }
            ],
        iptables.ICMP_TIMESTAMP: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "timestamp-request"
                }
            ],
        iptables.ICMP_TIMESTAMPREPLY: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "timestamp-reply"
                }
            ],
        iptables.ICMP_ADDRESS: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "address-mask-request"
                }
            ],
        iptables.ICMP_ADDRESSREPLY: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "address-mask-reply"
                }
            ] 
        }

def handle_matches(rule_buffer, match_tuple):
    match, value = match_tuple
    if match == "conntrack": 
        rule_buffer.write("-m conntrack ")
        if "state" in value:
            state_buffer = StringIO() 
            state_buffer.write("--ctstate ")
            state = value["state"] 
            state_buffer.write(" ".join([ctstate_dict[x] for x in ctstate_dict if x & state])+" ")
            rule_buffer.write(state_buffer.getvalue())
            state_buffer.close()
    elif match == "tcp":
        rule_buffer.write("-m tcp ") 
        tcp_buffer = StringIO()
        invflags = value["invflags"]
        if value["dpts"] != (0, 65535):
            ft = "--dports: %s " % "-".join([str(x) for x in value["dpts"]])
            if invflags & iptables.XT_TCP_INV_DSTPT:
                ft = "not " + ft
            tcp_buffer.write(ft)
        if value["spts"] != (0, 65535):
            ft = "--sports: %s " % "-".join([str(x) for x in value["spts"]])
            if invflags & iptables.XT_TCP_INV_SRCPT:
                ft = "not " + ft
            tcp_buffer.write(ft)
        if value["flag_cmp"]: 
            flags = value["flag_cmp"]
            ft = "--tcp-flags %s " % " ".join([tcp_flags_dict[x] for x in tcp_flags_dict if x & flags])
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
    elif match == "icmp":
        rule_buffer.write("-m icmp ")
        icmp_buffer = StringIO()
        typev = value["type"]
        if typev in icmp_code_dict:
            minv = value["min"]
            maxv = value["max"] 
            for i in icmp_code_dict[typev]:
                if minv == i["min"] and maxv == i["max"]:
                    ft = "--type %s " % i["name"]
                    if value["invflags"] & iptables.IPT_ICMP_INV:
                        ft = "not " + ft
                    icmp_buffer.write(ft)
        else:
            ft = "--type %d %d/%d " % (i["type"],i["min"], i["max"])
            if value["invflags"] & iptables.IPT_ICMP_INV:
                ft = "not " + ft
            icmp_buffer.write(ft)
        rule_buffer.write(icmp_buffer.getvalue())
        icmp_buffer.close()
    elif match == "limit":
        rule_buffer.write("-m limit ")
        limit_buffer = StringIO()
        if value["avg"]:
            limit_buffer.write("--avg %d " % value["avg"])
        if value["burst"]:
            limit_buffer.write("--burst %d " % value["burst"]) 
        rule_buffer.write(limit_buffer.getvalue())
        limit_buffer.close()
    elif match == "pkttype":
        rule_buffer.write("-m pkttype --type %s " % pkttype_dict[value["type"]]) 


def handle_rule(rule_buffer, rule_dict): 
    invflags = rule_dict["invflags"]
    if rule_dict["dstip"]:                     
        ft = "-dstip %s/%s " % (rule_dict["dstip"], rule_dict["dstip_mask"])
        if invflags & iptables.IPT_INV_DSTIP:
            ft = "not " + ft
        rule_buffer.write(ft)
    if rule_dict["srcip"]:
        ft = "-srcip %s/%s " % (rule_dict["srcip"], rule_dict["srcip_mask"])
        if invflags & iptables.IPT_INV_SRCIP:
            ft = "not " + ft 
        rule_buffer.write(ft)
    if rule_dict["iniface"]:
        ft = "-i %s/%s " % (rule_dict["iniface"], rule_dict["iniface_mask"])
        if invflags & iptables.IPT_INV_VIA_IN:
            ft = "not " + ft 
        rule_buffer.write(ft) 
    if rule_dict["outiface"]:
        ft = "-o %s/%s " % (rule_dict["outiface"], rule_dict["outiface_mask"])
        if invflags & iptables.IPT_INV_VIA_OUT:
            ft = "not " + ft
        rule_buffer.write(ft) 

    if rule_dict["protocol"]:
        ft = "-proto %s " % protocol_dict[rule_dict["protocol"]]
        if invflags & iptables.XT_INV_PROTO:
            ft = "not " + ft
        rule_buffer.write(ft)
    if rule_dict["flags"]:
        rule_buffer.write("-flags %d " % rule_dict["flags"])

    if rule_dict.get("verb"): 
        rule_buffer.write("-j %s " % str(rule_dict["verb"])) 
    if rule_dict["target"]: 
        rule_buffer.write("-j %s " % str(rule_dict["target"])) 
    if "matches" in rule_dict:
        #matches 
        for match_tuple in rule_dict["matches"].items(): 
            #match plugins
            handle_matches(rule_buffer, match_tuple) 
    
def handle_chains(table):
    t = iptables.get_entries(table) 
    print "table: %s" % t["tablename"]
    print "chains: ", " ".join(t["chains"].keys()) 
    for chain, rules in t["chains"].items(): 
        print "============in chain %s" % chain 
        for rule_dict in rules:
            rule_buffer = StringIO() 
            handle_rule(rule_buffer, rule_dict)                      
            print rule_buffer.getvalue()
            rule_buffer.close()

handle_chains("filter")
