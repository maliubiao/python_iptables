import _iptables
import pprint
import os
import pdb
import sys
from cStringIO import StringIO

jump_table = {
        }

verb_dict = {
        _iptables.NF_ACCEPT: "accept",
        _iptables.NF_DROP: "drop",
        _iptables.NF_QUEUE: "queue",
        _iptables.XT_RETURN: "return"
        }

protocol_dict = {
        _iptables.IPPROTO_IP: "IP",
        _iptables.IPPROTO_ICMP: "ICMP",
        _iptables.IPPROTO_IGMP: "IGMP",
        _iptables.IPPROTO_IPIP: "IPIP",
        _iptables.IPPROTO_TCP: "TCP",
        _iptables.IPPROTO_EGP: "EGP",
        _iptables.IPPROTO_PUP: "PUP",
        _iptables.IPPROTO_UDP: "UDP",
        _iptables.IPPROTO_IDP: "IDP",
        _iptables.IPPROTO_DCCP: "DCCP",
        _iptables.IPPROTO_RSVP: "RSVP",
        _iptables.IPPROTO_GRE: "GRE",
        _iptables.IPPROTO_IPV6: "IPV6",
        _iptables.IPPROTO_ESP: "ESP",
        _iptables.IPPROTO_AH: "AH",
        _iptables.IPPROTO_PIM: "PIM",
        _iptables.IPPROTO_COMP: "COMP",
        _iptables.IPPROTO_SCTP: "SCTP",
        _iptables.IPPROTO_UDPLITE: "UDPLITE",
        _iptables.IPPROTO_RAW: "RAW"
        }

ctstate_dict = {
        _iptables.CT_ESTABLISHED: "ESTABLISHED",
        _iptables.CT_INVALID: "INVALID",
        _iptables.CT_NEW: "NEW",
        _iptables.CT_RELATED: "RELATED",
        _iptables.CT_UNTRACKED: "UNTRACKED",
        _iptables.CT_DNAT: "DNAT",
        _iptables.CT_SNAT: "SNAT"
        }

tcp_flags_dict = { 
        _iptables.TCP_FLAG_ACK: "ACK",
        _iptables.TCP_FLAG_FIN: "FIN",
        _iptables.TCP_FLAG_NONE: "NONE",
        _iptables.TCP_FLAG_PSH: "PSH",
        _iptables.TCP_FLAG_RST: "RST",
        _iptables.TCP_FLAG_SYN: "SYN",
        _iptables.TCP_FLAG_URG: "URG"
        }

pkttype_dict = {
        _iptables.PACKET_HOST: "host",
        _iptables.PACKET_BROADCAST: "broadcast",
        _iptables.PACKET_MULTICAST: "multicast",
        _iptables.PACKET_OTHERHOST: "othercast",
        _iptables.PACKET_OUTGOING: "outgoing"
        }

log_dict = {
        _iptables.LOG_ALERT: "alert",
        _iptables.LOG_CRIT: "crit",
        _iptables.LOG_DEBUG: "debug",
        _iptables.LOG_EMERG: "emerg",
        _iptables.LOG_ERR: "err",
        _iptables.LOG_INFO: "info",
        _iptables.LOG_NOTICE: "notice",
        _iptables.LOG_WARNING: "warning",
        _iptables.LOG_TCPSEQ: "tcp-seq",
        _iptables.LOG_TCPOPT: "tcp-opt",
        _iptables.LOG_IPOPT: "ip-opt",
        _iptables.LOG_UID: "uid",
        _iptables.LOG_MACDECODE: "mac-decode"
        }

reject_dict = {
        _iptables.IPT_ICMP_NET_UNREACHABLE: "icmp-net-unreachable",
        _iptables.IPT_ICMP_HOST_UNREACHABLE: "icmp-host-unreachable",
        _iptables.IPT_ICMP_PROT_UNREACHABLE: "icmp-prot_unreachable",
        _iptables.IPT_ICMP_PORT_UNREACHABLE: "icmp-port_unreachable",
        _iptables.IPT_ICMP_ECHOREPLY: "icmp_echoreply",
        _iptables.IPT_ICMP_NET_PROHIBITED: "icmp-net-prohibited",
        _iptables.IPT_ICMP_HOST_PROHIBITED: "icmp-host-prohibited",
        _iptables.IPT_TCP_RESET: "tcp-reset",
        _iptables.IPT_ICMP_ADMIN_PROHIBITED: "icmp_admin_prohibited"
        }

icmp_code_dict = {
        0xff: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "any"
                } 
            ],
        _iptables.ICMP_ECHOREPLY: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "echo-reply"
                }
            ],
        _iptables.ICMP_DEST_UNREACH: [
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
        _iptables.ICMP_SOURCE_QUENCH: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "source-quench"
                }
            ],
        _iptables.ICMP_REDIRECT: [
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
        _iptables.ICMP_ECHO: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "echo-request"
                }
            ],
        _iptables.ICMP_TIME_EXCEEDED: [
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
        _iptables.ICMP_PARAMETERPROB: [
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
        _iptables.ICMP_TIMESTAMP: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "timestamp-request"
                }
            ],
        _iptables.ICMP_TIMESTAMPREPLY: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "timestamp-reply"
                }
            ],
        _iptables.ICMP_ADDRESS: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "address-mask-request"
                }
            ],
        _iptables.ICMP_ADDRESSREPLY: [
            {
                "min": 0x0,
                "max": 0xff,
                "name": "address-mask-reply"
                }
            ] 
        }


def all_avaiable_modules():
    result = []
    for root, dirs, files in os.walk("/lib/modules/%s/kernel/net" % os.uname()[2]):
        result.extend([x[8:-3] for x in files if x.startswith("iptable_")])
    return list(set(result))

def is_module_in_kernel(module):
    try:
        f = open("/proc/net/ip_tables_names", "r")
        modules = f.read()
        f.close()
    except Exception as e:
        raise Exception("read /proc/net/ip_tables_names failed")
       
    return module in modules: 

def load_iptables_module(module): 
    try:
        f = open("/proc/sys/kernel/modprobe", "r")
        modprobe = f.read().strip("\n")
        f.close()
    except Exception as e:
        raise Exception("find modprobe failed with %s", str(e))
      
    if not os.fork():
        os.execvp(modprobe, ["modprobe", "iptable_%s" % module])
        exit()
    pid, reason = os.wait()
    if (reason >> 8):
        raise Exception("failed to load module %s" % module) 


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
            if invflags & _iptables.XT_TCP_INV_DSTPT:
                ft = "not " + ft
            tcp_buffer.write(ft)
        if value["spts"] != (0, 65535):
            ft = "--sports: %s " % "-".join([str(x) for x in value["spts"]])
            if invflags & _iptables.XT_TCP_INV_SRCPT:
                ft = "not " + ft
            tcp_buffer.write(ft)
        if value["flag_cmp"]: 
            flags = value["flag_cmp"] 
            mask = value["flag_mask"]
            ft = "--tcp-flags %s/%s " % (
                    " ".join([tcp_flags_dict[x] for x in tcp_flags_dict if x & flags]),
                    ",".join([tcp_flags_dict[x] for x in tcp_flags_dict if x & mask]))
            if invflags & _iptables.XT_TCP_INV_FLAGS: 
                ft = "not " + ft
            tcp_buffer.write(ft) 
        if value["options"]:
            ft = "--tcp-option %s " % value["options"]
            if invflags & _iptables.XT_TCP_INV_OPTION:
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
                    if value["invflags"] & _iptables.IPT_ICMP_INV:
                        ft = "not " + ft
                    icmp_buffer.write(ft)
        else:
            ft = "--type %d %d/%d " % (i["type"],i["min"], i["max"])
            if value["invflags"] & _iptables.IPT_ICMP_INV:
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
        if invflags & _iptables.IPT_INV_DSTIP:
            ft = "not " + ft
        rule_buffer.write(ft)
    if rule_dict["srcip"]:
        ft = "-srcip %s/%s " % (rule_dict["srcip"], rule_dict["srcip_mask"])
        if invflags & _iptables.IPT_INV_SRCIP:
            ft = "not " + ft 
        rule_buffer.write(ft)
    if rule_dict["iniface"]:
        ft = "-i %s " % (rule_dict["iniface"])
        if invflags & _iptables.IPT_INV_VIA_IN:
            ft = "not " + ft 
        rule_buffer.write(ft) 
    if rule_dict["outiface"]:
        ft = "-o %s " % (rule_dict["outiface"])
        if invflags & _iptables.IPT_INV_VIA_OUT:
            ft = "not " + ft
        rule_buffer.write(ft) 
    if rule_dict["protocol"]:
        ft = "-proto %s " % protocol_dict[rule_dict["protocol"]]
        if invflags & _iptables.XT_INV_PROTO:
            ft = "not " + ft
        rule_buffer.write(ft)
    if rule_dict["flags"]:
        rule_buffer.write("-flags %d " % rule_dict["flags"]) 
    if rule_dict.get("target"): 
        if rule_dict["target_type"] == "standard":
            rule_buffer.write("-j %s " % rule_dict["target"])
        elif rule_dict["target_type"] == "module": 
            target = rule_dict["target"]
            try:
                target_dict = rule_dict["target_dict"]
            except:
                rule_buffer.write("-j %s " % target) 
            if target == "REJECT": 
                rule_buffer.write("-j REJECT --with-%s " % reject_dict[target_dict["with"]])
            if target == "LOG": 
                rule_buffer.write("-j LOG ")
                if target_dict.get("level"):
                    rule_buffer.write("--log-%s " % log_dict[target_dict["level"]])
                if target_dict.get("logflags"):
                    rule_buffer.write("--log-%s " % log_dict[target_dict["logflags"]])
                if target_dict.get("prefix"):
                    rule_buffer.write("--prefix \"%s\" " % target_dict["prefix"]) 
    else:
        if rule_dict["target_type"] == "jump":
            rule_buffer.write("-j %s " % jump_table[verb_dict[rule_dict["verb"]]])
        elif rule_dict["target_type"] == "standard":
            rule_buffer.write("-j %s " % verb_dict[rule_dict["verb"]])
    if "matches" in rule_dict:
        #matches 
        for match_tuple in rule_dict["matches"].items(): 
            #match plugins
            handle_matches(rule_buffer, match_tuple) 


def handle_chains(table):
    t = _iptables.get_table(table) 
    #jump table
    chains = t["chains"].items()
    chain2offset = {}
    for chain, rules in chains:
        chain2offset[rules[0]["offset"]] = chain 
    for chain, rules in chains:
        for rule in rules:
            if rule["target_type"] == "jump":
               jump_table[rule["verb"]] = chain2offset[rule["verb"]] 
    #print table detail
    print "table: %s" % t["name"]
    print "chains: ", " ".join(t["chains"].keys()) 
    for chain, rules in chains:
        print "============in chain %s" % chain 
        for rule_dict in rules:
            rule_buffer = StringIO() 
            handle_rule(rule_buffer, rule_dict)                      
            print rule_buffer.getvalue()
            rule_buffer.close() 

if __name__ == "__main__": 
    if len(sys.argv) < 3:
        print "usage: iptables.py -t table"
        exit(1)
    arg1 = sys.argv[1]
    arg2 = sys.argv[2]
    if arg1 == "-t":
        handle_chains(arg2)
    else: 
        print "usage: iptables.py -t table"
