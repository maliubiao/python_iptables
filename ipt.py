#-*-encoding=utf-8-*-

import _sockopt 
import socket
import struct
import cStringIO
import pdb
import io
import mmap
import pprint

TABLE_MAXNAMELEN = 32 
IFNAMSIZ = 16
XT_EXTENSION_MAXNAMELEN = 29

#内置的chain, 也叫hook
PRE_ROUTING = 0
LOCAL_IN = 1
FORWARD = 2
LOCAL_OUT = 3
POST_ROUTING = 4
NUMHOOKS = 5

blt_chain_table = {
        PRE_ROUTING: "prerouting",
        LOCAL_IN: "input",
        FORWARD: "forward",
        LOCAL_OUT: "output",
        POST_ROUTING: "postrouting"
        }

#控制选项
BASE_CTL = 64
SET_REPLACE = BASE_CTL
SET_ADD_COUNTERS = BASE_CTL + 1

GET_INFO = BASE_CTL
GET_ENTRIES = BASE_CTL + 1
GET_REVISION_MATCH = BASE_CTL + 2
GET_REVISION_TARGET = BASE_CTL + 3


def new_get_info(d):
    buf = []
    name = d["name"]
    if len(name) > TABLE_MAXNAMELEN:
        raise ValueError("max table name length: %d" % TABLE_MAXNAMELEN);
    buf.append(name)
    #padding
    buf.append((TABLE_MAXNAMELEN - len(name)) * "\x00")
    buf.append(struct.pack("I", d["valid_hooks"]))
    hooks = d["hook_entry"]
    for i in range(NUMHOOKS):
        buf.append(struct.pack("I", hooks[i]))
    underflow = d["underflow"]
    for i in range(NUMHOOKS):
        buf.append(struct.pack("I", underflow[i]))
    buf.append(struct.pack("II", d["num_entries"], d["size"]))
    return "".join(buf);


def parse_get_info(b):
    name = b.read(TABLE_MAXNAMELEN).strip("\x00")
    valid_hooks = struct.unpack("I", b.read(4))[0]
    hook_entry = struct.unpack("I" * NUMHOOKS, b.read(NUMHOOKS * 4))
    underflow = struct.unpack("I" * NUMHOOKS, b.read(NUMHOOKS * 4))
    num_entries, size = struct.unpack("II", b.read(8)) 
    return {
            "name": name,
            "valid_hooks": valid_hooks,
            "hook_entry": hook_entry,
            "underflow": underflow,
            "num_entries": num_entries,
            "size": size
            } 


def new_get_entries(d): 
    buf = []
    name = d["name"]
    if len(name) > TABLE_MAXNAMELEN:
        raise ValueError("max table name length: %d" % TABLE_MAXNAMELEN);
    buf.append(name)
    buf.append((TABLE_MAXNAMELEN - len(name)) * "\x00")
    buf.append(struct.pack("I", d["size"]))
    buf.append(d["entries"])
    #padding for struct ipt_entry entrytable[0]
    buf.append(4 * "\x00")
    return "".join(buf)


def parse_get_entries(b, mlen): 
    name = b.read(TABLE_MAXNAMELEN).strip("\x00")
    size = struct.unpack("I", b.read(4))[0]
    #skip padding
    b.seek(4, io.SEEK_CUR)
    entries = []
    while b.tell() < mlen:
        entries.append(parse_entry(b)) 
    return {
            "name": name,
            "size": size,
            "entries": entries
            } 


def new_ip(d):
    buf = []
    buf.append(struct.pack(">IIII", d["src"], d["dst"], d["smsk"], d["dmsk"]))
    buf.append(d["iniface"])
    buf.append((IFNAMSIZ - len(d["iniface"])) * "\x00")
    buf.append(d["outiface"])
    buf.append((IFNAMSIZ - len(d["outiface"])) * "\x00")
    buf.append(d["iniface_mask"])
    buf.append((IFNAMSIZ - len(d["iniface_mask"])) * "\x00")
    buf.append(d["outiface_mask"])
    buf.append((IFNAMSIZ - len(d["outiface_mask"])) * "\x00")
    buf.append(struct.pack("HBB", d["proto"], d["flags"], d["invflags"]))
    return "".join(buf) 

#Set if rule is a fragment rule
F_FRAG = 0x01
#Set if jump is a goto
F_GOTO = 0x02
#All possiable flag bits mask
F_MASK = 0x3

#invert
#Invert the sense of IN IFACE
INV_VIA_IN = 0x01
#Invert the sense of OUT IFACE
INV_VIA_OUT = 0x02
#Invert the sense of TOS
INV_TOS = 0x04
#Invert the sense of SRC IP
INV_SRCIP = 0x08
#Invert the sense of DST OP
INV_DSTIP = 0x10
#Invert the sense of Frag
INV_FRAG = 0x20 
INV_PROTO = 0x40
#All possible flag bits mask
INV_MASK = 0x7f


def parse_ip(b):
    src, dst, smsk, dmsk = struct.unpack(">IIII", b.read(4*4))
    iniface = b.read(IFNAMSIZ).strip("\x00")
    outiface = b.read(IFNAMSIZ).strip("\x00")
    iniface_mask = b.read(IFNAMSIZ).strip("\x00") 
    outiface_mask = b.read(IFNAMSIZ).strip("\x00")
    proto, flags, invflags = struct.unpack("HBB", b.read(4))
    return {
            "src": src,
            "dst": dst,
            "smsk": smsk,
            "dmsk": dmsk,
            "iniface": iniface,
            "outiface": outiface,
            "iniface_mask": iniface_mask,
            "outiface_mask": outiface_mask,
            "proto": proto,
            "flags": flags,
            "invflags": invflags 
            } 

def new_entry(d):
    buf = []
    buf.append(new_ip(d["ip"]))
    buf.append(struct.pack("IHHIQQ", d["nfcache"], 
        d["target_offset"], d["next_offset"], d["comefrom"],
        d["pcnt"], d["bcnt"])) 
    return "".join(buf)
            

def parse_entry(b): 
    start = b.tell()
    ip = parse_ip(b)
    nfcache, target_offset, next_offset, comefrom = struct.unpack("IHHI", b.read(12))
    pcnt, bcnt = struct.unpack("QQ", b.read(16)) 
    ipt_len = b.tell() - start 
    data = b.read(target_offset - ipt_len) 
    matches = parse_matches(cStringIO.StringIO(data), len(data))
    data = b.read(next_offset - target_offset) 
    target = parse_target(cStringIO.StringIO(data))
    return {
            "ip": ip,
            "nfcache": nfcache,
            "target_offset": target_offset,
            "next_offset": next_offset,
            "comefrom": comefrom,
            "pcnt": pcnt,
            "bcnt": bcnt,
            "offset": start,
            "matches": matches,
            "target": target
            } 


def parse_matches(b, mlen):
    matches = [] 
    while b.tell() < mlen: 
        match_size = struct.unpack("H", b.read(2))[0]
        if not match_size:
            break
        name = b.read(XT_EXTENSION_MAXNAMELEN)
        revision = struct.unpack("B", b.read(1))[0] 
        match = b.read(match_size)
        matches.append({
                "size": match_size,
                "match": match,
                "revision": revision,
                "name": name
                }) 
    return matches


def parse_target(b):
    target_size = struct.unpack("H", b.read(2))[0]
    name = b.read(XT_EXTENSION_MAXNAMELEN)
    revision = struct.unpack("B", b.read(1))[0]
    target = b.read(target_size)
    return {
            "size": target_size,
            "name": name,
            "revision": revision,
            "target": target
            }


NET_UNREACHABLE = 0
HOST_UNREACHABLE = 1
PROT_UNREACHABLE = 2
PORT_UNREACHABLE = 3
ECHOREPLY = 4
NET_PROHIBITED = 5
HOST_PROHIBITED = 6
TCP_RESET = 7
ADMIN_PROHIBITED = 8 


#Log TCP sequence numbers
LOG_TCPSEQ = 0x01
#Log TCP options
LOG_TCPOPT = 0x02
#Log IP options
LOG_IPOPT = 0x04
#Log UID owning local socket
LOG_UID = 0x08
#Unsupported, don't reuse
LOG_NFLOG = 0x10
#Decode MAC header
LOG_MACDECODE = 0x20


def parse_target_reject(b):
    return {
            "reject_with": struct.unpack("I", b.read(4))[0]
            }

def generate_target_reject(d):
    pass


def parse_target_log(b):
    level, logflags = struct.unpack("BB", b.read(2))
    prefix = b.read(30)
    i = prefix.find("\x00")
    if i > 0:
        prefix = prefix[:i]        
    return {
            "level": level,
            "logflags": logflags,
            "prefix": prefix
            }
   

def generate_target_log(d):
    pass


target_plugin = {
        "reject": (parse_target_reject, generate_target_reject), 
        "log": (parse_target_log, generate_target_log)
        }


def read_addr6(b):
    return struct.unpack("IIII", b.read(16))


def parse_match_conntrack(b): 
    """struct xt_conntracK_mtinfo3, 版本临时用3"""
    #type nf_inet_addr, 取struct in6_addr
    origsrc_ip = read_addr6(b)
    origsrc_mask = read_addr6(b)
    origdst_ip = read_addr6(b)
    origdst_mask = read_addr6(b)
    replsrc_ip = read_addr6(b)
    replsrc_mask = read_addr6(b)
    repldst_ip = read_addr6(b)
    repldst_mask = read_addr6(b)
    expires_min, expires_max = struct.unpack("II", b.read(8))
    l4proto, origsrc_port, origdst_port, replsrc_port, repldst_port = struct.unpack("HHHHH", b.read(10))
    match_flags, invert_flags, state_mask, status_mask = struct.unpack("HHHH", b.read(8))
    origsrc_port_high, origdst_port_high, replsrc_port_high, repldst_port_high = struct.unpack("HHHH", b.read(8))
    return {
            "origsrc_ip": origsrc_ip,
            "origsrc_mask": origsrc_mask,
            "origdst_ip": origdst_ip,
            "origdst_mask": origdst_mask,
            "replsrc_ip": replsrc_ip,
            "replsrc_mask": replsrc_mask,
            "repldst_ip": repldst_ip,
            "repldst_mask": repldst_mask,
            "expires_min": expires_min,
            "expires_max": expires_max,
            "l4proto": l4proto,
            "origsrc_port": origsrc_port,
            "replsrc_port": replsrc_port,
            "origdst_port": origdst_port,
            "repldst_port": repldst_port,
            "match_flags": match_flags,
            "invert_flags": invert_flags,
            "state_mask": state_mask,
            "status_mask": status_mask,
            "origsrc_port_high": origsrc_port_high,
            "origdst_port_high": origdst_port_high,
            "replsrc_port_high": replsrc_port_high,
            "repldst_port_high": repldst_port_high
            } 


def generate_match_conntrack(d):
    pass


def parse_match_limit(b):
    """struct xt_rateinfo"""
    avg, burst = struct.unpack("II", b.read(8))    
    #ignore 64 byte used by the kernel
    return {
            "avg": avg,
            "burst": burst
            }


def generate_match_limit(d):
    pass

def parse_match_pkttype(b):
    pkttype, invert = struct.unpack("ii", b.read(8))
    return {
            "pkttype": pkttype,
            "invert": invert
            }


def generate_match_pkttype(d):
    pass


def parse_match_icmp(b):
    tp, code_min, code_max, invflags = struct.unpack("BBBB", b.read(4))


def generate_match_icmp(d):
    pass


match_plugin = {
        "conntrack": (parse_match_conntrack, generate_match_conntrack),
        "limit": (parse_match_limit, generate_match_limit),
        "pkttype": (parse_match_pkttype, generate_match_pkttype),
        "icmp": (parse_match_icmp, generate_match_icmp), 
        }


#A -> B,  default, generator, parser 
def parse_chains(info, entries): 
    chains = {}
    offsetd = {}
    bltchain = {} 
    for i in entries:
        #fix offset
        i["offset"] -= 40 
        matches = i["matches"]
        for j, v in enumerate(matches): 
            off = v["name"].find("\x00")
            #blt chain
            if off < 0:
                continue
            match = v["name"][:off]
            #parse match 
            parser = match_plugin[match][0]
            matches[j] = parser(cStringIO.StringIO(v["match"])) 
        offsetd[i["offset"]] = i 
    #blt chain table 
    for i, v in enumerate(info["hook_entry"]):
        if v in offsetd:
            bltchain[v] = blt_chain_table[i]
    #built chains
    #target的判定, target是ERROR则用户定义的chain, target也是ERROR的是表尾, 得忽略它们
    #target的name为空则是标准target, 要看verdict, unsigned int
    #verdict如果可能直接指向下一个则是fallthrough, 如果小于0则是标准的, 其它则是jump
    #target有名则是扩展, chain的最后一个是policy.
    for i in entries:
        target = i["target"]
        name = target["name"]
        data = target["target"] 
        if i["offset"] in bltchain:
            newchain = []
            chains[bltchain[i["offset"]]] = newchain
        elif name.startswith("ERROR"): 
            newchain = [] 
            cname = data[:data.find("\x00")]
            if cname != "ERROR": 
                chains[cname] = newchain 
            continue
        newchain.append(i) 
        if name[0] == "\x00":
            verdict = struct.unpack("i", data[:4])[0]
            if verdict < 0:
                i["target"] = "accept"
            elif verdict == i["offset"] + i["next_offset"]:
                i["target"] = "next"
            else:
                i["target"] = offsetd[verdict]
        else:         
            #plugin 
            cname = name[:name.find("\x00")].lower() 
            parser = target_plugin[cname][0]
            i["target"] = parser(cStringIO.StringIO(data))
    return chains


def test_get_info():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    fd = sock.fileno() 
    data = new_get_info(
            {
                "name": "filter", 
                "valid_hooks": 0,
                "hook_entry": (0,) * NUMHOOKS,
                "underflow": (0, ) * NUMHOOKS,
                "num_entries": 0,
                "size": 0 
                }) 
    _sockopt.get(fd, socket.IPPROTO_IP, GET_INFO, data) 
    pprint.pprint(parse_get_info(cStringIO.StringIO(data))) 


def test_get_entries(): 
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    fd = sock.fileno() 
    data = new_get_info(
            {
                "name": "filter", 
                "valid_hooks": 0,
                "hook_entry": (0,) * NUMHOOKS,
                "underflow": (0, ) * NUMHOOKS,
                "num_entries": 0,
                "size": 0 
                }) 
    _sockopt.get(fd, socket.IPPROTO_IP, GET_INFO, data) 
    info = parse_get_info(cStringIO.StringIO(data)) 
    data = new_get_entries(
            {
                "name": "filter",
                "size": info["size"],
                "entries": info["size"] * "\x00"
            }) 
    _sockopt.get(fd, socket.IPPROTO_IP, GET_ENTRIES, data) 
    entries = parse_get_entries(cStringIO.StringIO(data), len(data)) 
    pprint.pprint(parse_chains(info, entries["entries"]))
    #pprint.pprint(entries)

test_get_entries()
