#-*-encoding=utf-8-*-

import _sockopt 
import socket
import struct
import cStringIO
import pdb
import io
import mmap
import pprint


XT_TABLE_MAXNAMELEN = 32 
IFNAMSIZ = 16
XT_EXTENSION_MAXNAMELEN = 29
XT_FUNCTION_MAXNAMELEN = 30


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

blt_chain_name = dict([(x[1], x[0]) for x in blt_chain_table.items()])

#控制选项
BASE_CTL = 64
SET_REPLACE = BASE_CTL
SET_ADD_COUNTERS = BASE_CTL + 1

GET_INFO = BASE_CTL
GET_ENTRIES = BASE_CTL + 1
GET_REVISION_MATCH = BASE_CTL + 2
GET_REVISION_TARGET = BASE_CTL + 3

XT_ALIGN = 8
XT_ERROR = "ERROR"

#新类型, cstring, struct array

TYPE_STR = 0x1
TYPE_SIMPLE = 0x2
TYPE_ARRAY = 0x4
TYPE_STRUCT = 0x8
TYPE_BUFFER = 0x10
TYPE_PADDING = 0x20 

#target类型
TARGET_CONVERT = lambda x: -(x + 1)

NF_DROP = TARGET_CONVERT(0)
NF_ACCEPT = TARGET_CONVERT(1)
NF_STOLEN = TARGET_CONVERT(2)
NF_QUEUE = TARGET_CONVERT(3)
NF_REPEAT = TARGET_CONVERT(4)
NF_STOP = TARGET_CONVERT(6)
NF_FALL = TARGET_CONVERT(10)

target_str_int = {
        "drop": NF_DROP,
        "accept": NF_ACCEPT,
        "stolen": NF_STOLEN,
        "queue": NF_QUEUE,
        "repeat": NF_REPEAT,
        "stop": NF_STOP
        } 

target_int_str = dict([(x[1], x[0]) for x in target_str_int.items()])

fmt_table = { }
types = "cbB?hHiIlLqQfdspP" 

#类型长度表
for i in types:
    fmt_table[i] = struct.calcsize(i) 

fmt_table["e"] = 0

align_table = {}

#内存对齐表
for i in types:
    align_table[i] = struct.calcsize("c"+i) - struct.calcsize(i) 
align_table["e"] = 0

def parse_struct(b, fmt):
    d = {}
    off = 0 
    for i,v in fmt:
        tp = v[0]
        #>H or <H, or H
        f = v[1][-1]
        align = align_table[f] 
        if tp & TYPE_PADDING: 
            b.seek(align, io.SEEK_CUR) 
            off += align
            continue 
        if off % align:
            b.seek(align - off % align, io.SEEK_CUR)
        if tp & TYPE_STR:
            size = v[2]
            d[i] = b.read(v[2]).rstrip("\x00") 
        elif tp & TYPE_SIMPLE: 
            size = fmt_table[f]
            d[i] = struct.unpack(v[1], b.read(size))[0] 
        elif tp & TYPE_ARRAY: 
            size = fmt_table[f] * v[2] 
            f = f * v[2]
            if len(v[1]) > 1:
                f = v[1][0] + f 
            d[i] = struct.unpack(f, b.read(size))
        elif tp & TYPE_STRUCT:
            parser = v[2]
            size = v[4]()
            d[i] = parser(cStringIO.StringIO(b.read(size)))
        elif tp & TYPE_BUFFER: 
            d[i] = b.read(v[2](d)) 
        off += size
    return d 


def generate_struct(d, fmt, default):
    buf = [] 
    off = 0 
    for i,v in fmt: 
        tp = v[0]
        f = v[1][-1]
        align = align_table[f] 
        if tp & TYPE_PADDING: 
            buf.append(align * "\x00") 
            off += align
            continue
        if i in d:
            value = d[i]
        else:  
            value = default[i] 
        if off % align:
            buf.append((align - off % align) * "\x00")
        if tp & TYPE_STR:
            size = v[2]
            buf.append(value + (v[2] - len(value)) * "\x00") 
        elif tp & TYPE_SIMPLE:
            size = fmt_table[f]
            buf.append(struct.pack(v[1], value))
        elif tp & TYPE_ARRAY: 
            size = fmt_table[f] * v[2]
            f = f * v[2]
            if len(v[1]) > 1:
                f = v[1][0] + f 
            buf.append(struct.pack(f, *value)) 
        elif tp & TYPE_STRUCT:
            generator = v[3]
            size = v[4]()
            buf.append(generator(value)) 
        elif tp & TYPE_BUFFER:
            buf.append(value) 
        off += size   
    return "".join(buf)



#A -> B,  default, generator, parser 
def parse_chains(info, entries): 
    chains = {}
    offsetd = {}
    bltchain = {} 
    jump = []
    for i in entries:
        offsetd[i["offset"]] = i
    #blt chain table 
    for i, v in enumerate(info["hook_entry"]):
        if v in offsetd:
            bltchain[v] = blt_chain_table[i] 
    for i,v in enumerate(entries): 
        target = v["target"]
        name = target["name"]
        payload = target["payload"] 
        #hook没有dummy head
        if v["offset"] in bltchain:
            newchain = []
            chains[bltchain[v["offset"]]] = newchain
        #新chain的标志
        elif name.startswith("ERROR"): 
            newchain = []
            cname = payload[:payload.find("\x00")] 
            #忽略掉tail
            if cname != "ERROR": 
                chains[cname] = newchain 
            continue
        newchain.append(v)
        verdict = v["target"]["payload"]
        #忽略处理过的target插件
        if isinstance(verdict, dict):
            continue
        #忽略std
        if verdict < 0: 
            continue
        #fallthrough
        elif verdict == entries[i+1]["offset"]: 
            v["target"]["payload"] = NF_FALL
        #跳到某个chain
        else: 
            jump.append(v) 
    for k, v in chains.items():
        bltchain[v[0]["offset"]] = k
    for i in jump:
        i["target"]["payload"] = bltchain[i["target"]["payload"]]
    return chains 


def generate_chains(chains): 
    fall = [] 
    chain_loc = {}
    buf = []
    off = 0
    for k,v in chains.items(): 
        start = off 
        #非hook, 加头
        if not k in blt_chain_name:
            h = new_error_entry(k)
            off += len(h)
            buf.append(h)  
        chain = v
        for i, v in enumerate(chain): 
            target = v["target"]
            if target["name"] == "std": 
                payload = target["payload"]
                #jump 
                if isinstance(payload, str):
                    #记录生成的位置，与v
                    jump.append((len(buf), v))
                #standard or fallthrough 
                if payload == NF_FALL:
                    #先算offset
                    d = generate_entry(v) 
                    #修改
                    v["target"]["payload"] = off + len(d) 
            pdb.set_trace()
            d = generate_entry(v)
            off += len(d)
            buf.append(d)
        #记录chain的始终位置
        chain_loc[k] = {
                "start": start,
                "end": off
                } 

    for k, j in jump:    
        #换chain名为其offset
        offset = chain_loc[j["target"]["payload"]]["start"] 
        j["target"]["payload"] = offset
        #重新生成
        buf[k] = generate_entry(j) 

    #添加tail
    tail = new_error_entry(XT_ERROR)
    buf.append(tail)
    return "".join(buf)


def new_error_entry(name):
    return generate_entry({
        "ip": {},
        "matches": [],
        "target": {
            "name": XT_ERROR,
            "revision": 0,
            "payload": {
                "name": name
                }
            }
        }) 


getinfo_fmt = (
        ("name", (TYPE_STR, "c", XT_TABLE_MAXNAMELEN)),
        ("valid_hooks", (TYPE_SIMPLE, "I")),
        ("hook_entry", (TYPE_ARRAY, "I", NUMHOOKS)),
        ("underflow", (TYPE_ARRAY, "I", NUMHOOKS)),
        ("num_entries", (TYPE_SIMPLE, "I")),
        ("size", (TYPE_SIMPLE, "I")),
        ("padding", (TYPE_PADDING, 'e'))
        ) 


getinfo_default = {
    "name": XT_TABLE_MAXNAMELEN * "\x00",
    "valid_hooks": 0,
    "hook_entry": (0, ) * NUMHOOKS,
    "underflow": (0, ) * NUMHOOKS,
    "num_entries": 0,
    "size": 0 
    } 


def generate_get_info(d):
    return generate_struct(d, getinfo_fmt, getinfo_default)


def parse_get_info(b):
    return parse_struct(b, getinfo_fmt)


entries_size = lambda d: d["size"]

get_entries_fmt = (
        ("name", (TYPE_STR, "c", XT_TABLE_MAXNAMELEN)),
        ("size", (TYPE_SIMPLE, "I")),
        ("padding", (TYPE_PADDING, "I")),
        ("entries", (TYPE_BUFFER, "c", entries_size)), 
        )


get_entries_default = {
        "name": XT_TABLE_MAXNAMELEN * "\x00", 
        "size": 0,
        "entries": "", 
        }

def generate_get_entries(d): 
    return generate_struct(d, get_entries_fmt,
            get_entries_default)


def parse_get_entries(b, mlen): 
    d = parse_struct(b, get_entries_fmt)
    b = cStringIO.StringIO(d["entries"])
    entries = []
    elen = len(d["entries"])
    while b.tell() < elen:
        entries.append(parse_entry(b))
    d["entries"] = entries
    return d


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



def generate_ip(d):
    return generate_struct(d, ip_fmt, ip_default) 


ip_fmt = (
        ("src", (TYPE_SIMPLE, ">I")),
        ("dst", (TYPE_SIMPLE, ">I")),
        ("smsk", (TYPE_SIMPLE, ">I")),
        ("dmsk", (TYPE_SIMPLE, ">I")),
        ("iniface", (TYPE_STR, "c", IFNAMSIZ)),
        ("outiface", (TYPE_STR, "c", IFNAMSIZ)),
        ("iniface_mask", (TYPE_STR, "c", IFNAMSIZ)),
        ("outiface_mask", (TYPE_STR, "c", IFNAMSIZ)),
        ("proto", (TYPE_SIMPLE, "H")),
        ("flags", (TYPE_SIMPLE, "B")),
        ("invflags", (TYPE_SIMPLE, "B"))
        ) 


ip_default = {
        "src": 0,
        "dst": 0,
        "smsk": 0,
        "dmsk": 0,
        "iniface": IFNAMSIZ * "\x00",
        "outiface": IFNAMSIZ * "\x00",
        "iniface_mask": IFNAMSIZ * "\x00",
        "outiface_mask": IFNAMSIZ * "\x00",
        "proto": 0,
        "flags": 0,
        "invflags": 0
        } 


def parse_ip(b):
    return parse_struct(b, ip_fmt)


def generate_entry(d):
    buf = [] 
    ip = generate_ip(d["ip"])
    buf.append(ip)
    matches = generate_matches(d["matches"]) 
    target = generate_target(d["target"]) 
    d["target_offset"] = (len(ip) + 
            struct.calcsize("IHHI") + 
            struct.calcsize("QQ") +
            len(matches))
    d["next_offset"] = d["target_offset"] + len(target)
    buf.append(struct.pack("IHHI", 0, 
        d["target_offset"], d["next_offset"], 0)) 
    buf.append(struct.pack("QQ", 0, 0))
    buf.append(matches)
    buf.append(target)
    data = "".join(buf) 
    parse_entry(cStringIO.StringIO(data))
    #bug
    if len(data) % XT_ALIGN:
        pdb.set_trace()
    return data
            

def parse_entry(b): 
    start = b.tell()
    ip = parse_ip(b)
    nfcache, target_offset, next_offset, comefrom = struct.unpack("IHHI", b.read(12))
    pcnt, bcnt = struct.unpack("QQ", b.read(16)) 
    matches = parse_matches(b, start + target_offset) 
    target = parse_target(b) 
    #bug
    if b.tell() != start + next_offset:
        pdb.set_trace()
    b.seek(start + next_offset)
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


def generate_matches(matches):
    buf = []
    for i in matches:
        pdb.set_trace()
        generator = match_plugin[i["name"]][1]
        payload = generator(i["payload"])
        plen = len(payload)
        if plen % XT_ALIGN: 
            payload += (XT_ALIGN - plen % XT_ALIGN) * "\x00" 
        i["payload"] = payload
        data = generate_match(i)
        buf.append(data) 
    return "".join(buf) 



def parse_matches(b, mlen):
    matches = [] 
    while b.tell() < mlen: 
        m = parse_match(b)
        off = m["name"].find("\x00")
        if off < 0:
            continue
        name = m["name"][:off]
        m["name"] = name
        parser = match_plugin[name][0] 
        m["payload"] = parser(cStringIO.StringIO(m["payload"]))
        matches.append(m) 
    return matches 


match_size = lambda d: d["match_size"] - 32


match_fmt = (
        ("match_size", (TYPE_SIMPLE, "H")),
        ("name", (TYPE_STR, "c", XT_EXTENSION_MAXNAMELEN)),
        ("revision", (TYPE_SIMPLE, "B")),
        ("payload", (TYPE_BUFFER, "c", match_size)),
        )


match_default = {
        "match_size": 0,
        "name": XT_EXTENSION_MAXNAMELEN * "\x00",
        "revision": 0,
        "payload": ""
        } 

def parse_match(b):
    return parse_struct(b, match_fmt) 


def generate_match(d): 
    return generate_struct(d, match_fmt, match_default)


target_size = lambda d: d["target_size"] - 32


target_fmt = (
    ("target_size", (TYPE_SIMPLE, "H")),
    ("name", (TYPE_STR, "c", XT_EXTENSION_MAXNAMELEN)),
    ("revision", (TYPE_SIMPLE, "B")),
    ("payload", (TYPE_BUFFER, "c", target_size))
    )

target_default = {
        "target_size": 0,
        "name": XT_EXTENSION_MAXNAMELEN * "\x00",
        "revision": 0,
        "payload": ""
        } 

def generate_target(d):
    if d["name"] == "std":
        generator = target_plugin["std"][1]
        pdb.set_trace()
        payload = generator(d["payload"])
        del d["name"]
    else:
        generator = target_plugin[d["name"]][1] 
        payload = generator(d["payload"])
    if len(payload) % XT_ALIGN:
        payload += (XT_ALIGN - len(payload) % XT_ALIGN) * "\x00"
    d["payload"] = payload 
    d["target_size"] = len(payload) + 32
    return generate_struct(d,  target_fmt, target_default)

    
def test_target():
    d = {
        "revision": 0,
        "name": "REJECT",
        "payload": {
            "reject_with": 7
            }
        }
    r = generate_target(d) 
    d2 = parse_target(cStringIO.StringIO(r)) 


def parse_target(b): 
    d =  parse_struct(b, target_fmt) 
    name = d["name"]
    payload = d["payload"]
    if not name or name[0] == "\x00":
        d["name"] = "std" 
        d["payload"] = struct.unpack("i", payload[:4])[0] 
    else:
        off = name.find("\x00")
        if off < 0:
            cname = name
        else:
            cname = name[:off] 
        if cname == "ERROR":
            return d
        d["name"] = cname
        parser = target_plugin[cname][0] 
        d["payload"] = parser(cStringIO.StringIO(payload)) 
    return d 


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
    return struct.pack("I", d["reject_with"])


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


audit_fmt = (
        ("type", (TYPE_SIMPLE, "B")),
        )


checksum_fmt = (
        ("operation", (TYPE_SIMPLE, "B")),
        )

classify_fmt = (
        ("priority", (TYPE_SIMPLE, "B")),
        )

""" 
static struct xt_target connmark_tg_reg __read_mostly = {
	.name           = "CONNMARK",
	.revision       = 1,
	.family         = NFPROTO_UNSPEC,
	.checkentry     = connmark_tg_check,
	.target         = connmark_tg,
	.targetsize     = sizeof(struct xt_connmark_tginfo1),
	.destroy        = connmark_tg_destroy,
	.me             = THIS_MODULE,
};


"""
connmark_tfmt = (
        ("ctmark", (TYPE_SIMPLE, "I")),
        ("ctmask", (TYPE_SIMPLE, "I")),
        ("nfmask", (TYPE_SIMPLE, "I")),
        ("mode", (TYPE_SIMPLE, "B"))
        )

"""
static struct xt_target connsecmark_tg_reg __read_mostly = {
	.name       = "CONNSECMARK",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.checkentry = connsecmark_tg_check,
	.destroy    = connsecmark_tg_destroy,
	.target     = connsecmark_tg,
	.targetsize = sizeof(struct xt_connsecmark_target_info),
	.me         = THIS_MODULE,
};
"""

CONNSECMARK_SAVE = 1
CONNSECMARK_RESTORE = 2

connsecmark_fmt = (
        ("mode", (TYPE_SIMPLE, "B")),
        )

"""
static struct xt_target notrack_tg_reg __read_mostly = {
	.name		= "NOTRACK",
	.revision	= 0,
	.family		= NFPROTO_UNSPEC,
	.checkentry	= notrack_chk,
	.target		= notrack_tg,
	.table		= "raw",
	.me		= THIS_MODULE,
};
{
		.name		= "CT",
		.family		= NFPROTO_UNSPEC,
		.revision	= 2,
		.targetsize	= sizeof(struct xt_ct_target_info_v1),
		.checkentry	= xt_ct_tg_check_v2,
		.destroy	= xt_ct_tg_destroy_v1,
		.target		= xt_ct_target_v1,
		.table		= "raw",
		.me		= THIS_MODULE,
	},

"""

CT_NOTRACK = 1 << 0
CT_NOTRACK_ALIAS = 1 << 1 

ct_v1_fmt = (
        ("flags", (TYPE_SIMPLE, "H")),
        ("zone", (TYPE_SIMPLE, "H")),
        ("ct_events", (TYPE_SIMPLE, "I")),
        ("exp_events", (TYPE_SIMPLE, "I")),
        ("helper", (TYPE_ARRAY, "c", 16)),
        ("timeout", (TYPE_ARRAY, "c", 32))
        )
"""
{
    .name		= "DSCP",
    .family		= NFPROTO_IPV4,
    .checkentry	= dscp_tg_check,
    .target		= dscp_tg,
    .targetsize	= sizeof(struct xt_DSCP_info),
    .table		= "mangle",
    .me		= THIS_MODULE,
}, 
{
    .name		= "TOS",
    .revision	= 1,
    .family		= NFPROTO_IPV4,
    .table		= "mangle",
    .target		= tos_tg,
    .targetsize	= sizeof(struct xt_tos_target_info),
    .me		= THIS_MODULE,
},

"""

dscp_tfmt = (
        ("dscp", (TYPE_SIMPLE, "B")),
        )


tos_tfmt = (
        ("value", (TYPE_SIMPLE, "B")),
        ("mask", (TYPE_SIMPLE, "B"))
        )

"""
{
    .name		= "HMARK",
    .family		= NFPROTO_IPV4,
    .target		= hmark_tg_v4,
    .targetsize	= sizeof(struct xt_hmark_info),
    .checkentry	= hmark_tg_check,
    .me		= THIS_MODULE,
},
"""

HMARK_SADDR_MASK = 0
HMARK_DADDR_MASK = 1
HMARK_SPI = 2
HMARK_SPI_MASK = 3
HMARK_SPORT = 4
HMARK_DPORT = 5
HMARK_SPORT_MASK = 6
HMARK_DPORT_MASK = 7
HMARK_PROTO_MASK = 8
HMARK_RND = 9
HMARK_MODULUS = 10
HMARK_OFFSET = 11
HMARK_CT = 12
HMARK_METHOD_L3 = 13
HMARK_METHOD_L3_4 = 14

hmark_fmt = (
        ("src_mask", (TYPE_ARRAY, ">I", 4)),
        ("dst_mask", (TYPE_ARRAY, ">I", 4)),
        ("port_mask", (TYPE_ARRAY, ">H", 2)),
        ("port_set", (TYPE_ARRAY, ">H", 2)),
        ("flags", (TYPE_SIMPLE, "I")),
        ("proto_mask", (TYPE_SIMPLE, "H")),
        ("hashrnd", (TYPE_SIMPLE, "I")),
        ("hmodulus", (TYPE_SIMPLE, "I")),
        ("hoffset", (TYPE_SIMPLE, "I"))
        )


"""
static struct xt_target idletimer_tg __read_mostly = {
	.name		= "IDLETIMER",
	.family		= NFPROTO_UNSPEC,
	.target		= idletimer_tg_target,
	.targetsize     = sizeof(struct idletimer_tg_info),
	.checkentry	= idletimer_tg_checkentry,
	.destroy        = idletimer_tg_destroy,
	.me		= THIS_MODULE,
};
"""

MAX_IDLETIMER_LABEL_SIZE = 28

idletimer_fmt = (
        ("timeout", (TYPE_SIMPLE, "I")), 
        ("label", (TYPE_STR, "c", MAX_IDLETIMER_LABEL_SIZE)), 
        )

"""
static struct xt_target led_tg_reg __read_mostly = {
	.name		= "LED",
	.revision	= 0,
	.family		= NFPROTO_UNSPEC,
	.target		= led_tg,
	.targetsize	= sizeof(struct xt_led_info),
	.checkentry	= led_tg_check,
	.destroy	= led_tg_destroy,
	.me		= THIS_MODULE,
};
"""

led_fmt = (
        ("id", (TYPE_STR, "c", 27)),
        ("always_blink", (TYPE_SIMPLE, "B")),
        ("delay", (TYPE_SIMPLE, "I"))
        )

"""
static struct xt_target mark_tg_reg __read_mostly = {
	.name           = "MARK",
	.revision       = 2,
	.family         = NFPROTO_UNSPEC,
	.target         = mark_tg,
	.targetsize     = sizeof(struct xt_mark_tginfo2),
	.me             = THIS_MODULE,
};
"""
mark_tfmt = (
        ("mark", (TYPE_SIMPLE, "I")),
        ("mask", (TYPE_SIMPLE, "I"))
        )

"""
static struct xt_target nflog_tg_reg __read_mostly = {
	.name       = "NFLOG",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.checkentry = nflog_tg_check,
	.target     = nflog_tg,
	.targetsize = sizeof(struct xt_nflog_info),
	.me         = THIS_MODULE,
};
"""

NFLOG_DEFAULT_GROUP = 0x1
NFLOG_DEFAULT_THRESHOLD = 0
NFLOG_MASK = 0x0 

nflog = (
        ("len", (TYPE_SIMPLE, "I")),
        ("group", (TYPE_SIMPLE, "H")),
        ("threshold", (TYPE_SIMPLE, "H")),
        ("flags", (TYPE_SIMPLE, "H")),
        ("pad", (TYPE_SIMPLE, "H")),
        ("prefix", (TYPE_STR, "c", 64))
        )


"""
{
		.name		= "NFQUEUE",
		.revision	= 3,
		.family		= NFPROTO_UNSPEC,
		.checkentry	= nfqueue_tg_check,
		.target		= nfqueue_tg_v3,
		.targetsize	= sizeof(struct xt_NFQ_info_v3),
		.me		= THIS_MODULE,
	},
"""

NFQ_FLAG_BYPASS = 0x01
NFQ_FLAG_CPU_FANOUT = 0x02
NFQ_FLAG_MASK = 0x03

nfq_v3_fmt = (
        ("num", (TYPE_SIMPLE, "H")),
        ("total", (TYPE_SIMPLE, "H")),
        ("flags", (TYPE_SIMPLE, "H"))
        )

"""
static struct xt_target secmark_tg_reg __read_mostly = {
	.name       = "SECMARK",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.checkentry = secmark_tg_check,
	.destroy    = secmark_tg_destroy,
	.target     = secmark_tg,
	.targetsize = sizeof(struct xt_secmark_target_info),
	.me         = THIS_MODULE,
}; 
"""

#SElinux
SECMARK_MODE_SEL = 0x01
SECMARK_SECCTX_MAX = 256

secmark_fmt = (
        ("mode", (TYPE_SIMPLE, "B")),
        ("secid", (TYPE_SIMPLE, "I")),
        ("secctx", (TYPE_STR, "c", SECMARK_SECCTX_MAX))
        )

"""
{
    .name		= "SET",
    .revision	= 2,
    .family		= NFPROTO_IPV4,
    .target		= set_target_v2,
    .targetsize	= sizeof(struct xt_set_info_target_v2),
    .checkentry	= set_target_v2_checkentry,
    .destroy	= set_target_v2_destroy,
    .me		= THIS_MODULE
},
"""
#skip

"""
{
    .family		= NFPROTO_IPV4,
    .name		= "TCPMSS",
    .checkentry	= tcpmss_tg4_check,
    .target		= tcpmss_tg4,
    .targetsize	= sizeof(struct xt_tcpmss_info),
    .proto		= IPPROTO_TCP,
    .me		= THIS_MODULE,
},
"""

tcpmss_tfmt = (
        ("mss", (TYPE_SIMPLE, "H")),
        )

"""
{
		.name       = "TCPOPTSTRIP",
		.family     = NFPROTO_IPV4,
		.table      = "mangle",
		.proto      = IPPROTO_TCP,
		.target     = tcpoptstrip_tg4,
		.targetsize = sizeof(struct xt_tcpoptstrip_target_info),
		.me         = THIS_MODULE,
},
"""

tcpoptstrip_fmt = (
        ("bmap", (TYPE_ARRAY, "I", 8)),
        )


"""
{
    .name		= "TPROXY",
    .family		= NFPROTO_IPV4,
    .table		= "mangle",
    .target		= tproxy_tg4_v1,
    .revision	= 1,
    .targetsize	= sizeof(struct xt_tproxy_target_info_v1),
    .checkentry	= tproxy_tg4_check,
    .hooks		= 1 << NF_INET_PRE_ROUTING,
    .me		= THIS_MODULE,
},
"""

tproxy_fmt = (
        ("mark_mask", (TYPE_SIMPLE, "I")),
        ("mark_value", (TYPE_SIMPLE, "I")),
        ("laddr", (TYPE_ARRAY, ">I", 4)),
        ("lport", (TYPE_SIMPLE, ">H"))
        )

def parse_target_std(b):
    pass

def generate_target_std(d):
    return struct.pack("i", d)


def parse_target_error(b):
    pass


def generate_target_error(d): 
    n = d["name"]
    return n + (XT_FUNCTION_MAXNAMELEN - len(n)) * "\x00"


target_plugin = {
        "REJECT": (parse_target_reject, generate_target_reject), 
        "LOG": (parse_target_log, generate_target_log),
        #下面的不是插件，不要用
        "std": (parse_target_std, generate_target_std),
        "ERROR": (parse_target_error, generate_target_error)
        }


def parse_match_conntrack(b): 
    """struct xt_conntracK_mtinfo3, 版本临时用3"""
    return parse_struct(b, conntrack_fmt_v3)


conntrack_fmt_v3 = (
        ("origsrc_ip", (TYPE_ARRAY, ">I", 4)),
        ("origsrc_mask", (TYPE_ARRAY, ">I", 4)),
        ("origdst_ip", (TYPE_ARRAY, ">I", 4)),
        ("origdst_mask", (TYPE_ARRAY, ">I", 4)),
        ("replsrc_ip", (TYPE_ARRAY, ">I", 4)), 
        ("replsrc_mask", (TYPE_ARRAY, ">I", 4)),
        ("repldst_ip", (TYPE_ARRAY, ">I", 4)),
        ("repldst_mask", (TYPE_ARRAY, ">I", 4)),
        ("expires_min", (TYPE_SIMPLE, "I")),
        ("expires_max", (TYPE_SIMPLE, "I")),
        ("l4proto", (TYPE_SIMPLE, "H")), 
        ("origsrc_port", (TYPE_SIMPLE, "H")),
        ("replsrc_port", (TYPE_SIMPLE, "H")),
        ("origdst_port", (TYPE_SIMPLE, "H")),
        ("repldst_port", (TYPE_SIMPLE, "H")),
        ("match_flags", (TYPE_SIMPLE, "H")),
        ("invert_flags",(TYPE_SIMPLE, "H")),
        ("state_mask", (TYPE_SIMPLE, "H")),
        ("status_mask", (TYPE_SIMPLE, "H")),
        ("origsrc_port_high", (TYPE_SIMPLE, "H")),
        ("origdst_port_high", (TYPE_SIMPLE, "H")),
        ("replsrc_port_high", (TYPE_SIMPLE, "H")),
        ("repldst_port_high", (TYPE_SIMPLE, "H")),
        ) 

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
    return struct.pack("ii", d["pkttype"], d["invert"])


icmp_fmt = (
        ("type", (TYPE_SIMPLE, "B")),
        ("codde_min", (TYPE_SIMPLE, "B")),
        ("code_max", (TYPE_SIMPLE, "B")),
        ("invflags", (TYPE_SIMPLE, "B"))
        )

icmp_default = {
        "type": 0,
        "code_min": 0,
        "code_max": 0,
        "invflags": 0
        }

def parse_match_icmp(b):
    return parse_struct(b, icmp_fmt) 


def generate_match_icmp(d):
    return generate_match_icmp(b, icmp_fmt, icmp_default)


tcp_fmt = (
        ("spts", (TYPE_ARRAY, "H", 2)),
        ("dpts", (TYPE_ARRAY, "H", 2)),
        ("option", (TYPE_SIMPLE, "B")),
        ("flg_mask", (TYPE_SIMPLE, "B")),
        ("flg_cmp", (TYPE_SIMPLE, "B")),
        ("invflags", (TYPE_SIMPLE, "B"))
        )


TCP_INV_SCPT = 0x01
TCP_INV_DSTPT = 0x02
TCP_INV_FLAGS = 0x04
TCP_INV_OPTION = 0x08
TCP_INV_MASK=  0x0F


def parse_match_tcp(b):
    return parse_struct(b, tcp_fmt)


def generate_match_tcp(d):
    pass



UDP_INV_SCRPT = 0x01
UDP_INV_DSTPT = 0x02
UDP_INV_MASK = 0x03

udp_fmt = (
        ("spts", (TYPE_ARRAY, "H", 2)),
        ("dpts", (TYPE_ARRAY, "H", 2)),
        ("invflags", (TYPE_SIMPLE, "B"))
        )

def parse_match_udp(b):
    return parse_struct(b, udp_fmt)


def generate_match_udp(b):
    pass



ADDRTYPE_UNSPEC = 1 << 0
ADDRTYPE_UNITCAST = 1 << 1
ADDRTYPE_LOCAL = 1 << 2
ADDRTYPE_BROADCAST = 1 << 3
ADDRTYPE_ANYCAST = 1 << 4
ADDRTYPE_MULTICAST = 1 << 5
ADDRTYPE_BLACKHOLE = 1 << 6
ADDRTYPE_UNREACHABLE = 1 << 7
ADDRTYPE_PROHIBIT = 1 << 8
ADDRTYPE_THROW = 1 << 9
ADDRTYPE_NAT = 1 << 10
ADDRTYPE_XRESOLVE = 1 << 11

ADDRTYPE_INVERT_SOUCE = 0x01
ADDRTYPE_INVERT_DEST = 0x02
ADDRTYPE_LIMIT_IFACE_IN = 0x04
ADDRTYPE_LIMIT_IFACE_OUT = 0x08



addrtype_v1_fmt = (
        ("source", (TYPE_SIMPLE, "H")),
        ("dest", (TYPE_SIMPLE, "H")),
        ("flags", (TYPE_SIMPLE, "I"))
        )


#revision 0
addrtype_fmt = (
        ("source", (TYPE_SIMPLE, "H")),
        ("dest", (TYPE_SIMPLE, "H")),
        ("invert_source", (TYPE_SIMPLE, "I")),
        ("invert_dest", (TYPE_SIMPLE, "I"))
        ) 

""" 
static struct xt_match cgroup_mt_reg __read_mostly = {
	.name       = "cgroup",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.checkentry = cgroup_mt_check,
	.match      = cgroup_mt,
	.matchsize  = sizeof(struct xt_cgroup_info),
	.me         = THIS_MODULE,
	.hooks      = (1 << NF_INET_LOCAL_OUT) |
		      (1 << NF_INET_POST_ROUTING) |
		      (1 << NF_INET_LOCAL_IN),
}; 
"""

cgroup_fmt = (
        ("id", (TYPE_SIMPLE, "I")),
        ("invert", (TYPE_SIMPLE, "I"))
        )

CLUSTER_F_INV = 0x1 << 0
CLUSTER_NODES_MAX = 32


""" 
static struct xt_match xt_cluster_match __read_mostly = {
	.name		= "cluster",
	.family		= NFPROTO_UNSPEC,
	.match		= xt_cluster_mt,
	.checkentry	= xt_cluster_mt_checkentry,
	.matchsize	= sizeof(struct xt_cluster_match_info),
	.me		= THIS_MODULE,
}; 
"""


cluster_fmt = (
        ("total_nodes", (TYPE_SIMPLE, "I")),
        ("node_mask", (TYPE_SIMPLE, "I")),
        ("hash_seed", (TYPE_SIMPLE, "I")),
        ("flags", (TYPE_SIMPLE, "I"))
        )

MAX_COMMENT_LEN = 256

comment_fmt = (
        ("comment", (TYPE_STR, "c", MAX_COMMENT_LEN)),
        )

"""
static struct xt_match connbytes_mt_reg __read_mostly = {
	.name       = "connbytes",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.checkentry = connbytes_mt_check,
	.match      = connbytes_mt,
	.destroy    = connbytes_mt_destroy,
	.matchsize  = sizeof(struct xt_connbytes_info),
	.me         = THIS_MODULE,
}; 
"""

CONNBYTES_PKTS = 0
CONNBYTES_BYTES = 1
CONNBYTES_AVGPKT = 2

CONNBYTES_DIR_ORIGINAL = 0
CONNBYTES_DIR_REPLY = 1
CONNBYTES_DIR_BOTH = 2


connbytes_fmt = (
        ("from", (TYPE_SIMPLE, "Q")),
        ("to", (TYPE_SIMPLE, "Q")),
        ("what", (TYPE_SIMPLE, "B")),
        ("direction", (TYPE_SIMPLE, "B"))
        )

"""
static struct xt_match connlabels_mt_reg __read_mostly = {
	.name           = "connlabel",
	.family         = NFPROTO_UNSPEC,
	.checkentry     = connlabel_mt_check,
	.match          = connlabel_mt,
	.matchsize      = sizeof(struct xt_connlabel_mtinfo),
	.destroy        = connlabel_mt_destroy,
	.me             = THIS_MODULE,
};
"""

CONNLABEL_OP_INVERT = 1 << 0
CONNLABEL_OP_SET = 1 << 1

connlabel_fmt = (
        ("bit", (TYPE_SIMPLE, "H")),
        ("options", (TYPE_SIMPLE, "H"))
        )


""" 
static struct xt_match connlimit_mt_reg __read_mostly = {
	.name       = "connlimit",
	.revision   = 1,
	.family     = NFPROTO_UNSPEC,
	.checkentry = connlimit_mt_check,
	.match      = connlimit_mt,
	.matchsize  = sizeof(struct xt_connlimit_info),
	.destroy    = connlimit_mt_destroy,
	.me         = THIS_MODULE,
}; 
"""

connlimit_fmt = (
        ("mask", (TYPE_ARRAY, ">I", 4)),
        ("limit", (TYPE_SIMPLE, "I"))
        )

connlimit_v1_fmt = (
        ("mask", (TYPE_ARRAY, ">I", 4)),
        ("limit", (TYPE_SIMPLE, "I")),
        ("flags", (TYPE_SIMPLE, "I"))
        ) 

""" 
static struct xt_match connmark_mt_reg __read_mostly = {
	.name           = "connmark",
	.revision       = 1,
	.family         = NFPROTO_UNSPEC,
	.checkentry     = connmark_mt_check,
	.match          = connmark_mt,
	.matchsize      = sizeof(struct xt_connmark_mtinfo1),
	.destroy        = connmark_mt_destroy,
	.me             = THIS_MODULE,
}; 
"""

connmark_mfmt = (
        ("mark", (TYPE_SIMPLE, "I")),
        ("mask", (TYPE_SIMPLE, "I")),
        ("invert", (TYPE_SIMPLE, "B")) 
        )

"""
static struct xt_match cpu_mt_reg __read_mostly = {
	.name       = "cpu",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.checkentry = cpu_mt_check,
	.match      = cpu_mt,
	.matchsize  = sizeof(struct xt_cpu_info),
	.me         = THIS_MODULE,
};
"""

cpu_info = (
        ("cpu", (TYPE_SIMPLE, "I")),
        ("invert", (TYPE_SIMPLE, "I"))
        )

"""
{
		.name 		= "dccp",
		.family		= NFPROTO_IPV4,
		.checkentry	= dccp_mt_check,
		.match		= dccp_mt,
		.matchsize	= sizeof(struct xt_dccp_info),
		.proto		= IPPROTO_DCCP,
		.me 		= THIS_MODULE,
}, 
"""

DCCP_SRC_PORTS = 0x01
DCCP_DEST_PORTS = 0x02
DCCP_TYPE = 0x04
DCCP_OPTION = 0x08

dccp_fmt = (
        ("dpts", (TYPE_ARRAY, "H", 2)),
        ("spts", (TYPE_ARRAY, "H", 2)), 
        ("flags", (TYPE_SIMPLE, "H")),
        ("invflags", (TYPE_SIMPLE, "H")),
        ("typemask", (TYPE_SIMPLE, "H")),
        ("option", (TYPE_SIMPLE, "B"))
    )

"""
static struct xt_match devgroup_mt_reg __read_mostly = {
	.name		= "devgroup",
	.match		= devgroup_mt,
	.checkentry	= devgroup_mt_checkentry,
	.matchsize	= sizeof(struct xt_devgroup_info),
	.family		= NFPROTO_UNSPEC,
	.me		= THIS_MODULE
}; 
"""

DEVGROUP_MATCH_SRC = 0x1,
DEVGROUP_MATCH_INVERT_SRC = 0x2
DEVGROUP_MATCH_DST=  0x4
DEVGROUP_MATCH_INVERT_DST = 0x8

devgroup_fmt = (
        ("flags", (TYPE_SIMPLE, "I")),
        ("src_group", (TYPE_SIMPLE, "I")),
        ("src_mask", (TYPE_SIMPLE, "I")),
        ("dst_group", (TYPE_SIMPLE, "I")),
        ("dst_mask", (TYPE_SIMPLE, "I"))
        )

"""
{
		.name		= "dscp",
		.family		= NFPROTO_IPV4,
		.checkentry	= dscp_mt_check,
		.match		= dscp_mt,
		.matchsize	= sizeof(struct xt_dscp_info),
		.me		= THIS_MODULE,
	},
{
		.name		= "tos",
		.revision	= 1,
		.family		= NFPROTO_IPV4,
		.match		= tos_mt,
		.matchsize	= sizeof(struct xt_tos_match_info),
		.me		= THIS_MODULE,
	},

"""

DSCP_MASK = 0xfc
DSCP_SHIFT = 2
DSCP_MAX = 0x3f

dscp_mfmt = (
        ("dscp", (TYPE_SIMPLE, "B")),
        ("invert", (TYPE_SIMPLE, "B")), 
        )

tos_mfmt = (
        ("tos_mask", (TYPE_SIMPLE, "B")),
        ("tos_value", (TYPE_SIMPLE, "B")),
        ("invert", (TYPE_SIMPLE, "B"))
        )

"""
{
    .name		= "ecn",
    .family		= NFPROTO_IPV4,
    .match		= ecn_mt4,
    .matchsize	= sizeof(struct xt_ecn_info),
    .checkentry	= ecn_mt_check4,
    .me		= THIS_MODULE,
}, 
"""

ECN_IP_MASK = ~DSCP_MASK
ECN_OP_MATCH_IP = 0x01
ECN_OP_MATCH_ECE = 0x10
ECN_OP_MATCH_CWR = 0x20
ECN_OP_MATCH_MASK = 0xce

ecn_fmt = (
        ("operation", (TYPE_SIMPLE, "B")), 
        ("invert", (TYPE_SIMPLE, "B")),
        ("ip_ect", (TYPE_SIMPLE, "B")),
        ("tcp_ect", (TYPE_SIMPLE, "B"))
        ) 

"""
{
    .name		= "esp",
    .family		= NFPROTO_IPV4,
    .checkentry	= esp_mt_check,
    .match		= esp_mt,
    .matchsize	= sizeof(struct xt_esp),
    .proto		= IPPROTO_ESP,
    .me		= THIS_MODULE,
},
"""

ESP_INV_SPI = 0x01 

esp_fmt = (
        ("spis", (TYPE_ARRAY, "I", 2)),
        ("invflags", (TYPE_SIMPLE, "B"))
        )

"""
{
    .name           = "hashlimit",
    .revision       = 1,
    .family         = NFPROTO_IPV4,
    .match          = hashlimit_mt,
    .matchsize      = sizeof(struct xt_hashlimit_mtinfo1),
    .checkentry     = hashlimit_mt_check,
    .destroy        = hashlimit_mt_destroy,
    .me             = THIS_MODULE,
},
"""

hashlimit_fmt = (
        ("name", (TYPE_STR, "c", IFNAMSIZ)),
        ("mode", (TYPE_SIMPLE, "I")),
        ("avg", (TYPE_SIMPLE, "I")),
        ("burst", (TYPE_SIMPLE, "I")),
        #how many buckets
        ("size", (TYPE_SIMPLE, "I")),
        #max number of entries
        ("max", (TYPE_SIMPLE, "I")),
        #gc interval
        ("gc_interval", (TYPE_SIMPLE, "I")),
        ("expire", (TYPE_SIMPLE, "I")),
        ("srcmask", (TYPE_SIMPLE, "B")),
        ("dstmask", (TYPE_SIMPLE, "B"))
        )
"""
static struct xt_match helper_mt_reg __read_mostly = {
	.name       = "helper",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.checkentry = helper_mt_check,
	.match      = helper_mt,
	.destroy    = helper_mt_destroy,
	.matchsize  = sizeof(struct xt_helper_info),
	.me         = THIS_MODULE,
};
"""

helper_fmt = (
        ("invert", (TYPE_SIMPLE, "I")),
        ("name", (TYPE_STR, "c", 30))
        )
"""
{
    .name		= "ipcomp",
    .family		= NFPROTO_IPV4,
    .match		= comp_mt,
    .matchsize	= sizeof(struct xt_ipcomp),
    .proto		= IPPROTO_COMP,
    .checkentry	= comp_mt_check,
    .me		= THIS_MODULE,
},
"""

IPCOMP_INV_SPI = 0x01
IPCOMP_INV_MASK = 0x01

ipcomp_fmt = (
        ("spis", (TYPE_ARRAY, "I", 2)),
        ("invflags", (TYPE_SIMPLE, "B")),
        ("hdrres", (TYPE_SIMPLE, "B"))
        )

"""
{
    .name      = "iprange",
    .revision  = 1,
    .family    = NFPROTO_IPV4,
    .match     = iprange_mt4,
    .matchsize = sizeof(struct xt_iprange_mtinfo),
    .me        = THIS_MODULE,
}, 
"""

IPRANGE_SRC = 1 << 0
IPRANGE_DST = 1 << 1
IPRANGE_SRC_INV = 1 << 4
IPRANGE_DST_INV = 1 << 5

iprange_fmt = (
        ("src_min", (TYPE_ARRAY, ">I", 4)),
        ("src_max", (TYPE_ARRAY, ">I", 4)),
        ("dst_min", (TYPE_ARRAY, ">I", 4)),
        ("dst_max", (TYPE_ARRAY, ">I", 4)),
        ("flags", (TYPE_SIMPLE, "B"))
        )

"""
static struct xt_match xt_ipvs_mt_reg __read_mostly = {
	.name       = "ipvs",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.match      = ipvs_mt,
	.checkentry = ipvs_mt_check,
	.matchsize  = XT_ALIGN(sizeof(struct xt_ipvs_mtinfo)),
	.me         = THIS_MODULE,
};
"""

IPVS_PROPERTY = 1 << 0
IPVS_PROTO = 1 << 1
IPVS_VADDR = 1 << 2
IPVS_VPORT = 1 << 3
IPVS_DIR = 1 << 4
IPVS_METHOD = 1 << 5
IPVS_VPORTCTL = 1 << 6
IPVS_MASK = 1 << 7 - 1

ipvs_fmt = (
        ("vaddr", (TYPE_ARRAY, ">I", 4)),
        ("vmask", (TYPE_ARRAY, ">I", 4)),
        ("vport", (TYPE_SIMPLE, ">H")), 
        ("l4proto", (TYPE_SIMPLE, "B")),
        ("fwd_method", (TYPE_SIMPLE, "B")),
        ("vportctl", (TYPE_SIMPLE, ">H")),
        ("invert", (TYPE_SIMPLE, "B")),
        ("bitmask", (TYPE_SIMPLE, "B"))
        )
"""
{
		.name      = "l2tp",
		.revision  = 0,
		.family    = NFPROTO_IPV4,
		.match     = l2tp_mt4,
		.matchsize = XT_ALIGN(sizeof(struct xt_l2tp_info)),
		.checkentry = l2tp_mt_check4,
		.hooks     = ((1 << NF_INET_PRE_ROUTING) |
			      (1 << NF_INET_LOCAL_IN) |
			      (1 << NF_INET_LOCAL_OUT) |
			      (1 << NF_INET_FORWARD)),
		.me        = THIS_MODULE,
	},
"""

L2TP_TYPE_CONTROL = 0
L2TP_TYPE_DATA = 1

L2TP_TID = 1 << 0
L2TP_SID = 1 << 1
L2TP_VERSION = 1 << 2
L2TP_TYPE = 1 << 3

l2tp_fmt = (
        #tunnel id
        ("tid", (TYPE_SIMPLE, "I")),
        #session id
        ("sid", (TYPE_SIMPLE, "I")),
        #l2tp version
        ("version", (TYPE_SIMPLE, "B")),
        #l2tp packet type
        ("type", (TYPE_SIMPLE, "B")),
        #valid field
        ("flags", (TYPE_SIMPLE, "B"))
        )
"""
{
		.name		= "length",
		.family		= NFPROTO_IPV4,
		.match		= length_mt,
		.matchsize	= sizeof(struct xt_length_info),
		.me		= THIS_MODULE,
},
"""

length_fmt = (
        ("min", (TYPE_SIMPLE, "H")),
        ("max", (TYPE_SIMPLE, "H")),
        ("invert", (TYPE_SIMPLE, "B"))
        ) 

"""
static struct xt_match mac_mt_reg __read_mostly = {
	.name      = "mac",
	.revision  = 0,
	.family    = NFPROTO_UNSPEC,
	.match     = mac_mt,
	.matchsize = sizeof(struct xt_mac_info),
	.hooks     = (1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_LOCAL_IN) |
	             (1 << NF_INET_FORWARD),
	.me        = THIS_MODULE,
};
"""
mac_fmt = (
        ("srcaddr", (TYPE_ARRAY, "B", 6)),
        ("invert", (TYPE_SIMPLE, "I")),
        )

"""
static struct xt_match mark_mt_reg __read_mostly = {
	.name           = "mark",
	.revision       = 1,
	.family         = NFPROTO_UNSPEC,
	.match          = mark_mt,
	.matchsize      = sizeof(struct xt_mark_mtinfo1),
	.me             = THIS_MODULE,
};
"""
mark_mfmt = (
        ("mark", (TYPE_SIMPLE, "I")),
        ("mask", (TYPE_SIMPLE, "I")),
        ("invert", (TYPE_SIMPLE, "B"))
        )

"""
{
    .name		= "multiport",
    .family		= NFPROTO_IPV4,
    .revision	= 1,
    .checkentry	= multiport_mt_check,
    .match		= multiport_mt,
    .matchsize	= sizeof(struct xt_multiport_v1),
    .me		= THIS_MODULE,
}, 
"""

MULTIPORT_SOURCE = 0
MULTIPORT_DEST = 1
MULTIPORT_EITHER = 2

MULTI_PORTS = 15

multiport_v1_fmt = (
        ("flags", (TYPE_SIMPLE, "B")),
        ("count", (TYPE_SIMPLE, "B")),
        ("ports", (TYPE_ARRAY, "H", MULTI_PORTS)),
        ("pflags", (TYPE_ARRAY, "B", MULTI_PORTS)),
        ("invert", (TYPE_SIMPLE, "B"))
        ) 

"""
static struct xt_match nfacct_mt_reg __read_mostly = {
	.name       = "nfacct",
	.family     = NFPROTO_UNSPEC,
	.checkentry = nfacct_mt_checkentry,
	.match      = nfacct_mt,
	.destroy    = nfacct_mt_destroy,
	.matchsize  = sizeof(struct xt_nfacct_match_info),
	.me         = THIS_MODULE,
};
"""

NFACCT_NAME_MAX = 32

nfacct_fmt = (
        ("name", (TYPE_STR, "c", NFACCT_NAME_MAX)),
        ("nfacct", (TYPE_SIMPLE, "Q"))
        )


"""
static struct xt_match xt_osf_match = {
	.name 		= "osf",
	.revision	= 0,
	.family		= NFPROTO_IPV4,
	.proto		= IPPROTO_TCP,
	.hooks      	= (1 << NF_INET_LOCAL_IN) |
				(1 << NF_INET_PRE_ROUTING) |
				(1 << NF_INET_FORWARD),
	.match 		= xt_osf_match_packet,
	.matchsize	= sizeof(struct xt_osf_info),
	.me		= THIS_MODULE,
};
"""

MAX_GENRELEN = 32
OSF_GENRE = 1 << 0
OSF_TTL = 1 << 1
OSF_LOG = 1 << 2
OSF_INVERT = 1 << 3

#log all matches fingerprints
OSF_LOGLEVEL_ALL = 0
#log only the first matched fingerprint
OSF_LOGLEVEL_FIRST = 1
#do not log unknown packets
OSF_LOGLEVEL_ALL_KNOWN = 2

#True ip and fingerprint TTL comparison
OSF_TTL_TRUE = 0
#Check if ip TTL is less than fingerprint one
OSF_TTL_LESS = 1
#Do not compare ip and fingerprint TTL at all
OSF_TTL_NOCHECK = 2



osf_fmt = (
        ("genre", (TYPE_STR, "c", MAX_GENRELEN)),
        ("len", (TYPE_SIMPLE, "I")),
        ("flags", (TYPE_SIMPLE, "I")),
        ("loglevel", (TYPE_SIMPLE, "I")),
        ("ttl", (TYPE_SIMPLE, "I"))
        )


"""
static struct xt_match owner_mt_reg __read_mostly = {
	.name       = "owner",
	.revision   = 1,
	.family     = NFPROTO_UNSPEC,
	.checkentry = owner_check,
	.match      = owner_mt,
	.matchsize  = sizeof(struct xt_owner_match_info),
	.hooks      = (1 << NF_INET_LOCAL_OUT) |
	              (1 << NF_INET_POST_ROUTING),
	.me         = THIS_MODULE,
};
"""

OWNER_UID = 1 << 0
OWNER_GID = 1 << 1
OWNER_SOCKET = 1 << 2

owner_fmt = (
        ("uid_min", (TYPE_SIMPLE, "I")),
        ("uid_max", (TYPE_SIMPLE, "I")),
        ("gid_min", (TYPE_SIMPLE, "I")),
        ("gid_max", (TYPE_SIMPLE, "I")),
        ("match", (TYPE_SIMPLE, "B")),
        ("invert", (TYPE_SIMPLE, "B"))
        )

"""
static struct xt_match physdev_mt_reg __read_mostly = {
	.name       = "physdev",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.checkentry = physdev_mt_check,
	.match      = physdev_mt,
	.matchsize  = sizeof(struct xt_physdev_info),
	.me         = THIS_MODULE,
};
"""

PHYSDEV_OP_IN = 0x01
PHYSDEV_OP_OUT = 0x02
PHYSDEV_OP_BRIDGED = 0x04
PHYSDEV_OP_ISIN = 0x08
PHYSDEV_OP_ISOUT = 0x10
PHYSDEV_OP_MASK = 0x20 -1

physdev_info = (
        ("physindex", (TYPE_STR, "c", IFNAMSIZ)),
        ("in_mask", (TYPE_STR, "c", IFNAMSIZ)),
        ("pyhsoutdev", (TYPE_STR, "c", IFNAMSIZ)),
        ("out_mask", (TYPE_STR, "c", IFNAMSIZ)), 
        ("invert", (TYPE_SIMPLE, "B")),
        ("bitmask", (TYPE_SIMPLE, "B"))
        )


"""
{
    .name		= "policy",
    .family		= NFPROTO_IPV4,
    .checkentry 	= policy_mt_check,
    .match		= policy_mt,
    .matchsize	= sizeof(struct xt_policy_info),
    .me		= THIS_MODULE,
},
"""

#skip
POLICY_MAX_ELEM = 4


"""
static struct xt_match quota_mt_reg __read_mostly = {
	.name       = "quota",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.match      = quota_mt,
	.checkentry = quota_mt_check,
	.destroy    = quota_mt_destroy,
	.matchsize  = sizeof(struct xt_quota_info),
	.me         = THIS_MODULE,
};
"""

QUOTA_INVERT = 0x1

quota_fmt = (
        ("flags", (TYPE_SIMPLE, "I")),
        ("pad", (TYPE_SIMPLE, "I")),
        ("quota", (TYPE_SIMPLE, "Q"))
        )


"""
static struct xt_match xt_rateest_mt_reg __read_mostly = {
	.name       = "rateest",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.match      = xt_rateest_mt,
	.checkentry = xt_rateest_mt_checkentry,
	.destroy    = xt_rateest_mt_destroy,
	.matchsize  = sizeof(struct xt_rateest_match_info),
	.me         = THIS_MODULE,
};
"""


RATEEST_INVERT = 1 << 0
RATEEST_ABS = 1 << 1
RATEEST_REL = 1 << 2
RATEEST_DELTA = 1 << 3
RATEEST_BPS = 1 << 4
RATEEST_PPS = 1 << 5

RATEEST_NONE = 0
RATEEST_EQ = 1
RATEEST_LT = 2
RATEEST_GT = 3

rateest_fmt = (
        ("name1", (TYPE_STR, "c", IFNAMSIZ)),
        ("name2", (TYPE_STR, "c", IFNAMSIZ)),
        ("flags", (TYPE_SIMPLE, "H")),
        ("mode", (TYPE_SIMPLE, "H")),
        ("bps1", (TYPE_SIMPLE, "I")),
        ("pps1", (TYPE_SIMPLE, "I")),
        ("bps2", (TYPE_SIMPLE, "I")),
        ("pps2", (TYPE_SIMPLE, "I"))
        )

"""
static struct xt_match realm_mt_reg __read_mostly = {
	.name		= "realm",
	.match		= realm_mt,
	.matchsize	= sizeof(struct xt_realm_info),
	.hooks		= (1 << NF_INET_POST_ROUTING) | (1 << NF_INET_FORWARD) |
			  (1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_LOCAL_IN),
	.family		= NFPROTO_UNSPEC,
	.me		= THIS_MODULE
};
"""

realm_fmt = (
        ("id", (TYPE_SIMPLE, "I")),
        ("mask", (TYPE_SIMPLE, "I")),
        ("invert", (TYPE_SIMPLE, "B"))
        )

"""
{
		.name       = "recent",
		.revision   = 1,
		.family     = NFPROTO_IPV4,
		.match      = recent_mt,
		.matchsize  = sizeof(struct xt_recent_mtinfo_v1),
		.checkentry = recent_mt_check_v1,
		.destroy    = recent_mt_destroy,
		.me         = THIS_MODULE,
},
"""

RECENT_CHECK = 1 << 0
RECENT_SET = 1 << 1
RECENT_UPDATE = 1 << 2
RECENT_REMOVE =  1 << 3
RECENT_TTL = 1 << 4
RECENT_REAP = 1 << 5
RECENT_SOURCE = 0
RECENT_DEST = 1

RECENT_NAME_LEN = 200

recent_v1_fmt = (
        ("seconds", (TYPE_SIMPLE, "I")),
        ("hit_count", (TYPE_SIMPLE, "I")),
        ("check_set", (TYPE_SIMPLE, "B")),
        ("invert", (TYPE_SIMPLE, "B")),
        ("name", (TYPE_STR, "c", RECENT_NAME_LEN)),
        ("side", (TYPE_SIMPLE, "B")),
        ("mask", (TYPE_ARRAY, ">I", 4))
        )

"""
{
    .name		= "sctp",
    .family		= NFPROTO_IPV4,
    .checkentry	= sctp_mt_check,
    .match		= sctp_mt,
    .matchsize	= sizeof(struct xt_sctp_info),
    .proto		= IPPROTO_SCTP,
    .me		= THIS_MODULE
},
"""
#skip 
"""
	{
		.name		= "set",
		.family		= NFPROTO_IPV4,
		.revision	= 3,
		.match		= set_match_v3,
		.matchsize	= sizeof(struct xt_set_info_match_v3),
		.checkentry	= set_match_v3_checkentry,
		.destroy	= set_match_v3_destroy,
		.me		= THIS_MODULE
	},
"""
#skip
"""
{
		.name		= "socket",
		.revision	= 2,
		.family		= NFPROTO_IPV4,
		.match		= socket_mt4_v1_v2,
		.checkentry	= socket_mt_v2_check,
		.matchsize	= sizeof(struct xt_socket_mtinfo1),
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN),
		.me		= THIS_MODULE,
},
"""

SOCKET_TRANSPARENT = 1 << 0
SOCKET_NOWILDCARD = 1 << 1

socket_fmt = (
        ("flags", (TYPE_SIMPLE, "B")),
        )

"""
static struct xt_match state_mt_reg __read_mostly = {
	.name       = "state",
	.family     = NFPROTO_UNSPEC,
	.checkentry = state_mt_check,
	.match      = state_mt,
	.destroy    = state_mt_destroy,
	.matchsize  = sizeof(struct xt_state_info),
	.me         = THIS_MODULE,
};
"""

state_fmt = (
        ("statemask", (TYPE_SIMPLE, "I")),
        )

"""
static struct xt_match xt_statistic_mt_reg __read_mostly = {
	.name       = "statistic",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.match      = statistic_mt,
	.checkentry = statistic_mt_check,
	.destroy    = statistic_mt_destroy,
	.matchsize  = sizeof(struct xt_statistic_info),
	.me         = THIS_MODULE,
};
"""
#skip

"""
static struct xt_match xt_string_mt_reg __read_mostly = {
	.name       = "string",
	.revision   = 1,
	.family     = NFPROTO_UNSPEC,
	.checkentry = string_mt_check,
	.match      = string_mt,
	.destroy    = string_mt_destroy,
	.matchsize  = sizeof(struct xt_string_info),
	.me         = THIS_MODULE,
};
"""
#skip

"""
{
    .name		= "tcpmss",
    .family		= NFPROTO_IPV4,
    .match		= tcpmss_mt,
    .matchsize	= sizeof(struct xt_tcpmss_match_info),
    .proto		= IPPROTO_TCP,
    .me		= THIS_MODULE,
},
"""

tcpmss_fmt = (
        ("min", (TYPE_SIMPLE, "H")),
        ("max", (TYPE_SIMPLE, "H")),
        ("invert", (TYPE_SIMPLE, "B"))
        )

"""
static struct xt_match xt_time_mt_reg __read_mostly = {
	.name       = "time",
	.family     = NFPROTO_UNSPEC,
	.match      = time_mt,
	.checkentry = time_mt_check,
	.matchsize  = sizeof(struct xt_time_info),
	.me         = THIS_MODULE,
};
"""
#match against local time (instead of UTC) 
TIME_LOCAL_TZ = 1 << 0
#treat timestart > timestop as single period
TIME_CONTIGUOUS = 1 << 1
TIME_ALL_MONTHDAYS = 0xFFFFFFFE
TIME_ALL_WEEKDAYS = 0xFE
TIME_MIN_DAYTIME = 0
TIME_MAX_DAYTIME = 24 * 60 * 60 - 1

time_fmt = (
        ("date_start", (TYPE_SIMPLE, "I")),
        ("date_stop", (TYPE_SIMPLE, "I")),
        ("daytime_start", (TYPE_SIMPLE, "I")),
        ("daytime_stop", (TYPE_SIMPLE, "I")),
        ("monthdays_match", (TYPE_SIMPLE, "I")),
        ("weekdays_match", (TYPE_SIMPLE, "B")),
        ("flags", (TYPE_SIMPLE, "B"))
        )

"""
static struct xt_match xt_u32_mt_reg __read_mostly = {
	.name       = "u32",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.match      = u32_mt,
	.matchsize  = sizeof(struct xt_u32),
	.me         = THIS_MODULE,
};
"""
#skip 

#parse_match都加revision参数

match_plugin = { 
        "conntrack": (parse_match_conntrack, generate_match_conntrack),
        "limit": (parse_match_limit, generate_match_limit),
        "pkttype": (parse_match_pkttype, generate_match_pkttype),
        "icmp": (parse_match_icmp, generate_match_icmp), 
        "tcp": (parse_match_tcp, generate_match_tcp),
        "udp": (parse_match_udp, generate_match_udp),
        } 


def test_get_info():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    fd = sock.fileno() 
    data = generate_get_info(
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


def dump_table(table): 
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    fd = sock.fileno() 
    data = generate_get_info(
            {
                "name": table,
                "valid_hooks": 0,
                "hook_entry": (0,) * NUMHOOKS,
                "underflow": (0,) * NUMHOOKS,
                "num_entries": 0,
                "size": 0 
                }) 
    _sockopt.get(fd, socket.IPPROTO_IP, GET_INFO, data) 
    info = parse_get_info(cStringIO.StringIO(data)) 
    data = generate_get_entries(
            {
                "name": table,
                "size": info["size"],
                "entries": info["size"] * "\x00"
            }) 
    _sockopt.get(fd, socket.IPPROTO_IP, GET_ENTRIES, data) 
    entries = parse_get_entries(cStringIO.StringIO(data), len(data)) 
    chains = parse_chains(info, entries["entries"]) 
    def print_rule(payload):
        pprint.pprint(payload)
    for i,v in chains.items():
        print "=============="
        print "chain:", i 
        for i in v:
            print_rule(i) 
    d = generate_chains(chains)


def ip_to_num(ip):
    return struct.unpack(">I", socket.inet_aton(ip))[0]


def test_entry(): 
    generate_entry({ "ip": { 
            "dst": ip_to_num("106.186.112.80"),
            "dmsk": 0xffffffff
            },
        "matches": [],
        "target": {
            "revision": 0,
            "name": "std",
            "payload": {
                "verdict": NF_DROP
                }
            }
    })


if __name__ == "__main__":
    import sys, argparse
    parser = argparse.ArgumentParser(
            description="iptables")
    parser.add_argument("-t", type=str, help="get by table")
    parser.add_argument("-e", type=str, help="test entry")
    args = parser.parse_args()
    if args.t:
        dump_table(args.t)
    if args.e:
        test_entry()
