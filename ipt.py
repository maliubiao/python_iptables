#-*-encoding=utf-8-*-

import _sockopt 
import socket
import struct
import cStringIO
import pdb
import pprint

TABLE_MAXNAMELEN = 32 
IFNAMSIZ = 16

#内置的chain, 也叫hook
PRE_ROUTING = 0
LOCAL_IN = 1
FORWARD = 2
LOCAL_OUT = 3
POST_ROUTING = 4
NUMHOOKS = 5

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
    buf.append(struct.pack("I", d["size"]))
    buf.append(d["payload"])
    return "".join(buf)


def parse_get_entries(b):
    name = b.read(TABLE_MAXNAMELEN).strip("\x00")
    size = struct.unpack("I", b.read(4))[0]
    payload = b.read()
    return {
            "name": name,
            "size": size,
            "payload": payload
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
    pass


def parse_entry(b):
    pass


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
