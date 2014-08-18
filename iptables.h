/* kernel header common */
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/types.h>
#include <linux/icmp.h>
/* netfilter */
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>
#include <linux/netfilter/xt_pkttype.h>
#include <linux/netfilter/xt_conntrack.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/xt_limit.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_LOG.h>
#include <linux/netfilter_ipv4/ipt_REJECT.h>

/* user headers common */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <syslog.h>



#define DICT_GET_INT(x, y) PyInt_AsLong(PyDict_GetItemString(x, y))
#define DICT_GET_ULONG(x, y) PyLong_AsUnsignedLong(PyDict_GetItemString(x, y))
#define DICT_GET_STRING(x, y) PyString_AsString(PyDict_GetItemString(x, y))
#define DICT_STORE_INT(x, y, z) PyDict_SetItemString(x, y, PyInt_FromLong(z))
#define DICT_STORE_ULONG(x, y, z) PyDict_SetItemString(x, y, PyLong_FromUnsignedLong(z))
#define DICT_STORE_STRING(x, y, z) PyDict_SetItemString(x, y, PyString_FromString(z))


struct replace_context { 
	PyObject *jumps;
	PyObject *chain_offsets; 
	unsigned offset; 
	socklen_t sockfd;
	unsigned memory_size; 
	void *memory; 
	struct ipt_getinfo info;
	struct ipt_replace replace[0]; 
};

struct chain_head {
	struct ipt_entry e;
	struct xt_error_target name;
}; 

struct chain_foot {
	struct ipt_entry e;
	struct xt_standard_target target;
};

struct chain_error {
	struct ipt_entry e;
	struct xt_error_target target;
};

