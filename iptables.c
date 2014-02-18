#include "Python.h" 
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

#define XTABLES_VERSION "9" 

#define DICT_GET_INT(x, y) PyInt_AsLong(PyDict_GetItemString(x, y))
#define DICT_GET_ULONG(x, y) PyLong_AsUnsignedLong(PyDict_GetItemString(x, y))
#define DICT_GET_STRING(x, y) PyString_AsString(PyDict_GetItemString(x, y))
#define DICT_STORE_INT(x, y, z) PyDict_SetItemString(x, y, PyInt_FromLong(z))
#define DICT_STORE_ULONG(x, y, z) PyDict_SetItemString(x, y, PyLong_FromUnsignedLong(z))
#define DICT_STORE_STRING(x, y, z) PyDict_SetItemString(x, y, PyString_FromString(z))


struct replace_context {
	struct ipt_replace *replace;
	struct ipt_getinfo *info;
	PyObject *jumps;
	PyObject *chain_offsets;
	void *memory; 
	unsigned offset; 
	unsigned memory_size; 
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
static const char *hooknames[] = {
	[NF_IP_PRE_ROUTING]	= "PREROUTING",
	[NF_IP_LOCAL_IN]	= "INPUT",
	[NF_IP_FORWARD]		= "FORWARD",
	[NF_IP_LOCAL_OUT]	= "OUTPUT",
	[NF_IP_POST_ROUTING]	= "POSTROUTING",
};


static int
is_builtin(char *chain_name)
{
	unsigned i;
	for(i = 0; i <= NF_IP_POST_ROUTING; i++) {
		if (strcmp(chain_name, hooknames[i]) == 0) {
			return i;
		}
	}
	return -1; 
}

static struct ipt_entry *
offset_get_entry(struct ipt_get_entries *entries, unsigned int offset)
{
	return (struct ipt_entry *)((char*)entries->entrytable + offset);
}

static unsigned long 
entry_get_offset(struct ipt_get_entries *entries, struct ipt_entry *e)
{
	return (void *)e - (void *)entries->entrytable;
}
/*
 * maybe a predefined chain, aka hook.
 */
static unsigned int 
entry_is_hook_entry(struct ipt_entry *e, struct ipt_getinfo *info,
		struct ipt_get_entries *entries)
{
	unsigned int i;
	for (i = 0; i < NF_IP_NUMHOOKS; i++) {
		if ((info->valid_hooks & (1 << i))
			&& offset_get_entry(entries,
				info->hook_entry[i]) == e) { 
			return i+1;
		}
	}
	return 0;
}


static int
handle_match_pkttype(PyObject *match_dict, void *data, unsigned write)
{
	if (write == 0) {
		struct xt_pkttype_info *info = data;
		DICT_STORE_INT(match_dict, "type", info->pkttype);
		DICT_STORE_ULONG(match_dict, "invert", info->invert);
	} else { 
		/* packet type plugin */
		struct xt_pkttype_info *info = data;
		info->pkttype = DICT_GET_INT(match_dict, "type"); 
		info->invert = DICT_GET_ULONG(match_dict, "invert"); 
	}
	return 0;
}

static int 
handle_match_tcp(PyObject *match_dict, void *data, unsigned write)
{
	if (write == 0) {
		struct xt_tcp *tcpinfo = data; 
		PyDict_SetItemString(match_dict, "spts",
			PyTuple_Pack(2, PyInt_FromLong(tcpinfo->spts[0]),
			    PyInt_FromLong(tcpinfo->spts[1])));
		PyDict_SetItemString(match_dict, "dpts",
			PyTuple_Pack(2, PyInt_FromLong(tcpinfo->dpts[0]),
			    PyInt_FromLong(tcpinfo->dpts[1])));
		DICT_STORE_ULONG(match_dict, "options", tcpinfo->option);	
		DICT_STORE_ULONG(match_dict, "flag_mask", tcpinfo->flg_mask);
		DICT_STORE_ULONG(match_dict, "flag_cmp", tcpinfo->flg_cmp);
		DICT_STORE_ULONG(match_dict, "invflags", tcpinfo->invflags);
	} else { 
		/* tcp match plugin */	
		struct xt_tcp *tcpinfo = data;
#define TUPLE_GET_INT(x, y) PyInt_AsLong(PyTuple_GetItem(x, y))
		PyObject *spts_tuple = PyDict_GetItemString(match_dict,
			"spts"); 
		tcpinfo->spts[0] = TUPLE_GET_INT(spts_tuple, 0); 
		tcpinfo->spts[1] = TUPLE_GET_INT(spts_tuple, 1); 
		PyObject *dpts_tuple = PyDict_GetItemString(match_dict,
			"dpts");
		tcpinfo->dpts[0] = TUPLE_GET_INT(dpts_tuple, 0);
		tcpinfo->dpts[1] = TUPLE_GET_INT(dpts_tuple, 1); 
#undef TUPLE_GET_INT
		tcpinfo->option = DICT_GET_ULONG(match_dict, "options");
		tcpinfo->flg_mask = DICT_GET_ULONG(match_dict,
			"flag_mask");
		tcpinfo->flg_cmp = DICT_GET_ULONG(match_dict, "flag_cmp");
		tcpinfo->invflags = DICT_GET_ULONG(match_dict, "invflags");
	}
	return 0;

}

static int
handle_match_conntrack(PyObject *match_dict, void *data, unsigned write)
{ 
	if (write == 0) { 
		struct xt_conntrack_mtinfo3 *info = data;
		if (info->match_flags & XT_CONNTRACK_STATE) { 
			DICT_STORE_ULONG(match_dict, "state",
					info->state_mask);
		}
		if (info->match_flags & XT_CONNTRACK_STATUS) { 
			DICT_STORE_ULONG(match_dict, "status",
					info->status_mask);
		}
		if (info->match_flags & XT_CONNTRACK_EXPIRES) {
			DICT_STORE_INT(match_dict, "expires_min",
					info->expires_min);	
			DICT_STORE_INT(match_dict, "expires_max",
					info->expires_max); 
		} 
		if (info->match_flags & XT_CONNTRACK_ORIGSRC) {
			DICT_STORE_ULONG(match_dict, "origscr_ip",
					info->origsrc_addr.in.s_addr);
			DICT_STORE_ULONG(match_dict, "origsrc_mask",
					info->origsrc_mask.in.s_addr); 
		} 
		if (info->match_flags & XT_CONNTRACK_ORIGDST) {
			DICT_STORE_ULONG(match_dict, "origdst_ip",
					info->origdst_addr.in.s_addr);
			DICT_STORE_ULONG(match_dict, "origdst_mask",
					info->origdst_mask.in.s_addr); 
		} 
		if (info->match_flags & XT_CONNTRACK_REPLSRC) {
			DICT_STORE_ULONG(match_dict, "replsrc_ip",
					info->replsrc_addr.in.s_addr);
			DICT_STORE_ULONG(match_dict, "replsrc_mask",
					info->replsrc_mask.in.s_addr); 
		} 

		if (info->match_flags & XT_CONNTRACK_REPLDST) {
			DICT_STORE_ULONG(match_dict, "repldst_ip",
					info->repldst_addr.in.s_addr);
			DICT_STORE_ULONG(match_dict, "repldst_mask",
					info->repldst_mask.in.s_addr); 
		} 
		DICT_STORE_ULONG(match_dict, "invflags",
				info->invert_flags); 
	} else { 
		struct xt_conntrack_mtinfo3 *info = data;
		unsigned match_flags = DICT_GET_ULONG(match_dict, "match_flags");
		if (match_flags & XT_CONNTRACK_STATE) {
			info->state_mask = DICT_GET_ULONG(match_dict, "state");
		}
		if (match_flags & XT_CONNTRACK_STATUS) {
			info->status_mask = DICT_GET_ULONG(match_dict, "status");
		} 
		if (match_flags & XT_CONNTRACK_EXPIRES) {
			info->expires_min = DICT_GET_INT(match_dict, "expires_min"); 
			info->expires_max = DICT_GET_INT(match_dict, "expires_max");
		}
		if (match_flags & XT_CONNTRACK_ORIGSRC) {
			info->origsrc_addr.in.s_addr = DICT_GET_ULONG(match_dict, "origsrc_ip");
			info->origsrc_mask.in.s_addr = DICT_GET_ULONG(match_dict, "origsrc_mask");
		}
		if (match_flags & XT_CONNTRACK_ORIGDST) {
			info->origdst_addr.in.s_addr = DICT_GET_ULONG(match_dict, "origdst_ip");
			info->origdst_mask.in.s_addr = DICT_GET_ULONG(match_dict, "origdst_mask");	
		}
		if (match_flags & XT_CONNTRACK_REPLSRC) {
			info->replsrc_addr.in.s_addr = DICT_GET_ULONG(match_dict, "replsrc_ip");
			info->replsrc_mask.in.s_addr = DICT_GET_ULONG(match_dict, "replsrc_mask");
		}
		if (match_flags & XT_CONNTRACK_REPLDST) {
			info->repldst_addr.in.s_addr = DICT_GET_ULONG(match_dict, "repldst_ip");
			info->repldst_addr.in.s_addr = DICT_GET_ULONG(match_dict, "repldst_mask"); 
		}
		info->invert_flags = DICT_GET_ULONG(match_dict, "invflags");
	
	}
	return 0;
}

static int
handle_match_limit(PyObject *match_dict, void *data, unsigned write)
{ 
	if (write == 0) {
		struct xt_rateinfo *r = data;
		DICT_STORE_ULONG(match_dict, "avg", r->avg);
		DICT_STORE_ULONG(match_dict, "burst", r->burst); 
	} else {
		struct xt_rateinfo *r = data;
		r->avg = DICT_GET_INT(match_dict, "avg"); 
		r->burst = DICT_GET_INT(match_dict, "burst");
	}
	return 0;
} 

static int 
handle_match_icmp(PyObject *match_dict, void *data, unsigned write)
{
	if (write == 0) {
		struct ipt_icmp *icmpinfo = data;
		DICT_STORE_INT(match_dict, "type", icmpinfo->type);	
		DICT_STORE_INT(match_dict, "min", icmpinfo->code[0]);
		DICT_STORE_INT(match_dict, "max", icmpinfo->code[1]);
		DICT_STORE_ULONG(match_dict, "invflags", icmpinfo->invflags); 
	} else {
		struct ipt_icmp *icmpinfo = data;
		icmpinfo->type = DICT_GET_INT(match_dict, "type"); 
		icmpinfo->code[0] = DICT_GET_INT(match_dict, "min"); 
		icmpinfo->code[1] = DICT_GET_INT(match_dict, "max"); 
		icmpinfo->invflags = DICT_GET_ULONG(match_dict, "invflags"); 
	}
	return 0;
}

static int
handle_target_log(PyObject *target_dict, void *target_data, unsigned write)
{
	if (write == 0) {			
		struct ipt_log_info *loginfo = target_data;
		DICT_STORE_ULONG(target_dict, "level", loginfo->level);
		DICT_STORE_ULONG(target_dict, "logflags",
				loginfo->logflags);
		DICT_STORE_STRING(target_dict, "prefix", loginfo->prefix); 
	} else {
		struct ipt_log_info *loginfo = target_data;
		loginfo->level = DICT_GET_ULONG(target_dict, "level");
		loginfo->logflags = DICT_GET_ULONG(target_dict,
				"logflags");
		strcpy(loginfo->prefix, DICT_GET_STRING(target_dict, "prefix")); 
	}
	return 0;

}

static int
handle_target_reject(PyObject *target_dict, void *target_data, unsigned write)
{
	if (write == 0) {
		struct ipt_reject_info *rjinfo = target_data;
		DICT_STORE_ULONG(target_dict, "with", rjinfo->with); 
	} else {
		struct ipt_reject_info *rjinfo = target_data;
		rjinfo->with = DICT_GET_ULONG(target_dict, "with");
	}
	return 0;
}


static int 
parse_match(struct xt_entry_match *m, PyObject *matches_dict)
{ 
	PyObject *match_dict = NULL; 
	match_dict = PyDict_New();  

	DICT_STORE_INT(match_dict, "size", m->u.user.match_size); 
	if (strcmp(m->u.user.name, "pkttype") == 0) { 
		handle_match_pkttype(match_dict, m->data, 0);
	} else if (strcmp(m->u.user.name, "tcp") == 0) { 
		handle_match_tcp(match_dict, m->data, 0); 
	} else if (strcmp(m->u.user.name, "conntrack") == 0) { 
		if (m->u.user.revision != 3) {
		    goto RETURN;
		}
		handle_match_conntrack(match_dict, m->data, 0);
	} else if (strcmp(m->u.user.name, "limit") == 0) {
		handle_match_limit(match_dict, m->data, 0);
	} else if (strcmp(m->u.user.name, "icmp") == 0) {
		handle_match_icmp(match_dict, m->data, 0);
	} 
	PyDict_SetItemString(matches_dict, m->u.user.name,
                    match_dict); 
RETURN:
	return 0;
}

static int parse_matches(PyObject *rule_dict, struct ipt_entry *e)
{ 
	PyObject *matches_dict = NULL;
	if (!(rule_dict && e)) {
		return 1;
	} 
	/* matches */
	matches_dict = PyDict_New(); 
	XT_MATCH_ITERATE(struct ipt_entry, e, parse_match, matches_dict); 
	PyDict_SetItemString(rule_dict, "matches", matches_dict); 
	return 0;
}

static int
parse_target(PyObject *rule_dict, struct xt_entry_target *t, struct ipt_entry *e, struct ipt_get_entries *entries)
{ 
	struct xt_standard_target *xt = (void *)t; 
	if (!(rule_dict && t && e && entries)) {
		return 1;
	}
	/* target */ 
	if (strcmp(t->u.user.name, XT_STANDARD_TARGET) == 0) { 
		if (xt->verdict < 0) {
			DICT_STORE_STRING(rule_dict, "target_type",
					"standard"); 
		} else if (xt->verdict == entry_get_offset(entries, e) + e->next_offset) {
			DICT_STORE_STRING(rule_dict, "target_type",
					"fallthrough"); 
		} else {
			DICT_STORE_STRING(rule_dict, "target_type",
					"jump"); 
		}
		DICT_STORE_INT(rule_dict, "verb", xt->verdict); 
	}  else {
		/* target extension */
		PyObject *target_dict;
		target_dict = PyDict_New();
		if (strcmp(t->u.user.name, "LOG") == 0) { 
			handle_target_log(target_dict, t->data, 0); 
			PyDict_SetItemString(rule_dict, "target_dict",
					target_dict);
		} else if (strcmp(t->u.user.name, "REJECT") == 0) {
			handle_target_reject(target_dict, t->data, 0);
			PyDict_SetItemString(rule_dict, "target_dict",
					target_dict);
		}
		PyDict_SetItemString(rule_dict, "target_type",
				PyString_FromString("module"));
		PyDict_SetItemString(rule_dict, "verb",
				PyInt_FromLong(xt->verdict)); 
	} 
	return 0;
}

static int 
parse_entry(struct ipt_entry *e, PyObject *chains_dict,
		PyObject **current_chain_ptr,
		struct ipt_getinfo *info,
		struct ipt_get_entries *entries)
{
	size_t i;	
	unsigned int builtin;
	struct xt_entry_target *t; 
	char iniface_buffer[IFNAMSIZ+1];
	char outiface_buffer[IFNAMSIZ+1];
	PyObject *rule_dict; 

	memset(iniface_buffer, 0, IFNAMSIZ+1);
	memset(outiface_buffer, 0, IFNAMSIZ+1);
	if ((unsigned long)((void *)e - (void *)entries->entrytable)
			+ e->next_offset == entries->size) {
		/* last one, policy rule do nothing*/	
		return 0;
	}
	/* rule data */
	rule_dict = PyDict_New();
	/* for jump target */
	DICT_STORE_ULONG(rule_dict, "offset", entry_get_offset(entries, e));
	DICT_STORE_ULONG(rule_dict, "srcip", e->ip.src.s_addr);
	DICT_STORE_ULONG(rule_dict, "srcip_mask", e->ip.smsk.s_addr);
	DICT_STORE_ULONG(rule_dict, "dstip", e->ip.dst.s_addr);
	DICT_STORE_ULONG(rule_dict, "dstip_mask", e->ip.dmsk.s_addr);

	for (i = 0; i < IFNAMSIZ; i++) {
		*(iniface_buffer+i) = e->ip.iniface_mask[i];
		*(outiface_buffer) = e->ip.outiface_mask[i];
	} 
	DICT_STORE_STRING(rule_dict, "iniface", e->ip.iniface);

	PyDict_SetItemString(rule_dict, "iniface_mask",
			PyByteArray_FromStringAndSize(iniface_buffer, IFNAMSIZ));
	DICT_STORE_STRING(rule_dict, "outiface", e->ip.outiface); 
	PyDict_SetItemString(rule_dict, "outiface_mask",
			PyByteArray_FromStringAndSize(outiface_buffer, IFNAMSIZ));
	DICT_STORE_INT(rule_dict, "protocol", e->ip.proto);
	DICT_STORE_ULONG(rule_dict, "flags", e->ip.flags);
	DICT_STORE_ULONG(rule_dict, "invflags", e->ip.invflags);
	DICT_STORE_ULONG(rule_dict, "packets", e->counters.pcnt);
	DICT_STORE_ULONG(rule_dict, "bytes", e->counters.bcnt);
	DICT_STORE_ULONG(rule_dict, "cache", e->nfcache); 

	/* matches */
	parse_matches(rule_dict, e);
	/* target */
	t = (void *)e + e->target_offset;
	DICT_STORE_STRING(rule_dict, "target", t->u.user.name); 
	/* new chain */ 
	if (strcmp(t->u.user.name, XT_ERROR_TARGET) == 0) {
		/* new user defined chain */
		*current_chain_ptr = PyList_New(0);
		PyDict_SetItemString(chains_dict, (char *)t->data,
				*current_chain_ptr); 
		Py_XDECREF(rule_dict);	
		return 0;
	} else if ((builtin = entry_is_hook_entry(e, info, entries)) != 0) {
		*current_chain_ptr = PyList_New(0); 
		PyDict_SetItemString(chains_dict,
				(char *)hooknames[builtin-1],
				*current_chain_ptr); 
	} 
	parse_target(rule_dict, t, e, entries);
	/* add rule to current_chain */
	if (*current_chain_ptr) {
		return PyList_Append(*current_chain_ptr, rule_dict) ? 1 : 0; 
	} else {
		return 1;
	}
}

static PyObject *
parse_entries(struct ipt_getinfo *info, struct ipt_get_entries *entries)
{
	PyObject *table_dict; 
	PyObject *chains_dict;
	PyObject *current_chain = NULL;

	table_dict = PyDict_New();
	DICT_STORE_STRING(table_dict, "iptver", XTABLES_VERSION); 
	DICT_STORE_INT(table_dict, "blobsize", entries->size); 
	DICT_STORE_STRING(table_dict, "name", info->name); 

	chains_dict = PyDict_New(); 
	unsigned int i, ret; 
	struct ipt_entry *entry;

	for (i = 0;i < entries->size;
			i += entry->next_offset) {
		entry = (void *)(entries->entrytable) + i; 
		ret = parse_entry(entry, chains_dict,
				&current_chain, info, entries); 
		if (ret != 0)
			break;
	}

	PyDict_SetItemString(table_dict, "chains", chains_dict);
	return table_dict;

} 

PyDoc_STRVAR(iptables_get_table_doc, "get entries of a table");

static PyObject *
iptables_get_table(PyObject *object, PyObject *args)
{ 
	struct ipt_getinfo *info;
	struct ipt_get_entries *entries;
	char *tablename; 
	socklen_t s;
	int sockfd; 
	unsigned int tmp; 

	if (!PyArg_ParseTuple(args, "s:get_entries", &tablename)) {
		return NULL;
	} 
	if (strlen(tablename) >= XT_TABLE_MAXNAMELEN) { 
		return NULL;
	}
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) == -1) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	info = PyMem_Malloc(sizeof(struct ipt_getinfo)); 
	if (!info)
		goto ERROR; 
	s = sizeof(struct ipt_getinfo);
	memset(info, 0, s);
	strcpy(info->name, tablename);
	if (getsockopt(sockfd, IPPROTO_IP,
				IPT_SO_GET_INFO, info, &s) < 0) {
		PyErr_SetFromErrno(PyExc_OSError); 
		goto FREE_INFO; 
	} 
	entries = PyMem_Malloc(sizeof(struct ipt_get_entries) + info->size);
	if (!entries) { 
		goto FREE_INFO;
	}
	entries->size = info->size; 
	strcpy(entries->name, info->name);
	tmp = sizeof(struct ipt_get_entries) + info->size;
	if (getsockopt(sockfd, IPPROTO_IP,
				IPT_SO_GET_ENTRIES, entries, &tmp) < 0) {
		PyErr_SetFromErrno(PyExc_OSError);	
		goto FREE_ENTRIES;
	}
	close(sockfd); 
	return parse_entries(info, entries); 
FREE_ENTRIES:
	PyMem_Free(entries);
FREE_INFO:
	PyMem_Free(info); 
ERROR:	
	close(sockfd); 
	return NULL;
}


static int
compile_target(struct replace_context *context, PyObject *rule_dict,  void **base, unsigned int *offset)
{ 
	if (!(context && rule_dict && base && offset)) {
		goto TARGET_FAILED;	
	}
	unsigned entry_size = sizeof(struct xt_standard_target);
	char *target_type = DICT_GET_STRING(rule_dict, "target_type");
	if (strcmp(target_type, "standard") == 0) {
		struct xt_standard_target *xst = *base;
		strcpy(xst->target.u.user.name, XT_STANDARD_TARGET);
		xst->target.u.target_size = entry_size;
		/* standard action */
		xst->verdict = DICT_GET_INT(rule_dict, "verb");
		/* move forward */
		*offset += entry_size;
		*base += entry_size;
	} else if (strcmp(target_type, "jump") == 0) {
		/* jump to another chain , add this later*/
		struct xt_standard_target *xst = *base;
		PyList_Append(context->jumps,
			PyTuple_Pack(2,
				PyLong_FromUnsignedLong((unsigned long long)xst),
				PyDict_GetItemString(rule_dict, "verb")
				)
			);
		strcpy(xst->target.u.user.name, XT_STANDARD_TARGET);
		xst->target.u.target_size = entry_size;
		/* target unknown yet */
		xst->verdict = 0;
		/* move forward */
		*offset += entry_size;
		*base += entry_size;
		
	} else if (strcmp(target_type, "fallthrough") == 0) {
		/* to next rule */
		struct xt_standard_target *xst  = *base; 
		strcpy(xst->target.u.user.name, XT_STANDARD_TARGET);
		xst->target.u.target_size = entry_size;
		xst->verdict = *offset + entry_size;
		/* move forward */
		*offset += entry_size;
		*base += entry_size;
	} else if (strcmp(target_type, "module") == 0) {
		/*target module */
		unsigned target_pl_size = 0; 
		char *module_name = DICT_GET_STRING(rule_dict, "target");
		PyObject *target_dict = PyDict_GetItemString(rule_dict, "target_dict");
		if (target_dict == NULL) {
			/* unknown target */
			goto TARGET_FAILED;
		}
		struct xt_entry_target *xet = *base;
		/* copy target name */ 
		strcpy(xet->u.user.name, module_name);
		/* move forawrd */
		*base += entry_size;
		*offset += entry_size;
		if (strcmp(module_name, "LOG") == 0) {
			/* base + paylaod size */
			target_pl_size = sizeof(struct ipt_log_info); 
			handle_target_log(target_dict, *base, 1);	

		} else if(strcmp(module_name, "REJECT") == 0) {
			target_pl_size = sizeof(struct ipt_reject_info); 
			handle_target_reject(target_dict,  *base,  1);	
		} else {
			goto TARGET_FAILED;
		}
		/* move forward */
		xet->u.target_size = entry_size + target_pl_size; 
		*offset += target_pl_size;
		*base += target_pl_size;
	} else {
		goto TARGET_FAILED;
	} 
	return 1;
TARGET_FAILED:
	return 0;
}

static int 
compile_matches(void **base, PyObject *this_match, unsigned int *match_offset) 
{
	/*supress gcc warning*/
	const char *keystr = NULL;
	unsigned xt_size = XT_ALIGN(sizeof(struct xt_entry_match));
	unsigned xt_pl_size = 0;
	struct xt_entry_match *match_entry = *base; 

	PyObject *match_name = PyTuple_GetItem(this_match, 0);
	PyObject *match_dict = PyTuple_GetItem(this_match, 1);

	if ((match_name == NULL) | (match_dict == NULL)) {
		return 0;
	}
	/*move forward */
	*base += xt_size;
	*match_offset += xt_size;
	/*which plugin */
	match_entry->u.user.revision = 3; 
	keystr = PyString_AsString(match_name);
	if (strcmp(keystr, "tcp") == 0) { 
		xt_pl_size = sizeof(struct xt_tcp);
		handle_match_tcp(match_dict, *base,  1);
		strcpy(match_entry->u.user.name, keystr); 
	} else if (strcmp(keystr, "pkttype")) {
		xt_pl_size = sizeof(struct xt_pkttype_info);
		handle_match_pkttype(match_dict, *base, 1);
		strcpy(match_entry->u.user.name, keystr); 
		
	}  else if (strcmp(keystr, "conntrack")) {
		/* conntrack plugin */
		xt_pl_size = sizeof(struct xt_conntrack_mtinfo3);
		handle_match_conntrack(match_dict, *base, 1);
		strcpy(match_entry->u.user.name, keystr);

	} else if (strcmp(keystr, "limit")) {
		/* limit plugin */
		xt_pl_size = sizeof(struct xt_rateinfo);
		handle_match_limit(match_dict, *base, 1);	
		strcpy(match_entry->u.user.name, keystr);

	} else if (strcmp(keystr, "icmp")) {
		/* icmp plugin */
		xt_pl_size = sizeof(struct ipt_icmp);
		handle_match_icmp(match_dict, *base, 1);
		strcpy(match_entry->u.user.name, keystr); 
	} else {
		/* unknown plugin failed */
		return 0;
	} 
	/* move forward */
	match_entry->u.match_size = xt_size + xt_pl_size;
	*base += xt_pl_size;
	*match_offset += xt_pl_size;
	return 1; 
}

static int
compile_rule(struct replace_context *context, PyObject *rule_dict, struct ipt_entry *this_entry, unsigned int *offset)
{ 
	unsigned match_offset = 0;
	struct xt_entry_match *base = NULL;
	if (!(context && rule_dict && this_entry)) {
		goto CLEAR;
	}
	/*copy ipt_entry */
	this_entry->ip.src.s_addr = DICT_GET_ULONG(rule_dict, "srcip");
	this_entry->ip.dst.s_addr = DICT_GET_ULONG(rule_dict, "dstip");
	this_entry->ip.smsk.s_addr = DICT_GET_ULONG(rule_dict, "srcip_mask");
	this_entry->ip.dmsk.s_addr = DICT_GET_ULONG(rule_dict, "dstip_mask");
	/*copy iface and mask*/
	strcpy(this_entry->ip.iniface, DICT_GET_STRING(rule_dict, "iniface"));
	strcpy(this_entry->ip.outiface,  DICT_GET_STRING(rule_dict, "outiface"));
	PyObject *iniface_mask = PyDict_GetItemString(rule_dict, "iniface_mask");
	memcpy(this_entry->ip.iniface_mask, PyByteArray_AsString(iniface_mask), PyByteArray_Size(iniface_mask));
	PyObject *outiface_mask = PyDict_GetItemString(rule_dict, "outiface_mask");
	memcpy(this_entry->ip.outiface_mask,  PyByteArray_AsString(outiface_mask), PyByteArray_Size(outiface_mask)); 
	this_entry->ip.proto = DICT_GET_INT(rule_dict, "protocol");	
	this_entry->ip.flags = DICT_GET_ULONG(rule_dict, "flags");
	this_entry->ip.invflags = DICT_GET_ULONG(rule_dict, "invflags");

	/*move forward, copy matches */
	base = (void *)this_entry + sizeof(struct ipt_entry);
	PyObject *matches_dict = PyDict_GetItemString(rule_dict, "matches");
	PyObject *matches_dict_iter = PyObject_GetIter(PyDict_Items(matches_dict)); 
	int ret;
	PyObject *matches_dict_next = PyIter_Next(matches_dict_iter);
	while (matches_dict_next) {
		ret = compile_matches((void **)(&base), matches_dict_next, &match_offset);
		Py_XDECREF(matches_dict_next);
		if (!ret) {
			Py_XDECREF(matches_dict_iter);	
			goto CLEAR;
		}
		matches_dict_next = PyIter_Next(matches_dict_iter); 
	}
	/* target offset */
	this_entry->target_offset = match_offset; 
	/* (standard? jump? fallthrough?), module? */	
	compile_target(context, rule_dict, (void **)(&base),  offset);	
	/* next_offset __align__(struct ipt_entry) */ 
	unsigned use_align = __alignof__(struct ipt_entry); 
	*offset += use_align - (*offset % use_align);
	this_entry->next_offset = *offset; 
	return 1;
CLEAR:
	return 0; 
}


static int 
compile_chain(struct replace_context *context, PyObject *chain_name,  PyObject *rule_list)
{ 
	int hooknum = 0; 
	unsigned int offset = 0;
	struct chain_head *header = NULL; 

	if (!(context && chain_name && rule_list)) {
		goto CLEAR;
	} 
	/*add chain header */
	/*collect chain_offsets*/
	PyDict_SetItem(context->chain_offsets, chain_name,
			PyLong_FromUnsignedLong((unsigned long long)context->memory));
	hooknum = is_builtin(PyString_AsString(chain_name));
	if (hooknum < 0) { 
		/* user defined chain header */
		header = context->memory;
		header->e.target_offset = sizeof(struct ipt_entry); 
		strcpy(header->name.target.u.user.name, XT_ERROR_TARGET); 
		header->name.target.u.target_size = 
			XT_ALIGN(sizeof(struct xt_error_target));
		/* chain name */
		strcpy(header->name.errorname, PyString_AsString(chain_name));
		/* move forward */
		context->memory += sizeof(struct chain_head); 
		offset += sizeof(struct chain_head);
	} else { 
		/*add hook */
		context->replace->hook_entry[hooknum] =(unsigned long)context->memory;
		/* set valid_hooks */
		context->replace->valid_hooks |= (1 << hooknum);
		/* add underflow later */	
	}

	PyObject *rule_list_iter = PyObject_GetIter(rule_list); 
	if (!rule_list_iter) {
		goto CLEAR;
	}

	PyObject *rule_list_next = PyIter_Next(rule_list_iter);
	while(rule_list_next) { 
		/*translate and copy chain */
		struct ipt_entry *this_entry = context->memory;
		if(!this_entry) {
			Py_XDECREF(rule_list_iter); 
			goto CLEAR;
		}
		int rule_ret = compile_rule(context, rule_list_next, this_entry, &offset); 
		Py_XDECREF(rule_list_next);
		if(!rule_ret) {
			Py_XDECREF(rule_list_iter); 
			goto CLEAR;
		} 
		/* move forward */
		context->memory += offset;
		rule_list_next = PyIter_Next(rule_list_iter);
	} 

	if (hooknum > 0) {
		/* add underflow */
		context->replace->underflow[hooknum] = (unsigned long)context->memory; 
	} 
	return 1;
CLEAR:	
	if (!PyErr_Occurred()) {
		PyErr_SetString(PyExc_OSError, "iptables runtime error");
	}
	return 0; 
}

PyDoc_STRVAR(iptables_replace_table_doc, "replace this table in kernel");

static PyObject *
iptables_replace_table(PyObject *object, PyObject *args)
{ 
	int sockfd = 0; 
	socklen_t info_size = 0; 
	PyObject *table_dict = NULL;
	PyObject *chains_dict = NULL;
	PyObject *chains_keys = NULL; 
	PyObject *tablename = NULL;

	//struct xt_counters_info *counter_info = NULL; 
	struct ipt_getinfo *info = NULL;
	struct ipt_replace *replace = NULL;
	struct chain_error *error = NULL;
	struct replace_context context; 

	if (!PyArg_ParseTuple(args, "O|replace_table", &table_dict)) {
		return NULL;
	} 

	/* check tablename */
	tablename = PyDict_GetItemString(table_dict, "name");
	if (!tablename) {
		PyErr_SetString(PyExc_KeyError, "no table name in this table dict");
		goto CLEAR; 
	} 
	if (strlen(PyString_AsString(tablename)) >= XT_TABLE_MAXNAMELEN) { 
		PyErr_SetString(PyExc_ValueError, "table name too big");
		goto CLEAR;
	}
	/* get chains */
	chains_dict = PyDict_GetItemString(table_dict, "chains");
	if (!chains_dict) {
		PyErr_SetString(PyExc_KeyError, "no chains in table");
		goto CLEAR;
	}
	/* init socket */
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		goto CLEAR;
	}
	if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) == -1) {
		PyErr_SetFromErrno(PyExc_OSError);
		goto CLEAR;
	}
	/* set ipt_info */
	info = PyMem_Malloc(sizeof(struct ipt_getinfo)); 
	if (!info)
		goto CLEAR; 
	info_size = sizeof(struct ipt_getinfo);
	memset(info, 0, info_size);
	strcpy(info->name, PyString_AsString(tablename));
	if (getsockopt(sockfd, IPPROTO_IP, IPT_SO_GET_INFO,
				info, &info_size) < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		PyMem_Free(info);
		goto CLEAR; 
	} 
	/* initialize context */
	replace = PyMem_Malloc(sizeof(struct ipt_replace));
	if(!replace) {
		PyMem_Free(info);
		goto CLEAR;
	}

	memset(&context, 0, sizeof(struct replace_context)); 
	memcpy(replace->name, PyString_AsString(tablename), PyString_Size(tablename)); 
	context.replace = replace;	
	context.info = info;
	context.offset = 0;
	/* for jump target */
	context.chain_offsets = PyDict_New();
	context.jumps = PyList_New(0);

	chains_keys = PyDict_Keys(chains_dict);
	replace->num_entries = PyList_Size(chains_keys); 
	/* allocate buffer*/
	context.memory_size = 50 * (replace->num_entries * 
		(sizeof(struct ipt_entry) +
		 sizeof(struct xt_entry_target) +
		 sizeof(struct xt_entry_match)));
	context.memory = PyMem_Malloc(context.memory_size);
	if (!context.memory) { 
		goto FREE_CONTEXT;
	}
	/* iter over chains */ 
	PyObject *chains_keys_iter = PyObject_GetIter(chains_keys);
	if (!chains_keys_iter) { 
		Py_XDECREF(chains_keys);
		goto FREE_MEMORY;
	}
	PyObject *chains_keys_next = PyIter_Next(chains_keys_iter);
	if (!chains_keys_next) { 
		Py_XDECREF(chains_keys); 
		goto FREE_MEMORY;
	}
	while (chains_keys_next) {
		/* handle chains*/
		PyObject *rule_list = PyDict_GetItem(chains_dict, chains_keys_next); 
		int chain_ret = compile_chain(&context, chains_keys_next, rule_list); 
		Py_XDECREF(chains_keys_next); 
		/* if compile chain failed */
		if (!chain_ret) { 
			Py_XDECREF(chains_keys_iter); 
			Py_XDECREF(chains_keys);
			goto FREE_MEMORY;
		}
		chains_keys_next = PyIter_Next(chains_keys_iter);
	} 
	Py_XDECREF(chains_keys); 
	/* Append error rule at end of table*/
	error = context.memory;	
	error->e.target_offset = sizeof(struct ipt_entry);
	error->e.next_offset = sizeof(struct ipt_entry) +
		XT_ALIGN(sizeof(struct xt_error_target));
	strcpy((char *)&error->target.target.u.user.name, XT_ERROR_TARGET);
	strcpy((char *)&error->target.errorname, "ERROR"); 
	/* fill jumps */
	PyObject *jumps_iter = PyObject_GetIter(context.jumps);
	PyObject *jumps_next = PyIter_Next(jumps_iter);
	while (jumps_next) {
		struct xt_standard_target *xet = (void *)(PyLong_AsUnsignedLong(PyTuple_GetItem(jumps_next, 0)));
		PyObject *jump_to = PyDict_GetItem(context.chain_offsets, PyTuple_GetItem(jumps_next, 1)); 
		Py_XDECREF(jumps_next);	
		if (!(jump_to && xet)) {
			Py_XDECREF(jumps_iter);
			goto FREE_MEMORY;
		}
		xet->verdict = PyLong_AsUnsignedLong(jump_to);
		jumps_next = PyIter_Next(jumps_iter); 
	}
	Py_RETURN_NONE;
FREE_MEMORY:
	PyMem_Free(context.memory); 
FREE_CONTEXT: 
	PyMem_Free(info);
	PyMem_Free(replace);
CLEAR:
	if (!PyErr_Occurred()) {
		PyErr_SetString(PyExc_OSError, "iptables runtime error");
	}
	return NULL; 
}

PyDoc_STRVAR(iptables_get_info_doc, "get table information: hooks underflow location, num_entries");

static PyObject *
iptables_get_info(PyObject *object, PyObject *args)
{
	char *tablename; 
	int sockfd;
	socklen_t info_size;
	struct ipt_getinfo *info;
	PyObject *info_dict;

	if (!PyArg_ParseTuple(args, "s:get_info", &tablename)) {
		return NULL;
	} 
	if (strlen(tablename) >= XT_TABLE_MAXNAMELEN) { 
		return NULL;
	}
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) == -1) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	info = PyMem_Malloc(sizeof(struct ipt_getinfo)); 
	if (!info)
		goto ERROR; 
	info_size = sizeof(struct ipt_getinfo);
	memset(info, 0, info_size);
	strcpy(info->name, tablename);
	if (getsockopt(sockfd, IPPROTO_IP,
				IPT_SO_GET_INFO, info, &info_size) < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		PyMem_Free(info);
		goto ERROR; 
	} 
	info_dict = PyDict_New();
	DICT_STORE_STRING(info_dict, "name", info->name);
	PyDict_SetItemString(info_dict, "name", PyString_FromString(info->name));
	DICT_STORE_ULONG(info_dict, "name", info->valid_hooks);
	DICT_STORE_INT(info_dict, "num_entries", info->num_entries);
	DICT_STORE_INT(info_dict, "size", info->size); 
	PyObject *hook_entry_list = PyList_New(0);
	PyObject *underflow_list = PyList_New(0);
	int i;
	for(i=0; i < NF_IP_NUMHOOKS; i++) {
		PyList_Append(hook_entry_list, PyInt_FromLong(info->hook_entry[i]));
		PyList_Append(underflow_list, PyInt_FromLong(info->underflow[i]));
	} 
	PyDict_SetItemString(info_dict, "hook_entry", hook_entry_list);
	PyDict_SetItemString(info_dict, "underflow", underflow_list);
	PyMem_Free(info);
	return info_dict; 
ERROR:
	return NULL;
}


static PyMethodDef iptables_methods[] = {
	{"get_info", (PyCFunction)iptables_get_info,
		METH_VARARGS, iptables_get_info_doc},
	{"get_table", (PyCFunction)iptables_get_table,
		METH_VARARGS, iptables_get_table_doc},
	{"replace_table", (PyCFunction)iptables_replace_table,
		METH_VARARGS, iptables_replace_table_doc},
	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC init_iptables(void)
{
	PyObject *m;
	m = Py_InitModule("_iptables", iptables_methods);
	if (m != NULL) {
#define OBJECT_ADD_INT(x, y, z) PyModule_AddObject(x, y, PyInt_FromLong(z))
	OBJECT_ADD_INT(m, "IPT_F_FRAG", IPT_F_FRAG); 
	OBJECT_ADD_INT(m, "IPT_F_GOTO", IPT_F_GOTO);
	OBJECT_ADD_INT(m, "IPT_F_MASK", IPT_F_MASK);	
	OBJECT_ADD_INT(m, "IPT_INV_SRCIP", IPT_INV_SRCIP);	
	OBJECT_ADD_INT(m, "IPT_INV_DSTIP", IPT_INV_DSTIP); 
	OBJECT_ADD_INT(m, "IPT_INV_VIA_IN", IPT_INV_VIA_IN); 
	OBJECT_ADD_INT(m, "IPT_INV_VIA_OUT", IPT_INV_VIA_OUT);
	OBJECT_ADD_INT(m, "XT_INV_PROTO", XT_INV_PROTO);	
	OBJECT_ADD_INT(m, "IPT_INV_FRAG", IPT_INV_FRAG);	
	/* protocol */
	OBJECT_ADD_INT(m, "IPPROTO_IP", IPPROTO_IP);
	OBJECT_ADD_INT(m, "IPPROTO_IP", IPPROTO_IP);
	OBJECT_ADD_INT(m, "IPPROTO_ICMP", IPPROTO_ICMP);
	OBJECT_ADD_INT(m, "IPPROTO_IGMP", IPPROTO_IGMP);
	OBJECT_ADD_INT(m, "IPPROTO_IPIP", IPPROTO_IPIP);
	OBJECT_ADD_INT(m, "IPPROTO_TCP", IPPROTO_TCP);
	OBJECT_ADD_INT(m, "IPPROTO_EGP", IPPROTO_EGP);
	OBJECT_ADD_INT(m, "IPPROTO_PUP", IPPROTO_PUP);
	OBJECT_ADD_INT(m, "IPPROTO_UDP", IPPROTO_UDP);
	OBJECT_ADD_INT(m, "IPPROTO_IDP", IPPROTO_IDP);
	OBJECT_ADD_INT(m, "IPPROTO_DCCP", IPPROTO_DCCP);
	OBJECT_ADD_INT(m, "IPPROTO_RSVP", IPPROTO_RSVP);
	OBJECT_ADD_INT(m, "IPPROTO_GRE", IPPROTO_GRE);
	OBJECT_ADD_INT(m, "IPPROTO_IPV6", IPPROTO_IPV6);
	OBJECT_ADD_INT(m, "IPPROTO_ESP", IPPROTO_ESP);
	OBJECT_ADD_INT(m, "IPPROTO_AH", IPPROTO_AH); 
	OBJECT_ADD_INT(m, "IPPROTO_PIM", IPPROTO_PIM);
	OBJECT_ADD_INT(m, "IPPROTO_COMP", IPPROTO_COMP);
	OBJECT_ADD_INT(m, "IPPROTO_SCTP", IPPROTO_SCTP);
	OBJECT_ADD_INT(m, "IPPROTO_UDPLITE", IPPROTO_UDPLITE);
	OBJECT_ADD_INT(m, "IPPROTO_RAW", IPPROTO_RAW);
	/* tcp match extension flag */
	OBJECT_ADD_INT(m, "TCP_FLAG_FIN", 0x01);
	OBJECT_ADD_INT(m, "TCP_FLAG_SYN", 0x02);
	OBJECT_ADD_INT(m, "TCP_FLAG_RST", 0x04);
	OBJECT_ADD_INT(m, "TCP_FLAG_PSH", 0x08);
	OBJECT_ADD_INT(m, "TCP_FLAG_ACK", 0x10);
	OBJECT_ADD_INT(m, "TCP_FLAG_URG", 0x20);
	OBJECT_ADD_INT(m, "TCP_FLAG_ALL", 0x3F);
	OBJECT_ADD_INT(m, "TCP_FLAG_NONE", 0x0);
	OBJECT_ADD_INT(m, "XT_TCP_INV_SRCPT", XT_TCP_INV_SRCPT);
	OBJECT_ADD_INT(m, "XT_TCP_INV_DSTPT", XT_TCP_INV_DSTPT);
	OBJECT_ADD_INT(m, "XT_TCP_INV_FLAGS", XT_TCP_INV_FLAGS);
	OBJECT_ADD_INT(m, "XT_TCP_INV_OPTION", XT_TCP_INV_OPTION);
	OBJECT_ADD_INT(m, "XT_TCP_INV_MASK", XT_TCP_INV_MASK);
	/* ctstate flags */	
	OBJECT_ADD_INT(m, "CT_INVALID",
			XT_CONNTRACK_STATE_INVALID);
	OBJECT_ADD_INT(m, "CT_NEW", XT_CONNTRACK_STATE_BIT(IP_CT_NEW));
	OBJECT_ADD_INT(m, "CT_ESTABLISHED", XT_CONNTRACK_STATE_BIT(IP_CT_ESTABLISHED));
	OBJECT_ADD_INT(m, "CT_RELATED", XT_CONNTRACK_STATE_BIT(IP_CT_RELATED));
	OBJECT_ADD_INT(m, "CT_UNTRACKED",
			XT_CONNTRACK_STATE_UNTRACKED);
	OBJECT_ADD_INT(m, "CT_SNAT",
			XT_CONNTRACK_STATE_SNAT);
	OBJECT_ADD_INT(m, "CT_DNAT",
			XT_CONNTRACK_STATE_DNAT);	
	/* icmp type, total 18*/
	OBJECT_ADD_INT(m, "ICMP_ECHOREPLY", ICMP_ECHOREPLY);			
	OBJECT_ADD_INT(m, "ICMP_DEST_UNREACH", ICMP_DEST_UNREACH);
	OBJECT_ADD_INT(m, "ICMP_SOURCE_QUENCH", ICMP_SOURCE_QUENCH);
	OBJECT_ADD_INT(m, "ICMP_REDIRECT", ICMP_REDIRECT);
	OBJECT_ADD_INT(m, "ICMP_ECHO", ICMP_ECHO);
	OBJECT_ADD_INT(m, "ICMP_TIME_EXCEEDED", ICMP_TIME_EXCEEDED);
	OBJECT_ADD_INT(m, "ICMP_PARAMETERPROB", ICMP_PARAMETERPROB);
	OBJECT_ADD_INT(m, "ICMP_TIMESTAMP", ICMP_TIMESTAMP);
	OBJECT_ADD_INT(m, "ICMP_TIMESTAMPREPLY", ICMP_TIMESTAMPREPLY);
	OBJECT_ADD_INT(m, "ICMP_INFO_REQUEST", ICMP_INFO_REQUEST);
	OBJECT_ADD_INT(m, "ICMP_INFO_REPLY", ICMP_INFO_REPLY);
	OBJECT_ADD_INT(m, "ICMP_ADDRESS", ICMP_ADDRESS);
	OBJECT_ADD_INT(m, "ICMP_ADDRESSREPLY", ICMP_ADDRESSREPLY);
	/* icmp for unreach  total 15*/
	OBJECT_ADD_INT(m, "ICMP_NET_UNREACH", ICMP_NET_UNREACH);
	OBJECT_ADD_INT(m, "ICMP_HOST_UNREACH", ICMP_HOST_UNREACH);
	OBJECT_ADD_INT(m, "ICMP_PROT_UNREACH", ICMP_PROT_UNREACH);
	OBJECT_ADD_INT(m, "ICMP_PORT_UNREACH", ICMP_PORT_UNREACH);
	OBJECT_ADD_INT(m, "ICMP_FRAG_NEEDED", ICMP_FRAG_NEEDED);
	OBJECT_ADD_INT(m, "ICMP_SR_FAILED", ICMP_SR_FAILED);
	OBJECT_ADD_INT(m, "ICMP_NET_UNKNOWN", ICMP_NET_UNKNOWN);
	OBJECT_ADD_INT(m, "ICMP_HOST_UNKNOWN", ICMP_HOST_UNKNOWN);
	OBJECT_ADD_INT(m, "ICMP_HOST_ISOLATED", ICMP_HOST_ISOLATED);
	OBJECT_ADD_INT(m, "ICMP_NET_ANO", ICMP_NET_ANO);
	OBJECT_ADD_INT(m, "ICMP_HOST_ANO", ICMP_HOST_ANO);
	OBJECT_ADD_INT(m, "ICMP_NET_UNR_TOS", ICMP_NET_UNR_TOS);
	OBJECT_ADD_INT(m, "ICMP_HOST_UNR_TOS", ICMP_NET_UNR_TOS);
	OBJECT_ADD_INT(m, "ICMP_PKT_FILTERED", ICMP_PKT_FILTERED);
	OBJECT_ADD_INT(m, "ICMP_PREC_VIOLATION", ICMP_PREC_VIOLATION);
	OBJECT_ADD_INT(m, "ICMP_PREC_CUTOFF", ICMP_PREC_CUTOFF);
	/* REDIRECT, total 3 */	
	OBJECT_ADD_INT(m, "ICMP_REDIR_NET", ICMP_REDIR_NET);
	OBJECT_ADD_INT(m, "ICMP_REDIR_HOST", ICMP_REDIR_HOST);
	OBJECT_ADD_INT(m, "ICMP_REDIR_NETTOS", ICMP_REDIR_NETTOS);
	OBJECT_ADD_INT(m, "ICMP_REDIR_HOSTTOS", ICMP_REDIR_HOSTTOS);
	/* TIME_EXCEEDED */
	OBJECT_ADD_INT(m, "ICMP_EXC_TTL", ICMP_EXC_TTL);
	OBJECT_ADD_INT(m, "ICMP_EXC_FRAGTIME", ICMP_EXC_FRAGTIME); 
	OBJECT_ADD_INT(m, "IPT_ICMP_INV", IPT_ICMP_INV);
	/* packet type */
	OBJECT_ADD_INT(m, "PACKET_HOST", PACKET_HOST);
	OBJECT_ADD_INT(m, "PACKET_BROADCAST", PACKET_BROADCAST);
	OBJECT_ADD_INT(m, "PACKET_MULTICAST", PACKET_MULTICAST);
	OBJECT_ADD_INT(m, "PACKET_OTHERHOST", PACKET_OTHERHOST);
	OBJECT_ADD_INT(m, "PACKET_OUTGOING", PACKET_OUTGOING);
	/* target LOG, syslog consts */
	OBJECT_ADD_INT(m, "LOG_ALERT", LOG_ALERT);
	OBJECT_ADD_INT(m, "LOG_CRIT", LOG_CRIT);
	OBJECT_ADD_INT(m, "LOG_DEBUG", LOG_DEBUG);
	OBJECT_ADD_INT(m, "LOG_EMERG", LOG_EMERG);
	OBJECT_ADD_INT(m, "LOG_ERR", LOG_ERR);
	OBJECT_ADD_INT(m, "LOG_INFO", LOG_INFO);
	OBJECT_ADD_INT(m, "LOG_NOTICE", LOG_NOTICE); 
	OBJECT_ADD_INT(m, "LOG_WARNING", LOG_WARNING);

	OBJECT_ADD_INT(m, "LOG_TCPSEQ", IPT_LOG_TCPSEQ);
	OBJECT_ADD_INT(m, "LOG_TCPOPT", IPT_LOG_TCPOPT);
	OBJECT_ADD_INT(m, "LOG_IPOPT", IPT_LOG_IPOPT);
	OBJECT_ADD_INT(m, "LOG_UID", IPT_LOG_UID);
	OBJECT_ADD_INT(m, "LOG_MACDECODE", IPT_LOG_MACDECODE);
	/* target REJECT consts */
	OBJECT_ADD_INT(m, "IPT_ICMP_NET_UNREACHABLE", IPT_ICMP_NET_UNREACHABLE);
	OBJECT_ADD_INT(m, "IPT_ICMP_HOST_UNREACHABLE", IPT_ICMP_HOST_UNREACHABLE);
	OBJECT_ADD_INT(m, "IPT_ICMP_PROT_UNREACHABLE", IPT_ICMP_PROT_UNREACHABLE);
	OBJECT_ADD_INT(m, "IPT_ICMP_PORT_UNREACHABLE", IPT_ICMP_PORT_UNREACHABLE);
	OBJECT_ADD_INT(m, "IPT_ICMP_ECHOREPLY", IPT_ICMP_ECHOREPLY);
	OBJECT_ADD_INT(m, "IPT_ICMP_NET_PROHIBITED", IPT_ICMP_NET_PROHIBITED);
	OBJECT_ADD_INT(m, "IPT_ICMP_HOST_PROHIBITED", IPT_ICMP_HOST_PROHIBITED);
	OBJECT_ADD_INT(m, "IPT_TCP_RESET", IPT_TCP_RESET);
	OBJECT_ADD_INT(m, "IPT_ICMP_ADMIN_PROHIBITED", IPT_ICMP_ADMIN_PROHIBITED); 
	OBJECT_ADD_INT(m, "NF_DROP", -NF_DROP - 1);
	OBJECT_ADD_INT(m, "NF_ACCEPT", -NF_ACCEPT - 1); 
	OBJECT_ADD_INT(m, "NF_STOLEN", -NF_STOLEN - 1);
	OBJECT_ADD_INT(m, "NF_QUEUE", -NF_QUEUE - 1);
	OBJECT_ADD_INT(m, "NF_REPEAT", -NF_REPEAT - 1);
	OBJECT_ADD_INT(m, "NF_STOP", -NF_STOP - 1); 
	OBJECT_ADD_INT(m, "XT_RETURN", XT_RETURN);
#undef OBJECT_ADD_INT
	} 
}

#undef DICT_GET_INT
#undef DICT_GET_ULONG
#undef DICT_GET_STRING
#undef DICT_STORE_INT
#undef DICT_STORE_ULONG
#undef DICT_STORE_STRING
