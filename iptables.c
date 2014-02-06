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

#define HOOK_PRE_ROUTING	NF_IP_PRE_ROUTING
#define HOOK_LOCAL_IN		NF_IP_LOCAL_IN
#define HOOK_FORWARD		NF_IP_FORWARD
#define HOOK_LOCAL_OUT		NF_IP_LOCAL_OUT
#define HOOK_POST_ROUTING	NF_IP_POST_ROUTING 


struct replace_context {
	struct ipt_replace *replace;
	struct ipt_getinfo *info;
	unsigned int current_offset;
	unsigned int memory_size;
	void *memory;
	unsigned int last_chain_end;
};

static const char *hooknames[] = {
	[HOOK_PRE_ROUTING]	= "PREROUTING",
	[HOOK_LOCAL_IN]		= "INPUT",
	[HOOK_FORWARD]		= "FORWARD",
	[HOOK_LOCAL_OUT]	= "OUTPUT",
	[HOOK_POST_ROUTING]	= "POSTROUTING",
};


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
add_matches(struct xt_entry_match *m, PyObject *matches_dict)
{ 
    PyObject *match_dict = NULL; 
        match_dict = PyDict_New();  
	PyDict_SetItemString(match_dict, "size",
			PyInt_FromLong(m->u.user.match_size));
    if (strcmp(m->u.user.name, "pkttype") == 0) {
        struct xt_pkttype_info *info  = (struct xt_pkttype_info *)m->data; 
        PyDict_SetItemString(match_dict, "type",
                PyInt_FromLong(info->pkttype));
        PyDict_SetItemString(match_dict, "invert",
                PyInt_FromLong(info->invert));
    } else if (strcmp(m->u.user.name, "tcp") == 0) { 
        struct xt_tcp *tcpinfo = (struct xt_tcp *)m->data;        
        PyDict_SetItemString(match_dict, "spts",
                PyTuple_Pack(2, PyInt_FromLong(tcpinfo->spts[0]),
                    PyInt_FromLong(tcpinfo->spts[1])));
        PyDict_SetItemString(match_dict, "dpts",
                PyTuple_Pack(2, PyInt_FromLong(tcpinfo->dpts[0]),
                    PyInt_FromLong(tcpinfo->dpts[1])));
        PyDict_SetItemString(match_dict, "options",
                PyInt_FromLong(tcpinfo->option));
        PyDict_SetItemString(match_dict, "flag_mask",
                PyInt_FromLong(tcpinfo->flg_mask)); 
        PyDict_SetItemString(match_dict, "flag_cmp",
                PyInt_FromLong(tcpinfo->flg_cmp));
        PyDict_SetItemString(match_dict, "invflags",
                PyInt_FromLong(tcpinfo->invflags)); 
    } else if (strcmp(m->u.user.name, "conntrack") == 0) {
	    if (m->u.user.revision == 3) {
		struct xt_conntrack_mtinfo3 *info = (void *)m->data; 
		
		if (info->match_flags & XT_CONNTRACK_STATE) { 
		    PyDict_SetItemString(match_dict, "state",
			    PyInt_FromLong(info->state_mask));
		}
		if (info->match_flags & XT_CONNTRACK_STATUS) {
		    PyDict_SetItemString(match_dict, "status",
			    PyInt_FromLong(info->status_mask));
		}
		if (info->match_flags & XT_CONNTRACK_EXPIRES) {
		    PyDict_SetItemString(match_dict, "expires_min", 
			    PyInt_FromLong(info->expires_min));
		    PyDict_SetItemString(match_dict, "expires_max",
			    PyInt_FromLong(info->expires_max));
		} 
		if (info->match_flags & XT_CONNTRACK_ORIGSRC) {
			PyDict_SetItemString(match_dict, "origsrc_ip",
					PyString_FromStringAndSize(
						(void *)&((struct in_addr *)&info->origsrc_addr.in)->s_addr, 4));
			PyDict_SetItemString(match_dict, "origsrc_mask",
					PyString_FromStringAndSize(
						(void *)&(((struct in_addr *)&info->origsrc_mask.in)->s_addr), 4)); 
		} 
		if (info->match_flags & XT_CONNTRACK_ORIGDST) {
			PyDict_SetItemString(match_dict, "origdst_ip",
					PyString_FromStringAndSize(
						(void *)&((struct in_addr *)&info->origdst_addr.in)->s_addr, 4));
			PyDict_SetItemString(match_dict, "origdst_mask",
					PyString_FromStringAndSize(
						(void *)&(((struct in_addr *)&info->origdst_mask.in)->s_addr), 4));
		} 
		if (info->match_flags & XT_CONNTRACK_REPLSRC) {
			PyDict_SetItemString(match_dict, "replsrc_ip",
					PyString_FromStringAndSize(
						(void *)&((struct in_addr *)&info->replsrc_addr.in)->s_addr, 4));
			PyDict_SetItemString(match_dict, "replsrc_mask",
					PyString_FromStringAndSize(
						(void *)&(((struct in_addr *)&info->replsrc_mask.in)->s_addr), 4)); 
		} 

		if (info->match_flags & XT_CONNTRACK_REPLDST) {
			PyDict_SetItemString(match_dict, "repldst_ip",
					PyString_FromStringAndSize(
						(void *)&((struct in_addr *)&info->repldst_addr.in)->s_addr, 4));
			PyDict_SetItemString(match_dict, "repldst_mask",
					PyString_FromStringAndSize(
						(void *)&(((struct in_addr *)&info->repldst_mask.in)->s_addr), 4)); 
		} 
		PyDict_SetItemString(match_dict, "invflags",
			PyInt_FromLong(info->invert_flags)); 
	}	
    } else if (strcmp(m->u.user.name, "limit") == 0) {
        struct xt_rateinfo *r =(struct xt_rateinfo *)m->data; 
        PyDict_SetItemString(match_dict, "avg",
                PyInt_FromLong(r->avg));
        PyDict_SetItemString(match_dict, "burst",
                PyInt_FromLong(r->burst));
    } else if (strcmp(m->u.user.name, "icmp") == 0) {
        struct ipt_icmp *icmpinfo = (struct ipt_icmp *)m->data; 
        PyDict_SetItemString(match_dict, "type",
                PyInt_FromLong(icmpinfo->type));
        PyDict_SetItemString(match_dict, "min",
                PyInt_FromLong(icmpinfo->code[0]));
        PyDict_SetItemString(match_dict, "max",
                PyInt_FromLong(icmpinfo->code[1]));
        PyDict_SetItemString(match_dict, "invflags",
                PyInt_FromLong(icmpinfo->invflags));
    } 


	PyDict_SetItemString(matches_dict, m->u.user.name,
                    match_dict); 

    return 0;
}

static int 
add_entry(struct ipt_entry *e, PyObject *chains_dict,
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
	PyObject *matches_dict; 

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
	PyDict_SetItemString(rule_dict, "offset", 
			PyInt_FromLong(entry_get_offset(entries, e)));
	PyDict_SetItemString(rule_dict, "srcip",
			PyInt_FromLong(e->ip.src.s_addr));
	PyDict_SetItemString(rule_dict, "srcip_mask",
			PyInt_FromLong(e->ip.smsk.s_addr));
	PyDict_SetItemString(rule_dict, "dstip",
			PyInt_FromLong(e->ip.dst.s_addr));
	PyDict_SetItemString(rule_dict, "dstip_mask",
			PyInt_FromLong(e->ip.dmsk.s_addr));
	for (i = 0; i < IFNAMSIZ; i++) {
		*(iniface_buffer+i) = e->ip.iniface_mask[i];
		*(outiface_buffer) = e->ip.outiface_mask[i];
	} 
	PyDict_SetItemString(rule_dict, "iniface",
			PyString_FromString(e->ip.iniface));
	PyDict_SetItemString(rule_dict, "iniface_mask",
			PyByteArray_FromStringAndSize(iniface_buffer, IFNAMSIZ));
	PyDict_SetItemString(rule_dict, "outiface",
			PyString_FromString(e->ip.outiface));
	PyDict_SetItemString(rule_dict, "outiface_mask",
			PyByteArray_FromStringAndSize(outiface_buffer, IFNAMSIZ));
	PyDict_SetItemString(rule_dict, "protocol",
			PyInt_FromLong(e->ip.proto));
	PyDict_SetItemString(rule_dict, "flags",
			PyInt_FromLong(e->ip.flags));
	PyDict_SetItemString(rule_dict, "invflags",
			PyInt_FromLong(e->ip.invflags));
	PyDict_SetItemString(rule_dict, "packets",
			PyInt_FromLong(
				(unsigned long long)e->counters.pcnt));
	PyDict_SetItemString(rule_dict, "bytes",
			PyInt_FromLong(
				(unsigned long long)e->counters.bcnt));
	PyDict_SetItemString(rule_dict, "cache",
			PyInt_FromLong(e->nfcache));
	/* matches */
	matches_dict = PyDict_New(); 
	XT_MATCH_ITERATE(struct ipt_entry, e, add_matches, matches_dict); 
	PyDict_SetItemString(rule_dict, "matches", matches_dict); 
	/* target */
	t = (void *)e + e->target_offset;
	PyDict_SetItemString(rule_dict, "target",
			PyString_FromString(t->u.user.name));
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
	/* target */
	struct xt_standard_target *xt = (void *)t; 
	if (strcmp(t->u.user.name, XT_STANDARD_TARGET) == 0) { 
		if (xt->verdict < 0) {
			PyDict_SetItemString(rule_dict, "target_type",
					PyString_FromString("standard"));
			PyDict_SetItemString(rule_dict, "verb",
				PyString_FromString(
					xt->verdict == -NF_ACCEPT-1 ? "ACCEPT"
					: xt->verdict == -NF_DROP-1 ? "DROP"
					: xt->verdict == -NF_QUEUE-1 ?"QUEUE"
					: xt->verdict == XT_RETURN ? "RETURN"
					: "UNKNOWN"));
		}
		else if (xt->verdict == entry_get_offset(entries, e) + e->next_offset) {
			PyDict_SetItemString(rule_dict, "target_type",
					PyString_FromString("fallthrough"));
			PyDict_SetItemString(rule_dict, "verb",
					PyInt_FromLong(xt->verdict));
		} else {
			PyDict_SetItemString(rule_dict, "target_type",
					PyString_FromString("jump"));
			PyDict_SetItemString(rule_dict, "verb",
					PyInt_FromLong(xt->verdict));
		}
	}  else {
		/* target extension */
		PyObject *target_dict;
		target_dict = PyDict_New();
		if (strcmp(t->u.user.name, "LOG") == 0) { 
			struct ipt_log_info *loginfo = (void *)t->data;
			PyDict_SetItemString(target_dict, "level",	
					PyInt_FromLong((long)loginfo->level));
			PyDict_SetItemString(target_dict, "logflags",
					PyInt_FromLong((long)loginfo->logflags));
			PyDict_SetItemString(target_dict, "prefix",
					PyString_FromString(loginfo->prefix));
			PyDict_SetItemString(rule_dict, "target_dict",
					target_dict);
		} 
		if (strcmp(t->u.user.name, "REJECT") == 0) {
			struct ipt_reject_info *rjinfo = (void *)t->data;
			PyDict_SetItemString(target_dict, "with",
					PyInt_FromLong(rjinfo->with));
			PyDict_SetItemString(rule_dict, "target_dict",
					target_dict);
		}
		PyDict_SetItemString(rule_dict, "target_type",
				PyString_FromString("module"));
		PyDict_SetItemString(rule_dict, "verb",
				PyInt_FromLong(xt->verdict)); 
	}
	/* add rule to current_chain */
	if (*current_chain_ptr) 
		return PyList_Append(*current_chain_ptr, rule_dict) ? 1 : 0; 
	else
		return 1;

}

static PyObject *
parse_entries(struct ipt_getinfo *info, struct ipt_get_entries *entries)
{
	PyObject *table_dict; 
	PyObject *chains_dict;
	PyObject *current_chain = NULL;

	table_dict = PyDict_New();
	PyDict_SetItemString(table_dict, "iptver",
			PyString_FromString(XTABLES_VERSION));		
	PyDict_SetItemString(table_dict, "blobsize",
			PyInt_FromLong(entries->size));
	PyDict_SetItemString(table_dict, "name",
			PyString_FromString(info->name)); 

	chains_dict = PyDict_New();
	
	unsigned int i, ret; 
	struct ipt_entry *entry;

	for (i = 0;i < entries->size;
			i += entry->next_offset) {
		entry = (void *)(entries->entrytable) + i; 
		ret = add_entry(entry, chains_dict,
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
		PyMem_Free(info);
		goto ERROR; 
	} 
	entries = PyMem_Malloc(sizeof(struct ipt_get_entries) + info->size);
	if (!entries) {
		PyMem_Free(info);
		goto ERROR;
	}
	entries->size = info->size; 
	strcpy(entries->name, info->name);
	tmp = sizeof(struct ipt_get_entries) + info->size;
	if (getsockopt(sockfd, IPPROTO_IP,
				IPT_SO_GET_ENTRIES, entries, &tmp) < 0) {
		PyErr_SetFromErrno(PyExc_OSError);	
		PyMem_Free(info);
		PyMem_Free(entries);
		goto ERROR;
	}
	close(sockfd); 
	return parse_entries(info, entries); 
ERROR:	
	close(sockfd); 
	return NULL;
}



static int
compile_rule(PyObject *rule_dict, struct ipt_entry *this_entry, unsigned int *current_offset)
{
	/*convert entry, match, target plugins */
	this_entry->ip.src.s_addr = PyInt_AsLong(PyDict_GetItemString(rule_dict, "srcip"));
	this_entry->ip.dst.s_addr = PyInt_AsLong(PyDict_GetItemString(rule_dict, "dstip"));
	this_entry->ip.smsk.s_addr = PyInt_AsLong(PyDict_GetItemString(rule_dict, "srcip_mask"));
	this_entry->ip.dmsk.s_addr = PyInt_AsLong(PyDict_GetItemString(rule_dict, "dstip_mask"));
	/*bug char * , unsgined char */
	strcpy(this_entry->ip.iniface, PyString_AsString(PyDict_GetItemString(rule_dict, "iniface")));
	strcpy(this_entry->ip.outiface,  PyString_AsString(PyDict_GetItemString(rule_dict, "outiface")));
	PyObject *iniface_mask = PyDict_GetItemString(rule_dict, "iniface_mask");
	memcpy(this_entry->ip.iniface_mask, PyByteArray_AsString(iniface_mask), PyByteArray_Size(iniface_mask));
	PyObject *outiface_mask = PyDict_GetItemString(rule_dict, "outiface_mask");
	memcpy(this_entry->ip.outiface_mask,  PyByteArray_AsString(outiface_mask), PyByteArray_Size(outiface_mask)); 
	this_entry->ip.proto = PyInt_AsLong(PyDict_GetItemString(rule_dict, "protocol"));	
	this_entry->ip.flags = PyInt_AsLong(PyDict_GetItemString(rule_dict, "flags"));
	this_entry->ip.invflags = PyInt_AsLong(PyDict_GetItemString(rule_dict, "invflags"));
	return 1;
CLEAR:
	return 0; 
}

static int 
compile_chain(struct replace_context *context, PyObject *chain_name,  PyObject *rule_list)
{
	PyObject *chain_offset;
	PyObject *rule0_dict; 
	int chain_header_offset;
	unsigned int current_offset;
	struct ipt_entry *chain_header; 
	struct ipt_entry *chain_footer;	
	if (!rule_list) {
		goto CLEAR;
	} 
	PyObject *rule_list_iter = PyObject_GetIter(rule_list); 
	if (!rule_list_iter) {
		goto CLEAR;
	}
	current_offset = 0;
	PyObject *rule_list_next = PyIter_Next(rule_list_iter);
	while(rule_list_next) { 
		struct ipt_entry *this_entry = context->memory;
		if(!this_entry) {
			Py_XDECREF(rule_list_iter); 
			goto CLEAR;
		}
		int rule_ret = compile_rule(rule_list_next, this_entry, &current_offset);
		Py_XDECREF(rule_list_next);
		if(!rule_ret) {
			Py_XDECREF(rule_list_iter); 
			goto CLEAR;
		} 
		rule_list_next = PyIter_Next(rule_list_iter);
	}
	rule0_dict = PyList_GetItem(rule_list, 0);	
	chain_offset = PyDict_GetItemString(rule0_dict, "offset"); 
	chain_header_offset = PyInt_AsLong(chain_offset);
	int i; 
	for (i = 0; i < NF_IP_NUMHOOKS; i++) { 
		if ((context->info->valid_hooks & (1 << i))
			&& ((context->info->hook_entry[i]) == chain_header_offset)) { 
			i = -1;
			break;
		}
	}
	/* only user-defined chains have header */		
	if (i > 0) {
		/*
		chain_header = context->memory;	
		chain_header->target_offset = sizeof(struct ipt_entry);
		chain_header->next_offset = (sizeof(struct ipt_entry) +\
				XT_ALIGN(sizeof(struct xt_error_target)));
		strcpy(chain_header->name.target.u.user.name, "ERROR");
		chain_header->name.target.u.target_size = XT_ALIGN(sizeof(struct xt_error_target));
		strcpy(chain_header->name.errorname, PyString_AsString(chain_name)); 
		*/
	} else {
		
	}
	
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
	PyObject *table_dict;
	PyObject *chains_dict;
	PyObject *chains_keys; 
	PyObject *tablename;
	int sockfd; 
	socklen_t info_size; 
	struct xt_counters_info *counter_info; 
	struct ipt_getinfo *info;
	struct ipt_replace *replace;
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
	chains_dict = PyDict_GetItemString(table_dict, "chains");
	if (!chains_dict) {
		PyErr_SetString(PyExc_KeyError, "no chains in table");
		goto CLEAR;
	}
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
	if (getsockopt(sockfd, IPPROTO_IP,
				IPT_SO_GET_INFO, info, &info_size) < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		PyMem_Free(info);
		goto CLEAR; 
	} 
	replace = PyMem_Malloc(sizeof(struct ipt_replace));
	if(!replace) {
		PyMem_Free(info);
		goto CLEAR;
	}
	/* initialize context */
	memcpy(replace->name, PyString_AsString(tablename), PyString_Size(tablename)); 
	context.replace = replace;	
	context.info = info;
	context.current_offset = 0;
	/* iter over chains */ 
	chains_keys = PyDict_Keys(chains_dict);
	replace->num_entries = PyList_Size(chains_keys); 
	context.memory_size = replace->num_entries * (sizeof(struct ipt_entry)\
			+ sizeof(struct xt_entry_target)\
			+ sizeof(struct xt_entry_match));
	context.memory = PyMem_Malloc(context.memory_size);
	if (!context.memory) {
		PyMem_Free(info);
		PyMem_Free(replace);
		goto CLEAR;
	}
	PyObject *chains_keys_iter = PyObject_GetIter(chains_keys);
	if (!chains_keys_iter) {
		PyMem_Free(info);
		PyMem_Free(replace);
		PyMem_Free(context.memory);
		Py_XDECREF(chains_keys);
		goto CLEAR;
	}
	PyObject *chains_keys_next = PyIter_Next(chains_keys_iter);
	if (!chains_keys_next) {
		PyMem_Free(info);
		PyMem_Free(replace);
		PyMem_Free(context.memory);
		Py_XDECREF(chains_keys); 
		goto CLEAR;
	}
	while (chains_keys_next) {
		/* handle chains*/
		PyObject *rule_list = PyDict_GetItem(chains_dict, chains_keys_next); 
		int chain_ret = compile_chain(&context, chains_keys_next, rule_list); 
		Py_XDECREF(chains_keys_next); 
		/* if prepare chain failed */
		if (!chain_ret) { 
			PyMem_Free(info);
			PyMem_Free(replace);
			PyMem_Free(context.memory); 
			Py_XDECREF(chains_keys_iter); 
			Py_XDECREF(chains_keys);
			goto CLEAR;
		}
		chains_keys_next = PyIter_Next(chains_keys_iter);
	} 
	Py_XDECREF(chains_keys);
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
	PyDict_SetItemString(info_dict, "name", PyString_FromString(info->name));
	PyDict_SetItemString(info_dict, "valid_hooks", PyInt_FromLong(info->valid_hooks));
	PyDict_SetItemString(info_dict, "num_entries", PyInt_FromLong(info->num_entries));
	PyDict_SetItemString(info_dict, "size", PyInt_FromLong(info->size));
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
	PyModule_AddObject(m, "IPT_F_FRAG", PyInt_FromLong(IPT_F_FRAG));
	PyModule_AddObject(m, "IPT_F_GOTO", PyInt_FromLong(IPT_F_GOTO));
	PyModule_AddObject(m, "IPT_F_MASK", PyInt_FromLong(IPT_F_MASK));
	PyModule_AddObject(m, "IPT_INV_SRCIP", PyInt_FromLong(IPT_INV_SRCIP));
	PyModule_AddObject(m, "IPT_INV_DSTIP", PyInt_FromLong(IPT_INV_DSTIP));
	PyModule_AddObject(m, "IPT_INV_VIA_IN", PyInt_FromLong(IPT_INV_VIA_IN));
	PyModule_AddObject(m, "IPT_INV_VIA_OUT", PyInt_FromLong(IPT_INV_VIA_OUT));
	PyModule_AddObject(m, "XT_INV_PROTO", PyInt_FromLong(XT_INV_PROTO));
	PyModule_AddObject(m, "IPT_INV_FRAG", PyInt_FromLong(IPT_INV_FRAG));
	/* protocol */
	PyModule_AddObject(m, "IPPROTO_IP", PyInt_FromLong(IPPROTO_IP));
	PyModule_AddObject(m, "IPPROTO_ICMP", PyInt_FromLong(IPPROTO_ICMP));
	PyModule_AddObject(m, "IPPROTO_IGMP", PyInt_FromLong(IPPROTO_IGMP));
	PyModule_AddObject(m, "IPPROTO_IPIP", PyInt_FromLong(IPPROTO_IPIP));
	PyModule_AddObject(m, "IPPROTO_TCP", PyInt_FromLong(IPPROTO_TCP));
	PyModule_AddObject(m, "IPPROTO_EGP", PyInt_FromLong(IPPROTO_EGP));
	PyModule_AddObject(m, "IPPROTO_PUP", PyInt_FromLong(IPPROTO_PUP));
	PyModule_AddObject(m, "IPPROTO_UDP", PyInt_FromLong(IPPROTO_UDP));
	PyModule_AddObject(m, "IPPROTO_IDP", PyInt_FromLong(IPPROTO_IDP));
	PyModule_AddObject(m, "IPPROTO_DCCP", PyInt_FromLong(IPPROTO_DCCP));
	PyModule_AddObject(m, "IPPROTO_RSVP", PyInt_FromLong(IPPROTO_RSVP));
	PyModule_AddObject(m, "IPPROTO_GRE", PyInt_FromLong(IPPROTO_GRE));
	PyModule_AddObject(m, "IPPROTO_IPV6", PyInt_FromLong(IPPROTO_IPV6));
	PyModule_AddObject(m, "IPPROTO_ESP", PyInt_FromLong(IPPROTO_ESP));
	PyModule_AddObject(m, "IPPROTO_AH", PyInt_FromLong(IPPROTO_AH)); 
	PyModule_AddObject(m, "IPPROTO_PIM", PyInt_FromLong(IPPROTO_PIM));
	PyModule_AddObject(m, "IPPROTO_COMP", PyInt_FromLong(IPPROTO_COMP));
	PyModule_AddObject(m, "IPPROTO_SCTP", PyInt_FromLong(IPPROTO_SCTP));
	PyModule_AddObject(m, "IPPROTO_UDPLITE", PyInt_FromLong(IPPROTO_UDPLITE));
	PyModule_AddObject(m, "IPPROTO_RAW", PyInt_FromLong(IPPROTO_RAW));
	/* tcp match extension flag */
	PyModule_AddObject(m, "TCP_FLAG_FIN", PyInt_FromLong(0x01));
	PyModule_AddObject(m, "TCP_FLAG_SYN", PyInt_FromLong(0x02));
	PyModule_AddObject(m, "TCP_FLAG_RST", PyInt_FromLong(0x04));
	PyModule_AddObject(m, "TCP_FLAG_PSH", PyInt_FromLong(0x08));
	PyModule_AddObject(m, "TCP_FLAG_ACK", PyInt_FromLong(0x10));
	PyModule_AddObject(m, "TCP_FLAG_URG", PyInt_FromLong(0x20));
	PyModule_AddObject(m, "TCP_FLAG_ALL", PyInt_FromLong(0x3F));
	PyModule_AddObject(m, "TCP_FLAG_NONE", PyInt_FromLong(0x0));
	PyModule_AddObject(m, "XT_TCP_INV_SRCPT", PyInt_FromLong(XT_TCP_INV_SRCPT));
	PyModule_AddObject(m, "XT_TCP_INV_DSTPT", PyInt_FromLong(XT_TCP_INV_DSTPT));
	PyModule_AddObject(m, "XT_TCP_INV_FLAGS", PyInt_FromLong(XT_TCP_INV_FLAGS));
	PyModule_AddObject(m, "XT_TCP_INV_OPTION", PyInt_FromLong(XT_TCP_INV_OPTION));
	PyModule_AddObject(m, "XT_TCP_INV_MASK", PyInt_FromLong(XT_TCP_INV_MASK));
	/* ctstate flags */	
	PyModule_AddObject(m, "CT_INVALID",
			PyInt_FromLong(XT_CONNTRACK_STATE_INVALID));
	PyModule_AddObject(m, "CT_NEW",
			PyInt_FromLong(XT_CONNTRACK_STATE_BIT(IP_CT_NEW)));
	PyModule_AddObject(m, "CT_ESTABLISHED",
			PyInt_FromLong(XT_CONNTRACK_STATE_BIT(IP_CT_ESTABLISHED)));
	PyModule_AddObject(m, "CT_RELATED",
			PyInt_FromLong(XT_CONNTRACK_STATE_BIT(IP_CT_RELATED)));
	PyModule_AddObject(m, "CT_UNTRACKED",
			PyInt_FromLong(XT_CONNTRACK_STATE_UNTRACKED));
	PyModule_AddObject(m, "CT_SNAT",
			PyInt_FromLong(XT_CONNTRACK_STATE_SNAT));
	PyModule_AddObject(m, "CT_DNAT",
			PyInt_FromLong(XT_CONNTRACK_STATE_DNAT));	
	/* icmp type, total 18*/
	PyModule_AddObject(m, "ICMP_ECHOREPLY", PyInt_FromLong(ICMP_ECHOREPLY));			
	PyModule_AddObject(m, "ICMP_DEST_UNREACH", PyInt_FromLong(ICMP_DEST_UNREACH));
	PyModule_AddObject(m, "ICMP_SOURCE_QUENCH", PyInt_FromLong(ICMP_SOURCE_QUENCH));
	PyModule_AddObject(m, "ICMP_REDIRECT", PyInt_FromLong(ICMP_REDIRECT));
	PyModule_AddObject(m, "ICMP_ECHO", PyInt_FromLong(ICMP_ECHO));
	PyModule_AddObject(m, "ICMP_TIME_EXCEEDED", PyInt_FromLong(ICMP_TIME_EXCEEDED));
	PyModule_AddObject(m, "ICMP_PARAMETERPROB", PyInt_FromLong(ICMP_PARAMETERPROB));
	PyModule_AddObject(m, "ICMP_TIMESTAMP", PyInt_FromLong(ICMP_TIMESTAMP));
	PyModule_AddObject(m, "ICMP_TIMESTAMPREPLY", PyInt_FromLong(ICMP_TIMESTAMPREPLY));
	PyModule_AddObject(m, "ICMP_INFO_REQUEST", PyInt_FromLong(ICMP_INFO_REQUEST));
	PyModule_AddObject(m, "ICMP_INFO_REPLY", PyInt_FromLong(ICMP_INFO_REPLY));
	PyModule_AddObject(m, "ICMP_ADDRESS", PyInt_FromLong(ICMP_ADDRESS));
	PyModule_AddObject(m, "ICMP_ADDRESSREPLY", PyInt_FromLong(ICMP_ADDRESSREPLY));
	/* icmp for unreach  total 15*/
	PyModule_AddObject(m, "ICMP_NET_UNREACH", PyInt_FromLong(ICMP_NET_UNREACH));
	PyModule_AddObject(m, "ICMP_HOST_UNREACH", PyInt_FromLong(ICMP_HOST_UNREACH));
	PyModule_AddObject(m, "ICMP_PROT_UNREACH", PyInt_FromLong(ICMP_PROT_UNREACH));
	PyModule_AddObject(m, "ICMP_PORT_UNREACH", PyInt_FromLong(ICMP_PORT_UNREACH));
	PyModule_AddObject(m, "ICMP_FRAG_NEEDED", PyInt_FromLong(ICMP_FRAG_NEEDED));
	PyModule_AddObject(m, "ICMP_SR_FAILED", PyInt_FromLong(ICMP_SR_FAILED));
	PyModule_AddObject(m, "ICMP_NET_UNKNOWN", PyInt_FromLong(ICMP_NET_UNKNOWN));
	PyModule_AddObject(m, "ICMP_HOST_UNKNOWN", PyInt_FromLong(ICMP_HOST_UNKNOWN));
	PyModule_AddObject(m, "ICMP_HOST_ISOLATED", PyInt_FromLong(ICMP_HOST_ISOLATED));
	PyModule_AddObject(m, "ICMP_NET_ANO", PyInt_FromLong(ICMP_NET_ANO));
	PyModule_AddObject(m, "ICMP_HOST_ANO", PyInt_FromLong(ICMP_HOST_ANO));
	PyModule_AddObject(m, "ICMP_NET_UNR_TOS", PyInt_FromLong(ICMP_NET_UNR_TOS));
	PyModule_AddObject(m, "ICMP_HOST_UNR_TOS", PyInt_FromLong(ICMP_NET_UNR_TOS));
	PyModule_AddObject(m, "ICMP_PKT_FILTERED", PyInt_FromLong(ICMP_PKT_FILTERED));
	PyModule_AddObject(m, "ICMP_PREC_VIOLATION", PyInt_FromLong(ICMP_PREC_VIOLATION));
	PyModule_AddObject(m, "ICMP_PREC_CUTOFF", PyInt_FromLong(ICMP_PREC_CUTOFF));
	/* REDIRECT, total 3 */	
	PyModule_AddObject(m, "ICMP_REDIR_NET", PyInt_FromLong(ICMP_REDIR_NET));
	PyModule_AddObject(m, "ICMP_REDIR_HOST", PyInt_FromLong(ICMP_REDIR_HOST));
	PyModule_AddObject(m, "ICMP_REDIR_NETTOS", PyInt_FromLong(ICMP_REDIR_NETTOS));
	PyModule_AddObject(m, "ICMP_REDIR_HOSTTOS", PyInt_FromLong(ICMP_REDIR_HOSTTOS));
	/* TIME_EXCEEDED */
	PyModule_AddObject(m, "ICMP_EXC_TTL", PyInt_FromLong(ICMP_EXC_TTL));
	PyModule_AddObject(m, "ICMP_EXC_FRAGTIME", PyInt_FromLong(ICMP_EXC_FRAGTIME)); 
	PyModule_AddObject(m, "IPT_ICMP_INV", PyInt_FromLong(IPT_ICMP_INV));
	/* packet type */
	PyModule_AddObject(m, "PACKET_HOST", PyInt_FromLong(PACKET_HOST));
	PyModule_AddObject(m, "PACKET_BROADCAST", PyInt_FromLong(PACKET_BROADCAST));
	PyModule_AddObject(m, "PACKET_MULTICAST", PyInt_FromLong(PACKET_MULTICAST));
	PyModule_AddObject(m, "PACKET_OTHERHOST", PyInt_FromLong(PACKET_OTHERHOST));
	PyModule_AddObject(m, "PACKET_OUTGOING", PyInt_FromLong(PACKET_OUTGOING));
	/* target LOG, syslog consts */
	PyModule_AddObject(m, "LOG_ALERT", PyInt_FromLong(LOG_ALERT));
	PyModule_AddObject(m, "LOG_CRIT", PyInt_FromLong(LOG_CRIT));
	PyModule_AddObject(m, "LOG_DEBUG", PyInt_FromLong(LOG_DEBUG));
	PyModule_AddObject(m, "LOG_EMERG", PyInt_FromLong(LOG_EMERG));
	PyModule_AddObject(m, "LOG_ERR", PyInt_FromLong(LOG_ERR));
	PyModule_AddObject(m, "LOG_INFO", PyInt_FromLong(LOG_INFO));
	PyModule_AddObject(m, "LOG_NOTICE", PyInt_FromLong(LOG_NOTICE)); 
	PyModule_AddObject(m, "LOG_WARNING", PyInt_FromLong(LOG_WARNING));

	PyModule_AddObject(m, "LOG_TCPSEQ", PyInt_FromLong(IPT_LOG_TCPSEQ));
	PyModule_AddObject(m, "LOG_TCPOPT", PyInt_FromLong(IPT_LOG_TCPOPT));
	PyModule_AddObject(m, "LOG_IPOPT", PyInt_FromLong(IPT_LOG_IPOPT));
	PyModule_AddObject(m, "LOG_UID", PyInt_FromLong(IPT_LOG_UID));
	PyModule_AddObject(m, "LOG_MACDECODE", PyInt_FromLong(IPT_LOG_MACDECODE));
	/* target REJECT consts */
	PyModule_AddObject(m, "IPT_ICMP_NET_UNREACHABLE", PyInt_FromLong(IPT_ICMP_NET_UNREACHABLE));
	PyModule_AddObject(m, "IPT_ICMP_HOST_UNREACHABLE", PyInt_FromLong(IPT_ICMP_HOST_UNREACHABLE));
	PyModule_AddObject(m, "IPT_ICMP_PROT_UNREACHABLE", PyInt_FromLong(IPT_ICMP_PROT_UNREACHABLE));
	PyModule_AddObject(m, "IPT_ICMP_PORT_UNREACHABLE", PyInt_FromLong(IPT_ICMP_PORT_UNREACHABLE));
	PyModule_AddObject(m, "IPT_ICMP_ECHOREPLY", PyInt_FromLong(IPT_ICMP_ECHOREPLY));
	PyModule_AddObject(m, "IPT_ICMP_NET_PROHIBITED", PyInt_FromLong(IPT_ICMP_NET_PROHIBITED));
	PyModule_AddObject(m, "IPT_ICMP_HOST_PROHIBITED", PyInt_FromLong(IPT_ICMP_HOST_PROHIBITED));
	PyModule_AddObject(m, "IPT_TCP_RESET", PyInt_FromLong(IPT_TCP_RESET));
	PyModule_AddObject(m, "IPT_ICMP_ADMIN_PROHIBITED", PyInt_FromLong(IPT_ICMP_ADMIN_PROHIBITED));
	} 
}
