#include <Python.h>
/* user headers */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h> 
/* kernel header */
#include <netinet/in.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#define XTABLES_VERSION "9"

#define IP_PARTS_NATIVE(n)			\
(unsigned int)((n)>>24)&0xFF,			\
(unsigned int)((n)>>16)&0xFF,			\
(unsigned int)((n)>>8)&0xFF,			\
(unsigned int)((n)&0xFF)

#define IP_PARTS(n) IP_PARTS_NATIVE(ntohl(n)) 

#define HOOK_PRE_ROUTING	NF_IP_PRE_ROUTING
#define HOOK_LOCAL_IN		NF_IP_LOCAL_IN
#define HOOK_FORWARD		NF_IP_FORWARD
#define HOOK_LOCAL_OUT		NF_IP_LOCAL_OUT
#define HOOK_POST_ROUTING	NF_IP_POST_ROUTING 

static const char *hooknames[] = {
	[HOOK_PRE_ROUTING]	= "PREROUTING",
	[HOOK_LOCAL_IN]		= "INPUT",
	[HOOK_FORWARD]		= "FORWARD",
	[HOOK_LOCAL_OUT]	= "OUTPUT",
	[HOOK_POST_ROUTING]	= "POSTROUTING",
};

static inline int 
add_matches(struct xt_entry_match *m, PyObject *matches_list)
{ 
	return PyList_Append(matches_list,
			PyString_FromString(m->u.user.name)) ? 1 : 0; 
}

static int 
add_entry(struct ipt_entry *e, PyObject *rules_list, 
		struct ipt_getinfo *info, struct ipt_get_entries *entries)
{
	size_t i;	
	struct xt_entry_target *t; 
	char iniface_buffer[IFNAMSIZ+1];
	char outiface_buffer[IFNAMSIZ+1];
	PyObject *rule_dict;
	PyObject *matches_list;
	memset(iniface_buffer, 0, IFNAMSIZ+1);
	memset(outiface_buffer, 0, IFNAMSIZ+1);
	rule_dict = PyDict_New();
	PyDict_SetItemString(rule_dict, "srcip",
			PyInt_FromLong(e->ip.src.s_addr));
	PyDict_SetItemString(rule_dict, "srcip_mask",
			PyInt_FromLong(e->ip.smsk.s_addr));
	PyDict_SetItemString(rule_dict, "dstip",
			PyInt_FromLong(e->ip.dst.s_addr));
	PyDict_SetItemString(rule_dict, "dstip_mask",
			PyInt_FromLong(e->ip.dmsk.s_addr));
	for (i = 0; i < IFNAMSIZ; i++) {
		*(iniface_buffer+i) = e->ip.iniface_mask[i] ? 'X' : '.';
		*(outiface_buffer) = e->ip.outiface_mask[i] ? 'X' : '.';
	} 
	PyDict_SetItemString(rule_dict, "iniface",
			PyString_FromString(e->ip.iniface));
	PyDict_SetItemString(rule_dict, "iniface_mask",
			PyString_FromString(iniface_buffer));
	PyDict_SetItemString(rule_dict, "outiface",
			PyString_FromString(e->ip.outiface));
	PyDict_SetItemString(rule_dict, "outiface_mask",
			PyString_FromString(outiface_buffer));
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

	matches_list = PyList_New(0); 
	XT_MATCH_ITERATE(struct ipt_entry, e, add_matches, matches_list); 
	PyDict_SetItemString(rule_dict, "matches", matches_list); 

	t = (void *)e + e->target_offset;
	PyDict_SetItemString(rule_dict, "target_name",
			PyString_FromString(t->u.user.name));
	PyDict_SetItemString(rule_dict, "target_size",
			PyInt_FromLong(t->u.target_size));

	if (strcmp(t->u.user.name, XT_STANDARD_TARGET) == 0) {
		const unsigned char *data = t->data;
		int pos = *(const int *)data;
		if (pos < 0) {
			PyDict_SetItemString(rule_dict, "verdict",
				PyString_FromString(
					pos == -NF_ACCEPT-1 ? "ACCEPT"
					: pos == -NF_DROP-1 ? "DROP"
					: pos == -NF_QUEUE-1 ?"QUEUE"
					: pos == XT_RETURN ? "RETURN"
					: "UNKNOWN"));
		}
		else {
			PyDict_SetItemString(rule_dict, "verdict",
					PyInt_FromLong(pos));
		}
	} else if (strcmp(t->u.user.name, XT_ERROR_TARGET) == 0) {
		PyDict_SetItemString(rule_dict, "error",	
				PyString_FromString((char *)t->data)); 
	}
	
	return PyList_Append(rules_list, rule_dict) ? 1 : 0;

}

static PyObject *
parse_entries(struct ipt_getinfo *info, struct ipt_get_entries *entries)
{
	PyObject *table_dict;
	PyObject *hooks_dict;
	PyObject *underflows_dict; 
	PyObject *rules_list;
	table_dict = PyDict_New();
	PyDict_SetItemString(table_dict, "iptables_protocol_version",
			PyString_FromString(XTABLES_VERSION));		
	PyDict_SetItemString(table_dict, "blobsize",
			PyInt_FromLong(entries->size));
	PyDict_SetItemString(table_dict, "tablename",
			PyString_FromString(info->name)); 
	hooks_dict = PyDict_New();			
	PyDict_SetItemString(hooks_dict, "pre",
			PyInt_FromLong(info->hook_entry[HOOK_PRE_ROUTING]));
	PyDict_SetItemString(hooks_dict, "in",
			PyInt_FromLong(info->hook_entry[HOOK_LOCAL_IN]));
	PyDict_SetItemString(hooks_dict, "fwd",
			PyInt_FromLong(info->hook_entry[HOOK_FORWARD]));
	PyDict_SetItemString(hooks_dict, "out",
			PyInt_FromLong(info->hook_entry[HOOK_LOCAL_OUT]));
	PyDict_SetItemString(hooks_dict, "post",
			PyInt_FromLong(info->hook_entry[HOOK_POST_ROUTING]));
	underflows_dict = PyDict_New();
	PyDict_SetItemString(underflows_dict, "pre",
			PyInt_FromLong(info->underflow[HOOK_PRE_ROUTING]));
	PyDict_SetItemString(underflows_dict, "in",
			PyInt_FromLong(info->underflow[HOOK_LOCAL_IN]));
	PyDict_SetItemString(underflows_dict, "fwd",
			PyInt_FromLong(info->underflow[HOOK_FORWARD]));
	PyDict_SetItemString(underflows_dict, "out",
			PyInt_FromLong(info->underflow[HOOK_LOCAL_OUT]));
	PyDict_SetItemString(underflows_dict, "post",
			PyInt_FromLong(info->underflow[HOOK_POST_ROUTING])); 
	PyDict_SetItemString(table_dict, "hooks", hooks_dict);
	PyDict_SetItemString(table_dict, "underflows", underflows_dict); 

	rules_list = PyList_New(0);
	XT_ENTRY_ITERATE(struct ipt_entry, entries->entrytable,
			entries->size, add_entry,
			rules_list, info, entries);
	PyDict_SetItemString(table_dict, "rules", rules_list);
	return table_dict;

} 

PyDoc_STRVAR(iptables_get_entries_doc, "get entries of a table");

static PyObject *
iptables_get_entries(PyObject *object, PyObject *args)
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
	if (sockfd < 0)
		return NULL;
	if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) == -1) {
		fprintf(stderr, "Could not set close on exec: %s\n",
				strerror(errno));
		abort();
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



static PyMethodDef iptables_methods[] = {
	{"get_entries", (PyCFunction)iptables_get_entries,
		METH_VARARGS, iptables_get_entries_doc},
	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initiptables(void)
{
	PyObject *m;
	m = Py_InitModule("iptables", iptables_methods);
	if (m != NULL) {
	}
}
