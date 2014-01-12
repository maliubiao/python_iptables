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

static const char *hooknames[] = {
	[HOOK_PRE_ROUTING]	= "PREROUTING",
	[HOOK_LOCAL_IN]		= "INPUT",
	[HOOK_FORWARD]		= "FORWARD",
	[HOOK_LOCAL_OUT]	= "OUTPUT",
	[HOOK_POST_ROUTING]	= "POSTROUTING",
};

static int 
add_entry(struct ipt_entry, PyObject *table_dict, 
		struct ipt_getinfo *info, struct ipt_get_entries *entries)
{
	
}

static PyObject *
parse_entries(struct ipt_getinfo *info, struct ipt_get_entries *entries)
{
	PyObbject *table_dict;
	PyObject *hooks_dict;
	PyObject *underflows_dict; 
	table_dict = PyDict_New();
	PyDict_SetItemString(table_dict, "version",
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
	PyDict_SetItemString(hooks_dict, "pre",
			PyInt_FromLong(info->underflow[HOOK_PRE_ROUTING]));
	PyDict_SetItemString(hooks_dict, "in",
			PyInt_FromLong(info->underflow[HOOK_LOCAL_IN]));
	PyDict_SetItemString(hooks_dict, "fwd",
			PyInt_FromLong(info->underflow[HOOK_FORWARD]));
	PyDict_SetItemString(hooks_dict, "out",
			PyInt_FromLong(info->underflow[HOOK_LOCAL_OUT]));
	PyDict_SetItemString(hooks_dict, "post",
			PyInt_FromLong(info->underflow[HOOK_POST_ROUTING]));
	PyDict_SetItemString(table_dict, "hooks", hooks_dict);
	PyDict_SetItemString(table_dict, "underflows", underflows_dict); 

	XT_MATCH_ITERATE(struct ipt_entry, entries->entrytable,
			entries->size, add_entry,
			hooks_dict, info, entries);

} 

static struct ipt_get_entries *
iptables_get_entries(const char *tablename)
{ 
	struct ipt_getinfo *info;
	struct ipt_get_entries *entries;
	unsigned int tmp;
	socklen_t s;
	int sockfd;
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
	s = sizeof(info);
	strcpy(info->name, tablename);
	if (getsockopt(sockfd, IPPROTO_IP,
				IPT_SO_GET_INFO, info, &s) < 0) {
		goto ERROR; 
	} 
	entries = PyMem_Malloc(sizeof(struct ipt_get_entries) + info->size);
	if (!entries)
		goto ERROR;
	entries->size = info->size; 
	strcpy(entries->name, info->name);
	tmp = sizeof(struct ipt_get_entries) + info->size;
	if (getsockopt(sockfd, IPPROTO_IP,
				IPT_SO_GET_ENTRIES, entries, &tmp) < 0) 
		goto ERROR;
	close(sockfd); 
	return parse_entries(info, entries); 
ERROR:	
	if info:
		PyMem_Free(info);
	if entries:
		PyMem_Free(entries);
	close(sockfd); 
	return NULL;
}

/* gdb debug */
int main(int argc, char **argv) {
	iptables_get_entries("raw");
	return 0;
}

