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


static struct ipt_get_entries *
iptables_get_entries(const char *tablename)
{ 
	struct ipt_getinfo info;
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
	s = sizeof(info);
	strcpy(info.name, tablename);
	if (getsockopt(sockfd, IPPROTO_IP,
				IPT_SO_GET_INFO, &info, &s) < 0) {
		goto ERROR; 
	} 
	entries = malloc(sizeof(struct ipt_get_entries) + info.size);
	if (!entries)
		goto ERROR;
	entries->size = info.size; 
	strcpy(entries->name, info.name);
	tmp = sizeof(struct ipt_get_entries) + info.size;
	if (getsockopt(sockfd, IPPROTO_IP,
				IPT_SO_GET_ENTRIES, entries, &tmp) < 0) 
		goto ERROR;
	close(sockfd);
	return entries; 
ERROR:	
	close(sockfd); 
	return NULL;
}

int main(int argc, char **argv) {
	iptables_get_entries("raw");
	return 0;
}

