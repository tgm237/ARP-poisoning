#ifndef __INTERFACE_H__
#define __INTERFACE_H__

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include "../general/default.h"

struct interface
{
	char name[IFACE_NAME_LEN];
	unsigned char eth_addr[6];
	unsigned char net_addr[4];
	unsigned int index;
};

/* Returned value: pointer on function 'interface' or NULL if it's error */
struct interface *get_interface_params(char *interface_name, char *errbuf);

#endif