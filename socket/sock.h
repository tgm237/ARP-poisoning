#ifndef __SOCK_H__
#define __SOCK_H__

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "interface.h"
#include "../general/default.h"

// Returned value: socket descriptor or -1 if it's error
int create_packet_socket(struct interface *iface, char *errbuf);

#endif