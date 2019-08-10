#ifndef __ARP_H__
#define __ARP_H__

#include <string.h>
#include <stdlib.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include "../../general/service_func.h"

// from /usr/include/net/if_arp.h
struct arp_header
{
	unsigned short int arp_hrd;       // format of hardware protocol   
	unsigned short int arp_protocol;  // format of protocol address
	unsigned char arp_hln;		      // length of hardware address
	unsigned char arp_pln;			  // length of protocol address
	unsigned short arp_op;			  // opcode

	unsigned char arp_hrd_src[ETH_ALEN]; // source hardware address
	unsigned char arp_pro_src[4];		 // source ip address
	unsigned char arp_hrd_dst[ETH_ALEN]; // destination dardware address
	unsigned char arp_pro_dst[4];        // destination protocol address
};

#define ARP_HEADER_SIZE sizeof(struct arp_header)

// arguments: binary address, returned value: pointer on structure 'arp_header'
struct arp_header *create_arp_header(u_char *hsource, u_char *psource, u_char *hdest, u_char *pdest, u_short opcode);

#endif