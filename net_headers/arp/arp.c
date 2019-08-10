#include "arp.h"

struct arp_header *create_arp_header(u_char *hsource, u_char *psource, u_char *hdest, u_char *pdest, u_short opcode)
{
	static struct arp_header arp;

	arp.arp_hrd = htons(ARPHRD_ETHER);
	arp.arp_protocol = htons(ETH_P_IP);
	arp.arp_hln = ETH_ALEN; 
	arp.arp_pln = 4;
	arp.arp_op = htons(opcode);

	// source address
	memcpy(arp.arp_hrd_src, hsource, ETH_ALEN);
	memcpy(arp.arp_pro_src, psource, 4);

	// destination address
	memcpy(arp.arp_hrd_dst, hdest, ETH_ALEN);
	memcpy(arp.arp_pro_dst, pdest, ETH_ALEN);

	return &arp;
}