#include "eth.h"

struct ethhdr *create_eth_header(u_char *eth_src, u_char *eth_dst, u_short protocol)
{
	static struct ethhdr eth;
	unsigned char *binary_mac;

	// sender mac
	memcpy(eth.h_source, eth_src, ETH_ALEN);

	// destination mac
	memcpy(eth.h_dest, eth_dst, ETH_ALEN);

	eth.h_proto = htons(protocol);

	return &eth;
}