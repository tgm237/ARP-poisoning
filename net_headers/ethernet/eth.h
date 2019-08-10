#ifndef __ETH_H__
#define __ETH_H__

#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

// Arguments: binary addresses and protocol defined in /usr/include/linux/if_ether.h
// Returned value: pointer on 'ethhdr' structure or NULL 
struct ethhdr *create_eth_header(u_char *eth_src, u_char *eth_dst, u_short protoctol);

#endif