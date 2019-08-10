#include "sock.h"

int create_packet_socket(struct interface *iface, char *errbuf)
{
	int returned_socket;
	struct sockaddr_ll sock_params;

	// set to zero "errbuf"
	memset(errbuf, 0, ERRBUF_SIZE);

	if((returned_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
	{
		strncpy(errbuf, strerror(errno), ERRBUF_SIZE);

		return -1;
	}

	// set this parameters for sockaddr_ll structure
	sock_params.sll_family = AF_PACKET; 		  // this is packet socket
	sock_params.sll_protocol = htons(ETH_P_ALL);  // all protocols
	sock_params.sll_halen = 6;					  // eternet address length
	sock_params.sll_ifindex = iface->index;		  // index of used interface
	memcpy(sock_params.sll_addr, iface->eth_addr, 6);	  // mac address of used interface

	// bind socket to selected interface
	if(bind(returned_socket, (struct sockaddr *)&sock_params, sizeof(struct sockaddr_ll)) == -1)
	{
		strncpy(errbuf, strerror(errno), ERRBUF_SIZE);

		return -1;
	}

	return returned_socket;
}