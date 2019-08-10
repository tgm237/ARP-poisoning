#include "interface.h"

struct interface *get_interface_params(char *interface_name, char *errbuf)
{
	int service_sock; // service socket for ioctl()
	struct ifreq ifr; // service structure for ioctl()
	static struct interface our_interface; // saved our got parameters

	// set to zero these structures
	memset(errbuf, 0, ERRBUF_SIZE);
	memset(&ifr, 0, sizeof(struct ifreq));

	service_sock = socket(PF_INET, SOCK_DGRAM, 0);

	if(service_sock == -1)
	{
		strncpy(errbuf, strerror(errno), ERRBUF_SIZE);

		return NULL;
	}

	// copy interface name to 'ifreq' structure
	strncpy(ifr.ifr_name, interface_name, IFACE_NAME_LEN);

	// try to get ethernet address
	if(ioctl(service_sock, SIOCGIFHWADDR, &ifr) == -1)
	{
		strncpy(errbuf, strerror(errno), ERRBUF_SIZE);

		return NULL;
	}

	memcpy(our_interface.eth_addr, ifr.ifr_hwaddr.sa_data, 6);

	// try to get network address
	if(ioctl(service_sock, SIOCGIFADDR, &ifr) == -1)
	{
		strncpy(errbuf, strerror(errno), ERRBUF_SIZE);

		return NULL;
	}

	memcpy(our_interface.net_addr, ifr.ifr_addr.sa_data + 2, 4);

	// try to get interface index
	if(ioctl(service_sock, SIOCGIFINDEX, &ifr) == -1)
	{
		strncpy(errbuf, strerror(errno), ERRBUF_SIZE);

		return NULL;
	}

	our_interface.index = ifr.ifr_ifindex;

	// copy interface name
	strncpy(our_interface.name, interface_name, IFACE_NAME_LEN);

	close(service_sock);

	return &our_interface;
}