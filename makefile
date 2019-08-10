interface.o: socket/interface.c
	gcc -c socket/interface.c 

sock.o: socket/sock.c
	gcc -c socket/sock.c

eth.o: net_headers/ethernet/eth.c
	gcc -c net_headers/ethernet/eth.c

arp.o: net_headers/arp/arp.c
	gcc -c net_headers/arp/arp.c

service_func.o: general/service_func.c
	gcc -c general/service_func.c

arp_poison.o: arp_poison.c
	gcc -c arp_poison.c

install: interface.o sock.o eth.o arp.o service_func.o arp_poison.o
	gcc -o arp_poison *.o -pthread -lrt
	$(MAKE) clean

clean:
	rm -rf *.o