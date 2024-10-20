analyse: analyse.c common.h ethernet.c ethernet.h ip.c ip.h tcp.h tcp.c
	gcc -o analyse analyse.c ethernet.c ip.c tcp.c

correction: analyse.c common.h ethernet_correction.c ethernet.h ip_correction.c ip.h tcp.h tcp_correction.c
	gcc -o correction analyse.c ethernet_correction.c ip_correction.c tcp_correction.c
