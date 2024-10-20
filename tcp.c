#include <stdio.h>
#include "common.h"
#include "tcp.h"

// Analyser entete TCP
void analyserTCP(char *trame, TCP *tcp) 
{
    error_exit("fonction analyserTCP() non implémentée");
}

// Afficher entete TCP
void afficherTCP(TCP tcp)
{
    printf("TCP:\n");
    printf("    source_port: %d\n", tcp.source_port);
    printf("    destination_port: %d\n", tcp.destination_port);
    printf("    sequence_number: %d\n", tcp.sequence_number);
    printf("    acknowledhment_number: %d\n", tcp.acknowledhment_number);
    printf("    data_offset: %d\n", tcp.data_offset);
    printf("    reserved: %d\n", tcp.reserved);
    printf("    flags: %d\n", tcp.flags);
    printf("    window: %d\n", tcp.window);
    printf("    checksum: %d\n", tcp.checksum);
    printf("    urgent_pointer: %d\n", tcp.urgent_pointer);
}
