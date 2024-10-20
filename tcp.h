#ifndef __TCP_H
#define __TCP_H

/* Define TCP Data structure*/
typedef struct TCP {
   unsigned short source_port;
   unsigned short destination_port;
   unsigned int sequence_number;
   unsigned int acknowledhment_number;
   unsigned int data_offset : 4;
   unsigned int reserved : 6;
   unsigned int flags : 6;
   unsigned short window;
   unsigned short checksum;
   unsigned short urgent_pointer;
} TCP;

void analyserTCP(char *trame, TCP *tcp);
void afficherTCP(TCP tcp);

#endif