#ifndef __IP_H
#define __IP_H

/* Define IP Data structure*/
typedef struct IP {
   unsigned int version : 4;
   unsigned int IHL : 4;
   unsigned char typeOfService;
   unsigned short totalLength;
   unsigned short identification;
   unsigned int flags : 3;
   unsigned int fragmentOffset : 13;
   unsigned char timeToLive;
   unsigned char protocol;
   unsigned short HeaderChecksum;
   unsigned int sourceIP;
   unsigned int destinationIP;
} IP;

void analyserIP(char *trame, IP *ip);
void afficherIPAddress(unsigned int address);
void afficherIP(IP ip);

#endif