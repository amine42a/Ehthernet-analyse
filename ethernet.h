#ifndef __ETHERNET_H
#define __ETHERNET_H

/* Define Ethernet Data structure*/
typedef struct Ethernet {
   unsigned char destination[6];
   unsigned char source[6];
   short longueur;
} Ethernet;

void analyserEthernet(char *trame, Ethernet *ethernet);
void afficherAdresseEthernet(char *adresse);
void afficherEthernet(Ethernet ethernet);

#endif