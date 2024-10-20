#include <stdio.h>
#include <string.h>
#include "common.h"
#include "ip.h"

// Analyser l'entête IP
void analyserIP(char *trame, IP *ip) 
{
    ip->version = (trame[0] >> 4) & 0x0F;           // Les 4 premiéres bit pour la version
    ip->IHL = trame[0] & 0x0F;                      // Les 4 dernieres bits pour IHL
    ip->typeOfService = trame[1];                   // Type de service (1 octets)
    ip->totalLength = (trame[2] << 8) | trame[3];   // Longueur totalle (2 octés)
    ip->identification = (trame[4] << 8) | trame[5]; // Identfication (2 octés)

    // Flag et Fragment ofet (3 bits pour les flag, 13 bit pour le fragment ofset)
    ip->flags = (trame[6] >> 5) & 0x07;             // Flags (3 bits)
    ip->fragmentOffset = ((trame[6] & 0x1F) << 8) | trame[7];  // Fragment ofset (13 bit)

    ip->timeToLive = trame[8];                      // TTL (1 octé)
    ip->protocol = trame[9];                        // Protocoles (1 octé)
    ip->HeaderChecksum = (trame[10] << 8) | trame[11]; // Checksum de l'entête (2 octet)

    // Adresses IP source et destination (4 octet chacune)
    ip->sourceIP = (trame[12] << 24) | (trame[13] << 16) | (trame[14] << 8) | trame[15];
    ip->destinationIP = (trame[16] << 24) | (trame[17] << 16) | (trame[18] << 8) | trame[19];
}

// Afficher une adresse IP
void afficherIPAddress(unsigned int address)
{
    // Extraire et afficher chaques octets de l'adresse ip
    printf("%d.%d.%d.%d", 
           (address >> 24) & 0xFF,  // Octé 1
           (address >> 16) & 0xFF,  // Octé 2
           (address >> 8) & 0xFF,   // Octé 3
           address & 0xFF);         // Octé 4
}

// Afficher l'entête IP
void afficherIP(IP ip)
{
    printf("IP:\n");
    printf("    version: %d\n", ip.version);
    printf("    IHL: %d\n", ip.IHL);
    printf("    typeOfService: %d\n", ip.typeOfService);
    printf("    totalLength: %d\n", ip.totalLength);
    printf("    identification: %d\n", ip.identification);
    printf("    flags: %d\n", ip.flags);
    printf("    fragmentOffset: %d\n", ip.fragmentOffset);
    printf("    timeToLive: %d\n", ip.timeToLive);
    printf("    protocol: %d\n", ip.protocol);
    printf("    HeaderChecksum: %d\n", ip.HeaderChecksum);
    printf("    sourceIP: ");
    afficherIPAddress(ip.sourceIP);
    printf("\n    destinationIP: ");
    afficherIPAddress(ip.destinationIP);
    printf("\n");
}