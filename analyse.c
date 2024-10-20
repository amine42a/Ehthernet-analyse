#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "common.h"
#include "ethernet.h"
#include "ip.h"
#include "tcp.h"

void dumpBlock(char *blockName, char *blockStart, int longueur);
void analyserData(char *trame, int longueur, char *data);

int main()
{
    char frame[] = {
        0x08, 0x00, 0x27, 0xa5, 0x1b, 0xb2, 0x08, 0x00, 
        0x27, 0x63, 0xee, 0xab, 0x00, 0x34, 0x45, 0x00, 
        0x00, 0x34, 0x42, 0x2b, 0x40, 0x10, 0x80, 0x06, 
        0x01, 0x00, 0xac, 0x10, 0x00, 0x64, 0xac, 0x10, 
        0x00, 0x14, 0xc0, 0x80, 0x00, 0x17, 0x7b, 0x02, 
        0xf9, 0xa2, 0x02, 0x4c, 0xda, 0x60, 0x50, 0x18, 
        0x01, 0x00, 0x58, 0xc8, 0x00, 0x00, 0x48, 0x65, 
        0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 
        0x64, 0x21, 0x31, 0x36, 0x31, 0x38
        };
    Ethernet ethernet;
    IP ip;
    TCP tcp;

    if (sizeof(frame) <= SIZEOF_PROTOCOLE) {
        error_exit("Taille frame incorrecte");
    }

    dumpBlock("frame", frame, sizeof(frame));

    char *entete_ethernet = frame;
    analyserEthernet(entete_ethernet, &ethernet);
    afficherEthernet(ethernet);

    char *entete_IP = &frame[SIZEOF_ETHERNET];
    analyserIP(entete_IP, &ip);
    afficherIP(ip);

    char *entete_TCP = &frame[SIZEOF_ETHERNET + SIZEOF_IP];
    analyserTCP(entete_TCP, &tcp);
    afficherTCP(tcp);

    // Taille données sans entetes Ethernet, IP, TCP et CRC
    const int sizeof_data = sizeof(frame) - SIZEOF_PROTOCOLE; 
    char data[sizeof_data + 1];
    char *data_start = &frame[SIZEOF_ETHERNET + SIZEOF_IP + SIZEOF_TCP];
    analyserData(data_start, sizeof_data, data);
    dumpBlock("data", data, sizeof_data);
    printf("Data: %s\n", data);

    return EXIT_SUCCESS;
}

// Analyser les données dans la trame
void analyserData(char *trame, int longueur, char *data)
{
    memcpy(data, trame, longueur);
    data[longueur] = '\0';   // Ajouter fin de chaine
}

// Afficher un bloc de données
void dumpBlock(char *blockName, char *blockStart, int longueur)
{
    unsigned char *p = blockStart;

    printf("\nBlock %s: size=%d", blockName, longueur);
    for (int i=0; i < longueur; i++) {
        if (i % 16 == 0) {
            printf("\n");
        }
        printf("%02X ", *p++);
    }
    printf("\n\n");
}

void error_exit(char *message)
{
    fprintf( stderr, "%s\n", message);
    exit(EXIT_FAILURE);
}