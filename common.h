#ifndef __COMMON_H
#define __COMMON_H

#define SIZEOF_ETHERNET 14
#define SIZEOF_IP 20
#define SIZEOF_TCP 20
#define SIZEOF_CRC 4
#define SIZEOF_PROTOCOLE (SIZEOF_ETHERNET + SIZEOF_IP + SIZEOF_TCP + SIZEOF_CRC)

#define MAKE_SHORT(x, y) (((x) << 8) + (y))
#define MAKE_INT(w, x, y, z) (((w) << 24) + ((x) << 16) + ((y) << 8) + (z))

void error_exit(char *message);
#endif