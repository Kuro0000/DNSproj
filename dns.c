#include <stdint.h>
#include "dns.h" 

uint16_t get16(const unsigned char *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

void put16(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)(v & 0xff);
}

