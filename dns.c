#include <stdint.h>
#include "dns.h" 

uint16_t get16(const unsigned char *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

void put16(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)(v & 0xff);
}

uint32_t get32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

void put32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)(v);
}
int parseNameDNS(const unsigned char *msg, int len, int off, char *out, size_t outsz);

int encodeNameDNS(const char *name, unsigned char *buf, int max);
int writeDNS(unsigned char *msg, int off, int max, const char *name,uint16_t type, uint32_t ttl,const unsigned char *rdata, int rdlen);

