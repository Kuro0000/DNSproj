#include <stddef.h>
#include <stdint.h>
#define T_A 1
#define T_NS 2
#define T_CNAME 5
#define C_IN 1
#define MAX_NAME 256
#define RC_NOERROR 0
#define RC_FORMERR 1
#define RC_SERVFAIL 2
#define RC_NXDOMAIN 3
#define RC_NOTIMP 4

uint16_t get16(const unsigned char *p);
void put16(unsigned char *p, uint16_t v);
uint32_t get32(const unsigned char *p);
void put32(unsigned char *p, uint32_t v);
int parseNameDNS(const unsigned char *msg, int len, int off, char *out, size_t outsz);
int encodeNameDNS(const char *name, unsigned char *buf, int max);
int writeDNS(unsigned char *msg, int off, int max, const char *name,uint16_t type, uint32_t ttl,const unsigned char *rdata, int rdlen);
