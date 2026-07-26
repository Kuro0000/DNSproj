#include <ctype.h>
#include <string.h>
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
int parseNameDNS(const unsigned char *msg, int len, int off, char *out, size_t outsz){
    int jumped = 0, after = -1, n = 0, hops = 0;

    if (outsz == 0)
        return -1;
    out[0] = '\0';
    while (off >= 0 && off < len) {
        unsigned l = msg[off];
        if ((l & 0xC0) == 0xC0) {
            if (off+1 >= len) 
                return -1;
            if (!jumped) after = off+2;
            jumped = 1;
            off = (int)(((l & 0x3F) << 8) | msg[off+1]);
            if (++hops > 15) 
                return -1;
            continue;
        }
        if (l & 0xC0) 
            return -1;

        if (l == 0) {
            if (!jumped) 
                after = off+1;
            out[n] = '\0';
            return after;
        }
        if (off+1+(int)l > len || (size_t)(n+(int)l+2) > outsz)
            return -1;

        for (unsigned i = 0; i < l; i++)
            out[n++] = (char)tolower(msg[off+1+i]);
        out[n++] = '.';

        off += 1+(int)l;
    }
    return -1;
}

int encodeNameDNS(const char *name, unsigned char *buf, int max){
    int off = 0;
    const char *p = name;

    while (*p) {
        const char *dot = strchr(p, '.');
        int l = dot ? (int)(dot - p) : (int)strlen(p);

        if (l == 0) { 
            p = dot ? dot+1 : p+l; 
            continue; 
        } 
        if (l >= MAX_LABEL) 
            return -1;
        if (off+1+l+1 > max) 
            return -1;

        buf[off++] = (unsigned char)l;
        for (int i = 0; i < l; i++)
            buf[off++] = (unsigned char)tolower((unsigned char)p[i]);

        p = dot ? dot+1 : p+l;
    }
    if (off+1 > max) return -1;
    buf[off++] = 0;
    return off;
}

int writeDNS(unsigned char *msg, int off, int max, const char *name,uint16_t type, uint32_t ttl,const unsigned char *rdata, int rdlen) {
    int w = encodeNameDNS(name, msg+off, max - off);
    if (w < 0) return -1;
    off += w;

    if (off+10+rdlen > max) return -1;

    put16(msg+off, type);
     off += 2;
    put16(msg+off, C_IN);
    off += 2;
    put32(msg+off, ttl);
     off += 4;
    put16(msg+off, (uint16_t)rdlen); 
    off += 2;
    memcpy(msg+off, rdata, (size_t)rdlen);
    off += rdlen;

    return off;
}

