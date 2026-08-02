#include "dns.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>
#define max(a, b) ((a) > (b) ? (a) : (b))
#define DNS_MAXMSG 512
#define MAX_STEPS 16  
#define MAX_DEPTH 4  
#define MAX_IPS 8
#define MAX_NS 8
#define QUERY_TIMEOUT 3  
#define QUERY_RETRIES 2
#define TTL_MIN 10
static struct in_addr root_hint;
static uint16_t port = 53;

int readDNS(const unsigned char *msg, int len, int off,char *name, size_t namesz, uint16_t *type, uint16_t *cls,uint32_t *ttl, int *rdoff, int *rdlen) {
    char scratch[MAX_NAME];
    int rl;

    if (name == NULL) { 
        name = scratch; 
        namesz = sizeof(scratch); 
    }

    off = parseNameDNS(msg, len, off, name, namesz);
    if (off < 0 || off+10 > len) 
        return -1;

    if (type) 
        *type= get16(msg+off);
    if (cls)  
        *cls = get16(msg+off+2);
    if (ttl)  
        *ttl = get32(msg+off+4);
    rl = (int)get16(msg+off+8);

    if (off+10+rl > len) 
        return -1;
    if (rdoff) 
        *rdoff = off+10;
    if (rdlen) 
        *rdlen = rl;

    return off+10+rl;
}


static int resolve(const char *name, uint16_t type, unsigned char ips[][4], int *nips, uint32_t *ttl, int depth) {
    if (depth > MAX_DEPTH) return RC_SERVFAIL;
     
    struct in_addr cur = root_hint;
    *nips = 0;
    *ttl = TTL_MIN;

    for (int step = 0; step < MAX_STEPS; step++) {
        unsigned char q[DNS_MAXMSG], resp[DNS_MAXMSG];
        char nslist[MAX_NS][MAX_NAME], rname[MAX_NAME];
        uint16_t id = rand() & 0xFFFF, rtype;
        uint32_t rttl;
        int rlen = -1, qlen = 12, off, rdoff, rdlen;
        int nns = 0, found_glue = 0, fd;

        printf("%*s[passo %d] interrogo %s per %s\n", depth * 2, "", step + 1, inet_ntoa(cur), name);
        memset(q, 0, 12);
        put16(q, id);
        put16(q + 4, 1);
        if ((off = encodeNameDNS(name, q + qlen, sizeof(q) - qlen)) < 0) return RC_SERVFAIL;
        qlen += off;
        put16(q + qlen, type); 
        put16(q + qlen + 2, C_IN); 
        qlen += 4;
        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
            struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr = cur };
            for (int try = 0; try <= QUERY_RETRIES; try++) {
                sendto(fd, q, qlen, 0, (struct sockaddr *)&to, sizeof(to));
                
                fd_set rs; FD_ZERO(&rs); FD_SET(fd, &rs);
                struct timeval tv = { .tv_sec = QUERY_TIMEOUT, .tv_usec = 0 };
                
                if (select(fd + 1, &rs, NULL, NULL, &tv) > 0) {
                    rlen = recvfrom(fd, resp, sizeof(resp), 0, NULL, NULL);
                    if (rlen >= 12 && get16(resp) == id) break; // Risposta valida
                    rlen = -1;
                }
            }
            close(fd);
        }

        if (rlen < 0) {
            printf("%*s  nessuna risposta\n", depth * 2, "");
            return RC_SERVFAIL;
        }
        int rcode = resp[3] & 0x0F, an = get16(resp + 6), ns = get16(resp + 8), ar = get16(resp + 10);
        char scratch[MAX_NAME];
        for (int i = 0; i < get16(resp + 4); i++) {
            off = parseNameDNS(resp, rlen, off, scratch, sizeof(scratch));
            if (off < 0 || off+4 > rlen) return -1;
            off += 4;
        }
        if (off< 0) 
            return RC_SERVFAIL;
        for (int i = 0; i < an; i++) {
            if ((off = readDNS(resp, rlen, off, rname, sizeof(rname), &rtype, NULL, &rttl, &rdoff, &rdlen)) < 0) return RC_SERVFAIL;
            if (rtype == T_A && rdlen == 4 && *nips < MAX_IPS) {
                memcpy(ips[(*nips)++], resp + rdoff, 4);
                *ttl = rttl;
            }
        }
        
        if (*nips > 0) {
            printf("%*s  risposta finale: %u.%u.%u.%u\n", depth * 2, "", ips[0][0], ips[0][1], ips[0][2], ips[0][3]);
            return RC_NOERROR;
        }
        if (rcode == RC_NXDOMAIN) {
            printf("%*s  il server dice che il nome non esiste\n", depth * 2, "");
            return RC_NXDOMAIN;
        }
        if (an > 0) return RC_NOERROR;   
        for (int i = 0; i < ns; i++) {
            if ((off = readDNS(resp, rlen, off, rname, sizeof(rname), &rtype, NULL, NULL, &rdoff, &rdlen)) < 0) return RC_SERVFAIL;
            if (rtype == T_NS && nns < MAX_NS && parseNameDNS(resp, rlen, rdoff, nslist[nns], MAX_NAME) >= 0) {
                nns++;
            }
        }
        
        if (nns == 0) {
            printf("%*s  nessuna delega utile: mi fermo\n", depth * 2, "");
            return rcode ? rcode : RC_SERVFAIL;
        }
        printf("%*s  delegato a %s%s\n", depth * 2, "", nslist[0], nns > 1 ? " (e altri)" : "");

        for (int i = 0; i < ar && !found_glue; i++) {
            if ((off = readDNS(resp, rlen, off, rname, sizeof(rname), &rtype, NULL, NULL, &rdoff, &rdlen)) < 0) break;
            if (rtype == T_A && rdlen == 4) {
                for (int k = 0; k < nns; k++) {
                    if (strcmp(rname, nslist[k]) == 0) {
                        memcpy(&cur.s_addr, resp + rdoff, 4);
                        found_glue = 1;
                        break;
                    }
                }
            }
        }
        if (!found_glue) {
            unsigned char nsip[MAX_IPS][4];
            int nn = 0;
            uint32_t nttl;
            printf("%*s  glue assente, risolvo prima %s\n", depth * 2, "", nslist[0]);
            if (resolve(nslist[0], T_A, nsip, &nn, &nttl, depth + 1) != RC_NOERROR || nn == 0) {
                return RC_SERVFAIL;
            }
            memcpy(&cur.s_addr, nsip[0], 4);
        }
    }
    return RC_SERVFAIL; 
}

static int build_client_response(const unsigned char *q, int qlen, unsigned char *r, int rmax) {
    char qname[MAX_NAME];
    unsigned char ips[MAX_IPS][4];
    int qend, off, nips = 0, rcode;
    uint32_t ttl = TTL_MIN;

    if (qlen < 12 || rmax < 12 || (q[2] & 0x80)) 
        return -1;

    qend = parseNameDNS(q, qlen, 12, qname, sizeof(qname));

    if (get16(q+4) != 1 || qend < 0 || qend+4 > qlen) {
        memcpy(r, q, 12);
        r[2] = 0x80; r[3] = RC_FORMERR; 
        memset(r + 4, 0, 8);
        return 12;
    }

    uint16_t qtype = get16(q + qend), qclass = get16(q + qend + 2);
    if ((qend += 4) > rmax) return -1;

    memcpy(r, q, qend);
    r[2] = 0x80 | (q[2] & 0x01);
    r[3] = 0x80;
    memset(r + 6, 0, 6);
    off = qend;

    printf("\n=== richiesta client: %s (type %u) ===\n", qname, qtype);

    if (qclass != C_IN || qtype != T_A) {
        r[3] |= RC_NOTIMP;
        return off;
    }
    rcode = resolve(qname, T_A, ips, &nips, &ttl, 0);

    for (int i = 0; i < nips && off + 16 <= rmax; i++) {
        r[off++] = 0xC0; r[off++] = 0x0C;
        put16(r + off, T_A);  off += 2;
        put16(r + off, C_IN); off += 2;
        put32(r + off, ttl);  off += 4;
        put16(r + off, 4);    off += 2;
        memcpy(r + off, ips[i], 4); off += 4;
    }

    put16(r + 6, nips);
    r[3] = 0x80 | (nips > 0 ? RC_NOERROR : rcode);

    printf("=== risposta al client: %d record, rcode %d ===\n", nips, nips > 0 ? 0 : rcode);
    return off;
}

static int read_n(int fd, unsigned char *buf, int n) {
    int got = 0, k;
    while (got < n && (k = read(fd, buf + got, n - got)) != 0) {
        if (k < 0 && errno == EINTR) continue;
        if (k < 0) return -1;
        got += k;
    }
    return got;
}

int main(int argc, char **argv) {
     unsigned char query[DNS_MAXMSG], resp[DNS_MAXMSG], prefix[2];
    int listenfd, connfd, udpfd, maxfdp1, port, nread, nready, qlun;
    const int on = 1;
    fd_set rset;
    socklen_t len;
    struct sockaddr_in cliaddr, servaddr;

if (argc < 3 || argc > 4) {
        printf("Uso: %s porta percorso_zone [indirizzo_bind]\n", argv[0]);
        exit(1);
    }
    nread = 0;
    while (argv[1][nread] != '\0') {
        if ((argv[1][nread] < '0') || (argv[1][nread] > '9')) {
            printf("Argomento non intero\n");
            exit(2);
        }
        nread++;
    }
    port = atoi(argv[1]);
    if (port < 1 || port > 65535) {
        printf("Porta scorretta...\n");
        exit(2);
    }
    memset((char *)&servaddr, 0, sizeof(struct sockaddr_in));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port =htons(port);

    if (argc == 4) {

        if (inet_pton(AF_INET, argv[3], &servaddr.sin_addr) != 1) {
            printf("Indirizzo di bind non valido\n");
            exit(2);
        }
    } else {
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    printf("inizializzo le socket\n");
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) { 
        perror("apertura socket TCP "); 
        exit(EXIT_FAILURE); 
    }
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) { 
        perror("TCP setsockopt");
        exit(EXIT_FAILURE);
    }
    if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) { 
        perror("bind TCP");
        exit(EXIT_FAILURE);
    }
    if (listen(listenfd, 5) < 0) { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    }

    udpfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpfd < 0) {
        perror("apertura socket UDP");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(udpfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) { 
        perror("UDP setsockopt");
        exit(EXIT_FAILURE);
    }
    if (bind(udpfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) { 
        perror("bind UDP");
        exit(EXIT_FAILURE);
    }

    FD_ZERO(&rset);
    maxfdp1 = max(listenfd, udpfd)+1;
    printf("inizio del demone\n");
    for (;;) {
        FD_SET(listenfd, &rset);
        FD_SET(udpfd, &rset);
        if ((nready = select(maxfdp1, &rset, NULL, NULL, NULL)) < 0) {
            if (errno == EINTR) continue;
            else { 
                perror("select"); 
                exit(EXIT_FAILURE); 
            }
        }
        //-----------------------------------------------------------------------------------------

        // STREAM: esecuzione remota comando (output inviato al client)
        if (FD_ISSET(listenfd, &rset)) {

            len = sizeof(cliaddr);
            connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &len);
            if (connfd < 0) {
                if (errno == EINTR) continue;
                perror("accept");
                continue;
            }
            printf("[TCP] connessione da %s:%d\n", inet_ntoa(cliaddr.sin_addr),ntohs(cliaddr.sin_port));
            unsigned char prefix[2];
            len = sizeof(cliaddr);
            connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &len);
            if (connfd < 0) { 
                if (errno != EINTR) 
                    perror("accept"); 
                continue; 
            }

            if (read_n(connfd, prefix, 2) == 2) {
                int qlen = (int)get16(prefix);
                if (qlen > 0 && qlen <= (int)sizeof(query) &&
                    read_n(connfd, query, qlen) == qlen) {
                    int rlen = build_client_response(query, qlen, resp, (int)sizeof(resp));
                    if (rlen > 0) {
                        unsigned char out[DNS_MAXMSG+2];
                        put16(out, (uint16_t)rlen);
                        memcpy(out+2, resp, (size_t)rlen);
                        if (write(connfd, out, (size_t)rlen+2) < 0)
                            perror("write");
                    }
                }
            }
                close(connfd);
        }
        //-----------------------------------------------------------------------------------------
        // DATAGRAM: esecuzione comando e invio solo valore di ritorno
        if (FD_ISSET(udpfd, &rset)) {
            len = sizeof(cliaddr);
            int nread = (int)recvfrom(udpfd, query, sizeof(query), 0,
                                      (struct sockaddr *)&cliaddr, &len);
            if (nread < 0) {
                if (errno != EINTR) 
                    perror("recvfrom");
            } else {
                int rlen = build_client_response(query, nread, resp, (int)sizeof(resp));
                if (rlen > 0 &&
                    sendto(udpfd, resp, (size_t)rlen, 0,(struct sockaddr *)&cliaddr, len) < 0)
                    perror("sendto");
            }
              
        }

    }
}