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
#define MAX_NS 8
#define RES_ANSWER 0
#define RES_REFERRAL 1
#define RES_NXDOMAIN 2
#define TTL_DEFAULT 60

static char uri[512]="./uri";

static int read_lines(const char *path, char out[][MAX_NAME], int maxlines) {
    int fd = open(path, O_RDONLY);
    char line[MAX_NAME];
    char ch;
    int n = 0, i = 0;
    int bytes_read;
    if (fd < 0) 
        return 0;

    while (n < maxlines && (bytes_read = read(fd, &ch, 1)) > 0) {
        if (ch == '\n') {
            if (i > 0) {
                line[i] = '\0';
                if (line[0] != '#') { sprintf(out[n], "%s", line); n++; }
                i = 0;
            }
            continue;
        }
        if (i < MAX_NAME - 1) line[i++] = ch;
    }
    if (n < maxlines && i > 0) {
        line[i] = '\0';
        if (line[0] != '#') {
            sprintf(out[n], "%s", line);
            n++;
        }
    }

    close(fd);
    return n;
}

static int node_path(char labels[MAX_LABEL][MAX_LABEL], int n, int from, char *out, size_t outsz) {
    int used = snprintf(out, outsz, "%s", uri);

    for (int i = n - 1; i >= from; i--) {
        int w = snprintf(out+used, outsz - (size_t)used, "/%s", labels[i]);
        if (w < 0 || (size_t)(used+w) >= outsz) return -1;
        used += w;
    }
    return used;
}
static int lookup_A_byname(const char *name, unsigned char ip[4]){
    char labels[MAX_LABEL][MAX_LABEL], path[1024], line[64];
    int n = 0;
    struct in_addr addr;
    while (*name) {
        const char *dot = strchr(name, '.');
        int l = dot ? (int)(dot - name) : (int)strlen(name);

        if (l == 0) { 
            name = dot ? dot+1 : name+l;
             continue; 
        }
        if (l >= MAX_LABEL || n >= MAX_LABEL) 
            return -1;

        memcpy(labels[n], name, (size_t)l);
        labels[n][l] = '\0';
        for (int i = 0; i < l; i++)
            labels[n][i] = (char)tolower((unsigned char)labels[n][i]);
        n++;
        name = dot ? dot+1 : name+l;
    }

    if (n < 0)
        return 0;
    if (node_path(labels, n, 0, path, sizeof(path)) < 0) 
        return 0;
    if (strlen(path)+3 >= sizeof(path))
        return 0;
    strcat(path, "/A");
    int fd = open(path, O_RDONLY);
    char ch;
    int i = 0;
    if (fd < 0)
     return 0;

    while ((n = read(fd, &ch, 1)) > 0) {
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
            break;
        }
        if (i < sizeof(line) - 1) {
            line[i++] = ch;
        } else {
            break;
        }
    }
    
    close(fd);
    
    if (i == 0) 
        return 0;
    line[i] = '\0';
    if (inet_pton(AF_INET, line, &addr) != 1) 
        return 0;
    memcpy(ip, &addr.s_addr, 4);
    
    return 1;
}
static int lookup(const char *name, unsigned char ip[4],char *uriIn, size_t urisz, char ns[MAX_NS][MAX_NAME], int *nns){
    char labels[MAX_LABEL][MAX_LABEL], path[1024], nspath[1100];
    int n = 0, w;
    int used;
    const char *tempName= name;

    while (*tempName) {
        const char *dot = strchr(tempName, '.');
        int l = dot ? (int)(dot - tempName) : (int)strlen(tempName);

        if (l == 0) { 
            tempName = dot ? dot+1 : tempName+l;
             continue; 
        }
        if (l >= MAX_LABEL || n >= MAX_LABEL) 
            return -1;

        memcpy(labels[n], tempName, (size_t)l);
        labels[n][l] = '\0';
        for (int i = 0; i < l; i++)
            labels[n][i] = (char)tolower((unsigned char)labels[n][i]);
        n++;
        tempName = dot ? dot+1 : tempName+l;
    }
    if (n<=0)
     return RES_NXDOMAIN; 
    used = sprintf(path, "%s", uri);

    for (int i = n - 1; i >= 0; i--) {


        w = sprintf(path+used, "/%s", labels[i]);
        if (w < 0 || (size_t)(used+w) >= sizeof(path)) 
            return RES_NXDOMAIN;
        used += w;
        sprintf(nspath, "%s/NS", path);

        *nns = read_lines(nspath, ns, MAX_NS);
        if (*nns > 0) {

            if (i > 0 || lookup_A_byname(name, ip) == 0) {
                int off = 0;
                uriIn[0] = '\0';
                for (int k = i; k < n; k++)
                    off += snprintf(uriIn+off, urisz - (size_t)off, "%s.", labels[k]);
                return RES_REFERRAL;
            }
        }
    }
    if (lookup_A_byname(name, ip)) 
        return RES_ANSWER;
    return RES_NXDOMAIN;
}

static int buildResponse(const unsigned char *reqBuf, int reqLen,  char unsigned *resBuf, int maxResLen) {
    char domainReq[MAX_NAME], uriNome[MAX_NAME], nsArray[MAX_NS][MAX_NAME];
    unsigned char addr[4], rawData[MAX_NAME];
    int offsetReq, count = 0, searchRes;
    uint16_t typeReq, classReq;

    if (reqLen < 12 || maxResLen < 12 || reqBuf[2] & 0x80) 
        return -1;

    memcpy(resBuf, reqBuf, 12);
    resBuf[2] = (unsigned char)(0x80 | (reqBuf[2] & 0x01)); 
    resBuf[3] = 0x00;
    put16(resBuf+6, 0);
    put16(resBuf+8, 0);
    put16(resBuf+10, 0);

    if (get16(reqBuf+4) != 1) { 
        put16(resBuf+4, 0); 
        resBuf[3] = RC_FORMERR; 
        return 12; 
    }

    offsetReq = parseNameDNS(reqBuf, reqLen, 12, domainReq, sizeof(domainReq));

    if (offsetReq < 0 || offsetReq+4 > reqLen) { 
        put16(resBuf+4, 0); 
        resBuf[3] = RC_FORMERR; 
        return 12; 
    }
    typeReq = get16(reqBuf+offsetReq);
    classReq = get16(reqBuf+offsetReq+2);
    offsetReq += 4;

    if (offsetReq > maxResLen) 
        return -1;
    memcpy(resBuf, reqBuf, (size_t)offsetReq);
    resBuf[2] = (unsigned char)(0x80 | (reqBuf[2] & 0x01));
    resBuf[3] = 0x00;
    put16(resBuf+4, 1);
    put16(resBuf+6, 0);
    put16(resBuf+8, 0);
    put16(resBuf+10, 0);

    printf("  query %s type=%u\n", domainReq[0] ? domainReq : ".", typeReq);

    if (classReq != C_IN || (typeReq != T_A && typeReq != T_NS)) {
        resBuf[3] = RC_NOTIMP;
        return offsetReq;
    }
    searchRes = lookup(domainReq, addr, uriNome, sizeof(uriNome), nsArray, &count);

    if (searchRes == RES_ANSWER) {
        resBuf[2] |= 0x04;
        resBuf[offsetReq++] = 0xC0;
        resBuf[offsetReq++] = 0x0C;
        put16(resBuf+offsetReq, T_A);
         offsetReq += 2;
        put16(resBuf+offsetReq, C_IN);
         offsetReq += 2;
        put32(resBuf+offsetReq, TTL_DEFAULT); 
        offsetReq += 4;
        put16(resBuf+offsetReq, 4);
         offsetReq += 2;
        memcpy(resBuf+offsetReq, addr, 4);
         offsetReq += 4;
        put16(resBuf+6, 1);
        printf("  -> ANSWER %u.%u.%u.%u (autoritativa)\n", addr[0], addr[1], addr[2], addr[3]);
        return offsetReq;
    }

    if (searchRes == RES_REFERRAL) {
        int auth_count = 0, add_count = 0;
        int new_offset;
           int rdata_length;
        for (int idx = 0; idx < count; idx++) {
            rdata_length = encodeNameDNS(nsArray[idx], rawData, (int)sizeof(rawData));
    
            if (rdata_length < 0) 
                continue;
            new_offset = writeDNS(resBuf, offsetReq, maxResLen, uriNome, T_NS, TTL_DEFAULT, rawData, rdata_length);
            if (new_offset < 0) 
                break;
            offsetReq = new_offset;
            auth_count++;
        }
         unsigned char glue_ip[4];
    
        for (int idx = 0; idx < count; idx++) {
            if (!lookup_A_byname(nsArray[idx], glue_ip)) 
                continue;
            new_offset = writeDNS(resBuf, offsetReq, maxResLen, nsArray[idx], T_A, TTL_DEFAULT, glue_ip, 4);
            if (new_offset < 0) 
                break;
            offsetReq = new_offset;
            add_count++;
            printf("  -> REFERRAL a %s (%u.%u.%u.%u) per la zona %s\n", nsArray[idx], glue_ip[0], glue_ip[1], glue_ip[2], glue_ip[3], uriNome);
        }
        put16(resBuf+8, (uint16_t)auth_count);
        put16(resBuf+10, (uint16_t)add_count);
        if (add_count == 0)
            printf("  -> REFERRAL per la zona %s (senza glue)\n", uriNome);
        return offsetReq;
    }

    resBuf[2] |= 0x04;
    resBuf[3] = RC_NXDOMAIN;
    printf("  -> NXDOMAIN\n");
    return offsetReq;
}

static int readN(int fd, unsigned char *buf, int n) {
    int count = 0;
    while(count<n){
        int k=read(fd, buf+count, (size_t)(n-count));
        if(k==0)
        return count;
        if(k<0){
            if (errno== EINTR)
            continue;
            return -1;
        }
        count+=k;
    }
    return count;
}

void gestore(int signo){
    int stato;
    while (waitpid(-1, &stato, WNOHANG) > 0);
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
    snprintf(uri, sizeof(uri), "%s", argv[2]);
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

    signal(SIGCHLD, gestore);
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
            if (fork() == 0) {
                close(listenfd);
                close(udpfd);
                    for(;;){
                            if(readN(connfd, prefix, 2) != 2){
                                break;
                            }
                            qlun=get16(prefix);
                            if (qlun <= 0 || qlun > (int)sizeof(query) || readN(connfd, query, qlun) != qlun) 
                                break;

                            int rlen = buildResponse(query, qlun, resp+2, (int)sizeof(resp) - 2);
                            if (rlen < 0) 
                                break;
                            put16(resp, (uint16_t)rlen);
                            if (write(connfd, resp, (size_t)rlen+2) < 0) 
                                break;
                    }
                close(connfd);
                exit(EXIT_SUCCESS);
            }

            close(connfd);
        }
        //-----------------------------------------------------------------------------------------
        // DATAGRAM: esecuzione comando e invio solo valore di ritorno
        if (FD_ISSET(udpfd, &rset)) {
            len = sizeof(cliaddr);
            int nread = recvfrom(udpfd, query, sizeof(query), 0,(struct sockaddr *)&cliaddr, &len);
            if (nread < 0) {
                if (errno != EINTR) perror("recvfrom");
            } else {
                printf("[UDP] %s:%d\n", inet_ntoa(cliaddr.sin_addr),
                       ntohs(cliaddr.sin_port));
                int rlen = buildResponse(query, nread, resp, (int)sizeof(resp));
                if (rlen > 0) {
                    if (sendto(udpfd, resp, (size_t)rlen, 0,(struct sockaddr *)&cliaddr, len) < 0)
                        perror("sendto");
                }
            }
              
        }

    }
}