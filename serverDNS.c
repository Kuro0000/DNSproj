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

static char zone_root[512]="./zone";

static int build_response(const  char *q, int qlen,  char *r, int rmax) {
    //DA FARE
}



void gestore(int signo){
    int stato;
    while (waitpid(-1, &stato, WNOHANG) > 0);
}

int main(int argc, char **argv) {
     char query[DNS_MAXMSG], resp[DNS_MAXMSG];
    int listenfd, connfd, udpfd, maxfdp1, port, nread, nready;
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
    snprintf(zone_root, sizeof(zone_root), "%s", argv[2]);
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
                    //MODIFICA

                close(connfd);
                exit(EXIT_SUCCESS);
            }
            shutdown(connfd, 0);
            shutdown(connfd,1);
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
                int rlen = build_response(query, nread, resp, (int)sizeof(resp));
                if (rlen > 0) {
                    if (sendto(udpfd, resp, (size_t)rlen, 0,(struct sockaddr *)&cliaddr, len) < 0)
                        perror("sendto");
                }
            }
              
        }

    }
}