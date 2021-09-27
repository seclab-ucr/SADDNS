/*
    DNS protocol implementation.
*/

#include "dns.h"
#include "network.h"
#include "util.h"
#include "common.h"

uint16_t        g_txid_counter = 0;
pthread_mutex_t g_txid_count_mutex;
int             g_dns_init = FALSE;

/* Init. */
void dns_init() {
    if (!g_dns_init) {
        g_dns_init = TRUE;
        pthread_mutex_init(&g_txid_count_mutex, NULL);
    }
}

/* Get up level of given domain name. */
char* domain_uplevel(char* domain) {
    size_t domain_len = strlen(domain);
    char* ret = strstr(domain, ".");
    if (ret == NULL)
        return NULL;
    
    return ret + 1;
}

/* Get a new string of sublevel of given domain name. */
int domain_sublevel(char* outbuf, size_t outbuf_len, char* domain, char* sublevel) {
    if (outbuf_len < strlen(domain) + strlen(sublevel) + 1)
        return -1;

    strcpy(outbuf, sublevel);
    outbuf[strlen(sublevel)] = '.';
    strcat(outbuf, domain);

    return 1;
}

/* Determine if given domain is in zone. */
int domain_is_in_zone(char* input, char* zone) {
    char *tmp = input;
    while (tmp != NULL) {
        if (strcmp(tmp, zone) == 0)
            return TRUE;
        tmp = domain_uplevel(input);
    }

    return FALSE;
}

/* Encode domain name. */
size_t dns_encode(uint8_t* out, size_t out_len, char* in) {
    if (out_len < strlen(in) * 2)
        return -1;
    
    uint8_t* ptr_out = out;
    uint8_t* ptr_in = in;
    uint8_t* ptr_segstart = ptr_in;
    uint8_t* i;
    while (ptr_in < (uint8_t*)in + strlen(in) + 1) {
        if (*ptr_in != '.' && *ptr_in != '\x00')
            ptr_in++;
        else {
            // Copy.
            *(ptr_out++) = ptr_in - ptr_segstart;
            for (i = ptr_segstart; i < ptr_in; i++)
                *(ptr_out++) = *i;
            ptr_in++;
            ptr_segstart = ptr_in;
        }
    }
    *ptr_out = '\x00';

    return ptr_out - out + 1;
}

/* Decode domain name. */
int dns_decode(char* outbuf, size_t outbuf_len, uint8_t* indata, size_t indata_len) {
    if (outbuf_len < indata_len)
        return -1;

    uint8_t seg_len;
    int i = 0;
    int j = 0;
    while (i < indata_len) {
        seg_len = indata[i];
        if (seg_len == 0)
            break;

        memcpy(outbuf + j, indata + i + 1, seg_len);
        outbuf[j + seg_len] = '.';
        j += seg_len + 1;

        i += seg_len + 1;
    }

    outbuf[j - 1] = '\x00';
    return 1;
}

/* Allocate a new DNS query of A type. */
struct dns_query* new_dns_query_a(char* domain_name) {
    struct dns_query* ret = (struct dns_query*)alloc_memory(sizeof(struct dns_query));

    ret->query_name = (uint8_t*)alloc_memory(64);
    ret->query_name_len = dns_encode(ret->query_name, 64, domain_name);

    ret->query_info.dclass = htons(RR_CLASS_IN);
    ret->query_info.type = htons(RR_TYPE_A);

    return ret;
}

/* Release a DNS query. */
void free_dns_query(struct dns_query* query) {
    free(query->query_name);
    free(query);
}

/* Allocate a new DNS answer of A type. */
struct dns_answer* new_dns_answer_a(char* domain_name, uint32_t ip_addr, uint32_t ttl) {
    struct dns_answer* ret = (struct dns_answer*)alloc_memory(sizeof(struct dns_answer) + sizeof(uint32_t));
    
    ret->res_name = (uint8_t*)alloc_memory(128);
    ret->res_name_len = dns_encode(ret->res_name, 128, domain_name);

    ret->res_info.type = htons(RR_TYPE_A);
    ret->res_info.dclass = htons(RR_CLASS_IN);
    ret->res_info.ttl = htonl(ttl);
    ret->res_info.len = htons(sizeof(uint32_t));
    memcpy(ret->res_info.data, &ip_addr, sizeof(ip_addr));

    return ret;
}

/* Allocate a new DNS answer of NS type. */
struct dns_answer* new_dns_answer_ns(char* domain_name, char* res_name, uint32_t ttl) {
    struct dns_answer* ret = (struct dns_answer*)alloc_memory(sizeof(struct dns_answer) + 128);
    
    ret->res_name = (uint8_t*)alloc_memory(128);
    ret->res_name_len = dns_encode(ret->res_name, 128, domain_name);

    ret->res_info.type = htons(RR_TYPE_NS);
    ret->res_info.dclass = htons(RR_CLASS_IN);
    ret->res_info.ttl = htonl(ttl);
    ret->res_info.len = htons(dns_encode(ret->res_info.data, 128, res_name));

    return ret;
}

/* Allocate a new DNS answer of CNAME type. */
struct dns_answer* new_dns_answer_cname(char* domain_name, char* res_name, uint32_t ttl) {
    struct dns_answer* ret = (struct dns_answer*)alloc_memory(sizeof(struct dns_answer) + 128);
    
    ret->res_name = (uint8_t*)alloc_memory(128);
    ret->res_name_len = dns_encode(ret->res_name, 128, domain_name);

    ret->res_info.type = htons(RR_TYPE_CNAME);
    ret->res_info.dclass = htons(RR_CLASS_IN);
    ret->res_info.ttl = htonl(ttl);
    ret->res_info.len = htons(dns_encode(ret->res_info.data, 128, res_name));

    return ret;
}

/* Release a DNS answer. */
void free_dns_answer(struct dns_answer* answer) {
    free(answer->res_name);
    free(answer);
}

/* Get a new TX ID. */
uint16_t get_tx_id() {
    pthread_mutex_lock(&g_txid_count_mutex);
    g_txid_counter++;
    pthread_mutex_unlock(&g_txid_count_mutex);
    return g_txid_counter;
}

/* Parse DNS packet and get request domain name. */
int parse_dns_req_domain(char* outbuf, size_t outbuf_len, struct dnshdr* dnsh, size_t dnspkt_len) {
    uint8_t* name_ptr = (uint8_t*)dnsh + sizeof(struct dnshdr);
    return dns_decode(outbuf, outbuf_len, name_ptr, dnspkt_len - sizeof(struct dnshdr));
}

/* Make a UDP payload of DNS. */
size_t make_dns_packet(uint8_t* buff, size_t buff_len, int is_resp, uint16_t tx_id,
        struct dns_query* queries[], uint16_t query_count, struct dns_answer* answers[], uint16_t answer_count,
        struct dns_answer* authories[], uint16_t authori_count, int edns0) {
    // Check memory.
    if (buff_len < sizeof(struct dnshdr)) {
#ifdef _DEBUG
        printf("make_dns_packet: buff_len is not enough.\n");
#endif
        abort();
    }
    
    // DNS header.
    struct dnshdr* dnsh = (struct dnshdr*)buff;
    dnsh->id = htons(tx_id);
    if (is_resp) {
        if (authori_count != 0)
            dnsh->flags = htons(0x8410); // Authoritive Response.
        else
            dnsh->flags = htons(0x8180); // Normal Response.
    } else
        dnsh->flags = htons(0x0100); // Query.
    dnsh->qdcount = htons(query_count);
    dnsh->ancount = htons(answer_count);
    dnsh->nscount = htons(authori_count);
    int i;

    // Queries.
    uint8_t* tmp_ptr = buff + sizeof(struct dnshdr);
    for (i = 0; i < query_count; i++) {
        // Memory check.
        if (tmp_ptr + queries[i]->query_name_len + sizeof(struct q_info) > buff + buff_len) {
#ifdef _DEBUG
            printf("make_dns_packet: Length of buff is not enough.\n");
#endif
            abort();
        }

        memcpy(tmp_ptr, queries[i]->query_name, queries[i]->query_name_len);
        memcpy(tmp_ptr + queries[i]->query_name_len, &queries[i]->query_info, sizeof(struct q_info));
        tmp_ptr += queries[i]->query_name_len + sizeof(struct q_info);
    }

    // Answers.
    for (i = 0; i < answer_count; i++) {
        // Memory check.
        if (tmp_ptr + answers[i]->res_name_len + sizeof(struct r_info) + ntohs(answers[i]->res_info.len) > buff + buff_len) {
#ifdef _DEBUG
            printf("make_dns_packet: Length of buff is not enough.\n");
#endif
            abort();
        }

        memcpy(tmp_ptr, answers[i]->res_name, answers[i]->res_name_len);
        memcpy(tmp_ptr + answers[i]->res_name_len, &answers[i]->res_info, sizeof(struct r_info) + ntohs(answers[i]->res_info.len));
        tmp_ptr += answers[i]->res_name_len + sizeof(struct r_info) + ntohs(answers[i]->res_info.len);
    }

    // Autoritives.
    for (i = 0; i < authori_count; i++) {
        // Memory check.
        if (tmp_ptr + authories[i]->res_name_len + sizeof(struct r_info) + ntohs(authories[i]->res_info.len) > buff + buff_len) {
#ifdef _DEBUG
            printf("make_dns_packet: Length of buff is not enough.\n");
#endif
            abort();
        }

        memcpy(tmp_ptr, authories[i]->res_name, authories[i]->res_name_len);
        memcpy(tmp_ptr + authories[i]->res_name_len, &authories[i]->res_info, sizeof(struct r_info) + ntohs(authories[i]->res_info.len));
        tmp_ptr += authories[i]->res_name_len + sizeof(struct r_info) + ntohs(authories[i]->res_info.len);
    }

    // Addtional.
    if (edns0) {
        dnsh->arcount = htons(1);
        memcpy(tmp_ptr, "\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00", 11);
        tmp_ptr += 11;
    }

    return tmp_ptr - buff;
}

/* Send a normal DNS request. */
void send_dns_req(int sockfd, char* dst_ip, uint16_t dst_port, struct dns_query* queries[],
        size_t query_count) {
    uint8_t* packet = (uint8_t*)alloc_memory(DNS_PKT_MAX_LEN);
    size_t packet_len = make_dns_packet(packet, DNS_PKT_MAX_LEN, FALSE, get_tx_id(), queries, query_count, NULL, 0, NULL, 0, FALSE);
    
    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(dst_port),
        .sin_addr.s_addr = inet_addr(dst_ip),
    };
    memset(dest_addr.sin_zero, '\x00', sizeof(dest_addr.sin_zero));

    ssize_t sent = sendto(sockfd, packet, packet_len, 0, (struct sockaddr*)&dest_addr, sizeof(struct sockaddr_in));
    if (sent < 0) {
#ifdef _DEBUG
        perror("send_dns_req");
#endif
        abort();
    }

    free(packet);
}

/* Send a spoofed DNS response. */
static void send_dns_resp_spoof(int sockfd, char* src_ip, char* dst_ip, uint16_t src_port,
        uint16_t dst_port, uint16_t tx_id, struct dns_query* query[], size_t query_count,
        struct dns_answer* answers[], size_t answer_count) {
    uint8_t* packet = (uint8_t*)alloc_memory(DNS_PKT_MAX_LEN);
    size_t packet_len = make_dns_packet(packet, DNS_PKT_MAX_LEN, TRUE, tx_id, query,
                                        query_count, answers, answer_count, NULL, 0, FALSE);

    // Make UDP RAW packet.
    uint8_t* packet_raw = (uint8_t*)alloc_memory(DNS_PKT_MAX_LEN);
    size_t packet_raw_len = make_udp_packet(packet_raw, DNS_PKT_MAX_LEN, inet_addr(src_ip), inet_addr(dst_ip),
                                            src_port, dst_port, packet, packet_len);

    // Send RAW packet.
    send_udp_packet(sockfd, packet_raw, packet_raw_len, inet_addr(src_ip), inet_addr(dst_ip),
                    src_port, dst_port);

    free(packet_raw);
    free(packet);
}

/* Send a normal DNS query and get response. */
enum DNS_RESP_STAT send_dns_query(char* server_ip, char* domain, unsigned int timeout) {
    enum DNS_RESP_STAT ret;
    int sockfd_udp = make_sockfd_for_dns(timeout);

    // Send DNS query to given server.
    struct dns_query* query[1];
    query[0] = new_dns_query_a(domain);
    send_dns_req(sockfd_udp, server_ip, 53, query, 1);
    free_dns_query(query[0]);

    // Get DNS response.
    uint8_t* buff = (uint8_t*)alloc_memory(DNS_PKT_MAX_LEN);
    struct dnshdr* dnsh = (struct dnshdr*)buff;
    ssize_t len = recvfrom(sockfd_udp, buff, 512, 0, NULL, NULL);
    if (len < 0)
        ret = DNS_R_TIMEOUT;
    else if (dnsh->flags == htons(0x8182))
        ret = DNS_R_SERVFAIL;
    else
        ret = DNS_R_NORMAL;

    free(buff);
    close(sockfd_udp);

    return ret;
}
