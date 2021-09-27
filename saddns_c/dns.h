/*
    DNS protocol implementation.
*/

#ifndef _DNS_H_
#define _DNS_H_

#include "common.h"

#define RR_TYPE_A       1
#define RR_TYPE_NS      2
#define RR_TYPE_CNAME   5
#define RR_TYPE_SOA     6
#define RR_TYPE_PTR     12
#define RR_TYPE_MX      15
#define RR_CLASS_IN     1

#define RES_PTR         "\xc0\x0c"
#define RES_TTL         65535
#define DNS_PKT_MAX_LEN 512

/* Status of DNS response. */
enum DNS_RESP_STAT {
    DNS_R_NORMAL = 0,
    DNS_R_SERVFAIL,
    DNS_R_TIMEOUT,
};

/* DNS header. */
#pragma pack (1)
struct dnshdr {
    uint16_t id;        // TXID
    uint16_t flags;     // Flags
    uint16_t qdcount;   // Question count
    uint16_t ancount;   // Answer RR count
    uint16_t nscount;   // Authority RR count
    uint16_t arcount;   // Addtional RR count
};
#pragma pack ()

/* Information of query. */
#pragma pack (1)
struct q_info {
    uint16_t type;
    uint16_t dclass;
};
#pragma pack ()

/* Information of resource. */
#pragma pack (1)
struct r_info {
    uint16_t type;
    uint16_t dclass;
    uint32_t ttl;
    uint16_t len;
    uint8_t  data[0];
};
#pragma pack ()

/* A DNS query. */
struct dns_query {
    uint8_t*      query_name;
    size_t        query_name_len;
    struct q_info query_info;
};

/* A DNS answer. */
struct dns_answer {
    uint8_t*      res_name;
    size_t        res_name_len;
    struct r_info res_info;
};

void dns_init();

char* domain_uplevel(char* domain);

int domain_sublevel(char* outbuf, size_t outbuf_len, char* domain, char* sublevel);

int domain_is_in_zone(char* input, char* zone);

size_t dns_encode(uint8_t* out, size_t out_len, char* in);

int dns_decode(char* outbuf, size_t outbuf_len, uint8_t* indata, size_t indata_len);

struct dns_query* new_dns_query_a(char* domain_name);

struct dns_answer* new_dns_answer_a(char* domain_name, uint32_t ip_addr, uint32_t ttl);

struct dns_answer* new_dns_answer_ns(char* domain_name, char* res_name, uint32_t ttl);

struct dns_answer* new_dns_answer_cname(char* domain_name, char* res_name, uint32_t ttl);

void free_dns_query(struct dns_query* query);

void free_dns_answer(struct dns_answer* answer);

uint16_t get_tx_id();

int parse_dns_req_domain(char* outbuf, size_t outbuf_len, struct dnshdr* dnsh, size_t dnspkt_len);

size_t make_dns_packet(uint8_t* buff, size_t buff_len, int is_resp, uint16_t tx_id,
        struct dns_query* queries[], uint16_t query_count, struct dns_answer* answers[], uint16_t answer_count,
        struct dns_answer* authories[], uint16_t authori_count, int edns0);

void send_dns_req(int sockfd, char* dst_ip, uint16_t dst_port, struct dns_query* queries[],
        size_t query_count);

static void send_dns_resp_spoof(int sockfd, char* src_ip, char* dst_ip, uint16_t src_port,
        uint16_t dst_port, uint16_t tx_id, struct dns_query* query[], size_t query_count,
        struct dns_answer* answers[], size_t answer_count);

enum DNS_RESP_STAT send_dns_query(char* server_ip, char* domain, unsigned int timeout);

#endif // !_DNS_H_
