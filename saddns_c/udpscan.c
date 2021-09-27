/*
    Stand alone UDP private port scanner.
*/

#include "network.h"
#include "dns.h"
#include "scanner.h"
#include "common.h"

/* Commence scan. */
void scan_udp(char* target_ip, char* spoof_ip, uint16_t start_port, uint16_t end_port,
        unsigned int icmp_limit, int verbos) {
    int stop_flag = FALSE;
    void scan_init();
    scan_set_ignore_dns_port(FALSE);
    scan(spoof_ip, target_ip, start_port, end_port, icmp_limit, verbos, &stop_flag);
}

int main(int argc, char** argv) {
    int ch;
    char* target_ip = NULL;
    char* spoof_ip = NULL;
    char* start_port = "0";
    char* end_port = "65535";
    char* icmp_limit = "50";
    int verbos = FALSE;

    while ((ch = getopt(argc, argv, "t:u:s:e:l:v")) != -1) {
        switch (ch) {
        case 't':
            target_ip = optarg;
            break;
        case 'u':
            spoof_ip = optarg;
            break;
        case 's':
            start_port = optarg;
            break;
        case 'e':
            end_port = optarg;
            break;
        case 'l':
            icmp_limit = optarg;
            break;
        case 'v':
            verbos = TRUE;
            break;
        default:
            printf("Unknown arg\n");
            return 1;
        }
    }

    if (target_ip == NULL || spoof_ip == NULL) {
        printf("Usage:\n");
        printf("./udpscan -t <target_ip> -u <spoof_ip> [-s start_port] [-e end_port] [-l icmp_limit] [-v]\n");
        return 1;
    }

    printf("[ * ] Start.\n");
    scan_udp(target_ip, spoof_ip, atoi(start_port), atoi(end_port), atoi(icmp_limit), verbos);
    printf("[ * ] Finished.\n");

    return 0;
}
