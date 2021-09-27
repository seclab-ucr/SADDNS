/*
    UDP private port scan implementation.
*/

#ifndef _SCANNER_H_
#define _SCANNER_H_

#include "util.h"
#include "common.h"

/* Callback type for spoof attack. */
typedef void (*scan_cb_t)(uint16_t port);

struct scan_result {
    struct link link_head;
    uint16_t port;
};

void scan_init();

struct scan_result* scan_get_result_opened();

void scan(char* spoof_ip, char* target_ip, uint16_t port_start, uint16_t port_end,
        unsigned int icmp_limit, int verbos, int* stop_flag);

void scan_set_verify_usec(signed long long verify_usec);

void scan_set_probe_src_port(uint16_t src_port);

void scan_set_verify_dst_port(uint16_t dst_port);

void scan_set_ignore_dns_port(int b);

void scan_set_scan_callback(scan_cb_t cb);

#endif // !_SCANNER_H_
