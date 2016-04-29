#ifndef TCP_PSEUDO_HDR_H
#define TCP_PSEUDO_HDR_H 1

#include <stdint.h>

/*
 * this one is copied from linux kernel.
 * in file "include/net/tcp.h"
 */
struct pseudo_tcphdr {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t pad;
        uint8_t protocol;
        uint16_t len;
};

#endif  /* tcp_pseudo_hdr.h */
