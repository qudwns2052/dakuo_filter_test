#ifndef PACKET_STRUCTURE_H
#define PACKET_STRUCTURE_H

#endif // PACKET_STRUCTURE_H

#include <stdint.h>

typedef struct ethernet_header
{
    uint8_t d_mac[6];
    uint8_t s_mac[6];
    uint16_t type;
}Ethernet;

typedef struct ip_header
{
    uint8_t VHL;
    uint8_t TOS;
    uint16_t Total_LEN;
    uint16_t Id;
    uint16_t Fragment;
    uint8_t TTL;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t s_ip[4];
    uint8_t d_ip[4];
}Ip;

typedef struct tcp_header
{
    uint16_t s_port;
    uint16_t d_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t HLR;
    uint8_t flags;
    uint16_t win_size;
    uint16_t check_sum;
    uint16_t urg_pointer;
}Tcp;
