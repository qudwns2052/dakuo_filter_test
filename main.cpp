#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <strings.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include "packet_structure.h"
#include <stdint.h>

#define buffer_size 65536

using namespace std;
void print_info(Ip * ip, Tcp * tcp)
{
    printf("s_ip = %u.%u.%u.%u\n", ip->s_ip[0], ip->s_ip[1], ip->s_ip[2], ip->s_ip[3]);
    printf("d_ip = %u.%u.%u.%u\n", ip->d_ip[0], ip->d_ip[1], ip->d_ip[2], ip->d_ip[3]);
    cout << "s_port = " << htons(tcp->s_port) << endl;
    cout << "d_port = " << htons(tcp->d_port) << endl;
}
u_int16_t get_checksum(u_int16_t* buf, int nwords)
{
    u_int32_t sum;
    for(sum=0; nwords>0; nwords--) sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (u_int16_t)(~sum);
}


int main(int argc, const char* argv[])
{

    int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if ( sock_raw < 0 )
    {
        cout << "socket() error" << endl;
        return -1;
    }

    int value = 1;

    setsockopt(sock_raw, IPPROTO_IP, IP_HDRINCL, (char *)&value, sizeof(value) );


    unsigned char * buffer = (unsigned char *)malloc(sizeof(unsigned char) * buffer_size);
    int data_size;

    Ip * ip_h;
    int ip_len;
    int total_len;
    Tcp * tcp_h;
    int tcp_len;
    unsigned char * payload;
    int payload_len;
    while (true)
    {
        cout << "---------------------------------" << endl;
        if ( (data_size = recv(sock_raw, buffer, buffer_size, 0)) < 0 )
        {
            cout << "recv() failed" << endl;
            return -1;
        }
        printf("data_size = %d\n", data_size);
        ip_h = (Ip *)(buffer);
        ip_len = (ip_h->VHL & 0x0F) * 4;
        total_len = ip_h->TTL;
        tcp_h = (Tcp *)(buffer+ip_len);
        tcp_len = ((tcp_h->HLR & 0xF0) >> 4) * 4;
        payload = (buffer+ip_len+tcp_len);
        payload_len = (total_len) - (ip_len+tcp_len);
        print_info(ip_h, tcp_h);
        cout << "total_len = " << total_len << endl << "ip_len = " << ip_len << endl;
        cout << "tcp_len = "<< tcp_len << endl << "payload_len = " << payload_len << endl;
        cout << "---------------------------------" << endl << endl;


            struct iphdr * iphdr = (struct iphdr *)(buffer);
            struct sockaddr_in din;
            din.sin_family = AF_INET;
            din.sin_port = 0;
            din.sin_addr.s_addr = inet_addr("192.168.1.5");

//            iphdr.ihl = 5;
//            iphdr.version = 4;
//            iphdr.tos = 0;
//            iphdr.tot_len = htons(sizeof(struct iphdr));
//            iphdr.id = htons(rand() % 65535);
//            iphdr.frag_off = 0;
//            iphdr.ttl = 64;
            iphdr->protocol = IPPROTO_TCP;
            iphdr->saddr = inet_addr("192.168.127.133");
            iphdr->daddr = inet_addr("192.168.1.5");

            if ( sendto(sock_raw, iphdr, total_len, 0, (struct sockaddr*)&din, sizeof(din)) < 0 ) {
                perror("sendto() error");
                return -1;

            }



    }

    free(buffer);

    return 0;
}
