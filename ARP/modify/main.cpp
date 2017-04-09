#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <netinet/if_ether.h>
#include "mac.h"

struct makearphdr
{
    uint16_t ar_hrd;
    uint16_t ar_pro;
    uint8_t ar_hln;
    uint8_t ar_pln;
    uint16_t ar_op;
};

int main(int argc, char *argv[])
{

        if(argc != 6)
        {
            printf("you must enter 6 parameter!!\n ");
            printf(" <dev> <sender ip> <target ip> <sender mac> <target mac>\n");
            return 0;
        }
        char *dev=argv[1];
//--------------------------------------------------------------------------------------ethernet protocol
        Mac sm,tm;
        tm=argv[4];
        sm=argv[5];
       
        u_int16_t ether_type=htons(0x0806);
//---------------------------------------------------------------------------------------arp protocol
        struct makearphdr ap;

        ap.ar_hrd = htons(0x0001);
        ap.ar_pro = htons(0x0800);
        ap.ar_hln = 0x06;
        ap.ar_pln = 0x04;
        ap.ar_op  = htons(0x0002);
        Mac arp_sm,arp_tm;


        arp_sm = argv[4];
        char *arp_sip = argv[2];
        u_int32_t s_ip;
        inet_pton(AF_INET, arp_sip, &s_ip);

        arp_tm = argv[5];
        char *arp_tip = argv[3];
        u_int32_t t_ip;
        inet_pton(AF_INET, arp_tip, &t_ip);


        uint8_t packet[42]; //make complete packet

        memset(packet,0,42);
        memcpy(packet,&tm,6);
        memcpy(packet+6,&sm,6);
        memcpy(packet+12,&ether_type,2);
        memcpy(packet+14,&ap.ar_hrd,2);
        memcpy(packet+16,&ap.ar_pro,2);
        memcpy(packet+18,&ap.ar_hln,1);
        memcpy(packet+19,&ap.ar_pln,1);
        memcpy(packet+20,&ap.ar_op,2);
        memcpy(packet+22,&arp_sm,6);
        memcpy(packet+28,&s_ip,4);
        memcpy(packet+32,&arp_tm,6);
        memcpy(packet+38,&t_ip,4);
    
        pcap_t *fp;
        char errbuf[PCAP_ERRBUF_SIZE];
        //---------------------------------------------------------------------------------------send arp
        fp=pcap_open_live(dev,BUFSIZ,0,1,errbuf);
        if(fp==NULL)
        {
            printf("%s\n",errbuf);
            return 0;
        }
        if(pcap_sendpacket(fp,(u_char*)packet,42) != 0)
        {
            fprintf(stderr,"\n Error sending the packet:\n",pcap_geterr(fp));
        }


}


