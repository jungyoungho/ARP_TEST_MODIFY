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

struct makearphdr
{
    uint8_t ar_hrd;
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
        uint8_t sender_mac[6];
        sscanf(argv[4],"%x:%x:%x:%x:%x:%x",&sender_mac[0],&sender_mac[1],&sender_mac[2],&sender_mac[3],&sender_mac[4],&sender_mac[5]);

        uint8_t target_mac[6];
        sscanf(argv[5],"%x:%x:%x:%x:%x:%x",&target_mac[0],&target_mac[1],&target_mac[2],&target_mac[3],&target_mac[4],&target_mac[5]);

        u_int16_t ether_type=0x0806;
//---------------------------------------------------------------------------------------arp protocol
        struct makearphdr ap;

        ap.ar_hrd = 0x0001;
        ap.ar_pro = 0x0800;
        ap.ar_hln = 0x06;
        ap.ar_pln = 0x04;
        ap.ar_op  = 0x0002;

        uint8_t arp_smac[6]; // my mac argv[4] =sender_mac

        sscanf(argv[4],"%x:%x:%x:%x:%x:%x",&arp_smac[0],&arp_smac[1],&arp_smac[2],&arp_smac[3],&arp_smac[4],&arp_smac[5]);


        char *arp_sip = argv[2];
        u_int32_t s_ip;
        inet_pton(AF_INET, arp_sip, &s_ip);
        unsigned long sendip;
        sendip=htonl(s_ip);

        uint8_t arp_tmac[6]; // hanbin mac argv[5] = target_mac
        sscanf(argv[5],"%x:%x:%x:%x:%x:%x",&arp_tmac[0],&arp_tmac[1],&arp_tmac[2],&arp_tmac[3],&arp_tmac[4],&arp_tmac[5]);


        char *arp_tip = argv[3];
        u_int32_t t_ip;
        inet_pton(AF_INET, arp_tip, &t_ip);
        unsigned long targip;
        targip=htonl(t_ip);

        char packet[]={0}; //make complete packet

        sprintf(packet, "%02x%02x%02x%02x%02x%02x/%02x%02x%02x%02x%02x%02x/%04x//%04x/%04x/%02x/%02x/%04x//%02x%02x%02x%02x%02x%02x/%x/%02x%02x%02x%02x%02x%02x/%x",
               *target_mac,*(target_mac+1),*(target_mac+2),*(target_mac+3),*(target_mac+4),*(target_mac+5),
               *sender_mac,*(sender_mac+1),*(sender_mac+2),*(sender_mac+3),*(sender_mac+4),*(sender_mac+5),
               ether_type,ap.ar_hrd,ap.ar_pro,ap.ar_hln,ap.ar_pln,ap.ar_op,
               *arp_smac,*(arp_smac+1),*(arp_smac+2),*(arp_smac+3),*(arp_smac+4),*(arp_smac+5),sendip,
               *arp_tmac,*(arp_tmac+1),*(arp_tmac+2),*(arp_tmac+3),*(arp_tmac+4),*(arp_tmac+5),targip);


        puts(packet);

        int length = sizeof(packet);
        pcap_t *fp;
        if(pcap_sendpacket(fp,(u_char*)packet,100) != 0)
        {
            fprintf(stderr,"\n Error sending the packet:\n",pcap_geterr(fp));
        }


}


