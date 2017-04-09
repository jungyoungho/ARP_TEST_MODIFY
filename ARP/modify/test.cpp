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
void my_mac(u_int8_t a[]);//

void make_t_mac(const u_char *packet);//


int main(int argc, char *argv[])
{
    
    if(argc != 5) //fix 4!!
    {
        printf("you must enter 4 parameter!!\n ");
        printf(" <dev> <sender ip> <target ip> \n");
        return 0;
    }
    char *dev=argv[1];
    //make request
    /* auto check idea -> auto check success but string..
    FILE *mymac;
    char buff[1024];
    mymac = popen("ifconfig -a | grep ether | awk '{print $2}'","r"); //command check my mac
    if(NULL==mymac)
    {
        printf("error\n");
        return -1;
    }
    while(fgets(buff,1024,mymac))
        printf("%s",buff); // no string............-> change :(

    pclose(mymac);

*/
    Mac des_mac;
    des_mac="ff:ff:ff:ff:ff:ff";

    Mac sor_mac; //auto check..         <-fix
    sor_mac=argv[4];//                  <-fix

    uint16_t etype = htons(0x0806);

    struct makearphdr rq;

    rq.ar_hrd = htons(0x0001);
    rq.ar_pro = htons(0x0800);
    rq.ar_hln = 0x06;
    rq.ar_pln = 0x04;
    rq.ar_op  = htons(0x0001);
    
    
    Mac arpsm;//auto check..    <-fix
    arpsm=argv[4];//            <-fix
    char *seip=argv[2];
    uint32_t asip;
    inet_pton(AF_INET, seip, &asip);
    
    Mac arptm;
    arptm = "ff:ff:ff:ff:ff:ff";//broadcast

    char *taip=argv[3];
    uint32_t atip;
    inet_pton(AF_INET, taip, &atip);

    uint8_t rq_packet[42]; //make complete packet

    memset(rq_packet,0,42);
    
    memcpy(rq_packet,&des_mac,6);
    memcpy(rq_packet+6,&sor_mac,6);
    memcpy(rq_packet+12,&etype,2);
    memcpy(rq_packet+14,&rq.ar_hrd,2);
    memcpy(rq_packet+16,&rq.ar_pro,2);
    memcpy(rq_packet+18,&rq.ar_hln,1);
    memcpy(rq_packet+19,&rq.ar_pln,1);
    memcpy(rq_packet+20,&rq.ar_op,2);
    memcpy(rq_packet+22,&arpsm,6);
    memcpy(rq_packet+28,&asip,4);
    memcpy(rq_packet+32,&arptm,6);
    memcpy(rq_packet+38,&atip,4);



    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    //---------------------------------------------------------------------------------------send arp
    fp=pcap_open_live(dev,BUFSIZ,0,1,errbuf);
    if(fp==NULL)
    {
        printf("%s\n",errbuf);
        return 0;
    }
    if(pcap_sendpacket(fp,(u_char*)rq_packet,42) != 0)
    {
        fprintf(stderr,"\n Error sending the packet:\n",pcap_geterr(fp));
    }
  /*  ////////////////////////////////////////////////////////////////////*/ -->get reply info -> target mac
    const u_char *pkt_data;
    struct pcap_pkthdr *header;

    int res;
    while((res=pcap_next_ex(fp, &header, &pkt_data))>=0)
    {
        if(res==1)
        {
           make_t_mac(pkt_data); // get reply data -> target mac   //---------------modify test
        }
        break;
    }
/*/////////////////////////////////////////////////////////////////////////////////////////////////////////////////*/reply
 /*
//--------------------------------------------------------------------------------------ethernet protocol
        Mac sm;//,tm;//--
        //
        //uint8_t tm;
        sm=argv[4];

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

        //arp_tm = argv[5];
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

*/
}

void make_t_mac(const u_char *packet)
{
    struct ether_header *ep = (struct ether_header *)packet;
    my_mac(ep->ether_shost);//------modify test
}

void my_mac(u_int8_t a[]) //del later
{
    uint8_t t_m[6];
    for (int i = 0; i < 6; i++)
    {
        t_m[i]=a[i];
        printf("%02x",t_m[i]);
    }
    printf("\n");
}
