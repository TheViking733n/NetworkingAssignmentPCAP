#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <netinet/ether.h>
#include <string.h>

const int maximumPackets = 225;

int packetCount = 0;
char PROTOCOL_TYPE[16];
int filteredPacketCount = 0;

void packetHandler(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    struct ether_header *eptr;
    eptr = (struct ether_header *)packet;
    int ether_type = ntohs(eptr->ether_type);
    int flag = false;
    if(ether_type == ETHERTYPE_IP){
        struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ether_header));
        int protocol = iph->protocol;
        if(protocol == IPPROTO_UDP){
            struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            if (ntohs(udph->dest) == 67){
                // Check the Protocol type
                if(strcmp(PROTOCOL_TYPE, "DHCP") == 0){
                    flag = true;
                    filteredPacketCount++;
                }
                else return;
                printf("DHCP packet received\n");
            }
            if (flag) {
                printf("Source port: %d\n", ntohs(udph->source));
                printf("Destination port: %d\n", ntohs(udph->dest));
            }
        }
        else if(protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            if (strcmp(PROTOCOL_TYPE, "TCP") == 0) {
                flag = true;
                filteredPacketCount++;
            } else {
                return;
            }
            printf("TCP packet received\n");
            printf("Source port: %d\n", ntohs(tcph->source));
            printf("Destination port: %d\n", ntohs(tcph->dest));
        }
        else if(protocol == IPPROTO_ICMP){
            if (strcmp(PROTOCOL_TYPE, "ICMP") == 0) {
                flag = true;
                filteredPacketCount++;
            } else return;
            printf("ICMP packet received\n");
        }
        if (!flag) return;
        struct in_addr src, dest;
        src.s_addr = iph->saddr;
        dest.s_addr = iph->daddr;
        printf("Source ip: %s\n", inet_ntoa(src));
        printf("Destination ip: %s\n", inet_ntoa(dest));
    }

    
    if (!flag) return;


    // Print packet information
    printf("Packet No.: %d\n", ++packetCount);
    printf("Packet Length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Packet type: ");
    switch (ether_type)
    {
    case ETHERTYPE_IP:
        printf("ip\n");
        break;
    case ETHERTYPE_ARP:
        printf("ARP\n");
        break;
    default:
        printf("Unknown\n");
        break;
    }

    printf("Source: %s\n", ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
    printf("Destination: %s\n", ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));
    printf("Recieved time: %s\n", ctime((const time_t *)&pkthdr->ts.tv_sec));
    fflush(stdout);
}

int main(int argc, char **argv)
{
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;    /* pcap.h */
    struct ether_header *eptr; /* net/ethernet.h */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("Enter which protocol to capture:\n");
    printf("1. DHCP\n");
    printf("2. ICMP\n");
    printf("3. TCP\n");
    printf("Enter the number: ");
    int choice;
    scanf("%d", &choice);
    if(choice == 1) strcpy(PROTOCOL_TYPE, "DHCP");
    else if(choice == 2) strcpy(PROTOCOL_TYPE, "ICMP");
    else if(choice == 3) strcpy(PROTOCOL_TYPE, "TCP");
    else{
        printf("Invalid choice\n");
        exit(0);
    }
    printf("\nInterface: %s\n", dev);
    printf("Capturing %d packets\n", maximumPackets);
    descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
    if (descr == NULL){
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }
    pcap_loop(descr, maximumPackets, packetHandler, NULL);
    printf("\nFiltered packets: %d\n", filteredPacketCount);
    return 0;
}
