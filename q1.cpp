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

const int maximumPackets = 100;

int packetCount = 0;
void packetHandler(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    struct ether_header *eptr;
    eptr = (struct ether_header *)packet;
    int ether_type = ntohs(eptr->ether_type);
    if(ether_type == ETHERTYPE_IP) {
        struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ether_header));
        int protocol = iph->protocol;
        if (protocol == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            printf("Source port: %d\n", ntohs(udph->source));
            printf("Destination port: %d\n", ntohs(udph->dest));
            if(ntohs(udph->dest) == 67) printf("DHCP packet\n");
        }
        if(protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            printf("Source port: %d\n", ntohs(tcph->source));
            printf("Destination port: %d\n", ntohs(tcph->dest));
            printf("TCP packet\n");
        }
        else if(protocol == IPPROTO_ICMP) {
            printf("ICMP packet\n");
        }
        struct in_addr src, dest;
        src.s_addr = iph->saddr;
        dest.s_addr = iph->daddr;
        printf("source ip : %s\n", inet_ntoa(src));
        printf("destination ip : %s\n", inet_ntoa(dest));
    }
    packetCount++;
    printf("Packet No.: %d\n", packetCount);
    printf("Packet Length: %d\n\n", pkthdr->len);
    printf("Source: %s\n", ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
    printf("Destination: %s\n", ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));
    printf("Recieved time: %s\n", ctime((const time_t *)&pkthdr->ts.tv_sec));
    fflush(stdout);
}

int main(int argc, char **argv)
{
    char errorbuffer[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    pcap_t *descr;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr; 
    char *dev;
    dev = pcap_lookupdev(errorbuffer);
    if(dev == NULL){
        printf("%s\n", errorbuffer);
        exit(1);
    }
    printf("\nInterface: %s\n", dev);
    printf("Capturing %d packets\n", maximumPackets);
    descr = pcap_open_live(dev, BUFSIZ, 0, -1, errorbuffer);
    if(descr == NULL){
        printf("pcap_open_live(): %s\n", errorbuffer);
        exit(1);
    }
    pcap_loop(descr, maximumPackets, packetHandler, NULL);
    return 0;
}
