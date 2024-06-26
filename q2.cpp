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

#define MAX_PACKETS 200

int packetCount = 0;
char PROTOCOL_NAME[16];
int filteredPacketCount = 0;

void packetHandler(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // Get the Ethernet header
    struct ether_header *eptr;
    eptr = (struct ether_header *)packet;
    int ether_type = ntohs(eptr->ether_type);

    int ok = false;

    // Check if the packet is an IP packet
    if (ether_type == ETHERTYPE_IP) {
        // Get the IP header
        struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ether_header));
        int protocol = iph->protocol;
        if (protocol == IPPROTO_UDP) {
            // Get the UDP header
            struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            if (ntohs(udph->dest) == 67) {
                if (strcmp(PROTOCOL_NAME, "DHCP") == 0) {
                    ok = true;
                    filteredPacketCount++;
                } else {
                    return;
                }
                printf("DHCP packet\n");
            }
            if (ok) {
                printf("Source port: %d\n", ntohs(udph->source));
                printf("Destination port: %d\n", ntohs(udph->dest));
            }
        }

        else if (protocol == IPPROTO_TCP) {
            // Get the TCP header
            struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            if (strcmp(PROTOCOL_NAME, "TCP") == 0) {
                ok = true;
                filteredPacketCount++;
            } else {
                return;
            }
            printf("TCP packet\n");
            printf("Source port: %d\n", ntohs(tcph->source));
            printf("Destination port: %d\n", ntohs(tcph->dest));
        }

        else if (protocol == IPPROTO_ICMP) {
            if (strcmp(PROTOCOL_NAME, "ICMP") == 0) {
                ok = true;
                filteredPacketCount++;
            } else {
                return;
            }
            printf("ICMP packet\n");
        }

        if (!ok) return;

        // Print IP addresses
        struct in_addr src, dest;
        src.s_addr = iph->saddr;
        dest.s_addr = iph->daddr;
        printf("Source IP: %s\n", inet_ntoa(src));
        printf("Destination IP: %s\n", inet_ntoa(dest));
    }

    
    if (!ok) return;


    // Print packet information
    printf("Packet No.: %d\n", ++packetCount);
    printf("Packet Length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Packet type: ");
    switch (ether_type)
    {
    case ETHERTYPE_IP:
        printf("IP\n");
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

    // Get the device to sniff on
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    printf("Enter the type of protocol to sniff:\n");
    printf("1. DHCP\n");
    printf("2. ICMP\n");
    printf("3. TCP\n");
    printf("Enter your choice: ");
    int choice;
    scanf("%d", &choice);
    switch (choice)
    {
    case 1:
        strcpy(PROTOCOL_NAME, "DHCP");
        break;
    case 2:
        strcpy(PROTOCOL_NAME, "ICMP");
        break;
    case 3:
        strcpy(PROTOCOL_NAME, "TCP");
        break;
    default:
        printf("Invalid choice\n");
        exit(1);
    }


    printf("\n\nInterface: %s\n", dev);
    printf("Capturing %d packets\n\n", MAX_PACKETS);

    // Open the device for sniffing
    descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
    if (descr == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    // Loop through packets and call packetHandler
    pcap_loop(descr, MAX_PACKETS, packetHandler, NULL);

    printf("\nFiltered packets: %d\n", filteredPacketCount);

    printf("\nDone processing packets...\n");
    return 0;
}
