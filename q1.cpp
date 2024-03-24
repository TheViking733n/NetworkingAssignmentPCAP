#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <time.h>


#define MAX_PACKETS 20

int packetCount = 0;

void packetHandler(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    printf("Packet No.: %d\n", ++packetCount);
    printf("Packet Length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
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

    printf("DEV: %s\n", dev);
    printf("Capturing %d packets\n", MAX_PACKETS);

    // Open the device for sniffing
    descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
    if (descr == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    // Loop through packets and call packetHandler
    pcap_loop(descr, MAX_PACKETS, packetHandler, NULL);

    printf("\nDone processing packets... wheew!\n");
    return 0;
}
