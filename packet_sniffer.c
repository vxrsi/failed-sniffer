#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define BUFFER_SIZE 65536

void print_ethernet_header(unsigned char *buffer, int size) {
    struct ethhdr *eth = (struct ethhdr *)buffer;

    printf("\n");
    printf("Ethernet Header\n");
    printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("   |-Protocol            : %u \n", (unsigned short)eth->h_proto);
}

void print_ip_header(unsigned char *buffer, int size) {
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct sockaddr_in source, dest;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    printf("\n");
    printf("IP Header\n");
    printf("   |-IP Version        : %d\n", (unsigned int)iph->version);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",
           (unsigned int)iph->ihl, ((unsigned int)(iph->ihl)) * 4);
    printf("   |-Type Of Service   : %d\n", (unsigned int)iph->tos);
    printf("   |-IP Total Length   : %d Bytes\n", ntohs(iph->tot_len));
    printf("   |-Identification    : %d\n", ntohs(iph->id));
    printf("   |-TTL               : %d\n", (unsigned int)iph->ttl);
    printf("   |-Protocol          : %d\n", (unsigned int)iph->protocol);
    printf("   |-Checksum          : %d\n", ntohs(iph->check));
    printf("   |-Source IP         : %s\n", inet_ntoa(source.sin_addr));
    printf("   |-Destination IP    : %s\n", inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char *buffer, int size) {
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));

    printf("\n");
    printf("TCP Header\n");
    printf("   |-Source Port      : %u\n", ntohs(tcph->source));
    printf("   |-Destination Port : %u\n", ntohs(tcph->dest));
    printf("   |-Sequence Number  : %u\n", ntohl(tcph->seq));
    printf("   |-Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
    printf("   |-Header Length    : %d DWORDS or %d BYTES\n",
           (unsigned int)tcph->doff, (unsigned int)tcph->doff * 4);
    printf("   |-Flags:\n");
    printf("      |-URG: %d\n", (unsigned int)tcph->urg);
    printf("      |-ACK: %d\n", (unsigned int)tcph->ack);
    printf("      |-PSH: %d\n", (unsigned int)tcph->psh);
    printf("      |-RST: %d\n", (unsigned int)tcph->rst);
    printf("      |-SYN: %d\n", (unsigned int)tcph->syn);
    printf("      |-FIN: %d\n", (unsigned int)tcph->fin);
    printf("   |-Window           : %d\n", ntohs(tcph->window));
    printf("   |-Checksum         : %d\n", ntohs(tcph->check));
    printf("   |-Urgent Pointer   : %d\n", tcph->urg_ptr);
}

void print_udp_packet(unsigned char *buffer, int size) {
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct udphdr *udph = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));

    printf("\n");
    printf("UDP Header\n");
    printf("   |-Source Port      : %d\n", ntohs(udph->source));
    printf("   |-Destination Port : %d\n", ntohs(udph->dest));
    printf("   |-UDP Length       : %d\n", ntohs(udph->len));
    printf("   |-UDP Checksum     : %d\n", ntohs(udph->check));
}

void print_icmp_packet(unsigned char *buffer, int size) {
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));

    printf("\n");
    printf("ICMP Header\n");
    printf("   |-Type : %d", (unsigned int)(icmph->type));
    if ((unsigned int)(icmph->type) == 11) {
        printf("  (TTL Expired)\n");
    } else if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY) {
        printf("  (ICMP Echo Reply)\n");
    }
    printf("   |-Code : %d\n", (unsigned int)(icmph->code));
    printf("   |-Checksum : %d\n", ntohs(icmph->checksum));
}

void process_packet(unsigned char *buffer, int size) {
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    printf("\n========================================");
    printf("\nPacket Captured (Size: %d bytes)", size);
    printf("\n========================================");

    print_ethernet_header(buffer, size);

    switch (iph->protocol) {
        case 6:  // TCP
            print_ip_header(buffer, size);
            print_tcp_packet(buffer, size);
            break;

        case 17: // UDP
            print_ip_header(buffer, size);
            print_udp_packet(buffer, size);
            break;

        case 1:  // ICMP
            print_ip_header(buffer, size);
            print_icmp_packet(buffer, size);
            break;

        default:
            print_ip_header(buffer, size);
            break;
    }

    printf("\n");
}

int main() {
    int sock_raw;
    int saddr_size, data_size;
    struct sockaddr saddr;
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);

    printf("Starting Packet Sniffer...\n");
    printf("Note: This requires root/sudo privileges\n\n");

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket Error");
        printf("\nError: Could not create socket. Make sure to run with sudo.\n");
        return 1;
    }

    printf("Packet sniffer started. Capturing packets...\n");
    printf("Press Ctrl+C to stop.\n\n");

    while (1) {
        saddr_size = sizeof(saddr);
        data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, (socklen_t *)&saddr_size);

        if (data_size < 0) {
            perror("Recvfrom error");
            break;
        }

        process_packet(buffer, data_size);
    }

    close(sock_raw);
    free(buffer);

    return 0;
}
