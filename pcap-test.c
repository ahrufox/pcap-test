#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_mac(uint8_t *m){
    printf("%02x:%02x:%02x:%02x:%02x:%02x",m[0],m[1],m[2],m[3],m[4],m[5]);
}

void print_payload(const u_char *payload, int len){
    int i;
    for(i = 0; i < len; i++){
        printf("%02x ", *(payload + i));
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct libnet_ethernet_hdr *eth_hdr =(struct libnet_ethernet_hdr *)packet;
        struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *)(packet + SIZE_ETHERNET);
        struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(packet + SIZE_ETHERNET + (ip_hdr->ip_hl << 2));
        const u_char *payload = (u_char *)(packet + SIZE_ETHERNET + (ip_hdr->ip_hl << 2) + (tcp_hdr->th_off << 2));

        if(ntohs(eth_hdr->ether_type) != ETHERTYPE_IP || ip_hdr->ip_p != IPPROTO_TCP){
            continue;
        }

        printf("Type\tMAC\tIP\tPort\n");
        printf("src\t");
        print_mac(eth_hdr->ether_dhost);
        printf("\t");
        printf("%s\t", inet_ntoa(ip_hdr->ip_src));
        printf("%d\n", ntohs(tcp_hdr->th_sport));

        printf("dst\t");
        print_mac(eth_hdr->ether_shost);
        printf("\t");
        printf("%s\t", inet_ntoa(ip_hdr->ip_dst));
        printf("%d\n", ntohs(tcp_hdr->th_dport));

        printf("Payload: ");
        print_payload(payload, 10);
        printf("\n");
    }
    pcap_close(pcap);
}

