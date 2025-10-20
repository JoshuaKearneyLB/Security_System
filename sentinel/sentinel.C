#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

void process_packet(const u_char *packet, struct pcap_pkthdr header, FILE *log)
{
    /* Ethernet header = 14 bytes, then IPv4 header starts */
    if (header.caplen < 34) return;            /* not enough data for Ethernet + IP */

    uint16_t ethertype = (packet[12] << 8) | packet[13];
    if (ethertype != 0x0800) {
        //Skipping non 0x0800 or IPv4 packets.
       return;  
    }         

    const u_char *ip_header = packet + 14;
    struct in_addr src, dst;
    memcpy(&src, ip_header + 12, 4);
    memcpy(&dst, ip_header + 16, 4);

    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &dst, dst_str, sizeof(dst_str));

    /* log with timestamp */
    fprintf(log, "[%ld] SRC=%s  DST=%s  LEN=%d\n",
            header.ts.tv_sec, src_str, dst_str, header.len);
    fflush(log);
}

int main(){
    
    char errbuf[PCAP_ERRBUF_SIZE];

    //Open network interface
    pcap_t *handle = pcap_open_live("eth0", 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live() failed %s\n", errbuf);
        return 1;
    }

    FILE *log = fopen("packets.log", "a");
    if(log == NULL){
        perror("fopen");
        pcap_close(handle);
        return 1;
    }

    printf("Listening on eth0");

    while(1){
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);
        if(packet != NULL){
            process_packet(packet, header, log);
        }
    }

    fclose(log);
    pcap_close(handle);
    return 0;

}
