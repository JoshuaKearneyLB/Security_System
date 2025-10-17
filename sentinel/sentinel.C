#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

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





    printf("Listening on etho0");

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
