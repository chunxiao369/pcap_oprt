#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <memory.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>
#include <semaphore.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "pcap.h"

void show_help(char *str)
{
    printf("%s pcap_file num\n", str);
    printf("\n");
}

char *file = NULL;
int packet_num = 0;
int main(argc, argv)
    int argc;
    char *argv[];
{
    int i = 0;
	char  pcap_error[256] = {0} ;
	struct pcap_pkthdr hdr;
	pcap_t  *p = NULL ;
    const unsigned char *pkt;

    if (argc >= 2) {
        if (strcmp(argv[1], "help") == 0 ||
            strcmp(argv[1], "--help") == 0 ||
            strcmp(argv[1], "-h") == 0) {
            show_help(argv[0]);
            return 0;
        }
        if (argc < 3) {
            show_help(argv[0]);
            return 0;
        }
        packet_num = atoi(argv[2]);
        file = argv[1];
    }

    p = pcap_open_offline(file, pcap_error);

	if(NULL == p) {
		printf("pcap open error! ... %s\r\n",pcap_error) ;
		return -1;
	}
    //printf("cxxu len : %d.\n", __LINE__);
    i = 0;
	while(1) {
		pkt = pcap_next(p,&hdr);
		if (NULL == pkt) {
			break;
        } else {
            if (i == packet_num) {
                printf(" packet len : %d.\n", hdr.caplen);
                break;
            }
        }
        i++;
    }
    printf("cxxu packet num is : %d.\n", i);
    pcap_close(p);
    return 0;
}
