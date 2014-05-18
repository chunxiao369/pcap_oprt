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
    printf("%s -c pcap_file num\n", str);
    printf("%s -n pcap_file pcap_file2\n", str);
    printf("\n");
}

char *file = NULL;
char *file2 = NULL;
int packet_num = 0;
extern uint64_t error;
pcap_info_t *p_i = NULL;
int main(argc, argv)
    int argc;
    char *argv[];
{
    uint64_t i = 0;
    char buff[2048];
	char  pcap_error[256] = {0} ;
    pcaprec_hdr_t pHdr;

    if (argc >= 2) {
        if (strcmp(argv[1], "help") == 0 ||
            strcmp(argv[1], "--help") == 0 ||
            strcmp(argv[1], "-h") == 0) {
            show_help(argv[0]);
            return 0;
        }
        if (argc < 4) {
            show_help(argv[0]);
            return 0;
        }

        if (strcmp(argv[1], "-c") == 0) {
            file = argv[2];
            packet_num = atoi(argv[3]);
        } else if (strcmp(argv[1], "-n") == 0) {
            file = argv[2];
            file2 = argv[3];
        }
    }

    p_i = pktgen_pcap_open(file);

	if(NULL == p_i) {
		printf("pcap open error! ... %s\r\n",pcap_error) ;
		return -1;
	}
    if (file2 != NULL) {
        printf("change packet num: %u.\n", pktgen_pcap_mdf0(p_i, file2));
        pktgen_pcap_close(p_i);
        return 0;
    }
    //printf("cxxu len : %d.\n", __LINE__);
    i = 0;
    if (packet_num == 0) {
        while(1) {
            i++;
            //if (pktgen_pcap_chk(p_i, &pHdr, i) == 0)
            //if (pktgen_pcap_mdf0(p_i, &pHdr, i) == 0)
            if (pktgen_pcap_mdf1(p_i, &pHdr, i) == 0)
                break;
        }
    } else {
        while(1) {
            i++;
            if (i == packet_num) {
                //pktgen_pcap_read(p_i, &pHdr, buff, 2048, 1);
                pktgen_pcap_chk(p_i, &pHdr, i);
                printf(" packet len : %d.\n", pHdr.incl_len);
                //print_content((uint8_t *)buff, pHdr.incl_len);
                break;
            } else {
                pktgen_pcap_chk(p_i, &pHdr, i);
                //pktgen_pcap_read(p_i, &pHdr, buff, 2048, 0);
            }
        }
    }
    printf("cxxu packet num is : %lu, error: %lu.\n", i, error);
    pktgen_pcap_close(p_i);
    return 0;
}
