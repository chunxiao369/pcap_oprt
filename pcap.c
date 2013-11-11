
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <termios.h>

#include <arpa/inet.h>

#include "pcap.h"

pcap_info_t *
pktgen_pcap_open(char * filename)
{
	FILE		  * fd = 0;
	size_t			len;
	pcap_info_t	  * pcap = NULL;
	
	if ( filename == NULL ) {
		printf("pktgen_pcap_open: filename is NULL\n");
		goto leave;
	}
	
	pcap = (pcap_info_t *)malloc(sizeof(pcap_info_t));
	if ( pcap == NULL ) {
		printf("pktgen_pcap_open: malloc failed for pcap_info_t structure\n");
		goto leave;
	}
	
	fd = fopen((const char *)filename, "r");
	if ( fd == NULL )
		goto leave;
	
	pcap->fd = fd;
	len = fread(&pcap->info, 1, sizeof(pcap_hdr_t), fd);
	if ( len != sizeof(pcap_hdr_t) ) {
		printf("pktgen_pcap_open: failed to read the file header\n");
		goto leave;
	}
	
	if ( pcap->info.magic_number != PCAP_MAGIC_NUMBER ) {
		printf("pktgen_pcap_open: Magic Number does not match!\n");
		goto leave;
	}
	pcap->filename = strdup(filename);
	
	return pcap;
	
leave:
	if ( fd )
		fclose(fd);
	if ( pcap )
		free(pcap);
	return NULL;
}

void
pktgen_pcap_info(pcap_info_t * pcap)
{
	printf("pcap file      : %s\n", pcap->filename);
	printf("  magic        : %08x\n", pcap->info.magic_number);
	printf("  Version      : %d.%d\n", pcap->info.version_major, pcap->info.version_minor);
	printf("  Zone         : %d\n", pcap->info.thiszone);
	printf("  snaplen      : %d\n", pcap->info.snaplen);
	printf("  sigfigs      : %d\n", pcap->info.sigfigs);
	printf("  network      : %d\n", pcap->info.network);
}

void
pktgen_pcap_rewind(pcap_info_t * pcap)
{
	if ( pcap == NULL )
		return;

	// Rewind to the beginning
	rewind(pcap->fd);

	// Seek past the pcap header
	(void)fseek(pcap->fd, sizeof(pcap_hdr_t), SEEK_SET);
}

void
pktgen_pcap_close(pcap_info_t * pcap)
{
	if ( pcap == NULL )
		return;
	if ( pcap->fd )
		fclose(pcap->fd);
	if ( pcap->filename )
		free(pcap->filename);
	free(pcap);
}

void print_content(uint8_t * ptr, int length)
{
    int i;
    for (i = 0; i < length; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", ptr[i]);
    }
    printf("\n");
}

size_t
pktgen_pcap_read(pcap_info_t * pcap, pcaprec_hdr_t * pHdr, char * pktBuff, uint32_t bufLen, int print)
{
    char buff[1024];
	size_t			len;
	
	len = fread(pHdr, 1, sizeof(pcaprec_hdr_t), pcap->fd);
	if ( len != sizeof(pcaprec_hdr_t) )
		return 0;
	
	if ( bufLen < pHdr->incl_len )
		return 0;
	
	len = fread(pktBuff, 1, pHdr->incl_len, pcap->fd);
    if (print) {
        len = fread(buff, 1, 1024, pcap->fd);
        print_content((uint8_t *)buff, 1024);
    }
	
	return len;
}

