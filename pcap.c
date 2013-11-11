
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
	
	fd = fopen((const char *)filename, "r+");
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
    //char buff[1024];
	size_t			len;
	
	len = fread(pHdr, 1, sizeof(pcaprec_hdr_t), pcap->fd);
	if ( len != sizeof(pcaprec_hdr_t) )
		return 0;
	
	if ( bufLen < pHdr->incl_len )
		return 0;
	
	len = fread(pktBuff, 1, pHdr->incl_len, pcap->fd);
    /*
    if (print) {
        len = fread(buff, 1, 1024, pcap->fd);
        print_content((uint8_t *)buff, 1024);
    }
    */
	
	return len;
}

typedef struct mac {
    uint64_t dst : 48;
    uint64_t src : 48;
    uint64_t unuse : 32;
} __attribute__((packed)) mac_t ;

uint64_t error = 0ul;
size_t
pktgen_pcap_chk(pcap_info_t * pcap, pcaprec_hdr_t * pHdr, uint64_t i)
{
	size_t			len;
    mac_t m_mac;
    int length = sizeof(mac_t);
	
	len = fread(pHdr, 1, sizeof(pcaprec_hdr_t), pcap->fd);
	if ( len != sizeof(pcaprec_hdr_t))
		return 0;
	len = fread(&m_mac, 1, length, pcap->fd);
	if ( len != length)
		return 0;
    if (m_mac.dst != 0x222222020000) {
        //printf("length: %d, dst mac: 0x%012lx, src mac: 0x%012lx.\n", length, m_mac.dst, m_mac.src);
        //printf("error! %lu\n", i);
        error++;
        fseek(pcap->fd, -length, SEEK_CUR);
        len = fread(pHdr, 1, sizeof(pcaprec_hdr_t), pcap->fd);
        if ( len != length)
            return 0;
    } else {
        //len = fread(pktBuff, 1, pHdr->incl_len, pcap->fd);
        fseek(pcap->fd, -length, SEEK_CUR);
    }
    len = fseek(pcap->fd, pHdr->incl_len, SEEK_CUR);
    if ( len < 0)
        return 0;

	return pHdr->incl_len;
}

size_t pktgen_pcap_mdf0(pcap_info_t * pcap, pcaprec_hdr_t * pHdr, uint64_t i)
{
	size_t			len;
    mac_t m_mac;
    int length = sizeof(mac_t);
	
	len = fread(pHdr, 1, sizeof(pcaprec_hdr_t), pcap->fd);
	if ( len != sizeof(pcaprec_hdr_t))
		return 0;
	len = fread(&m_mac, 1, length, pcap->fd);
	if ( len != length)
		return 0;
    if (m_mac.dst != 0x222222020000) {
        //printf("length: %d, dst mac: 0x%012lx, src mac: 0x%012lx.\n", length, m_mac.dst, m_mac.src);
        //printf("error! %lu\n", i);
        error++;
        // find first pcap hdr
        fseek(pcap->fd, -length, SEEK_CUR);
        fseek(pcap->fd, -length, SEEK_CUR);
        // wirte incl_len 0 to pcap hdr
        pHdr->incl_len = 0;
        pHdr->orig_len = 0;
        fwrite(pHdr, 1, sizeof(pcaprec_hdr_t), pcap->fd);
        // read send pcap hdr
        len = fread(pHdr, 1, sizeof(pcaprec_hdr_t), pcap->fd);
        if ( len != length)
            return 0;
    } else {
        //len = fread(pktBuff, 1, pHdr->incl_len, pcap->fd);
        fseek(pcap->fd, -length, SEEK_CUR);
    }
    len = fseek(pcap->fd, pHdr->incl_len, SEEK_CUR);
    if ( len < 0)
        return 0;

	return pHdr->incl_len;
}

static uint32_t last_len = 0;
size_t pktgen_pcap_mdf1(pcap_info_t * pcap, pcaprec_hdr_t * pHdr, uint64_t i)
{
	size_t			len;
    mac_t m_mac;
    int length = sizeof(mac_t);
    long tmp;
	
	len = fread(pHdr, 1, sizeof(pcaprec_hdr_t), pcap->fd);
	if ( len != sizeof(pcaprec_hdr_t))
		return 0;
	len = fread(&m_mac, 1, length, pcap->fd);
	if ( len != length)
		return 0;
    if (m_mac.dst != 0x222222020000) {
        //printf("length: %d, dst mac: 0x%012lx, src mac: 0x%012lx.\n", length, m_mac.dst, m_mac.src);
        //printf("error! %lu\n", i);
        error++;
        // find last pcap hdr
        tmp = (long)last_len;
        fseek(pcap->fd, -length, SEEK_CUR);
        fseek(pcap->fd, -length, SEEK_CUR);
        fseek(pcap->fd, -tmp, SEEK_CUR);
        fseek(pcap->fd, -length, SEEK_CUR);
        // set  last pcap hdr + hdr_len
        fread(pHdr, 1, sizeof(pcaprec_hdr_t), pcap->fd);
        pHdr->incl_len += 16;
        pHdr->orig_len += 16;
        fseek(pcap->fd, -length, SEEK_CUR);
        fwrite(pHdr, 1, sizeof(pcaprec_hdr_t), pcap->fd);
        // find first pcap hdr
        fseek(pcap->fd, tmp, SEEK_CUR);
        pHdr->incl_len = 0;
        pHdr->orig_len = 0;
        pHdr->ts_sec   = 0; 
        pHdr->ts_usec  = 0;
        fwrite(pHdr, 1, sizeof(pcaprec_hdr_t), pcap->fd);
        // read send pcap hdr
        len = fread(pHdr, 1, sizeof(pcaprec_hdr_t), pcap->fd);
        if ( len != length)
            return 0;
    } else {
        //len = fread(pktBuff, 1, pHdr->incl_len, pcap->fd);
        fseek(pcap->fd, -length, SEEK_CUR);
    }
    len = fseek(pcap->fd, pHdr->incl_len, SEEK_CUR);
    if ( len < 0)
        return 0;
    last_len = pHdr->incl_len;

	return pHdr->incl_len;
}
