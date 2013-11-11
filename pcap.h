
#ifndef PCAP_H_
#define PCAP_H_

#define PCAP_MAGIC_NUMBER	0xa1b2c3d4
#define PCAP_MAJOR_VERSION	2
#define PCAP_MINOR_VERSION	4

typedef struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct pcap_info_s {
	FILE	  * fd;
	char 	  * filename;
	pcap_hdr_t	info;
} pcap_info_t;

extern pcap_info_t * pktgen_pcap_open(char * filename);
extern int pktgen_pcap_valid(char * filename);
extern void pktgen_pcap_close(pcap_info_t * pcap);
extern void pktgen_pcap_rewind(pcap_info_t * pcap);
extern void pktgen_pcap_info(pcap_info_t * pcap);
extern size_t pktgen_pcap_read(pcap_info_t * pcap, pcaprec_hdr_t * pHdr, char * pktBuff, uint32_t bufLen, int print);
extern int pktgen_payloadOffset(const unsigned char *pkt_data, unsigned int *offset,
                          unsigned int *length);
extern void print_content(uint8_t * ptr, int length);
extern size_t pktgen_pcap_chk(pcap_info_t * pcap, pcaprec_hdr_t * pHdr, uint64_t i);
#endif /* PCAP_H_ */
