/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"
#include "string.h"

 /* MAC header 802.3 */
typedef struct mac_header {
	u_int8_t srcAddr[6];
	u_int8_t dstAddr[6];
	u_int16_t ehtType;
}mac_header;

/* 4 bytes IP address */
typedef struct ip_address
{
	u_int8_t byte1;
	u_int8_t byte2;
	u_int8_t byte3;
	u_int8_t byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header
{
	u_int8_t	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_int8_t	tos;			// Type of service 
	u_int16_t tlen;			// Total length 
	u_int16_t identification; // Identification
	u_int16_t flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_int8_t	ttl;			// Time to live
	u_int8_t	proto;			// Protocol
	u_int16_t crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
							//	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_int16_t sport;			// Source port
	u_int16_t dport;			// Destination port
	u_int16_t len;			// Datagram length
	u_int16_t crc;			// Checksum
}udp_header;

/* TCP header */
typedef struct tcp_header {
	u_int16_t sport;				//Source port
	u_int16_t dport;				//Destination port
	u_int32_t sequenceNum;			//Sequence number
	u_int32_t ackNum;				//Acknowledgment number
	u_int16_t datOff_ecn_control;	//Data offset + reserved + ECN + Control bits
	u_int16_t window;				//Window
	u_int16_t crc;					//Checksum
	u_int16_t urgentPointer;		//Ugernt pointer
}tcp_header;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/* memmem prototype */
void * memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen);

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the device */
	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
						// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	mac_header* macHeader;
	ip_header* ipv4Header;
	udp_header* udpHeader;
	tcp_header* tcpHeader;
	char* payload;
	char url[255];
	char request[5];
	char stringaMax[1500];
	char* line;
	char headerHttp[60], valueHeaderHttp[300];

	/*
	* unused parameters
	*/
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* print timestamp */
	printf("%s,%.6d\t", timestr, header->ts.tv_usec);

	/* check the presence of mac header */
	if (header->caplen > sizeof(mac_header)) {
		macHeader = (mac_header *)pkt_data;

		/* print src and dst mac addresses */
		printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\t",
			macHeader->srcAddr[0], macHeader->srcAddr[1], macHeader->srcAddr[2], macHeader->srcAddr[3],
			macHeader->srcAddr[4], macHeader->srcAddr[5], macHeader->dstAddr[0], macHeader->dstAddr[1],
			macHeader->dstAddr[2], macHeader->dstAddr[3], macHeader->dstAddr[4], macHeader->dstAddr[5]);
		if (ntohs(macHeader->ehtType) == 0x800) {
			/* IPV4 */
			if (header->caplen > (sizeof(mac_header) + sizeof(ip_header))) {
				ipv4Header = (ip_header *)(pkt_data + sizeof(mac_header));

				/* print src and dst ip addresses */
				printf("%d.%d.%d.%d -> %d.%d.%d.%d\t",
					ipv4Header->saddr.byte1, ipv4Header->saddr.byte2, ipv4Header->saddr.byte3, ipv4Header->saddr.byte4,		//Source address
					ipv4Header->daddr.byte1, ipv4Header->daddr.byte2, ipv4Header->daddr.byte3, ipv4Header->daddr.byte4		//Destination address
					);

				if (ipv4Header->proto == 0x06) {
					/* TCP */
					printf("TCP\t");
					if (header->caplen > (sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header))) {
						tcpHeader = (tcp_header *)(pkt_data + sizeof(mac_header) + sizeof(ip_header));
						printf("%d -> %d\t", ntohs(tcpHeader->sport), ntohs(tcpHeader->dport));
						if (ntohs(tcpHeader->dport) == 80) {
							/* TCP:80 probabile http */
							//TODO fare un ciclo che legge fino a quando a trova GET/POST e ritrova l'url facendo attenzione al buffer overflow
							payload = (char *)(pkt_data + sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header));
							size_t payloadLength = header->caplen - sizeof(mac_header) - sizeof(ip_header) - sizeof(tcp_header);
							if (strncmp(payload,"GET",3)==0 || strncmp(payload,"POST",4) == 0) 
							{
								sscanf(payload, "%s %s", request, url);
								int byteLetti = 0, i = 0;
								while (payloadLength > byteLetti) {
									stringaMax[i] = payload[byteLetti];
									if(payload[byteLetti] == '\n'){
										stringaMax[i + 1] = '\0';
										sscanf(stringaMax, "%s %s", headerHttp, valueHeaderHttp);
										i = 0;
										if (strncmp(headerHttp, "Host:", 5) == 0) {
											printf("%s%s", valueHeaderHttp, url);
										}
										memset(stringaMax, 0, 1500);
									}
									else {
										i++;
									}
									byteLetti++;
								}
							}
						}
					}
				}
				else if (ipv4Header->proto == 0x11) {
					/* UDP */
					printf("UDP\t");
					if (header->caplen > (sizeof(mac_header) + sizeof(ip_header) + sizeof(udp_header))) {
						udpHeader = (udp_header *)(pkt_data + sizeof(mac_header) + sizeof(ip_header));
						printf("%d -> %d", ntohs(udpHeader->sport), ntohs(udpHeader->dport));
					}
				}
			}
		}
		printf("\n");
	}
}