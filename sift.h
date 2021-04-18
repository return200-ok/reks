/*
 *  $Id: sift.h,v 1.4 2002/11/10 10:55:10 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  sift.h - Vulnerability Scanning Technique example code
 *
 *  Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <libnet.h>     
#include <pcap.h>  
#include <sys/ioctl.h>   
/*misc defines */     
#define SNAPLEN         150        /*150 bytes should cover us nicely */     
#define PROMISC         0          /*dont need to be in promise mode */     
#define TIMEOUT         0          /*no timeout, return immediately */     
#define SOURCE_PORT     31337      /* we are */     
#define FILTER          "udp port 53" 
/*only DNS responses please */     
#define NETWORK_TIMEOUT 3          
/*3 seconds and we're crying foul */     
/*sitt return codes */     
#define TIMEDOUT        0          /*no response */     
#define NO_ANSWER       1          
/*a response without an answer */     
#define RESPONSE        2          /*a response with an answer */
/*DNS flags */     
#define DNS_NOTIMPL     0x0004     
#define DNS_SERVFAILED  0x0002     
#define DNS_FORMATERR   0x0001
/**The chaos class query resource record:*07 'V' 'E' R' 'S' 'I' '0' 'N' 04 'B' 'I' 'N' 'D' 00 16 00 03*/
u_char chaos_query[] = { 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e, 0x64, 0x00, 0x00, 0x10, 0x00, 0x03 };

#define CHAOS_QUERY_S 18 /*our chaos class RR is 18 bytes */
/*sift statistics structure */
struct sift_stats
{
	u_long total_queries; /*total queries sent */
	u_long total_responses; /*total responses received */
	u_long valid_responses; /*real responses received */
	u_long timed_out; /*total timeouts */
	u_long timed_out_resolving; /*total timeouts resolving */
	u_long not_implemented; /*DNS servers NI */
	u_long server_failed; /*DNS server failed */
	u_long format_error; /*DNS server format errors */
}; 
/*sift control context */
struct sift_pack
{
	pcap_t *p; /*pcap descriptor */
	libnet_t *l; /*libnet descriptor */
	FILE *in_hosts; /*file to read hosts from */
	FILE *in_db; /*file to read db from */
	u_char *packet; /*everyone's favorite: packet! */
	struct pcap_pkthdr h; /*pcap packet header */
	libnet_ptag_t dns; /*DNS header */
	libnet_ptag_t udp; /*UDP header */
	libnet_ptag_t ip; /*IP header */
	u_long src_ip; /*source ip */
	u_long dst_ip; /*host to scan */
	u_short id; /*session id */
	u_char to; /*packet read timeout */
	u_char cnt; /*probe count */
	u_char flags; /*control flags */
#define SIFT_QUIET      0x1         /* keep quiet! */
	struct sift_stats stats; /*statistics */
	char errbuf[LIBNET_ERRBUF_SIZE];
};
struct sift_pack *sift_init(char *, char *, u_char, u_char, u_char, char *);
void sift_destroy(struct sift_pack *);
void sift(struct sift_pack *);
void sift_stats(struct sift_pack *);
int build_packet(struct sift_pack *, char *);
int write_packet(struct sift_pack *);
int receive_packet(struct sift_pack *);
void cleanup(int);
int catch_sig(int, void(*)());
void usage(char *); 
/*EOF */