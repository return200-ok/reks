/*
 *  $Id: sift.c,v 1.4 2002/11/10 10:55:10 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  sift.c - Vulnerability Scanning Technique example code
 *
 *  1.1 - maintenence release:
 *      - Moved the host resolution function call to the beginning of
 *        build_packet() to catch non-resolvers before we actually build part
 *        of the packet.
 *      - Sift erroneously ignored ASCII 0x20 (space characters)
 *      - Sift was not stepping over the proper number of bytes when skipping
 *        over certain header information (it was off by one).
 *      - A SNAPLEN of 150 bytes was too short.  I've increased this to 350
 *        bytes which is sufficient.
 *      - Changed the timeout character from * to <sift_time_out> this reduces
 *        the false negatives we'd get from a DNS server with a version string
 *        of "*".
 *  1.0 - initial release
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

#include "./sift.h"

int loop = 1;
int main(int argc, char **argv)
	{
		int c;
		u_char to, cnt, flags;
		char *device;
		struct sift_pack *sp;
		char errbuf[LIBNET_ERRBUF_SIZE], file[64];
		printf("Sift 1.0[DNS Version scanning tool]\n");
		to = 0;
		cnt = 0;
		flags = 0;
		device = NULL;
		memset (&file, NULL, sizeof (file));
		while ((c = getopt(argc, argv, "hi:r:t:")) != EOF)
		{
			switch (c)
			{
				case 'h':
					usage(argv[0]);
					exit(EXIT_SUCCESS);
					break;
				case 'i':
					device = optarg;
					break;
				case 'r':
					cnt = atoi(optarg);
					break;
				case 't':
					to = atoi(optarg);
					break;
				default:
					usage(argv[0]);
                    exit(EXIT_FAILURE);
            }
        }
        c = argc - optind;
        if (c != 1)
        {
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
        else
        {
            /*target IPs */
            strncpy(file, argv[optind], sizeof(file) - 1);
        }
        sp = sift_init(device, file, flags, to, cnt, errbuf);
        if (sp == NULL)
        {
            fprintf(stderr, "sift_init() failed: %s\n", errbuf);
            goto done;
        }
        printf("<ctrl-c > to quit\n");
        sift(sp);
        sift_stats(sp);
        done:
            sift_destroy(sp);
            return (EXIT_SUCCESS);
        }
        struct sift_pack *
            sift_init(char *device, char *file, u_char flags, u_char to, u_char cnt, char *errbuf)
            {
                struct sift_pack * sp;
                struct bpf_program filter_code;
                bpf_u_int32 local_net, netmask;
                int one;
                /*
                *We want to catch the interrupt signal so we can inform the user
                *how many packets we captured before we exit.
                */
                if (catch_sig(SIGINT, cleanup) == -1)
                {
                    sprintf(errbuf, "can't catch SIGINT signal. /n");
                    return (NULL);
                }
                sp = malloc(sizeof(struct sift_pack));
                if (sp == NULL)
                {
                    snprintf(errbuf, LIBNET_ERRBUF_SIZE, strerror(errno));
                    return (NULL);
                }
                /*open the host list */
                sp->in_hosts = fopen(file, "r");
                if (sp->in_hosts == NULL)
                {
                    snprintf(errbuf, LIBNET_ERRBUF_SIZE, strerror(errno));
                    sift_destroy(sp);
                    return (NULL);
                }
                sp->id = getpid();
                sp->flags = flags;
                sp->to = to == 0 ? NETWORK_TIMEOUT : to;
                sp->cnt = cnt;
                sp->dns = LIBNET_PTAG_INITIALIZER;
                sp->udp = LIBNET_PTAG_INITIALIZER;
                sp->ip = LIBNET_PTAG_INITIALIZER;
                /*
                *If device is NULL, that means the user did not specify one and
                *is leaving it up libpcap / libnet to find one. We'll use
                *libpcap's lookup routine, but they're both from the same
                *codebase so it doesn't matter... ;)
                */
                if (device == NULL)
                {
                    device == pcap_lookupdev(errbuf);
                    if (device == NULL)
                    {
                        sift_destroy(sp);
                        return (NULL);
                    }
                }
                /*
                *Open the packet capturing device with the following values:
                *
                *SNAPLEN: We shouldn't need more than 150 bytes
                *PROMISC: off
                *TIMEOUT: Oms
                */
                sp->p = pcap_open_live(device, SNAPLEN, PROMISC, TIMEOUT, errbuf);
                if (sp->p == NULL)
                {
                    return (NULL);
                }
                /*
                *BPF, by default, will buffer packets inside the kernel until
                *either the timer expires (which we do not use) or when the
                *buffer fills up. This is not sufficient for us since we could
                * miss responses to our probes. So we set BIOCIMMEDIATE to tell
                * BPF to return immediately when it gets a packet. This is pretty
                * much the same behavior we see with Linux which returns every
                * time it sees a packet. This is less than efficient since we're
                * spending more time interrupting the kernel, but hey, we gotta
                * get our work done!
                *
                * We don't check for error here on purpose. Since we're not
                * doing any robust precompilation configuration via autoconf
                * we can't be sure if this system supports BPF. As such we'll
                * just try the ioctl and if it fails - so be it. We'll assume
                * the system does not support the ioctl(). This IS pretty naive.
                * For the right way to do this, see Chapter 12. Also we do hope
                * that this ioctl() won't cause unexpected side effects on non
                * bpf-enabled machines.
                */
               one = 1;
            // if (ioctl(pcap_fileno(sp->p), BIOCIMMEDIATE, &one) < 0)
            // {
            //     /*it's ok if this fails... */
            // }
            /*
            *We need to make sure this is Ethernet. The DLT_EN10MB specifies
            *standard 10MB and higher Ethernet.
            */
            if (pcap_datalink(sp->p) != DLT_EN10MB)
            {
                sprintf(errbuf, "Sift only works with ethernet.\n");
                sift_destroy(sp);
                return (NULL);
            }
            /*get the subnet mask of the interface */
            if (pcap_lookupnet(device, &local_net, &netmask, errbuf) == -1)
            {
                snprintf(errbuf, LIBNET_ERRBUF_SIZE, "pcap_lookupnet()");
                sift_destroy(sp);
                return (NULL);
            }
            /*compile the BPF filter code */
            if (pcap_compile(sp-> p, &filter_code, FILTER, 1, netmask) == -1)
            {
                snprintf(sp->errbuf, LIBNET_ERRBUF_SIZE, "pcap_compile(): %s", 
                    pcap_geterr(sp->p));
                sift_destroy(sp);
                return (NULL);
            }
            /*apply the filter to the interface */
            if (pcap_setfilter(sp-> p, &filter_code) == -1)
            {
                snprintf(sp->errbuf, LIBNET_ERRBUF_SIZE, "pcap_setfilter(): %s",
                    pcap_geterr(sp-> p));
                sift_destroy(sp);
                return (NULL);
            }
            sp->l = libnet_init(LIBNET_RAW4, device, errbuf);
            if (sp->l == NULL)
            {
                sift_destroy(sp);
                return (NULL);
            }
            /*set the source address of our interface */
            sp->src_ip = libnet_get_ipaddr4(sp->l);
            return (sp);
            }
            void
            sift_destroy(struct sift_pack *sp)
            {
                if (sp)
                {
                    if (sp->p)
                    {
                        pcap_close(sp->p);
                    }
                    if (sp->l)
                    {
                        libnet_destroy(sp->l);
                    }
                    if (sp->in_hosts)
                    {
                        fclose(sp->in_hosts);
                    }
                }
            }
            int
            catch_sig(int signo, void(*handler)())
            {
                struct sigaction action;
                action.sa_handler = handler;
                sigemptyset(&action.sa_mask);
                action.sa_flags = 0;
                if (sigaction(signo, &action, NULL) == -1)
                {
                    return (-1);
                }
                else
                {
                    return (1);
                }
            }
            void
            sift(struct sift_pack *sp)
            {
                u_char retry_cnt;
                char host[128];
                retry_cnt = 0;
                /*pull entries from the host list and send queries */
                while (fgets(host, sizeof(host) - 1, sp->in_hosts) && loop)
                {
                    if (host[0] == '#')
                    { /*ignore comments */
                        continue;
                    }
                    /*remove the newline */
                    host[strlen(host) - 1] = 0;
                    /*build a chaos query packet using host as the destination */
                    if (build_packet(sp, host) == -1)
                    {
                        fprintf(stderr, "build_packet(): %s", sp-> errbuf);
                        continue;
                    }
                    /*set retry counter, accounting for the probe just sent */
                    sp->cnt ? retry_cnt = sp->cnt - 1 : 0;
                    retry:
                        /*write query the network */
                        if (write_packet(sp) == -1)
                        {
                            fprintf(stderr, "write_packet(): %s", sp->errbuf);
                            continue;
                        }
                    else
                    {
                        sp->stats.total_queries++;
                        fprintf(stderr, "Chaos class query to %s: t",
                            libnet_addr2name4(sp-> dst_ip, 0));
                    }
                    /*read the response handling timeouts if so configured */
                    if (receive_packet(sp) == TIMEDOUT)
                    { /*timed out, check for retry */
                        if (retry_cnt)
                        {
                            retry_cnt--;
                            goto retry;
                        }
                    }
                }
            }
            int
            build_packet(struct sift_pack *sp, char *host)
                {
                    u_long packet_size;
                    if ((sp->dst_ip = libnet_name2addr4(sp->l, host,
                            LIBNET_RESOLVE)) == -1)
                    {
                        sprintf(sp->errbuf, "%s (%s)\n", libnet_geterror(sp->l), host);
                        sp->stats.timed_out_resolving++;
                        return (-1);
                    }

                    packet_size = LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H +
                        CHAOS_QUERY_S;
                    /*
                    *Increment the session id per packet. We do this in case a DNS
                    *server happened to respond late to a query we had already deemed
                    *expired. If we used the same transaction id for every query,
                    *these late comers could give us false results.
                    */
                    ++sp->id;
                    /*
                    *Build a dns chaos class query request packet. As before, we
                    *save the ptag after the first usage so future calls will modify
                    *this packet header template rather than build a new one.
                    */
                    sp->dns = libnet_build_dnsv4(	
                        1,		
                        sp->id,                        /*transaction id */
                        0x0100,                        /*flags (request) */
                        1,                        /*1 question RR */
                        0,                        /*no answer RR */
                        0,                        /*no authority RR */
                        0,                        /*no additional RR */
                        chaos_query,                        /*payload */
                        CHAOS_QUERY_S,                        /*payload size */
                        sp->l,                        /*libnet context */
                        sp->dns);                    /*ptag */
                    if (sp->dns == -1)
                    {
                        sprintf(sp->errbuf, "Can't build DNS header: %s /n",
                            libnet_geterror(sp->l));
                        return (-1);
                    }
                    /*
                    The UDP header only has to be built once. Checksums will have
                    to be recomputed everytime since the DNS header is changing
                    but we don't need to modify the header explicitly after it's
                    built. */
                    if (sp->udp == LIBNET_PTAG_INITIALIZER)
                    {
                        sp->udp = libnet_build_udp(		
                            SOURCE_PORT,    /*source port */
                            53,		/*destination port */
                            LIBNET_UDP_H + LIBNET_DNS_H + CHAOS_QUERY_S,
                            0,		/*checksum */
                            NULL,		/*payload */
                            0,		/*payload size */
                            sp->l,		/*libnet context */
                            sp->udp);	/*ptag */
                        if (sp->udp == -1)
                        {
                            sprintf(sp->errbuf, "Can't build UDP header: %s /n",
                                libnet_geterror(sp->l));
                            return (-1);
                        }
                    }
                    /*resolve the host in a big endian number */
                    if ((sp->dst_ip = libnet_name2addr4(sp->l, host,
                            LIBNET_RESOLVE)) == -1)
                    {
                        sprintf(sp->errbuf, "%s (%s)\n", libnet_geterror(sp->l), host);
                        sp->stats.timed_out_resolving++;
                        return (-1);
                    }
                    /*
                    *After building it, we'll need to update the IP header every time
                    *with the new address.
                    */
                    sp->ip = libnet_build_ipv4(	
                        packet_size,	/*total packet size */
                        0,	/*type of service */
                        242,	/*identification */
                        0,	/*fragmentation */
                        64,	/*time to live */
                        IPPROTO_UDP,	/*protocol */
                        0,	/*checksum */
                        sp->src_ip,	/*source */
                        sp->dst_ip,	/*destination */
                        NULL,	/*payload */
                        0,	/*payload size */
                        sp->l,	/*libnet context */
                        sp->ip);    /*ptag */
                    if (sp->ip == -1)
                    {
                        sprintf(sp->errbuf, "Can't build IP header: %s\n",
                            libnet_geterror(sp->l)
                        );
                        return (-1);
                    }
                    return (1);
                    }
                    int
                    write_packet(struct sift_pack *sp)
                    {
                        int c;
                        c = libnet_write(sp->l);
                        if (c == -1)
                        {
                            sprintf(sp->errbuf, "libnet_write(): %s /n",
                                libnet_geterror(sp->l));
                        }
                        return (c);
                    }
int receive_packet(struct sift_pack * sp){
		u_short ip_hl;
		u_char *payload;
		char version[128];
		fd_set read_set;
		u_short count, offset;
		struct timeval timeout;
		struct libnet_ipv4_hdr * ip;
		struct libnet_dnsv4_hdr * dns;
		int c, j, l, m, timed_out, pcap_fd;
		timeout.tv_sec = sp->to;
		timeout.tv_usec = 0;
		pcap_fd = pcap_fileno(sp->p);
		FD_ZERO(&read_set);
		FD_SET(pcap_fd, &read_set);
		/*run through the packet capturing loop until a timeout or ctrl-c */
		for (timed_out = 0; !timed_out && loop;)
		{ /*synchronous I/O multiplexing */
			c = select(pcap_fd + 1, &read_set, 0, 0, &timeout);
			switch (c)
			{
				case -1:
					snprintf(sp->errbuf, LIBNET_ERRBUF_SIZE,
						"select() %s", strerror(errno));
					return (-1);
				case 0:
					timed_out = 1;
					continue;
				default:
					if (FD_ISSET(pcap_fd, &read_set) == 0)
					{
						timed_out = 1;
						continue;
					}
					/*fall through to read the packet */
			}
			sp->packet = (u_char*) pcap_next(sp->p, &sp->h);
			if (sp->packet == NULL)
			{ 	/*
				 *We have to be careful here as pcap_next() can return
				 *NULL if the timer expires with no data in the packet
				 *buffer or under some special circumstances under linux.
				 */
				continue;
			}
			ip = (struct libnet_ipv4_hdr *)(sp->packet + LIBNET_ETH_H);
			if (ip->ip_src.s_addr == sp->src_ip)
			{ 	/*packets we send are of no interest to us here. */
				continue;
			}
			ip_hl = ip->ip_hl << 2;
			dns = (struct libnet_dnsv4_hdr *)(sp->packet + LIBNET_ETH_H +
				ip_hl + LIBNET_UDP_H);
			/*check to see if this is a response to our query */
			if (ntohs(dns->id) == sp->id)
			{ 	/*check to see if the CHAOS class is implemented */
				if ((ntohs(dns->flags) &DNS_NOTIMPL))
				{
					fprintf(stderr, "not implemented /n");
					sp->stats.total_responses++;
					sp->stats.not_implemented++;
					return (NO_ANSWER);
				}
				/*check to see if the server failed */
				if ((ntohs(dns->flags) &DNS_SERVFAILED))
				{
					fprintf(stderr, "server failed /n");
					sp->stats.total_responses++;
					sp->stats.server_failed++;
					return (NO_ANSWER);
				}
				/*check to see if there was a format error */
				if ((ntohs(dns->flags) &DNS_FORMATERR))
				{
					fprintf(stderr, "format error\n");
					sp->stats.total_responses++;
					sp->stats.format_error++;
					return (NO_ANSWER);
				}
				/*
				 *Every response to our chaos class query should have our
				 *original uncompressed question in it. As such we can
				 *safely point payload past that query rr directly to
				 *the answer rr which is what we want to parse.
				 */
				payload = (u_char*)(sp->packet + LIBNET_ETH_H + ip_hl +
					LIBNET_UDP_H + LIBNET_DNS_H + CHAOS_QUERY_S);
				/*
				 *Some DNS servers will be smart and compress their
				 *response to our query. We check for that case here.
				 */
				if (payload[0] & 0xc0 )
				{ 		/*
					 *When the two high-order bits are set (values
					 *192 - 255) it indicates the response is compressed.
					 *Shave off the low-order 14 bits to determine the
					 *offset. It's pretty bitwise code but unfortunately
					 *we have no use for it in this version.
					 */
					offset = (payload[0] << 0x08 | payload[l]) & 0x3fff;
					/*
					 *The llth and 12th bytes will contain the count
					 *(number of bytes) of the answer.
					 */
					count = payload[10] << 0x08 | payload[11];
					j = 12;
				}
				else
				{ 		/*
					 *If we're not compressed step over the 24 bytes of
					 *answer stuff we don't care about.
					 */
					count = payload[22] << 0x08 | payload[23];
					j = 24;
				}
				/*
				 *Our buffer to hold the version info is only 128 bytes
				 *and we need to account for the terminating NULL.
				 */
				count > 127 ? count = 127 : count;
				memset(version, 0, 128);
				/*
				 *Run through the payload pulling out only the printable
				 *ASCII characters which are between 0x21 (!) and 0x7e
				 *(~).
				 */
				for (l = 0, m = 0; l < count; l++)
				{
					if (payload[j + l] = 0x21 && payload[j + l] <= 0x7e)
				{
					version[m] = payload[j + l];
					m++;
				}
			}
			/*report the version to the user */
			fprintf(stderr, "%s /n", version);
			sp->stats.valid_responses++;
			sp->stats.total_responses++;
			return (RESPONSE);
		}
	}
	/*we timed out waiting for a response */
	fprintf(stderr, "*\n"); 
    sp->stats.timed_out ++;
	return (TIMEDOUT);
}
void cleanup(int signo){
	loop = 0;
	printf("Interrupt signal caught... /n");
}
void sift_stats(struct sift_pack *sp){
	printf("Sift statistics: /n"
		"total queries sent:\t\t%41d\n"
		"total responses received:\t%41d\n"
		"total valid responses received:\t%41d\n"
		"total timeouts:\t\t\t%41d\n"
		"total timeouts resolving:\t%41d\n"
		"total not implemented:\t\t%41d\n"
		"total server failed:\t\t%41d\n"
		"total format errors:\t\t%41d\n",
		sp->stats.total_queries, sp->stats.total_responses,
		sp->stats.valid_responses, sp->stats.timed_out,
		sp->stats.not_implemented, sp->stats.server_failed,
		sp->stats.format_error
        );
}
void usage(char *name){
	printf("usage %s[options] host_file\n"
		"-h\t\tthis blurb you see right here\n"
		"-i device\tspecify a device\n"
		"-r count\tnumber of times to retry the guery\n"
		"-t timeout\tseconds to wait for a response\n", name);
}
/*EOF */
