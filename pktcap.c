/*-----------------------------------------------------------------------------------------------
--	Source File:	pktcap.c - Contains the main datagram receiving functions used by pscan.c
--
--	Functions:	Misc libpcap functions- packet filtering library based on the BSD 
--			packet filter (BPF)
--
--	Interface:	void * ReceiveDatagram (void *pcap_arg)
--				pcap_arg - pointer which will be cast into a pointer to 
--					   struct PcapInfo 
--			    struct PcapInfo: contains all of the packet capture components
--				pcap_t* nic_descr - descriptor to the active NIC
--				bpf_u_int32 netp - address/subnet mask
--				char cmd[MAXLINE] - Packet Filter string to be compiled into the NIC
--
--	Date:		June 24, 2011
--
--	Revisions:	(Date and Description)
--
--	Designer:	Aman Abdulla
--
--	Programmer:	Aman Abdulla
--
--	Notes:
--	This function will use the address and filter string and use them in the pcap_compile() and 
-- 	pcap_setfilter() functions to selectively capture packets of interest. It then invokes 
--	the main callback function to start the packet capture loop.
--
--
--	
-------------------------------------------------------------------------------------------------*/

#include <errno.h>
#include "tscan.h"

// Function Prototypes
void pkt_callback (u_char*, const struct pcap_pkthdr*, const u_char*);
int PrintInHex (char *, unsigned char *, int);


void* ReceiveDatagram (void *pcap_arg)
{ 
	struct bpf_program fp;      // holds the compiled program     
	void *status = NULL;
	PcapInfo *pcap_ptr = (PcapInfo *)pcap_arg;
		
	if(pcap_compile (pcap_ptr->nic_descr, &fp, pcap_ptr->cmd, 0, pcap_ptr->netp) == -1)
    	{ 
		fprintf(stderr,"Error calling pcap_compile\n"); 
		exit(1); 
	}

    	// Load the filter into the capture device
	if (pcap_setfilter(pcap_ptr->nic_descr, &fp) == -1)
    	{ 
		fprintf(stderr,"Error setting filter\n"); 
		exit(1); 
	}

    	// Start the capture session 
    	pcap_loop (pcap_ptr->nic_descr, -1, pkt_callback, NULL);
	if (ExitFlag == TRUE)
		pthread_exit (status);
    		exit (0);
	return NULL;
}

/*-----------------------------------------------------------------------------------------------
--
--	Function:	This is the callback function that is passed to pcap_loop(..) and called 
--			each time a packet is received.
--
--	Interface:	void pkt_callback (u_char *ptr_null, const struct pcap_pkthdr* pkthdr, 
--						const u_char* packet)
--				u_char *ptr_null - a pointer which is passed in the user 
--						   argument to pcap_loop()
--				const struct pcap_pkthdr* pkthdr - struct pcap_pkthdr pointer 
--								   pointing to the packet time stamp 
--								   and lengths 
--			   	const u_char* packet - pointer to the first caplen (as given in 
--						       the struct pcap_pkthdr a pointer, which is 
--						       passed to the callback routine) bytes of data 
--						       from the packet.
--
--	Date:		June 24, 2011
--
--	Revisions:	(Date and Description)
--
--	Designer:	Aman Abdulla
--
--	Programmer:	Aman Abdulla
--
--	Notes:
--	This callback function is the main capture engine that will parse the captured packet headers
--	and print out the most useful fields from the Ethernet, IP, and TCP headers. 
-- 	
--	
-------------------------------------------------------------------------------------------------*/

void pkt_callback (u_char *ptr_null, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	static int count = 1;
	int len;
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
			
	fprintf(stdout,"\nPacket Number: %d\n", count);
	fflush(stdout);
    	count++;

	// Ensure that there are enough bytes to make up the complete set of headers
	
	if ((len = (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))) > 40)
	{
		/* Do all the checks: 1. Is it an IP pkt ? 2. is it TCP ? */
		
		ethernet_header = (struct ethhdr *)packet;

		// Print some Ethernet Header fields
		//Source MAC Address (6 Bytes) 
		PrintInHex("Source MAC: ", ethernet_header->h_source, 6);
		printf("\n");
		
		// Destination MAC Address (6 Bytes) 
		PrintInHex("Destination MAC: ", ethernet_header->h_dest, 6);
		printf("\n");
		
		// Embedded Protocol
		PrintInHex("Protocol: ",(void *)&ethernet_header->h_proto, 2);
		printf("\n");

		if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
		{
			ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

			// Print some IP Header Fields
			printf("Source IP address: %-15s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr));
			printf("Dest IP address: %-15s\n", inet_ntoa(*(struct in_addr *)&ip_header->daddr));
			

			if(ip_header->protocol == IPPROTO_TCP)
			{
				tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4);
				/* Print the Dest and Src ports */
				printf("======== TCP ========\n");
				printf("Source Port: %d\n", ntohs(tcp_header->source));
				printf("Dest Port: %d\n", ntohs(tcp_header->dest));
				printf("ACK #: %u\n", ntohl(tcp_header->ack_seq));
				printf("SEQ #: %u\n", ntohl(tcp_header->seq));	
				printf ("TCP Flags:\n");
				printf("  URG: %u\n", tcp_header->urg);
				printf("  ACK: %u\n", tcp_header->ack);
				printf("  PSH: %u\n", tcp_header->psh);
				printf("  RST: %u\n", tcp_header->rst);
				printf("  SYN: %u\n", tcp_header->syn);
				printf("  FIN: %u\n", tcp_header->fin);
			}
			else if(ip_header->protocol == IPPROTO_UDP)
			{
				udp_header = (struct udphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4);
				printf("======== UDP ========\n");
				printf("Source Port: %d\n", ntohs(udp_header->source));
				printf("Dest Port: %d\n", ntohs(udp_header->dest));
			}
		}
		else
		{
			printf("Not an IP packet\n");
		}	
	}
	else
	{
		printf("TCP Header not present \n");
	}
	ExitFlag = TRUE;
}

int PrintInHex(char *mesg, unsigned char *p, int len)
{
	printf(mesg);

	while(len--)
	{
		printf("%.2X ", *p);
		p++;
	}
	return 0;
}



