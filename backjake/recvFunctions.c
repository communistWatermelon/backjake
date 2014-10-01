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

#include "backjake.h"

// Function Prototypes
void pkt_callback (u_char*, const struct pcap_pkthdr*, const u_char*);
int PrintInHex (char *, unsigned char *, int);


void* ReceiveDatagram (void *pcap_arg)
{ 
	struct bpf_program fp;      // holds the compiled program     
	void *status = NULL;
	PcapInfo *pcap_ptr = (PcapInfo *)pcap_arg;
		
	pcapCompile();
	pcapFilter();
	pcapListen();

	return NULL;
}

void pcapListen()
{
	pcap_loop (pcap_ptr->nic_descr, -1, packetHandler, NULL);

	if (ExitFlag == TRUE)
	{
		pthread_exit (status);
	}
	
	exit (0);
}

void pcapCompile()
{
	if(pcap_compile (pcap_ptr->nic_descr, &fp, pcap_ptr->cmd, 0, pcap_ptr->netp) == -1)
	{ 
		fprintf(stderr,"Error calling pcap_compile\n"); 
		exit(1); 
	}
}

void pcapFilter()
{
	if (pcap_setfilter(pcap_ptr->nic_descr, &fp) == -1)
	{ 
		fprintf(stderr,"Error setting filter\n"); 
		exit(1); 
	}
}

int checkPacketSize()
{
	return ((sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)) > 40)
}

void packetHandler()
{
	static int count = 1;
	int len;
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;

	if (checkPacketSize())
	{
		ethernet_header = (struct ethhdr *)packet;
		if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
		{
			ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));	
			if(ip_header->protocol == IPPROTO_TCP)
			{
				tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4);
				printf("Source Port: %d\n", ntohs(tcp_header->source));
				printf("Dest Port: %d\n", ntohs(tcp_header->dest));
				printf("Payload: %d\n", ntohs(tcp_header->dest));
			}
		}
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
	printf("\n")
	return 0;
}
