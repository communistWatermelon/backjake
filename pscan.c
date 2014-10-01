/*---------------------------------------------------------------------------------------
--	Source File:		pscan.c -   A raw sockets application - port scanner
--
--	Functions:		SendDatagram - dgram.c
--				ReceiveDatagram - pktcap.c
--				resolve_host - utils.c
--				GetIPAddress - utils.c
--
--	Date:			June 3, 2011
--
--	Revisions:		(Date and nic_description)
--					
--	Designer:		Aman Abdulla
--				
--	Programmer:		Aman Abdulla
--
--	Notes:
--	The program illustrates the use of raw sockets to craft header fields. The application 
-- 	scans a port on a remote system using addressing and other protocol information 
--	supplied by the user. User must at least supply the remote host name or IP address. 
--	By default the source IP is set to the local machine IP together with a default 
--	destination port. The default source port is randomly relected. Optionally the 
--	source IP address, the destination port, and the source port can be supplied by the user. 
--	
--	The application spawns two threads, one to run SendDatagram function and the other for
--	the ReceiveDatagram function. 	
--
--	To compile the application run the makefile provided:
--			make clean
--			make
---------------------------------------------------------------------------------------*/

#include <signal.h>
#include "tscan.h"

int main (int argc, char **argv)
{
    AddrInfo *Addr_Ptr;
    PcapInfo *pcap_ptr;
    int arg, opt;
    pthread_t ThreadID, ThreadID2;
    char *nic_dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 maskp;          // subnet mask    
    unsigned int iseed = (unsigned int)time(NULL);    // use the current time as the random seed value
    
    if (argc < 2)
    {
	usage(argv);
    }
    
    if ((Addr_Ptr = malloc (sizeof (AddrInfo))) == NULL)
    {
	perror ("malloc");
	exit (1);
    }
    
    // Seed the random number generator
    srand (iseed);
    
    // Set the default values
    Addr_Ptr->SrcHost = GetIPAddress ();	// Default Source IP
    Addr_Ptr->DstHost = NULL;			// Must be specified by user!
    Addr_Ptr->dport = DEFAULT_DST_PORT;		// Default Destination Port
    Addr_Ptr->sport = rand()% 40000 + 2000;	// Default (Random) Source Port between 2000 and 60000
    
    // Process command line options
    while ((opt = getopt (argc, argv, OPTIONS)) != -1)
    {
	switch (opt)
	{
	    case 'h': 
	      Addr_Ptr->SrcHost = optarg;
	    break;
		
	    case 'd':
	      Addr_Ptr->DstHost = resolve_host (optarg);	// Destination Host name
	    break;
	  
	    case 'p':
	      Addr_Ptr->dport = atoi (optarg);
	    break;
		
	    case 's':
	      Addr_Ptr->sport = atoi (optarg);
	    break;
		
	    default:
	      case '?':
	      usage (argv);
	    break;
	}
    }
    
    if (Addr_Ptr->DstHost == NULL)
	usage (argv);

    // set up the packet capture structure and thread
    if ((pcap_ptr = malloc (sizeof (PcapInfo))) == NULL)
    {
	perror ("malloc");
	exit (1);
    }
    
    // find the first NIC that is up and sniff packets from it
    nic_dev = "p2p1";//pcap_lookupdev(errbuf);
 //    if(nic_dev == NULL)
 //    { 
	// fprintf(stderr,"%s\n",errbuf); 
	// exit(1); 
 //    }

    // Use pcap to get the IP address and subnet mask of the device 
    pcap_lookupnet (nic_dev, &pcap_ptr->netp, &maskp, errbuf);

    // open device for reading 
  	
    // set the device in promiscuous mode 
    pcap_ptr->nic_descr = pcap_open_live (nic_dev, BUFSIZ, 1, -1, errbuf);
    if (pcap_ptr->nic_descr == NULL)
    { 
	printf("pcap_open_live(): %s\n",errbuf); 
	exit(1); 
    }

    // Compile the filter expression
    snprintf (pcap_ptr->cmd, sizeof(pcap_ptr->cmd), CMD, Addr_Ptr->DstHost, Addr_Ptr->dport);
	
    //Create a raw socket
    Addr_Ptr->RawSocket = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    
    // Set SO_REUSEADDR so that the port can be resused for further invocations of the application
    arg = 1;
    if (setsockopt (Addr_Ptr->RawSocket, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1) 
	perror("setsockopt");
    
    // Spawn new threads for the sender and receiver
    pthread_create (&ThreadID, NULL, SendDatagram, (void*)Addr_Ptr);
    pthread_create (&ThreadID2, NULL, ReceiveDatagram, (void *)pcap_ptr);
    pthread_join (ThreadID2, NULL);
    pthread_join (ThreadID, NULL);
    pthread_kill (ThreadID2, SIGALRM);
    free (Addr_Ptr);
    free (pcap_ptr);
    exit (0);
}

