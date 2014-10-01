/*-------------------------------------------------------------------------------------------------------
--  Source File:    dgram.c -  Contains the main datagram sending function used by pscan.c
--
--  Date:           June 3, 2011
--
--  Revisions:      (Date and nic_description)
--
--              May 15, 2012
--              Moved the mutex lock into the sigsetjmp loop.
--              No more segfaults
--
--  Designer:       Aman Abdulla
--              
--
--  Programmer:     Aman Abdulla
--
--  Functions:  SendDatagram 
--
--  Interface:  void * SendDatagram (void *addr_ptr)
--              addr_ptr - pointer which will be cast into a pointer to struct AddrInfo
                struct AddrInfo: contains all of the addressing components
                RawSocket: raw socket descriptor 
                *DstHost: Destination host IP
                *SrcHost: Source host IP
                dport: Destination port
                sport: Source port
--              
--  Description:    This function will craft the TCP and IP header fields based on the user-supplied
--          information. 
--
--  Returns:    NULL
--
--
--  Notes:
--  The function will send out three scanning probes, spaced apart exponentially.The retransmit 
--  mechanism is implemented using signals and the alarm function. The thread locking mechanism
--  is implemented using Mutexes.
--  The following fields in the IP and TCP headers are ramdomized:
--      IP Indentification Number, TCP Sequence Number, TCP Window Size
--  The function also makes use of a public domain checksum function "csum" (utils.c)
--
--------------------------------------------------------------------------------------------------------*/

#include <setjmp.h>
#include <time.h>
#include <signal.h>
#include "tscan.h"

// Function Prototypes
static void sig_alrm (int);
void cleanup (void);

// Globals
static sigjmp_buf jmpbuf;
static volatile sig_atomic_t canjump;

// Mutex variables
pthread_mutex_t ThreadLock = PTHREAD_MUTEX_INITIALIZER;

void* SendDatagram (void *addr_ptr)
{
    char datagram[PKT_SIZE];    // set the Datagram (packet) size
    struct iphdr *iph = (struct iphdr *) datagram;   //IP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));    //TCP header
    struct sockaddr_in sin;
    pseudo_header psh;
    volatile int nsent = 0, timeout = 1;
    //int nsent = 0, timeout = 1;
    AddrInfo *UserAddr = (AddrInfo *)addr_ptr;
    unsigned int iseed = (unsigned int)time(NULL);
    
    sin.sin_family = AF_INET;
    sin.sin_port = htons (UserAddr->dport);
    sin.sin_addr.s_addr = inet_addr (UserAddr->DstHost); 
    
    memset (datagram, 0, PKT_SIZE); // zero out the buffer where the datagram will be stored
    
    // Seed the random number generator
    srand (iseed);
    
    //IP Header Fields
    iph->ihl = 5;       // IP Header Length
    iph->version = 4;       // Version 4
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr); // Calculate the total Datagram size
    iph->id = htonl (rand()%65354);     //Random IP Identification Field
    iph->frag_off = 0;
    iph->ttl = DEFAULT_TTL;     // Set the TTL value
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;         //Initialize to zero before calculating checksum
    iph->saddr = inet_addr (UserAddr->SrcHost);  //Source IP address
    iph->daddr = sin.sin_addr.s_addr;
    
    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
    
    
    //TCP Header Fields
    tcph->source = htons (UserAddr->sport); // TCP source port
    tcph->dest = htons (UserAddr->dport);   // TCP destination port
    tcph->seq = rand()%RAND_MAX;        // Randomized sequence number between 0 and 2^31 -1 
    tcph->ack_seq = 0;
    tcph->doff = 5;      // Data Offset is set to the TCP header length 
    tcph->fin=0;
    tcph->syn=1;    // Set the SYN bit
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons (rand()% 4000 + 1024);     // Maximum allowable window size (between 1024 and 5024 Bytes)
    tcph->check = 0;                // Initialize the checksum to zero
                            // The kernel's IP stack will fill in the correct checksum during transmission 
    tcph->urg_ptr = 0;
    
    // calcluate the IP checksum
    psh.source_address = inet_addr(UserAddr->SrcHost);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(20);
    
    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
    
    tcph->check = csum( (unsigned short*) &psh , sizeof (pseudo_header));
    
    //IP_HDRINCL to stop the kernel from building the packet headers 
    {
        int one = 1;
        const int *val = &one;
        if (setsockopt (UserAddr->RawSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
            perror ("setsockopt");
    }
    
    // Set up the signals
    if (signal(SIGALRM, sig_alrm) == SIG_ERR)
        perror("signal(SIGALRM) error");
    printf("starting the scan: \n");  
    
    //lock the mutex
    //pthread_mutex_lock (&ThreadLock);

    if (sigsetjmp(jmpbuf, 1)) 
    {
        pthread_mutex_lock (&ThreadLock);
        if (ExitFlag == TRUE)
            cleanup();
        
        //Send the packet
        if (sendto (UserAddr->RawSocket, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        {
            perror ("sendto");
            exit (1);
        }
        else    //Data sent successfully
        {
            if (nsent > 0)
                printf("timeout\n");
            printf ("Datagram Sent!\n");
            nsent++;
            timeout *= 2;   // increase the timeout exponentially
        }
    }
        canjump = 1;            // sigsetjmp ready
    alarm (timeout);    // initialize the signal 
    
    for (; ;)
    {
        if (nsent == 3)
        {
            printf ("No response..quiting\n");
            //fflush (stdout);
            break;
        }
        if (ExitFlag == TRUE)
            break;
        pthread_mutex_lock (&ThreadLock);       
    }
    cleanup();
    return NULL;
}

static void sig_alrm (int signo)
{
    if (canjump == 0)
        return;
    pthread_mutex_unlock (&ThreadLock);
    siglongjmp (jmpbuf, 1);
}

void cleanup (void)
{
    canjump = 0;
    alarm (0);  // turn signal off
    exit (0);
}

