#include "backjake.h"

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

