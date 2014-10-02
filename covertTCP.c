/*---------------------------------------------------------------------------------------
--  SOURCE FILE:    covertTCP.c - A robust tcp load testing client.
--
--  PROGRAM:        covertTCP
--
--  FUNCTIONS:      void forgepacket(struct options*); 
--                  unsigned short in_cksum(unsigned short *, int);
--                  unsigned int host_convert(char *);
--                  void usage(char *);
--                  void checkRoot();
--                  void selectOpts(struct options *, int*, char**);
--                  void validateOpts(struct options *);
--                  void openFile(char[80], FILE**, int);
--                  void initializeTCPPacket(struct send_tcp *, struct options *);
--                  void sendPacket(int *, struct send_tcp *, struct sockaddr_in *);
--                  void finalizePacket(struct send_tcp *, struct pseudo_header *);
--                  void initializeWriteSocket(struct sockaddr_in *, struct send_tcp *, int *);
--                  void initializeReadSocket(int*);
--                  void embedPacket(struct send_tcp *, struct options *, int);
--                  void writeFile(FILE **, int);
--                  int checkPacket(struct recv_tcp *, struct options *);
--                  int decodePacket(struct recv_tcp *, struct options *);
--
--  DATE:           September 22, 2014
--
--  DESIGNERS:      Jacob Miner
--
--  PROGRAMMERS:    Jacob Miner
--
--  NOTES:
--  The program will act as either a client or a server, embedding and decoding cover 
--  communications within a packet.
---------------------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>

struct options 
{
    unsigned int source_host;
    unsigned int dest_host;
    unsigned short source_port;
    unsigned short dest_port;
    int encodeType;
    int server;
    char filename[80];
} myOptions;

struct send_tcp
{
    struct iphdr ip;
    struct tcphdr tcp;
} send_pkt;

struct recv_tcp
{
    struct iphdr ip;
    struct tcphdr tcp;
    char buffer[10000];
} recv_pkt;

struct pseudo_header
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
} pseudo_header;

void forgepacket(struct options*); 
unsigned short in_cksum(unsigned short *, int);
unsigned int host_convert(char *);
void usage(char *);
void checkRoot();
void selectOpts(struct options *, int*, char**);
void validateOpts(struct options *);
void openFile(char[80], FILE**, int);
void initializeTCPPacket(struct send_tcp *, struct options *);
void sendPacket(int *, struct send_tcp *, struct sockaddr_in *);
void finalizePacket(struct send_tcp *, struct pseudo_header *);
void initializeWriteSocket(struct sockaddr_in *, struct send_tcp *, int *);
void initializeReadSocket(int*);
void embedPacket(struct send_tcp *, struct options *, int);
void writeFile(FILE **, int);
int checkPacket(struct recv_tcp *, struct options *);
int decodePacket(struct recv_tcp *, struct options *);

/*------------------------------------------------------------------------------
--
--  FUNCTION:   main
--
--  DATE:       February 14, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: main(int argc, char **argv)
--
--  RETURNS:  int - 0 on success
--
--  NOTES: The main thread of the program. Calls all other functions.
--  
------------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
    struct options opt = { 0 };
    checkRoot();
    selectOpts(&opt, &argc, argv);
    validateOpts(&opt);
    forgepacket(&opt);
    return 0;
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   forgepacket
--
--  DATE:       February 14, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: forgepacket(struct options * opt)
--              options - a struct containing the user arguments 
--
--  RETURNS:  void
--
--  NOTES: The main thread of the program. Calls all other functions.
--  
------------------------------------------------------------------------------*/
void forgepacket(struct options * opt)
{
    int ch = 0;
    int send_socket;
    int recv_socket;
    struct sockaddr_in sin = { 0 };
    struct send_tcp send = { 0 };
    struct recv_tcp recv = { 0 };
    struct pseudo_header ph = { 0 };
    FILE *input = 0;
    FILE *output = 0;

    srand((getpid())*(opt->dest_port));

    if (!(opt->server)) // you're the client
    {
        openFile(opt->filename, &input, 0);
        while((ch = fgetc(input)) != EOF)
        {
            sleep(1);
            initializeTCPPacket(&send, opt);
            initializeWriteSocket(&sin, &send, &send_socket);
            embedPacket(&send, opt, ch);
            finalizePacket(&send, &ph);
            sendPacket(&send_socket, &send, &sin);
            printf("sending packet with %c\n", ch);
        }

        fclose(input);
    } else { // you're the server
        openFile(opt->filename, &output, 1);
        while(1)
        {
            initializeReadSocket(&recv_socket);
            read(recv_socket, (struct recv_tcp *)&recv, 9999);
            writeFile(&output, checkPacket(&recv, opt));
            close(recv_socket);
        }
        fclose(output);
    }
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   writeFile
--
--  DATE:       September 22, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: writeFile(FILE ** output, int ch)
--                  output  - pointer to the output file
                    ch      - the character to write
--
--  RETURNS: void
--
--  NOTES: writes a character to the output file
--  
------------------------------------------------------------------------------*/
void writeFile(FILE ** output, int ch)
{
    printf("%c\n", ch);
    fprintf(*output,"%c",ch);
    fflush(*output);
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   checkPacket
--
--  DATE:       September 22, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: checkPacket(struct recv_tcp * recv, struct options * opt)
--                          recv    - a struct containing the recieved tcp packet
--                          opt     - a structure containing the users arguments
--
--  RETURNS: int - the character decoded by decodePacket
--
--  NOTES: Checks to see if the packet is relevent, then calls decodePacket 
--  
------------------------------------------------------------------------------*/
int checkPacket(struct recv_tcp * recv, struct options * opt)
{
    int embedded = 0;

    if (opt->source_port == 0)
    {
        if((recv->tcp.syn == 1) && (recv->ip.saddr == opt->source_host))
        {
            embedded = decodePacket(recv, opt);
        }
    } else {
        if((recv->tcp.syn==1) && (ntohs(recv->tcp.dest) == opt->source_port)) 
        {
            embedded = decodePacket(recv, opt);
        }
    }
    return embedded;
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   decodePacket
--
--  DATE:       September 22, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: decodePacket(struct recv_tcp * recv, struct options * opt)
--                          recv    - a struct containing the recieved tcp packet
--                          opt     - a structure containing the users arguments
--
--  RETURNS: int - the character embedded in the packet
--
--  NOTES: Checks the packet for data encoded, based on users encoding type
--  
------------------------------------------------------------------------------*/
int decodePacket(struct recv_tcp * recv, struct options * opt)
{
    switch(opt->encodeType)
    {
        case 0:
            return recv->ip.id;
        case 1:
            return recv->tcp.seq;
        case 2:
            return recv->tcp.ack_seq;
        case 3:
            return recv->tcp.urg_ptr;
        default:
            return -1;
    }
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   embedPacket
--
--  DATE:       September 22, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: embedPacket(struct send_tcp * send, struct options * opt, int ch)
--                          send    - the structure containing the tcp packet to embed the character into
--                          opt     - the structure containing the users arguments
--                          ch      - the character to embed
--
--  RETURNS: void
--
--  NOTES: Embeds the character into the packet, based on the users encoding type
--  
------------------------------------------------------------------------------*/
void embedPacket(struct send_tcp * send, struct options * opt, int ch)
{
    switch(opt->encodeType)
    {
        case 0:
            send->ip.id =ch;
            break;
        case 1:
        case 2: 
            send->tcp.seq = ch;
            break;
        case 3:
           send->tcp.urg_ptr = ch;
    }
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   sendPacket
--
--  DATE:       September 22, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: sendPacket(int * socket, struct send_tcp * send, struct sockaddr_in * sin)
--                              socket  - the socket to send the packet through
--                              send    - the structure containing the tcp packet to embed the character into
--                              sin     - the addressing info used by the socket
--
--  RETURNS: void
--
--  NOTES: Sends the packet over the socket
--  
------------------------------------------------------------------------------*/
void sendPacket(int * socket, struct send_tcp * send, struct sockaddr_in * sin)
{
    sendto(*socket, send, 40, 0, (struct sockaddr*)sin, sizeof(*sin));
    close(*socket);
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   finalizePacket
--
--  DATE:       September 22, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: finalizePacket(struct send_tcp * send, struct pseudo_header * ph)
--                              send    - the structure containing the tcp packet to embed the character into
--                              ph      - a psuedoheader structure containg the IP packet header
--
--  RETURNS: void
--
--  NOTES: Calculates checksum and finishes populating the packet data
--  
------------------------------------------------------------------------------*/
void finalizePacket(struct send_tcp * send, struct pseudo_header * ph)
{
    send->ip.check = in_cksum((unsigned short *)&send->ip, 20);
    ph->source_address = send->ip.saddr;
    ph->dest_address = send->ip.daddr;
    ph->placeholder = 0;
    ph->protocol = IPPROTO_TCP;
    ph->tcp_length = htons(20);
    bcopy((char *)&send->tcp, (char *)&ph->tcp, 20);
    send->tcp.check = in_cksum((unsigned short *)ph, 32);
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   initializeReadSocket
--
--  DATE:       September 22, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: initializeReadSocket(int * recv)
--                      recv - the socket to read from
--
--  RETURNS: void
--
--  NOTES: Opens a socket for reading. Exit program on failure.
--  
------------------------------------------------------------------------------*/
void initializeReadSocket(int * recv)
{
    *recv = socket(AF_INET, SOCK_RAW, 6);
    if(*recv < 0)
    {
        perror("receive socket cannot be open. Are you root?");
        exit(1);
    }
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   initializeWriteSocket
--
--  DATE:       September 22, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: initializeWriteSocket(struct sockaddr_in * sin, struct send_tcp * send, int * sock)
--                                          sin      - the socket addressing information
--                                          send     - the structure containing the tcp packet 
--                                          sock     - the socket to open for writing
--
--  RETURNS: void
--
--  NOTES: Opens a socket for writing. Exit program on failure.
--  
------------------------------------------------------------------------------*/
void initializeWriteSocket(struct sockaddr_in * sin, struct send_tcp * send, int * sock)
{
    sin->sin_family = AF_INET;
    sin->sin_port = send->tcp.source;
    sin->sin_addr.s_addr = send->ip.daddr; 
    *sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(*sock < 0)
    {
        perror("send socket cannot be open. Are you root?");
        exit(1);
    }  
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   initializeTCPPacket
--
--  DATE:       September 22, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: initializeTCPPacket(struct send_tcp * send, struct options * opt)
--                                  send - the structure containing the tcp packet to initialize
--                                  opt  - the structure containing the users arguments
--
--  RETURNS: void
--
--  NOTES: Populates the TCP packet with relevent data based on user args and static content
--  
------------------------------------------------------------------------------*/
void initializeTCPPacket(struct send_tcp * send, struct options * opt)
{
    send->ip.ihl = 5;
    send->ip.version = 4;
    send->ip.tos = 0;
    send->ip.tot_len = htons(40);
    send->ip.frag_off = 0;
    send->ip.ttl = 64; 
    send->ip.protocol = IPPROTO_TCP;
    send->ip.check = 0;
    send->ip.saddr = opt->source_host;
    send->ip.daddr = opt->dest_host;

    if(opt->source_port == 0) 
    {
        send->tcp.source = 1+(int)(10000.0*rand()/(RAND_MAX+1.0));
    } else {
        send->tcp.source = htons(opt->source_port);
    }
    
    send->tcp.dest = htons(opt->dest_port);     
    send->tcp.ack_seq = 0;
    send->tcp.res1 = 0;
    send->tcp.doff = 5;
    send->tcp.fin = 0;
    send->tcp.syn = 1;
    send->tcp.rst = 0;
    send->tcp.psh = 0;
    send->tcp.ack = 0;
    send->tcp.urg = 0;
    send->tcp.res2 = 0;
    send->tcp.window = htons(512);
    send->tcp.check = 0;
    send->ip.id =(int)(255.0*rand()/(RAND_MAX+1.0)); // *** sets id to random if you don't use the pid encoder
    send->tcp.seq = 1+(int)(10000.0*rand()/(RAND_MAX+1.0)); // *** sets seq to random if you don't use the seq encoder
    send->tcp.urg_ptr = 0;
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   openFile
--
--  DATE:       September 22, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: openFile(char *filename, FILE** input, int write)
--                          filename    - the filename of the file to open
--                          input       - the file pointer to set to the open file
--                          write       - an int used as a boolean. 1 opens in write mode, 0 in read
--
--  RETURNS: void
--
--  NOTES: Opens a file in either read or write mode.
--  
------------------------------------------------------------------------------*/
void openFile(char *filename, FILE** input, int write)
{
    if (write == 1) 
    {
        *input=fopen(filename,"wb"); // check if file can be opened
    } else {
        *input=fopen(filename,"rb");
    }
    
    if(*input== NULL) // check if file can be opened
    {
        exit(1);
    }
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   checkRoot
--
--  DATE:       September 22, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: checkRoot()
--
--  RETURNS: void
--
--  NOTES: Checks if user is root. Program exit if not root.
--  
------------------------------------------------------------------------------*/
void checkRoot()
{
    if(geteuid() !=0) // if not root
    {
        printf("Run as root!");
        exit(0);
    }
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   selectOpts
--
--  DATE:       September 22, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: selectOpts(struct options * opt, int * argc, char ** argv)
--                          opt      - structure containing user args
--                          argc     - number of arguments
--                          argv     - the program argument array
--
--  RETURNS: void 
--
--  NOTES: goes through program switches, setting arguments in program
--  
------------------------------------------------------------------------------*/
void selectOpts(struct options * opt, int * argc, char ** argv)
{
    int ops = 0;
    while ((ops = getopt(*argc, argv, "d:s:f:le:t:u:")) != -1) 
    {
        switch (ops) 
        {
        case 'd': //dest ip
            opt->dest_host = host_convert(optarg);
            break;
        case 's': //source ip
            opt->source_host = host_convert(optarg);
            break;
        case 'f': // file
            strcpy(opt->filename, optarg);
            break;
        case 'l': // server
            opt->server = 1;
            break;
        case 'e': // encoding
            opt->encodeType = atoi(optarg);
            break;
        case 't': // dest port
            opt->dest_port = atoi(optarg);
            break;
        case 'u': // source port
            opt->source_port = atoi(optarg);
            break;
        default:
            usage(argv[0]);
            exit(0);
        }
    }
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   validateOpts
--
--  DATE:       September 22, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: validateOpts(struct options * opt)
--                      opt - structure containing user args
--
--  RETURNS: void
--
--  NOTES: Ensures the user is using the arguments correctly. Program exit on failure.
--  
------------------------------------------------------------------------------*/
void validateOpts(struct options * opt)
{
    int invalid = 0; //anything above 0 is invalid
    char error[80] = {0};

    if (opt->encodeType > 3)
    {
        invalid++;
        strcpy(error, "Encoding type must be 0, 1, 2, 3");
    }

    if (strcmp(opt->filename, "") == 0) //if there is no dest port or file to read/write to
    {
        invalid++;
        strcpy(error, "Must have Okay!file to read/write"); 
    }

    if (!(opt->server)) // if you are the client
    {
        if (opt->dest_port == 0 || opt->dest_host == 0) // and if there is no dest port or destination ip  
        {
            invalid++;
            strcpy(error, "Client must have destination ip");   
        }
    } else { // if you are the server
        if (opt->source_host == 0 ) // and if there is no source ip
        {
            invalid++;
            strcpy(error, "Server must have source ip");    
        }
    }

    if (invalid > 0)
    {
        printf("%s\n", error);
        exit(0);
    }
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   host_convert
--
--  DATE:       November 15, 1996
--
--  DESIGNERS:  Craig Rowland  
--
--  PROGRAMMER: Craig Rowland
--
--  INTERFACE: host_convert(char *hostname)
--                  hostname - the name of the host to convert
--
--  RETURNS: unsigned int - the internet address of the hostname
--
--  NOTES: Converts a hostname into internet address format
--  
------------------------------------------------------------------------------*/
unsigned int host_convert(char *hostname)
{
    static struct in_addr i;
    struct hostent *h;
    i.s_addr = inet_addr(hostname);

    if(i.s_addr == -1)
    {
        h = gethostbyname(hostname);
        if(h == NULL)
        {
            exit(0);
        }
        bcopy(h->h_addr, (char *)&i.s_addr, h->h_length);
    }
    return i.s_addr;
} 

/*------------------------------------------------------------------------------
--
--  FUNCTION:   in_cksum
--
--  DATE:       November 15, 1996
--
--  DESIGNERS:  Craig Rowland  
--
--  PROGRAMMER: Craig Rowland
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
unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
    register long       sum;        
    u_short         oddbyte;
    register u_short    answer;

    sum = 0;
    while (nbytes > 1)  {
        sum += *ptr++;
        nbytes -= 2;
    } 

    if (nbytes == 1) {
        oddbyte = 0;        
        *((u_char *) &oddbyte) = *(u_char *)ptr;   
        sum += oddbyte;
    }

    sum  = (sum >> 16) + (sum & 0xffff);    
    sum += (sum >> 16);         
    answer = ~sum;      
    return(answer);
} 

/*------------------------------------------------------------------------------
--
--  FUNCTION:   usage
--
--  DATE:       September 22, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner 
--
--  INTERFACE: usage(char *progname)
--              progname - the name of the program being run
--
--  RETURNS: void 
--
--  NOTES: Tells the user how to use this program
--  
------------------------------------------------------------------------------*/
void usage(char *progname)
{
    printf("Client Covert TCP usage: %s -d dest_ip -f filename -t dest_port [-u source_port] [-s source_ip] [-e encodeType]\n", progname);
    printf("Server Covert TCP usage: %s -l -s source_ip -f filename [-t dest_port] [-e encodeType] \n", progname);
    printf("-d dest_ip      - Host to send data to.\n");
    printf("-s source_ip    - Host where you want the data to originate from.\n");
    printf("-u port         - IP source port you want data to appear from. (Random by default) \n");
    printf("-t port         - IP source port you want data to go to. (Port 80 by Default)\n");
    printf("-f filename     - Name of the file to encode and transfer.\n");
    printf("-l              - Server mode to allow receiving of data.\n");
    printf("-e              - Optional encoding type, values of 0, 1, 2, and 3\n");
    printf("                    - 1. Encode data a byte at a time in the IP packet ID. [DEFAULT]\n");
    printf("                    - 2. Encode data a byte at a time in the packet sequence number.\n");
    printf("                    - 3. DECODE data a byte at a time from the ACK field. Only available to server!\n");
    printf("                        NOTE - This is used in conjucction with a remote server, where data is being encoded using (2)!\n");
    printf("                    - 4. Encode data a byte at a time from the URG-PTR field.\n");
    exit(0);
} 
