#include "backjake.h"
/*---------------------------------------------------------------------------------------
--  Source File:    utils.c -  This file contains some miscellaneous functions
--                     used by the rest of the application.
--
--  Functions:      See function headers below 
--  Date:           June 3, 2011
--                
--  Designer:       Jacob Miner
--              
--  Programmer:     Jacob Miner
--
---------------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------------------------
--
--  Function:   This is a public doman checksum function as per RFC 791
--
--  Interface:  unsigned short csum (unsigned short *ptr, int nbytes)  
--
--              unsigned short *ptr - a pointer to an array that contains the payload
--                            over which the checksum is calculated. 
--              int nbytes - the total length of the header 
--
--  Returns:    The calaculated checksum
--
--  Designer:   RFC 791
--
--  Programmer: RFC 791
--
--  Notes:
--  See RFC 791 for more information
--  
--  
-------------------------------------------------------------------------------------------------*/
unsigned short csum (unsigned short *ptr, int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum = 0;
    while (nbytes > 1) 
    {
        sum+=*ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) 
    {
        oddbyte=0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }
 
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return(answer);
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   resolve_host
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  char * resolve_host (const char *host)
--                      host - the host to resolve
--
--  RETURNS:    char *  - the host
--
--  NOTES:      resolves host to an ip address
--  
------------------------------------------------------------------------------*/
char * resolve_host(const char *host)
{
    struct addrinfo hints, *res;
    int errcode;
    static char addrstr[100];
    void *ptr;

    memset (&hints, 0, sizeof (hints));
    hints.ai_family = PF_UNSPEC;	// Handle IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;
    
    errcode = getaddrinfo (host, NULL, &hints, &res);
    if (errcode != 0)
    {
	perror ("getaddrinfo");
	return NULL;
    }
    
    while (res)
    {
	inet_ntop (res->ai_family, res->ai_addr->sa_data, addrstr, 100);

	switch (res->ai_family)
        {
	    case AF_INET:
	      ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
	    break;
	    case AF_INET6:
	      ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
	    break;
        }
	inet_ntop (res->ai_family, ptr, addrstr, 100);
	printf ("IPv%d address: %s (%s)\n", res->ai_family == PF_INET6 ? 6 : 4,
              addrstr, res->ai_canonname);
	res = res->ai_next;
    }
    return addrstr;
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   GetIPAddress
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  GetIPAddress()
--
--  RETURNS:    char * - the ip address of the host machine's interface
--
--  NOTES:      Opens a socket using the specified interface, then gets the ip address
--  
------------------------------------------------------------------------------*/
char * GetIPAddress()
{
	int sd;
 	struct sockaddr_in *addrp;
	struct ifreq ifrcopy;
	char *interface = "p2p1", *ip_addr;
	
	if ((sd = socket( PF_INET, SOCK_DGRAM, 0 )) < 0)
 	{
  		printf("Cannot create socket :%s\n", strerror(errno));
  		return (NULL);
 	}
	
    interface = "p2p1";

 	memset (&ifrcopy,0,sizeof( struct ifreq ) );
 	strncpy (ifrcopy.ifr_name, interface, IFNAMSIZ); //IFNAMSIZ is defined in "if.h"

 	if( ioctl (sd, SIOCGIFADDR, &ifrcopy) < 0 )
 	{
  		printf("Cannot obtain IP address of '%s' :%s\n", interface, strerror(errno));
  		close(sd);
  		return (NULL);
 	}
 	else
	{
		addrp = (struct sockaddr_in *)&(ifrcopy.ifr_addr);
		ip_addr = inet_ntoa(addrp->sin_addr);
	}
	close(sd);
 	return (ip_addr);
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   usage
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  usage(char ** argv)
--                      argv - the program's arguments
--
--  RETURNS:    void
--
--  NOTES:      tells the user how to use the program
--  
------------------------------------------------------------------------------*/
void usage(char ** argv)
{
    printf("you done goofed!\n");
    printf("try again!\n");
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   XOR
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  XOR(char * command)
--                  command - the string to be encoded using XOR
--
--  RETURNS:    void
--
--  NOTES:      XORs the string to encode it.
--  
------------------------------------------------------------------------------*/
void XOR(char * command)
{
    size_t l = 0;
    
    for(l = 0; l < strlen(command); l++)
    {
        if (command[l] != 21)
            command[l] = command[l] ^ XORVALUE;
        else
            command[l] = 0;
    }
    printf("command: %s\n", command);
}

/*------------------------------------------------------------------------------
--
--  FUNCTION:   length
--
--  DATE:       October 5, 2014
--
--  DESIGNERS:  Jacob Miner  
--
--  PROGRAMMER: Jacob Miner
--
--  INTERFACE:  length(char* command)
--                  command - the array to get the length of
--
--  RETURNS:    int - the length of the array
--
--  NOTES:      calculates the length of an array pointer
--  
------------------------------------------------------------------------------*/
int length(char* command)
{
    size_t m = 0;
    while(1)
    {
        if(command[m] == 0 || command[m] == -1 || command[m] == '\n')
            return m;
        m++;
    }
}
