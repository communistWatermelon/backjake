/*---------------------------------------------------------------------------------------
--	Source File:		utils.c -  This file contains some miscellaneous functions
--					   used by the rest of the application.
--
--	Functions:		See function headers below 

--	Date:			June 3, 2011
--
--	Revisions:		(Date and nic_description)
--					
--	Designer:		Aman Abdulla
--				
--	Programmer:		Aman Abdulla
--
---------------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------------------------
--
--	Function:	This is a public doman checksum function as per RFC 791
--
--	Interface:	unsigned short csum (unsigned short *ptr, int nbytes)  
--
--				unsigned short *ptr - a pointer to an array that contains the payload
--						      over which the checksum is calculated. 
--				int nbytes - the total length of the header 
--
--	Returns:	The calaculated checksum
--
--	Date:		November 23, 2006
--
--	Revisions:	(Date and Description)
--
--	Designer:	RFC 791
--
--	Programmer:	RFC 791
--
--	Notes:
--	See RFC 791 for more information
-- 	
--	
-------------------------------------------------------------------------------------------------*/


#include "tscan.h"

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

/*-----------------------------------------------------------------------------------------------
--
--	Function:	This function resolves and IP or Hostname supplied by user
--
--	Interface:	char * resolve_host (const char *host)
--
--				const char *host - a pointer to a string containing and IP address
--						   or a hostname. 
--	Returns:	A string containing the IP address 
--
--	Date:		June 3, 2011
--
--	Revisions:	(Date and Description)
--
--	Designer:	Aman Abdulla
--
--	Programmer:	Aman Abdulla
--
--	Notes:
--	The function receives a string containing an IP address or a hostname and uses the 
--	getaddrinfo function to resolve it into an IP address. The function can resolve 
--	both IPv4 and IPv6 addresses.
-- 	
--	
-------------------------------------------------------------------------------------------------*/

char * resolve_host (const char *host)
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

/*-----------------------------------------------------------------------------------------------
--
--	Function:	This function gets the IP address bound to an active NIC
--
--	Interface:	char * GetIPAddress (void)
--
--				
--	Returns:	A string containing the IP address bound to the first active NIC 
--
--	Date:		June 3, 2011
--
--	Revisions:	(Date and Description)
--
--	Designer:	Aman Abdulla
--
--	Programmer:	Aman Abdulla
--
--	Notes:
--	This function uses the pcap_lookupdev to obtain address of the first active NIC.
--	The ioctl function is used to obtain the IP address of the active NIC.
-- 	
--	
-------------------------------------------------------------------------------------------------*/

char * GetIPAddress (void)
{
	int sd;
 	struct sockaddr_in *addrp;
	struct ifreq ifrcopy;
	char *interface = "p2p1", *ip_addr;
	//char errbuf[PCAP_ERRBUF_SIZE];
	
	
	if ((sd = socket( PF_INET, SOCK_DGRAM, 0 )) < 0)
 	{
  		printf("Cannot create socket :%s\n", strerror(errno));
  		return (NULL);
 	}
	
    interface = "p2p1";
    // Get the first active NIC
    // interface = pcap_lookupdev(errbuf);
	// if(interface == NULL)
	// { 
	//     fprintf(stderr,"%s\n",errbuf); 
	//     exit(1); 
	// }

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


// Usage Message

void usage (char **argv)
{
      fprintf(stderr, "Usage: %s -d <Destination IP> -p [Destination Port] -h [Source IP] -s [Source Port]\n", argv[0]);
      fprintf(stderr, "You must specify the destination address!\n");
      exit(1);
}