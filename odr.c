#include "unp.h"
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<linux/if_arp.h>


#define	IF_NAME		16	/* same as IFNAMSIZ    in <net/if.h> */
#define	IF_HADDR	 6	/* same as IFHWADDRLEN in <net/if.h> */

#define	IP_ALIAS  	 1	/* hwa_addr is an alias */

#define	ODR_PATH			"/tmp/ndixit_odr"
#define SERVER_PATH			"/tmp/ndixit_server"
#define	SERVER_PORT			51838
#define	CLIENT_PATH			"/tmp/ndixit_client_XXXXXX"
#define	PROTOCOL_NO			51838
#define PF_PACKET_HEADER	14 
#define ETH0             	"eth0"
#define LOOPBACK            "lo"  

int		broadcast_id = 1;
char    client_msg_recv[100];
char    server_msg_recv[100];
int		ephemeral_port = 1;

struct hwa_info {
	char    if_name[IF_NAME];		/* interface name, null terminated */
	char    if_haddr[IF_HADDR];		/* hardware address */
	int     if_index;				/* interface index */
	short   ip_alias;				/* 1 if hwa_addr is an alias IP address */
	struct  sockaddr  *ip_addr;		/* IP address */
	struct  hwa_info  *hwa_next;	/* next of these structures */
};

typedef struct route_table_	{
   
	char		mac_nh[IF_HADDR];
	int			hopcount;
	uint32_t	timestamp;
	int			if_index_nh;
	long		cano_ip_dest;
	int			status;
	int			broadcast_id;
}route_table;

typedef struct rreq_info_ {
	long	server_ip;
	int		port_no;
	int		route_rediscovery;
	int     rreq_sent_already;  
}rreq_info;

typedef struct rrep_info_{
	long	destination_ip;
	long	source_ip;
	int     source_port_no; 
	int		destination_port_no;
	int		route_rediscovery;
	int     broadcast_id_recovered;
	int     hop_count;
}rrep_info;

typedef struct print_hdr_details_{
	int	   type;
	char   source_ip[100];
	int    source_port;
    char   dest_ip[100];
    int    dest_port;  	
	int    hop_count;
	char   msg[100];   
}print_hdr_details;

typedef struct packet_info_{
	long	destination_ip;
	long	source_ip;
	int     source_port_no; 
	int		destination_port_no;
	int		route_rediscovery;
	int     broadcast_id_recovered;
	int     hop_count;
}packet_info;

typedef struct port_path_ {
	int		port_num;
	char	sun_path[25];
	int		status;
}port_path;

typedef enum aodv_msg_type_  {
	PF_PACKET_RREQ,
	PF_PACKET_RREP,
	PF_PACKET_APP_PAYLOAD,
	PF_PACKET_NONE
}aodv_msg_type;

typedef enum route_table_status_	{
	ROUTE_VALID,
	ROUTE_INVALID,
	ROUTE_NONE
}route_table_status;

typedef enum staleness_entry__ {
	A_STALE_ENTRY,
	NOT_A_STALE_ENTRY,
	NONE_STALE
}staleness_entry;


typedef enum payload_destination_info_ {
	DESTINATION_SERVER,
	DESTINATION_CLIENT,
	DESTINATION_NONE
}payload_destination_info;

/* function prototypes */
struct hwa_info	*get_hw_addrs();
struct hwa_info	*Get_hw_addrs();
void   free_hwa_info(struct hwa_info *);

/* Count digits in the number */
int
count_digits(int	number) {
	int		count = 0;
	while(number != 0) {
		number = number/10;
		count++;
	}
	return count;
}

int
count_digits_long(long	number) {
	int		count = 0;
	while(number != 0) {
		number = number/10;
		count++;
	}
	return count;
}

int
fill_packet_data(char	*packet,
				 int	data,
				 int	data_size) {
	int		no_digit = count_digits(data);
	int		iter;
	
	iter = data_size - 1;
	for(; iter >= 0; iter --) {
		packet[iter] = data%10 + 48;
		data = data/10;
	}
	
	for(iter = 0; iter < data_size - no_digit; iter ++) {
		packet[iter] = 48;
	}
	return 0;
}

int
fill_packet_data_long(char	*packet,
					  long	data,
					  int	data_size) {
	int		no_digit = count_digits_long(data);
	int		iter;
	
	iter = data_size - 1;
	for(; iter >= 0; iter --) {
		packet[iter] = data%10 + 48;
		data = data/10;
	}
	
	for(iter = 0; iter < data_size - no_digit; iter ++) {
		packet[iter] = 48;
	}
	return 0;
}


uint32_t 
get_timestamp_current_seconds(){
	
	uint32_t ts;
	struct timeval tv;
	Gettimeofday(&tv, NULL);
	ts = (tv.tv_sec*1000) + (tv. tv_usec/1000);
	return (ts);
	
}




/*Function Reterives Details from Packet Header Recieved*/
int
get_packet_data(char	*packet,
				int		data_size,
				int		*ret) {
	char	number[30];
	int		iter;
	
	for (iter = 0; iter < data_size; iter++) {
		number[iter] = packet[iter];
	}
	number[iter] = '\0';
	*ret = atoi(number);
	return 0;
}

/*Function Reterives Details from Packet Header Recieved*/
int
get_packet_data_long(char	*packet,
					int		data_size,
					long	*ret) {
	char	number[30];
	int		iter;
	
	for (iter = 0; iter < data_size; iter++) {
		number[iter] = packet[iter];
	}
	number[iter] = '\0';
	*ret = atol(number);
	return 0;
}

struct hwa_info *
get_hw_addrs()	{
	struct hwa_info	*hwa, *hwahead, **hwapnext;
	int		sockfd, len, lastlen, alias, nInterfaces, i;
	char	*buf, lastname[IF_NAME], *cptr;
	struct ifconf	ifc;
	struct ifreq	*ifr, *item, ifrcopy;
	struct sockaddr	*sinptr;

	sockfd = Socket(AF_INET, SOCK_DGRAM, 0);

	lastlen = 0;
	len = 100 * sizeof(struct ifreq);	/* initial buffer size guess */
	for ( ; ; ) {
		buf = (char*) Malloc(len);
		ifc.ifc_len = len;
		ifc.ifc_buf = buf;
		if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
			if (errno != EINVAL || lastlen != 0)
				err_sys("ioctl error");
		} else {
			if (ifc.ifc_len == lastlen)
				break;		/* success, len has not changed */
			lastlen = ifc.ifc_len;
		}
		len += 10 * sizeof(struct ifreq);	/* increment */
		free(buf);
	}

	hwahead = NULL;
	hwapnext = &hwahead;
	lastname[0] = 0;
    
	ifr = ifc.ifc_req;
	nInterfaces = ifc.ifc_len / sizeof(struct ifreq);
	for(i = 0; i < nInterfaces; i++)  {
		item = &ifr[i];
 		alias = 0; 
		hwa = (struct hwa_info *) Calloc(1, sizeof(struct hwa_info));
		memcpy(hwa->if_name, item->ifr_name, IF_NAME);		/* interface name */
		hwa->if_name[IF_NAME-1] = '\0';
				/* start to check if alias address */
		if ( (cptr = (char *) strchr(item->ifr_name, ':')) != NULL)
			*cptr = 0;		/* replace colon will null */
		if (strncmp(lastname, item->ifr_name, IF_NAME) == 0) {
			alias = IP_ALIAS;
		}
		memcpy(lastname, item->ifr_name, IF_NAME);
		ifrcopy = *item;
		*hwapnext = hwa;		/* prev points to this new one */
		hwapnext = &hwa->hwa_next;	/* pointer to next one goes here */

		hwa->ip_alias = alias;		/* alias IP address flag: 0 if no; 1 if yes */
                sinptr = &item->ifr_addr;
		hwa->ip_addr = (struct sockaddr *) Calloc(1, sizeof(struct sockaddr));
	        memcpy(hwa->ip_addr, sinptr, sizeof(struct sockaddr));	/* IP address */
		if (ioctl(sockfd, SIOCGIFHWADDR, &ifrcopy) < 0)
                          perror("SIOCGIFHWADDR");	/* get hw address */
		memcpy(hwa->if_haddr, ifrcopy.ifr_hwaddr.sa_data, IF_HADDR);
		if (ioctl(sockfd, SIOCGIFINDEX, &ifrcopy) < 0)
                          perror("SIOCGIFINDEX");	/* get interface index */
		memcpy(&hwa->if_index, &ifrcopy.ifr_ifindex, sizeof(int));
	}
	free(buf);
	return(hwahead);	/* pointer to first structure in linked list */
}

void
free_hwa_info(struct hwa_info *hwahead)	{
	struct hwa_info	*hwa, *hwanext;

	for (hwa = hwahead; hwa != NULL; hwa = hwanext) {
		free(hwa->ip_addr);
		hwanext = hwa->hwa_next;	/* can't fetch hwa_next after free() */
		free(hwa);			/* the hwa_info{} itself */
	}
}
/* end free_hwa_info */

struct hwa_info *
Get_hw_addrs()	{
	struct hwa_info	*hwa;

	if ( (hwa = get_hw_addrs()) == NULL)
		err_quit("get_hw_addrs error");
	return(hwa);
}

int
fill_source_mac(char	*dest,
				int		if_index)	{
	struct hwa_info		*hwa;
	int					status = 1;
	
	
	hwa = Get_hw_addrs();
	for (; hwa != NULL; hwa = hwa->hwa_next) {
		if(hwa->if_index == if_index) {
			memcpy((void*)dest, (void*)hwa->if_haddr, ETH_ALEN);
			status = 0;
			break;
		}
	}
	return status;
}

int
check_local_mac(char *if_name) {
	int	status;
	status = strncmp(if_name, LOOPBACK, strlen(LOOPBACK));
	if(status == 0){
		return(1);
	}
	
	status = strncmp(if_name, ETH0, strlen(ETH0));
	if(status == 0){
		return(1);
	}
	return(0);	
}

void 
get_vmname(long ip,
			char	*dest) {
	struct hostent 		*hesrc = NULL;
	struct in_addr 		ipsrc;
	socklen_t			len = 0;
	
	//printf("\nIP address in function is %s\n", ip_addr);
	//Inet_pton(AF_INET, ip_addr , &ipsrc);
	ipsrc.s_addr = ip;
	len = sizeof(ipsrc);
    hesrc = gethostbyaddr((const char *)&ipsrc, len, AF_INET);
	strncpy(dest, hesrc->h_name, strlen(hesrc->h_name));
}

int 
get_header_print_details(char *packet_soc_msg){
    
	int 				status;
	char 				selfhostname[10];
	long 				source_ip, dest_ip;
	print_hdr_details   hdr_details;
    char 				src_name[100] = {0};
	char				dest_name[100] = {0};
	char   				*ptr;
	int    				i;
	
    status = gethostname(selfhostname, 10);
	if (status < 0) {
		printf("\nUnable to get hostname of the machine !!!");
	}
	
	
    status = get_packet_data(packet_soc_msg+PF_PACKET_HEADER, 1, &(hdr_details.type));
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill type !!! Exiting ...",status);
		return -1;
	}
	status = get_packet_data(packet_soc_msg+PF_PACKET_HEADER+1, 5, &(hdr_details.source_port));
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill Port Number !!! Exiting ...",status);
		return -1;
	}
	
	status = get_packet_data_long(packet_soc_msg+PF_PACKET_HEADER+6, 10, &source_ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address of Source !!! Exiting ...",status);
		return 0;
	}
	inet_ntop(AF_INET, &(source_ip), (hdr_details.source_ip), INET_ADDRSTRLEN);
	get_vmname(source_ip, src_name);
		
	status = get_packet_data(packet_soc_msg+PF_PACKET_HEADER+16, 5, &(hdr_details.dest_port));
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill Port Number !!! Exiting ...",status);
		return -1;
	}
	 
	status = get_packet_data_long(packet_soc_msg+PF_PACKET_HEADER+21, 10, &dest_ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
		return 0;
	}
	inet_ntop(AF_INET, &(dest_ip), (hdr_details.dest_ip), INET_ADDRSTRLEN);
	get_vmname(dest_ip, dest_name);
	
	status = get_packet_data(packet_soc_msg+PF_PACKET_HEADER+31, 5, &(hdr_details.hop_count));
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill Hop Count !!! Exiting ...",status);
		return -1;
	}

	if(hdr_details.type == PF_PACKET_RREQ) {
		fflush(stdout);
		printf("\n=================================================");
		printf("\nODR at node %s sending RREQ to ", selfhostname);

		ptr = packet_soc_msg;
		i = IF_HADDR;
		do {
			printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
		} while (--i > 0);
			
		printf("\nPacket from Source: %s to Destination: %s",src_name, dest_name);
		printf("\n=================================================");
	} else if(hdr_details.type == PF_PACKET_RREP) {
		fflush(stdout);
		printf("\n=================================================");
		printf("\nODR at node %s sending RREP to ", selfhostname);

		ptr = packet_soc_msg;
		i = IF_HADDR;
		do {
			printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
		} while (--i > 0);
			
		printf("\nPacket from Source: %s to Destination: %s", dest_name, src_name);
		printf("\n=================================================");
	} else if(hdr_details.type == PF_PACKET_APP_PAYLOAD) {
		memcpy((void*)(hdr_details.msg), (void*)packet_soc_msg+PF_PACKET_HEADER+50, 35);
		fflush(stdout);
		printf("\n=================================================");
		printf("\nODR at node %s sending application PAYLOAD to ", selfhostname);

		ptr = packet_soc_msg;
		i = IF_HADDR;
		do {
			printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
		} while (--i > 0);
			
		printf("\nPacket from Source: %s to Destination: %s",src_name, dest_name);
		printf("\nPayload MSG is - %s",(hdr_details.msg));
		printf("\n=================================================");
	}
	
	return 0;
}


int
extract_info_from_unix(char			*unix_domain_msg,
					   rreq_info	*rreq,
					   packet_info  *packet_msg) {
	int				status;
	char			serverip[INET_ADDRSTRLEN];
	
	
	status = get_packet_data_long(unix_domain_msg+5, 10, &(rreq->server_ip));
	if (status != 0) {
		printf("\nStatus = %d, Unable to get server IP address !!! Exiting ...",status);
		return -1;
	}
	packet_msg->destination_ip = rreq->server_ip;
	inet_ntop(AF_INET, (void *)&(rreq->server_ip), serverip, INET_ADDRSTRLEN);
	//printf("\nThe server IP address is %s", serverip);
		
	status = get_packet_data(unix_domain_msg+15, 5, &(rreq->port_no));
	if (status != 0) {
		printf("\nStatus = %d, Unable to get port number !!! Exiting ...",status);
		return -1;
	}
	packet_msg->destination_port_no=rreq->port_no;
	//printf("\nThe server port number is %d", port_no);
	
	
	status = get_packet_data(unix_domain_msg+20, 1, &(rreq->route_rediscovery));
	if (status != 0) {
		printf("\nStatus = %d, Unable to get route rediscovery flag !!! Exiting ...",status);
		return -1;
	}
	packet_msg->route_rediscovery=rreq->route_rediscovery;
	
	memcpy((void*)client_msg_recv, (void*)(unix_domain_msg+21), 5);

	//printf("\nThe server port number is %d", route_rediscovery);
	return 0;
}


int
flood_rreq (int				packet_soc_fd,
			struct hwa_info	*hwa,
			char			*msg,
			int				src_ifindex) {
	int					status, hop_count;
	struct sockaddr_ll 	pack_addr;
	struct ethhdr 		*eh = (struct ethhdr *)msg;
	unsigned char 		dest_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	
	for(; hwa != NULL; hwa = hwa->hwa_next) {
		status = check_local_mac(hwa->if_name);
		if(status == 1)	{
			continue;
		}
		
		if (hwa->if_index == src_ifindex) {
			continue;
		}
		
		pack_addr.sll_family   = PF_PACKET;
		pack_addr.sll_protocol = htons(PROTOCOL_NO);
		pack_addr.sll_ifindex  = hwa->if_index;
		pack_addr.sll_hatype   = ARPHRD_ETHER;
		pack_addr.sll_pkttype  = PACKET_OTHERHOST;
		pack_addr.sll_halen    = ETH_ALEN;
		
		pack_addr.sll_addr[0]  = 0xFF;
		pack_addr.sll_addr[1]  = 0xFF;
		pack_addr.sll_addr[2]  = 0xFF;
		pack_addr.sll_addr[3]  = 0xFF;
		pack_addr.sll_addr[4]  = 0xFF;
		pack_addr.sll_addr[5]  = 0xFF;
		pack_addr.sll_addr[6]  = 0x00;
		pack_addr.sll_addr[7]  = 0x00;
	
	    memcpy((void*)msg, (void*)dest_mac, ETH_ALEN);
		memcpy((void*)(msg+ETH_ALEN), (void*)hwa->if_haddr, ETH_ALEN);
		eh->h_proto = PROTOCOL_NO;
	
		status = get_packet_data(msg+PF_PACKET_HEADER+31, 5, &hop_count);
		if (status != 0) {
			printf("\nStatus = %d, Unable to get route rediscovery flag !!! Exiting ...",status);
			return -1;
		}
		
		status = fill_packet_data(msg+PF_PACKET_HEADER+31, hop_count+1, 5);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Hop Count !!! Exiting ...",status);
			return -1;
		}
		
		status = sendto(packet_soc_fd, msg, 100, 0, (struct sockaddr *)&pack_addr, sizeof(pack_addr));
		if (status <= 0) {
			printf("\nError in sending RREQ !!!\n");
			return -1;
		}
	}
	return 0;
}

int
generate_packet_soc_msg(packet_info			*packet_msg,
						long 				my_ip,
						char				*msg,
						int					client_port){
							
	    int  status;
		
		status = fill_packet_data(msg+PF_PACKET_HEADER+1, client_port, 5);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Port Number !!! Exiting ...",status);
			return -1;
		}
		
		status = fill_packet_data_long(msg+PF_PACKET_HEADER+6, my_ip, 10);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill IP address !!! Exiting ...",status);
			return -1;
		}
		
		/* Fill in the destination ip address and port no */
		status = fill_packet_data(msg+PF_PACKET_HEADER+16, packet_msg->destination_port_no, 5);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Port Number of Destination !!! Exiting ...",status);
			return -1;
		}
		
		status = fill_packet_data_long(msg+PF_PACKET_HEADER+21, packet_msg->destination_ip, 10);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
			return -1;
		}
		
		/* Initialize RREQ hop count to 1 */
		status = fill_packet_data(msg+PF_PACKET_HEADER+31, 0, 5);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Hop Count !!! Exiting ...",status);
			return -1;
		}
		
		status = fill_packet_data(msg+PF_PACKET_HEADER+36, packet_msg->route_rediscovery, 1);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Rediscovery Flag !!! Exiting ...",status);
			return -1;
		}
		
		/* Fill in the broad cast Id  */
		status = fill_packet_data(msg+PF_PACKET_HEADER+37, broadcast_id, 5);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Broadcast Id !!! Exiting ...",status);
			return -1;
		}
		
		status = fill_packet_data(msg+PF_PACKET_HEADER+42, 0, 5);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Payload Bytes !!! Exiting ...",status);
			return -1;
		}
		
		status = fill_packet_data(msg+PF_PACKET_HEADER+47, 0, 3);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Payload Bytes !!! Exiting ...",status);
			return -1;
		}						
							
        msg[64] = '\0';
		return 0;					
}							

int
gen_send_rreq(int				packet_soc_fd,
			  struct hwa_info	*hwa,
			  rreq_info			*rreq,
			  long 				my_ip,
			  int				client_port) {
	char				msg[100];
	int					status;
	struct sockaddr_ll 	pack_addr;
	struct ethhdr 		*eh = (struct ethhdr *)msg;
	unsigned char 		dest_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	
	for(; hwa != NULL; hwa = hwa->hwa_next) {
		status = check_local_mac(hwa->if_name);
		if(status == 1)	{
			continue;
		}
		
		pack_addr.sll_family   = PF_PACKET;
		pack_addr.sll_protocol = htons(PROTOCOL_NO);
		pack_addr.sll_ifindex  = hwa->if_index;
		pack_addr.sll_hatype   = ARPHRD_ETHER;
		pack_addr.sll_pkttype  = PACKET_OTHERHOST;
		pack_addr.sll_halen    = ETH_ALEN;
		
		pack_addr.sll_addr[0]  = 0xFF;
		pack_addr.sll_addr[1]  = 0xFF;
		pack_addr.sll_addr[2]  = 0xFF;
		pack_addr.sll_addr[3]  = 0xFF;
		pack_addr.sll_addr[4]  = 0xFF;
		pack_addr.sll_addr[5]  = 0xFF;
		pack_addr.sll_addr[6]  = 0x00;
		pack_addr.sll_addr[7]  = 0x00;
		
		memcpy((void*)msg, (void*)dest_mac, ETH_ALEN);
		memcpy((void*)(msg+ETH_ALEN), (void*)hwa->if_haddr, ETH_ALEN);
		eh->h_proto = PROTOCOL_NO;
		
		status = fill_packet_data(msg+PF_PACKET_HEADER, PF_PACKET_RREQ, 1);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill type RREQ !!! Exiting ...",status);
			return -1;
		}
		
		status = fill_packet_data(msg+PF_PACKET_HEADER+1, client_port, 5);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Port Number !!! Exiting ...",status);
			return -1;
		}
		
		status = fill_packet_data_long(msg+PF_PACKET_HEADER+6, my_ip, 10);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill IP address !!! Exiting ...",status);
			return -1;
		}
		
		/* Fill in the destination ip address and port no */
		status = fill_packet_data(msg+PF_PACKET_HEADER+16, rreq->port_no, 5);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Port Number of Destination !!! Exiting ...",status);
			return -1;
		}
		
		status = fill_packet_data_long(msg+PF_PACKET_HEADER+21, rreq->server_ip, 10);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
			return -1;
		}
		
		/* Initialize RREQ hop count to 1 */
		status = fill_packet_data(msg+PF_PACKET_HEADER+31, 1, 5);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Hop Count !!! Exiting ...",status);
			return -1;
		}
		
		status = fill_packet_data(msg+PF_PACKET_HEADER+36, rreq->route_rediscovery, 1);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Rediscovery Flag !!! Exiting ...",status);
			return -1;
		}
		
		/* Fill in the broad cast Id  */
		status = fill_packet_data(msg+PF_PACKET_HEADER+37, broadcast_id, 5);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Broadcast Id !!! Exiting ...",status);
			return -1;
		}
		
		status = fill_packet_data(msg+PF_PACKET_HEADER+42, 0, 5);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Payload Bytes !!! Exiting ...",status);
			return -1;
		}
		rreq->rreq_sent_already=0;
		status = fill_packet_data(msg+PF_PACKET_HEADER+47, rreq->rreq_sent_already, 1);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Payload Bytes !!! Exiting ...",status);
			return -1;
		}
		
		status = fill_packet_data(msg+PF_PACKET_HEADER+48, 0, 2);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Payload Bytes !!! Exiting ...",status);
			return -1;
		}
		msg[64] = '\0';
		
		status = sendto(packet_soc_fd, msg, 100, 0, (struct sockaddr *)&pack_addr, sizeof(pack_addr));
		if (status <= 0) {
			printf("\nError in sending RREQ !!!\n");
			return -1;
		}	
        get_header_print_details(msg);	
	}
	broadcast_id++;
	return 0;
}



int
check_route_staleness(int staleness_parameter,
					  uint32_t route_timestamp){
					  
	uint32_t current_timestamp=get_timestamp_current_seconds();
	//printf("\ncurrent_timestamp:-%d",current_timestamp);
	//printf("\nroute_timestamp:-%d",route_timestamp);
	uint32_t route_difference=current_timestamp-route_timestamp;
	//printf("\nroute_difference:-%d",route_difference);
	if(route_difference<staleness_parameter){
		return(NOT_A_STALE_ENTRY);
	} else {
		return(A_STALE_ENTRY);
	}
}



int
gen_update_send_rrep(int					packet_soc_fd,
					 char		        	*packet_soc_msg,
					 rrep_info	    		*rrep,
					 int					hop_flag,
					 route_table			*table) {
	
	int					status;
   	long				ip = 0;
	struct ethhdr 		*eh = (struct ethhdr *)packet_soc_msg;
	struct sockaddr_ll	pack_addr;
	int    iter;
	
	//memcpy((void*)packet_soc_msg, (void*)pack_addr->sll_addr, ETH_ALEN);
	status = get_packet_data_long(packet_soc_msg+PF_PACKET_HEADER+6, 10, &ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address !!! Exiting ...",status);
		return -1;
	}
	
	for(iter = 1; iter <= 10; iter++) {
		if (ip == table[iter].cano_ip_dest &&
			table[iter].status == ROUTE_VALID) {
		
		    pack_addr.sll_family   = PF_PACKET;
			pack_addr.sll_protocol = htons(PROTOCOL_NO);
			pack_addr.sll_ifindex  = table[iter].if_index_nh;
			pack_addr.sll_hatype   = ARPHRD_ETHER;
			pack_addr.sll_pkttype  = PACKET_OTHERHOST;
			pack_addr.sll_halen    = ETH_ALEN;
		    
			memcpy((void*)packet_soc_msg, (void*)table[iter].mac_nh, ETH_ALEN);
			status = fill_source_mac(packet_soc_msg+ETH_ALEN, table[iter].if_index_nh);
			if (status != 0) {
				printf("\nStatus = %d, Unable to fill source MAC address !!!", status);
				return 0;
			}  
			//memcpy((void*)(packet_soc_msg+ETH_ALEN), (void*)source_mac, ETH_ALEN);
			eh->h_proto = PROTOCOL_NO;
			
			pack_addr.sll_addr[0]  = table[iter].mac_nh[0];
			pack_addr.sll_addr[1]  = table[iter].mac_nh[1];
			pack_addr.sll_addr[2]  = table[iter].mac_nh[2];
			pack_addr.sll_addr[3]  = table[iter].mac_nh[3];
			pack_addr.sll_addr[4]  = table[iter].mac_nh[4];
			pack_addr.sll_addr[5]  = table[iter].mac_nh[5];
			pack_addr.sll_addr[6]  = 0x00;
			pack_addr.sll_addr[7]  = 0x00;
		}
	}
	
	status = fill_packet_data(packet_soc_msg+PF_PACKET_HEADER, PF_PACKET_RREP, 1);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill type RREP !!! Exiting ...",status);
		return -1;
	}
	
	/* RREP at intermediate node */
    if(hop_flag == 0)	{	
		status = get_packet_data(packet_soc_msg+PF_PACKET_HEADER+31, 5, &(rrep->hop_count));
		if (status != 0) {
			printf("\nStatus = %d, Unable to get route rediscovery flag !!! Exiting ...",status);
			return -1;
		}
		
		/* Hop count is to be filled in RREP */	
		status = fill_packet_data(packet_soc_msg+PF_PACKET_HEADER+31, rrep->hop_count+1, 5);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Hop Count !!! Exiting ...",status);
			return -1;
		}
	} else {
		/* RREP at destination */
		rrep->hop_count = 1;
		status = fill_packet_data(packet_soc_msg+PF_PACKET_HEADER+31, rrep->hop_count, 5);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Hop Count !!! Exiting ...",status);
			return -1;
		}
	}
	
    status = sendto(packet_soc_fd,packet_soc_msg, 100, 0,
					(struct sockaddr *)&pack_addr, sizeof(pack_addr));
	if (status <= 0) {
		printf("\nError in sending RREP !!!\n");
		return -1;
	}	
	get_header_print_details(packet_soc_msg);
	return 0;
}

int
update_route_entry(route_table			*table,
				   int					hop_count,
				   long					ip,
				   struct sockaddr_ll	*pack_addr) {
	int		iter;
	
	for(iter = 1; iter <= 10; iter++) {
		if (ip == table[iter].cano_ip_dest) {
			if (table[iter].hopcount > hop_count) {
				
				/* Update entry */
				table[iter].hopcount = hop_count;
				table[iter].if_index_nh = pack_addr->sll_ifindex;
				memcpy((void*)table[iter].mac_nh, (void*)pack_addr->sll_addr, ETH_ALEN);
				table[iter].mac_nh[0] = pack_addr->sll_addr[0];
				table[iter].mac_nh[1] = pack_addr->sll_addr[1];
				table[iter].mac_nh[2] = pack_addr->sll_addr[2];
				table[iter].mac_nh[3] = pack_addr->sll_addr[3];
				table[iter].mac_nh[4] = pack_addr->sll_addr[4];
				table[iter].mac_nh[5] = pack_addr->sll_addr[5];
				table[iter].status 	  = ROUTE_VALID;
				table[iter].timestamp = get_timestamp_current_seconds();
				break;
			}
		}
	}
	return 0;
}

int
print_route_table(route_table	*table)
{
	int		iter,i;
	char 	str[INET_ADDRSTRLEN];
    char   	*ptr;
	
	printf("\nRouting Table");
	printf("\n===================================================================");
	printf("\nDestination IP\tNext Hop\tNext IF_INDEX\tHop Count\tTimestamp");
	printf("\n===================================================================\n");
	for(iter = 1; iter <= 10; iter++) {
	
		if(table[iter].status == ROUTE_VALID){
			inet_ntop(AF_INET, &table[iter].cano_ip_dest, str, INET_ADDRSTRLEN);
			printf("\n%s\t",str);
			ptr = (char *)table[iter].mac_nh;
			i = IF_HADDR;
			do {
				printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
			} while (--i > 0);
			printf("\t%d",table[iter].if_index_nh);
			printf("\t%d",table[iter].hopcount);
			printf("\t\t%d",table[iter].timestamp);		
		}
	}
	printf("\n=================================================================");
	return 0;
}

int
update_routing_table(route_table			*table,
					 char					*msg,
					 struct sockaddr_ll 	*pack_addr) {
	int		status, packet_type, hop_count;
	long	ip = 0;
	
	/* Check packet type */
	status = get_packet_data(msg+PF_PACKET_HEADER, 1, &packet_type);
	if (status != 0) {
		printf("\nStatus = %d, Unable to get route rediscovery flag !!! Exiting ...",status);
		return -1;
	}
	
	status = get_packet_data(msg+PF_PACKET_HEADER+31, 5, &hop_count);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill Hop Count !!! Exiting ...",status);
		return -1;
	}
		
	if (packet_type == PF_PACKET_RREQ) {
		
		/* Extract source address */	
		status = get_packet_data_long(msg+PF_PACKET_HEADER+6, 10, &ip);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill IP address !!! Exiting ...",status);
			return -1;
		}
		
		
	} else if (packet_type == PF_PACKET_RREP) {
		
		/* Extract destination address */
		status = get_packet_data_long(msg+PF_PACKET_HEADER+21, 10, &ip);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill IP address !!! Exiting ...",status);
			return -1;
		}
		
	} else if (packet_type == PF_PACKET_APP_PAYLOAD) {
		/* TBD */
		status = get_packet_data_long(msg+PF_PACKET_HEADER+6, 10, &ip);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill IP address !!! Exiting ...",status);
			return -1;
		}
	}
	
	status = update_route_entry(table, hop_count, ip, pack_addr);
	if (status != 0) {
		printf("\nUnable to update routing entry !!!");
		return -1;
	}
	return 0;
}


int
gen_update_send_payload(int				packet_soc_fd,
						char		   	*packet_soc_msg,
						route_table		*table,
						int				hop_flag) {
	
	int					status;
   	long				ip = 0;
	struct ethhdr 		*eh = (struct ethhdr *)packet_soc_msg;
	struct sockaddr_ll	pack_addr;
	int    				hop_count;
	int    				iter;
	
	//memcpy((void*)packet_soc_msg, (void*)pack_addr->sll_addr, ETH_ALEN);
	status = get_packet_data_long(packet_soc_msg+PF_PACKET_HEADER+21, 10, &ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address !!! Exiting ...",status);
		return -1;
	}
	
	for(iter = 1; iter <= 10; iter++) {
		if (ip == table[iter].cano_ip_dest &&
			table[iter].status == ROUTE_VALID) {
		
		    pack_addr.sll_family   = PF_PACKET;
			pack_addr.sll_protocol = htons(PROTOCOL_NO);
			pack_addr.sll_ifindex  = table[iter].if_index_nh;
			pack_addr.sll_hatype   = ARPHRD_ETHER;
			pack_addr.sll_pkttype  = PACKET_OTHERHOST;
			pack_addr.sll_halen    = ETH_ALEN;
		    
			memcpy((void*)packet_soc_msg, (void*)table[iter].mac_nh, ETH_ALEN);
			status = fill_source_mac(packet_soc_msg+ETH_ALEN, table[iter].if_index_nh);
			if (status != 0) {
				printf("\nStatus = %d, Unable to fill source MAC address !!!", status);
				return 0;
			}
			eh->h_proto = PROTOCOL_NO;
						
			pack_addr.sll_addr[0]  = table[iter].mac_nh[0];
			pack_addr.sll_addr[1]  = table[iter].mac_nh[1];
			pack_addr.sll_addr[2]  = table[iter].mac_nh[2];
			pack_addr.sll_addr[3]  = table[iter].mac_nh[3];
			pack_addr.sll_addr[4]  = table[iter].mac_nh[4];
			pack_addr.sll_addr[5]  = table[iter].mac_nh[5];
			pack_addr.sll_addr[6]  = 0x00;
			pack_addr.sll_addr[7]  = 0x00;
			
			break;
		}
	}
	
	status = fill_packet_data(packet_soc_msg+PF_PACKET_HEADER, PF_PACKET_APP_PAYLOAD, 1);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill type RREP !!! Exiting ...",status);
		return -1;
	}
		
	if(hop_flag == 0)	{	
		status = get_packet_data(packet_soc_msg+PF_PACKET_HEADER+31, 5, &(hop_count));
		if (status != 0) {
			printf("\nStatus = %d, Unable to get route rediscovery flag !!! Exiting ...",status);
			return -1;
		}
		
		/* Hop count is to be filled in RREP */	
		status = fill_packet_data(packet_soc_msg+PF_PACKET_HEADER+31, hop_count+1, 5);
	 	if (status != 0) {
			printf("\nStatus = %d, Unable to fill Hop Count !!! Exiting ...",status);
			return -1;
		}
	} else {
		/* RREP at destination */
		hop_count = 1;
		status = fill_packet_data(packet_soc_msg+PF_PACKET_HEADER+31, hop_count, 5);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill Hop Count !!! Exiting ...",status);
			return -1;
		}	
	}
	
	get_header_print_details(packet_soc_msg);
	status = sendto(packet_soc_fd, packet_soc_msg, 100, 0,
					(struct sockaddr *)&pack_addr, sizeof(pack_addr));
	if (status <= 0) {
		printf("\nError in sending payload !!!\n");
		return -1;
	}
	
	return 0;
}


int
check_routing_table_staleness(route_table	*table,
							  char			*msg,
							  int			packet_soc_fd,
							  int			staleness_parameter,
							  int           route_flag){
	int					iter, status;
	long				src_ip = 0, dst_ip = 0;
	struct sockaddr_ll	pack_addr;
	struct ethhdr 		*eh = (struct ethhdr *)msg;
	int					valid_entry = 0;
    staleness_entry     staleness;
	int					hop_flag;
	char				ipadd[50];
	
	/* Check the destination IP routing entry */
	status = get_packet_data_long(msg+PF_PACKET_HEADER+21, 10, &dst_ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address !!! Exiting ...",status);
		return -1;
	}
     
	for(iter = 1; iter <= 10; iter++) {
		if (dst_ip == table[iter].cano_ip_dest &&
			table[iter].status == ROUTE_VALID) {
			
			staleness=check_route_staleness(staleness_parameter,table[iter].timestamp);
			if(staleness == NOT_A_STALE_ENTRY){
				inet_ntop(AF_INET, &(dst_ip), ipadd, INET_ADDRSTRLEN);
				printf("\nRouting Table entry for %s is NOT stale", ipadd);
				status = fill_packet_data(msg+PF_PACKET_HEADER+31, table[iter].hopcount+1, 5);
				if (status != 0) {
					printf("\nStatus = %d, Unable to fill Hop Count !!! Exiting ...",status);
					return -1;
				}
				valid_entry = 1;
				break;
			} else {
				valid_entry = 0;
				inet_ntop(AF_INET, &(dst_ip), ipadd, INET_ADDRSTRLEN);
				printf("\nRouting Table entry for %s is stale", ipadd);
				table[iter].status = ROUTE_INVALID;
				table[iter].hopcount = 10000;
				status = fill_packet_data(msg+PF_PACKET_HEADER+36, 1, 1);
				if (status != 0) {
					printf("\nStatus = %d, Unable to fill Rediscovery Flag !!! Exiting ...",status);
					return -1;
				}
				break;
			}
		}		
	}
	
	if (valid_entry == 0) {
		return 0;
	}
	
	/* Check the source IP routing entry */
	status = get_packet_data_long(msg+PF_PACKET_HEADER+6, 10, &src_ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address !!! Exiting ...",status);
		return -1;
	}
	
	for(iter = 1; iter <= 10; iter++) {
		if (src_ip == table[iter].cano_ip_dest &&
			table[iter].status == ROUTE_VALID) {
			
			pack_addr.sll_family   = PF_PACKET;
			pack_addr.sll_protocol = htons(PROTOCOL_NO);
			pack_addr.sll_ifindex  = table[iter].if_index_nh;
			pack_addr.sll_hatype   = ARPHRD_ETHER;
			pack_addr.sll_pkttype  = PACKET_OTHERHOST;
			pack_addr.sll_halen    = ETH_ALEN;
		
          	memcpy((void*)msg, (void*)table[iter].mac_nh, ETH_ALEN);
			status = fill_source_mac(msg+ETH_ALEN, table[iter].if_index_nh);
			if (status != 0) {
				printf("\nStatus = %d, Unable to fill source MAC address !!!", status);
				return 0;
			}  
			eh->h_proto = PROTOCOL_NO;
			
			pack_addr.sll_addr[0]  = table[iter].mac_nh[0];
			pack_addr.sll_addr[1]  = table[iter].mac_nh[1];
			pack_addr.sll_addr[2]  = table[iter].mac_nh[2];
			pack_addr.sll_addr[3]  = table[iter].mac_nh[3];
			pack_addr.sll_addr[4]  = table[iter].mac_nh[4];
			pack_addr.sll_addr[5]  = table[iter].mac_nh[5];
			pack_addr.sll_addr[6]  = 0x00;
			pack_addr.sll_addr[7]  = 0x00;
		
			break;
		}		
	}
	
	if(route_flag == 0) {
		status = fill_packet_data(msg+PF_PACKET_HEADER, PF_PACKET_RREP, 1);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill type RREP !!! Exiting ...",status);
			return -1;
		}
	
		printf("\nRoute to destination present, sending RREP from non-destination ODR");
		get_header_print_details(msg);
		status = sendto(packet_soc_fd, msg, 100, 0,
						(struct sockaddr *)&pack_addr, sizeof(pack_addr));
		if (status <= 0) {
			printf("\nError in sending RREP !!!\n");
			return -1;
		}
	} else {
		status = fill_packet_data(msg+PF_PACKET_HEADER+48, DESTINATION_SERVER, 1);
		if (status != 0) {
			printf("\nStatus = %d, Unable to fill type RREP !!! Exiting ...",status);
			return -1;
		}
					
		memcpy((void*)msg+PF_PACKET_HEADER+50, (void*)client_msg_recv, 5);					
		msg[69] = '\0';
		hop_flag = 1;
		status = gen_update_send_payload(packet_soc_fd, msg,
										 table, hop_flag);
		if (status != 0) {
			printf("\nStatus = %d, Unable to send Payload message !!!", status);
			return 0;	
		}
	}
	return 1;
}


int
update_broadcast_id(route_table			*table,
					char				*msg) {
	int		status, iter, broadcast_id;
	long	ip;
	
	/* Extract source address */
	status = get_packet_data_long(msg+PF_PACKET_HEADER+6, 10, &ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to get IP address !!! Exiting ...",status);
		return -1;
	}

	status = get_packet_data(msg+PF_PACKET_HEADER+37, 5, &broadcast_id);
	if (status != 0) {
		printf("\nStatus = %d, Unable to get Broadcast Id !!! Exiting ...",status);
		return -1;
	}
		
	for(iter = 1; iter <= 10; iter++) {
		if (ip == table[iter].cano_ip_dest) {
			table[iter].broadcast_id = broadcast_id;
			return 0;
		}
	}
	return -1;
}

int
is_valid_broadcast(route_table		*table,
				   char				*msg) {
	int		status, iter, broadcast_id;
	long	ip;

	/* Extract source address */
	status = get_packet_data_long(msg+PF_PACKET_HEADER+6, 10, &ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to get IP address !!! Exiting ...",status);
		return -1;
	}

	status = get_packet_data(msg+PF_PACKET_HEADER+37, 5, &broadcast_id);
	if (status != 0) {
		printf("\nStatus = %d, Unable to get Broadcast Id !!! Exiting ...",status);
		return -1;
	}
		
	for(iter = 1; iter <= 10; iter++) {
		if (ip == table[iter].cano_ip_dest) {
			if (table[iter].broadcast_id < broadcast_id) {
				return 1;
			} else {
				return 0;
			}
			break;
		}
	}
	return 1;
}


int
print_port_path(port_path	*port_table) {
	int		iter;
	
	fflush(stdout);
	printf("\n=========================================");
	printf("\nPort-number\t\tSun-path");
	printf("\n=========================================");
	for (iter = 0; iter < 100; iter++) {
		if (port_table[iter].status == 1) {
			printf("\n%d\t\t%s", port_table[iter].port_num, port_table[iter].sun_path);
		}
	}
	printf("\n=========================================");
	return 0;
}

int 
port_to_path_conv(port_path				*port_table,
				  struct sockaddr_un 	*recv,
				  int					*ret) {
	int		 iter;
	
	for (iter = 0; iter < 100; iter++) {
		if (port_table[iter].status == 0) {
			port_table[iter].port_num = ++ephemeral_port;
			memcpy((void*)port_table[iter].sun_path, (void*)recv->sun_path,
					strlen(recv->sun_path));
			*ret = ephemeral_port;
			port_table[iter].status = 1;
			return 0;
		}
	}	
	return -1;
}



int
invoke_server(int		unix_soc_fd,
			  char		*msg,
			  char		*packet_soc_msg){
	
	int					status;
	struct sockaddr_un 	servaddr, recvdata;
	char				msg_send[100],msg_recv[100];
	socklen_t			len = 0;  
    long                source_ip;
	
	bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_LOCAL;
    strcpy(servaddr.sun_path, SERVER_PATH);
	
	//send_msg_len = strlen(client_msg_recv);
	status = get_packet_data_long(packet_soc_msg+PF_PACKET_HEADER+6, 10, &source_ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
		return 0;
	}
	
	status = fill_packet_data(msg_send, unix_soc_fd, 5);
	if (status != 0) {
		printf("\nFailed to fill socket FD in packet !!!");
		return -1;
	}

	
	status = fill_packet_data_long(msg_send+5, source_ip , 10);
	if (status != 0) {
		printf("\nFailed to fill socket ip in packet !!!");
		return -1;
	}
	
	status = fill_packet_data(msg_send+15, SERVER_PORT, 5);
	if (status != 0) {
		printf("\nFailed to fill server port in packet !!!");
		return -1;
	}
	
	memcpy((void*)msg_send+20, (void*)client_msg_recv, 5);
	msg_send[25]='\0';
	printf("\nsent msg to server:-%s",msg_send);
	
	
	status = sendto(unix_soc_fd, msg_send, 50, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
	if (status <= 0) {
		printf("\nError in sendto API !!!\nExiting ...\n");
	}

	len = sizeof(recv);
	status = recvfrom(unix_soc_fd, msg_recv, 100, 0, (struct sockaddr *)&recvdata, &len);
	if (status <= 0) {
		printf("\nError in receiving message from server !!!\n");
		return -1;
	}
	
	memcpy((void*)msg,(void*)msg_recv+20, 29);
	
	return 0; 
}



int
invoke_client(int					unix_soc_fd,
			  char					*packet_soc_msg,
			  port_path				*port_table) {
	int					status, iter;
	struct sockaddr_un 	cliaddr;
	char				msg_recv[100];
	long                source_ip;
	int					port_num;
	int					is_valid = 0;
		
	status = get_packet_data_long(packet_soc_msg+PF_PACKET_HEADER+6, 10, &source_ip);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
		return -1;
	}
	
	status = fill_packet_data(msg_recv, unix_soc_fd, 5);
	if (status != 0) {
		printf("\nFailed to fill socket FD in packet !!!");
		return -1;
	}
	
	status = fill_packet_data_long(msg_recv+5, source_ip , 10);
	if (status != 0) {
		printf("\nFailed to fill socket ip in packet !!!");
		return -1;
	}
	
	status = fill_packet_data(msg_recv+15, SERVER_PORT, 5);
	if (status != 0) {
		printf("\nFailed to fill server port in packet !!!");
		return -1;
	}
		
	memcpy((void*)msg_recv+20, (void*)packet_soc_msg+PF_PACKET_HEADER+50, 35);
	msg_recv[51]='\0';
	

	/* Extract sun path from port table */
	status = get_packet_data(packet_soc_msg+PF_PACKET_HEADER+1, 5, &port_num);
	if (status != 0) {
		printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
		return -1;
	}
	
	bzero(&cliaddr, sizeof(cliaddr));
    cliaddr.sun_family = AF_UNIX;
	for (iter = 0; iter < 100; iter++) {
		if (port_table[iter].status == 1 &&
			port_table[iter].port_num == port_num) {
			memcpy((void*)cliaddr.sun_path , (void*)port_table[iter].sun_path,
					strlen(port_table[iter].sun_path));
			port_table[iter].status = 0;
			is_valid = 1;
			break;
		}
	}
	
	if (is_valid == 0) {
		return -1;
	}
	
	status = sendto(unix_soc_fd, msg_recv, 100, 0,
					(struct sockaddr *)&cliaddr, sizeof(cliaddr));
	if (status <= 0) {
		printf("\nError in sendto API !!!\nExiting ...\n");
	}
	
	return 0;
}


	
int
main (int argc,
	  char **argv)	{
	struct hwa_info		*hwa, *hwahead;
	int    				i, packet_soc_fd;
	int     			unix_soc_fd, status = 0;
    struct sockaddr_un 	servaddr, recv;
	char				fname[30], unix_domain_msg[100];
	socklen_t			len = 0;
	struct sockaddr_ll 	pack_addr;
	char			    packet_soc_msg[100];
	rreq_info			rreq;
	rrep_info           rrep;
	packet_info         packet_msg; 
    int					packet_type;
	int                 payload_destination;
	long				dest_ip, my_ip = 0, source_ip;
	struct sockaddr_in	*temp;
	char				server_msg[100];
	route_table 		routing_table[11];
	struct hostent 		*host_IP = NULL;
	struct in_addr 		**addr_list = NULL;
	char				temp_hostname[10];
	int					staleness_parameter;
	int                 hop_flag=0;
    int 				route_rediscovery_flag=0; 
	int					client_port = 0;
	port_path			port_table[100];
	
	
	if(argc != 2){
		printf("Invalid Argument:-<Enter Staleness Parameter>\n");
		return 0;
	}
	staleness_parameter=(atoi(argv[1])*1000);
	fflush(stdout);
	printf("Staleness parameter in %d seconds ",staleness_parameter/1000);
	
	for (i = 0; i < 100; i++) {
		port_table[i].status = 0;
	}
	
	/* Initialize routing table */
	for(i = 1; i <= 10; i++)	{ 
		snprintf(temp_hostname, 10, "vm%d", i);
		host_IP = gethostbyname(temp_hostname);
		if (host_IP == NULL) { 
			printf("\nNo IP address associated with %s\n", temp_hostname); 
		} else {
			addr_list = (struct in_addr **)host_IP->h_addr_list;
		}
		routing_table[i].cano_ip_dest = (**addr_list).s_addr;
		routing_table[i].status = ROUTE_INVALID;
		routing_table[i].hopcount = 999;
		routing_table[i].broadcast_id	=	0;
	}
	
	hwahead = hwa = Get_hw_addrs();
	for (; hwa != NULL; hwa = hwa->hwa_next) {
		
		status = strncmp(hwa->if_name, ETH0, strlen(ETH0));
		if(status == 0)	{
			temp = (struct sockaddr_in *)hwa->ip_addr;
			my_ip = temp->sin_addr.s_addr;
		}
	}
	/*free_hwa_info(hwahead);*/
	
	/* Create unix domain socket */
    unix_soc_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(unix_soc_fd < 0) {
		printf("\nError in creating domain socket !!!\nExiting client ...\n");
		return 0;
	}

	strcpy(fname, ODR_PATH);
	
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;
    strcpy(servaddr.sun_path, fname);
	unlink(servaddr.sun_path);
	
    status = bind(unix_soc_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	if (status < 0) {
		printf("\nError in bind !!!\n");
		return 0;
	}
	
	/* Create packet socket */
	packet_soc_fd = socket(AF_PACKET, SOCK_RAW, PROTOCOL_NO);
	if (packet_soc_fd < 0) {
		printf("\nError in creating socket !!!");
	}
	
	/* Monitor unix socket and packet socket */
	while(1) {
		fd_set 		mon_fd;

		FD_ZERO(&mon_fd);
		FD_SET(unix_soc_fd, &mon_fd);
		FD_SET(packet_soc_fd, &mon_fd);
		
		if (unix_soc_fd > packet_soc_fd) {
			status = select(unix_soc_fd + 1, &mon_fd, NULL, NULL, NULL);
		} else {
			status = select(packet_soc_fd + 1, &mon_fd, NULL, NULL, NULL);
		}
		if (status < 0) {
			printf("\nStatus = %d, Unable to monitor sockets !!! Exiting ...",status);
			return 0;
		}

		if (FD_ISSET(unix_soc_fd, &mon_fd)) {

			/* Request from client on same machine */
			len = sizeof(recv);
			status = recvfrom(unix_soc_fd, unix_domain_msg, 100, 0, (struct sockaddr *)&recv, &len);
			if (status <= 0) {
				printf("\nError in receiving packet from UNIX domain socket !!!\n");
			}
			
			status = port_to_path_conv(port_table, &recv, &client_port);
			if (status != 0) {
				printf("\nStatus = %d, Unable to store sun path for client !!!\nExiting !!!", status);
				return -1;
			}
			
			printf("\nClient request adding mapping from Port to Sun-path");
			status = print_port_path(port_table);
			if (status != 0) {
				printf("\nStatus = %d, Unable to print port-sunpath table !!!", status);
			}
			
		    /* Extract info from UNIX domain message */
			status = extract_info_from_unix(unix_domain_msg, &rreq, &packet_msg);
			if (status != 0) {
				printf("\nStatus = %d, Unable to extract info from UNIX domain message !!!", status);
				return 0;
			}
									
		    status = generate_packet_soc_msg(&packet_msg, my_ip, packet_soc_msg, client_port);
			if (status != 0) {
				printf("\nStatus = %d, Unable to form packet message !!!", status);
				return 0;
			} 
			
            if(my_ip==packet_msg.destination_ip){
			fflush(stdout);
			printf("\n Server and Client on same Virtual Machine");
			
			status = invoke_server(unix_soc_fd, server_msg, packet_soc_msg);
					if (status != 0) {
						printf("\nStatus = %d, Unable to communicate with server !!!\nExiting",status);
						return 0;
					}
			memcpy((void*)packet_soc_msg+PF_PACKET_HEADER+50, (void*)server_msg, 35);		
			
			status = invoke_client(unix_soc_fd, packet_soc_msg, port_table);				
					continue;
			
			}
			
			
            status = check_routing_table_staleness(routing_table, packet_soc_msg, 
													packet_soc_fd, staleness_parameter, 1);
			if (status == 1) {
				/* Entry present, RREP sent */
				continue;
			}			
			
			/* Generate RREQ message */			
			status = gen_send_rreq(packet_soc_fd, hwahead, &rreq, my_ip, client_port);
			if (status != 0) {
				printf("\nUnable to send broadcase message !!!");
				return 0;
			}			
		} else if (FD_ISSET(packet_soc_fd, &mon_fd)) {
			
			/* Request from ODR from another machine */
			len = sizeof(pack_addr);
			status = recvfrom(packet_soc_fd, packet_soc_msg, 100, 0, (struct sockaddr *)&pack_addr, &len);
			if (status <= 0) {
				printf("\nError in receiving packet from packet domain socket !!!\n");
			}
			
			/* Check packet type */
			status = get_packet_data(packet_soc_msg+PF_PACKET_HEADER, 1, &packet_type);
			if (status != 0) {
				printf("\nStatus = %d, Unable to get route rediscovery flag !!! Exiting ...",status);
				return -1;
			}
			
			if (packet_type == PF_PACKET_RREQ) {
			
			    fflush(stdout);
				printf("\n--------------------");
			    printf("\nA RREQ is Received..");
				printf("\n--------------------");
				fflush(stdout);
				printf("\nRREQ updating routing entry for source");			
				/* Update routing table for source address */
                 status = update_routing_table(routing_table, packet_soc_msg, &pack_addr);
				 if (status != 0) {
					 printf("\nUnable to update routing table !!!\nExiting !!!\n");
					 return 0;
				}   
				
				status = print_route_table(routing_table);
				  if (status != 0) {
					 printf("\nUnable to print routing table !!!\nExiting !!!\n");
					 return 0;
				}
				
				/* Check destination node */
				status = get_packet_data_long(packet_soc_msg+PF_PACKET_HEADER+21, 10, &dest_ip);
				if (status != 0) {
					printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
					return 0;
				}
                
                status = get_packet_data(packet_soc_msg+PF_PACKET_HEADER+36, 1, &route_rediscovery_flag);
				if (status != 0) {
					printf("\nStatus = %d, Unable to fill Rediscovery Flag !!! Exiting ...",status);
					return -1;
				}                
 				
				if (dest_ip == my_ip) {
					printf("\nRREQ has reached the destination");
					hop_flag = 1;
					status = gen_update_send_rrep(packet_soc_fd, packet_soc_msg,
												  &rrep, hop_flag, routing_table);
												 
					if (status != 0) {
						printf("\nStatus = %d, Unable to send RREP message !!!", status);
						return 0;	
					}
					continue;
				}				
				
				if(route_rediscovery_flag == 0){
				
					status = check_routing_table_staleness(routing_table, packet_soc_msg, 
															packet_soc_fd, staleness_parameter, 0);
					if (status == 1) {
					 /* Entry present, RREP sent */
						continue;
					}
          		}	
				    				 
				/* Check broadcast validity */
				status = is_valid_broadcast(routing_table, packet_soc_msg);
				if (status == 0) {
					/* RREQ already sent, ignore this one */
					printf("\nAvoiding re-broadcast of RREQ packet !!!");
					continue;
				}			
				
				status = update_broadcast_id(routing_table, packet_soc_msg);
				if (status != 0) {
					printf("\nUnable to modify broadcast_id of source !!!");
				}
				
				/* Flood if all conditions fail */
			    status = flood_rreq(packet_soc_fd, hwahead, packet_soc_msg, pack_addr.sll_ifindex);
				if (status != 0) {
					printf("\nStatus = %d, Unable to flood RREQ message !!!", status);
					return 0;
				}
			} else if (packet_type == PF_PACKET_RREP) {
			    
				fflush(stdout);
			    printf("\n--------------------");
			    printf("\nA RREP is Received..");
				printf("\n--------------------"); 
				/* Update routing table for destination address */
				fflush(stdout);
				printf("\nRREP updating the routing entry for destination");
				status = update_routing_table(routing_table, packet_soc_msg, &pack_addr);
				if (status != 0) {
					 printf("\nUnable to update routing table !!!\nExiting !!!\n");
					 return 0;
				}
				
				status = print_route_table(routing_table);
				  if (status != 0) {
					 printf("\nUnable to print routing table !!!\nExiting !!!\n");
					 return 0;
				}
				
				/* Check for source node */
				status = get_packet_data_long(packet_soc_msg+PF_PACKET_HEADER+6, 10, &source_ip);
				if (status != 0) {
					printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
					return 0;
				}
                
				/* Check if RREP is back at source */
				if (source_ip == my_ip) {
					printf("\nRREP message has reached back to the source");
					status = fill_packet_data(packet_soc_msg+PF_PACKET_HEADER+48, DESTINATION_SERVER, 1);
					if (status != 0) {
						printf("\nStatus = %d, Unable to fill type RREP !!! Exiting ...",status);
						return -1;
					}
					
					memcpy((void*)packet_soc_msg+PF_PACKET_HEADER+50, (void*)client_msg_recv, 5);					
					packet_soc_msg[69] = '\0';
					hop_flag = 1;
					status = gen_update_send_payload(packet_soc_fd, packet_soc_msg,
													routing_table, hop_flag);
					if (status != 0) {
						printf("\nStatus = %d, Unable to send Payload message !!!", status);
						return 0;	
					}
					continue;					
				}
				
				/* Send RREP back to sender */
				hop_flag = 0;
				status = gen_update_send_rrep(packet_soc_fd, packet_soc_msg,
											  &rrep, hop_flag, routing_table);
				if (status != 0) {
					printf("\nStatus = %d, Unable to send RREP message !!!", status);
					return 0;
				}						
			} else if (packet_type == PF_PACKET_APP_PAYLOAD) {
			    
				fflush(stdout);
				printf("\n------------------------------------");
			    printf("\nA APPLICATION PAYLOAD is Received..");
				printf("\n------------------------------------"); 
			   
				
			    status = get_packet_data(packet_soc_msg+PF_PACKET_HEADER+48, 1, &payload_destination);
				if (status != 0) {
					printf("\nStatus = %d, Unable to get route rediscovery flag !!! Exiting ...",status);
					return -1;
				}  
				
				hop_flag = 0;
				status = get_packet_data_long(packet_soc_msg+PF_PACKET_HEADER+6, 10, &source_ip);
				if (status != 0) {
					printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
					return 0;
				}
				
				status = get_packet_data_long(packet_soc_msg+PF_PACKET_HEADER+21, 10, &dest_ip);
				if (status != 0) {
					printf("\nStatus = %d, Unable to fill IP address of Destination !!! Exiting ...",status);
					return 0;
				}
				
				if(payload_destination == DESTINATION_SERVER) {
					fflush(stdout);
					printf("\nFree RREQ's updating the routing table");
					status = update_routing_table(routing_table, packet_soc_msg, &pack_addr);
					if (status != 0) {
						printf("\nUnable to update routing table !!!\nExiting !!!\n");
						return 0;
					}
				
					status = print_route_table(routing_table);
					if (status != 0) {
						printf("\nUnable to print routing table !!!\nExiting !!!\n");
						return 0;
					}
				}
			    
				if (dest_ip == my_ip && payload_destination == DESTINATION_SERVER){
				    
                    hop_flag = 1;					
					memcpy((void*)client_msg_recv,(void*)packet_soc_msg+PF_PACKET_HEADER+50, 10);	
					status = invoke_server(unix_soc_fd, server_msg, packet_soc_msg);
					if (status != 0) {
						printf("\nStatus = %d, Unable to communicate with server !!!\nExiting",status);
						return 0;
					}
				
					status = fill_packet_data_long(packet_soc_msg+PF_PACKET_HEADER+6, dest_ip, 10);
					if (status != 0) {
						printf("\nStatus = %d, Unable to fill type RREP !!! Exiting ...",status);
						return -1;
					}
					
					status = fill_packet_data_long(packet_soc_msg+PF_PACKET_HEADER+21, source_ip, 10);
					if (status != 0) {
						printf("\nStatus = %d, Unable to fill type RREP !!! Exiting ...",status);
						return -1;
					}			    
								
                    status = fill_packet_data(packet_soc_msg+PF_PACKET_HEADER+48, DESTINATION_CLIENT, 1);
					if (status != 0) {
						printf("\nStatus = %d, Unable to fill type RREP !!! Exiting ...",status);
						return -1;
					} 					
				   
					memcpy((void*)packet_soc_msg+PF_PACKET_HEADER+50, (void*)server_msg, 35);								
				}
                
                if (dest_ip == my_ip && payload_destination == DESTINATION_CLIENT) {
					status = invoke_client(unix_soc_fd, packet_soc_msg, port_table);				
					continue;
				}
				
				/* forward to next hop */				
				status = gen_update_send_payload(packet_soc_fd, packet_soc_msg,
												 routing_table, hop_flag);
				if (status != 0) {
					printf("\nStatus = %d, Unable to send Payload message !!!", status);
					return 0;	
				}
			} else {
				printf("\nInvalid packet type !!!\nExiting !!!\n");
				return 0;
			}			
		} else {
			/* Un-expected behaviour */
			continue;
		}
	}
	
	return 0;
}