#include<stdio.h>
#include<sys/socket.h>
#include<sys/un.h>
#include<sys/types.h>
#include<string.h>
#include<unistd.h>
#include<stdlib.h>
#include "unp.h"

#define	ODR_PATH		"/tmp/ndixit_odr"
#define SERVER_PATH		"/tmp/ndixit_server"
#define	SERVER_PORT		51838
#define	CLIENT_PATH		"/tmp/ndixit_client_XXXXXX"

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

int msg_send(int 				sockfd,
			struct sockaddr_un	servaddr,
			int					vm_no,
			int                 route_rediscover_flag){
	
	int                 status; 
	char				hostname[5],selfhostname[10];
	char				msg[100];
	struct hostent 		*host_IP = NULL;
	struct in_addr 		**addr_list = NULL;
	
	
	status=gethostname(selfhostname, 10);
	if (status < 0) {
		printf("\nUnable to get hostname of the machine !!!");
		return -1;
	}
	
	snprintf(hostname, 5, "vm%d", vm_no);
	host_IP = gethostbyname(hostname);
	if (host_IP == NULL) {
		printf("\nNo IP address associated with %s\n", hostname);
	} else {
	    addr_list = (struct in_addr **)host_IP->h_addr_list;
	}
	
	status = fill_packet_data(msg, sockfd, 5);
	if (status != 0) {
		printf("\nFailed to fill socket FD in packet !!!");
		return -1;
	}

	status = fill_packet_data_long(msg+5, (**addr_list).s_addr, 10);
	if (status != 0) {
		printf("\nFailed to fill sequence in packet !!!");
		return -1;
	}
	
	status = fill_packet_data(msg+15, SERVER_PORT, 5);
	if (status != 0) {
		printf("\nFailed to fill sequence in packet !!!");
		return -1;
	}

	
	status = fill_packet_data(msg+20, route_rediscover_flag, 1);
	if (status != 0) {
		printf("\nFailed to fill sequence in packet !!!");
		return -1;
	}
	
	memcpy((void*)msg+21, (void*)selfhostname,5);	
	msg[26] = '\0';
	printf("\n====================================================");
	printf("\nClient at node: %s\tSending request to server at : %s",selfhostname, hostname);
	
	status = sendto(sockfd, msg, strlen(msg)+1, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
	if (status <= 0) {
		printf("\nError in sendto API !!!\nExiting ...\n");
		return -1;
	}			
	
	return 0;
	
}			

int 
msg_recv(int  sockfd){
    
	int                	status;
	struct sockaddr_un 	recv;
	socklen_t   		len;
	char                rmsg[100], recived_timestamp[40],selfhostname[10];
	
	status=gethostname(selfhostname, 10);
	if (status < 0) {
		printf("\nUnable to get hostname of the machine !!!");
	return -1;
	}
	
	len = sizeof(recv);
	status = recvfrom(sockfd, rmsg, 100, 0, (struct sockaddr *)&recv, &len);
	if (status <= 0) {
		printf("\nError in sendto !!!\n");
	}
	
	memcpy((void*)recived_timestamp, (void*)rmsg+20, 33);
	fflush(stdout);
	printf("\nClient at node: %s\tReceived request from %s = ",selfhostname, recived_timestamp);
	printf("\n====================================================");

	return 0;
}

int main() {
	int     			sockfd, status, vm_no;
    struct sockaddr_un 	servaddr;
	char				fname[30],selfhostname[10];
	int					route_rediscover_flag = 0;
	struct timeval 		timeout;
	
    status = gethostname(selfhostname, 10);
	if (status < 0) {
		printf("\nUnable to get hostname of the machine !!!");
	}
	
	while(1) {
	    printf("\nChoose the server VM (Enter numbers between 1 and 10)\t");
		printf("\nEnter the VM number of the server:\t");
		status = scanf("%d", &vm_no);
		if (vm_no > 0 && vm_no < 11)
			break;
		printf("\nPlease enter VM between 1 and 10 !!!");
	}

send:	
    sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(sockfd < 0) {
		printf("\nError in creating domain socket !!!\nExiting client ...\n");
		return 0;
	}

	strcpy(fname, CLIENT_PATH);
	status = mkstemp(fname);
	unlink(fname);
	
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;
    strcpy(servaddr.sun_path, fname);

    status = bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	if (status < 0) {
		printf("\nError in UNIX domain bind !!!\nExiting ...\n");
		return 0;
	}
	
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_LOCAL;
    strcpy(servaddr.sun_path, ODR_PATH);
    
    status = msg_send(sockfd, servaddr, vm_no, route_rediscover_flag);
	if (status < 0) {
		printf("\nUnable to send data to client !!!\nExiting ...\n");
		return 0;
	}
	
	fd_set 		read_fd;
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;
		
	FD_ZERO(&read_fd);
	FD_SET(sockfd, &read_fd);
	
	status = select(sockfd + 1, &read_fd, NULL, NULL, &timeout);
	if (status < 0) {
		printf("\nStatus = %d, Unable to monitor sockets !!! Exiting ...",status);
		return 0;
	}
		
	if (FD_ISSET(sockfd, &read_fd)) {
	
		status = msg_recv(sockfd);
		if (status < 0) {
			printf("\nUnable to recive data from client !!!\nExiting ...\n");
			return 0;
		}
	
		unlink(fname);
		return 0;
	
	} else {
		route_rediscover_flag = 1;
		goto send;
	
	}
	
	return 0;
}