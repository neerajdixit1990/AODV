#include<stdio.h>
#include<sys/socket.h>
#include<sys/un.h>
#include<sys/types.h>
#include<string.h>
#include<unistd.h>
#include<stdlib.h>
#include "unp.h"
#include<time.h>

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


int
msg_recv(int sockfd){
    struct sockaddr_un      recv;
	char        			msg[100], hostname[10];
	socklen_t   			len;
	char                    recv_data[50];
    int                     status;  

	len = sizeof(recv);
    status = recvfrom(sockfd, msg, 100, 0, (struct sockaddr *)&recv, &len);
	if (status <= 0) {
		printf("\nError in sendto !!!\n");
		return -1;
	}
	
	
	memcpy((void*)recv_data,(void*)msg+20,5);
	
	status = gethostname(hostname, 10);
	if (status < 0) {
		printf("\nUnable to get hostname of the machine !!!");
		return -1;
	}
	    
	fflush(stdout);
	printf("\n====================================================");
    printf("\nServer at node: %s\tReceived request from client: %s",hostname, recv_data); 

	return 0;
}

int msg_send(int   				sockfd,
			 struct sockaddr_un	servaddr){
        
	int   					status=0;
    char        			msg[100], reply_msg[100] ;
	time_t      			timeofday;
	char					hostname[5],selfhostname[10];
	struct hostent 			*host_IP = NULL;
	struct in_addr 			**addr_list = NULL;
	 
	
	status=gethostname(selfhostname, 10);
	if (status < 0) {
		printf("\nUnable to get hostname of the machine !!!");
		return -1;
	}
	
	host_IP = gethostbyname(selfhostname);;
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
    
	
	timeofday = time(NULL);
	snprintf(reply_msg, sizeof(reply_msg), "%s%s%s",
	hostname, ":", ctime(&timeofday));
	memcpy((void*)msg+20, (void*)reply_msg ,35);
	msg[55]='\0';
   
   	fflush(stdout);
	printf("\nResponse Msg of Server %s",reply_msg);
		
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sun_family = AF_LOCAL;
	strcpy(servaddr.sun_path, ODR_PATH);
		
	status = sendto(sockfd, msg, strlen(msg), 0,
	(struct sockaddr *)&servaddr, sizeof(servaddr));
	if (status <= 0) {
		printf("\nError in sendto API !!!\nExiting ...\n");
		return -1;
	}
    
	return 0;


}

int main() {

	int   					sockfd,status=0;
	struct sockaddr_un      servaddr;

	sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(sockfd < 0) {
		printf("\nError in creating server domain socket !!!\nExiting ...\n");
		return 0;
	}

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sun_family=AF_LOCAL;
	strcpy(servaddr.sun_path, SERVER_PATH);
	unlink(SERVER_PATH);
	
	status = bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
	if (status < 0) {
		printf("\nError in UNIX domain bind !!!\nExiting ...\n");
		return 0;
	}
	
	
	while(1){
		fflush(stdout);
        printf("\nWaiting for Client Request");
	    status = msg_recv(sockfd);
		if (status < 0) {
			printf("\nError in receiveing data !!!\nExiting ...\n");
			return 0;
		}	
		
		status = msg_send(sockfd, servaddr);
		if (status < 0) {
			printf("\nError in sending data !!!\nExiting ...\n");
			return 0;
		}	
	}
}