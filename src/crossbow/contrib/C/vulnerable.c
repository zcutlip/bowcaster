#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int accept_remote(const char *local_port);
int receive_data(int sockfd);
int use_stack_space(int sockfd);

int main(int argc, char **argv)
{
    int sockfd;
    char *local_port;
    int bytes_received;

    if(argc != 2)
    {
        printf("Please specify local port.\n");
        exit(1);
    }

    local_port=argv[1];

    sockfd=accept_remote(local_port);
    if(sockfd < 0)
    {
        printf("Failed to accept connection.\n");
        exit(1);
    }

    bytes_received=use_stack_space(sockfd);
    
    printf("recieved %d bytes\n",bytes_received);

    shutdown(sockfd,SHUT_RDWR);
    close(sockfd);

    return 0;
}


int use_stack_space(int sockfd)
{
    /* allocate a bunch of space on the stack
     * before calling the vulnerable function.
     * so we can overflow with a larger buffer.
     */
    char buf[2048];
    memset(buf,1,sizeof(buf));

    return receive_data(sockfd);
}

/*
 * vulnerable function.
 * reads up to 2048 off a socket onto a small buffer on the stack.
 */
int receive_data(int sockfd)
{
    int read_bytes;
    char buf[512];


    if(sockfd < 0)
    {
        return -1;
    }
    
    read_bytes=recv(sockfd,buf,2048,0);
    if(read_bytes < 0)
    {
        perror("recv");
    }else
    {
        printf("read %d bytes.\n",read_bytes);
    }

    return read_bytes;
    
}

int accept_remote(const char *local_port)
{
    int server_sockfd;
    int connection_sockfd;
    socklen_t sin_size;
    struct addrinfo hints;
    struct addrinfo *srvinfo;
    struct addrinfo *p;
    struct sockaddr_storage their_addr;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    if(NULL == local_port)
    {
        printf("Invalid parameter: local_port string was NULL.\n");
        return -1;
    }
    

    memset(&hints,0,sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; //use my ip
    
    if((rv = getaddrinfo(NULL,local_port,&hints,&srvinfo)) != 0)
    {
        printf("getaddrinfo: %s\n",gai_strerror(rv));
        return -1;
    }

    for(p=srvinfo; p != NULL; p=p->ai_next)
    {
        if((server_sockfd = socket(p->ai_family,p->ai_socktype,
                        p->ai_protocol)) == -1)
        {
            printf("server: socket %s",strerror(errno));
            continue;
        }
        if(setsockopt(server_sockfd, SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1)
        {
            printf("setsockopt: %s",strerror(errno));
            return -1;
        }

        if(bind(server_sockfd,p->ai_addr, p->ai_addrlen) == -1)
        {
            printf("server: bind %s",strerror(errno));
            close(server_sockfd);
            continue;
        }
        break;
    }

    if(NULL == p)
    {
        printf("server: failed to bind.");
        return -1;
    }

    freeaddrinfo(srvinfo);

    if(listen(server_sockfd,1) == -1)
    {
        printf("listen=: %s",strerror(errno));
        return -1;
    }

    while(1)
    {
        sin_size=sizeof(their_addr);
        connection_sockfd = accept(server_sockfd,(struct sockaddr *)&their_addr,&sin_size);
        if(connection_sockfd == -1)
        {
            printf("accept: %s",strerror(errno));
            continue;
        }
        inet_ntop(their_addr.ss_family,
                &(((struct sockaddr_in *)&their_addr)->sin_addr),
                s,sizeof(s));
        printf("Connection from %s",s);
        
        close(server_sockfd); //done with listener
        return connection_sockfd;
    }

}


