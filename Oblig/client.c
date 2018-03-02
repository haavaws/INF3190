#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <errno.h>

#define PONG_MSG_SIZE 5 /* size of a pong message */
#define PONG_TIMEOUT_US 500000 /* timeout to wait for PONG message in microseconds */

//Based on code from plenumstime 3

int main(int argc,char *argv[]){
  char *un_sock_name;
  char *ping_msg;
  char pong_msg[PONG_MSG_SIZE];
  int un_sock;
  struct timeval ping_start,ping_end;
  time_t latency_s;
  suseconds_t latency_us;
  int ret;
  int dest_mip;

  //Check arguments
  if(argc<4){
    if(argc>1){
      if(strcmp(argv[1],"[-h]")){
        printf("print HELP");
        exit(EXIT_FAILURE);
      }
    }
    fprintf(stderr,"USAGE: %s [-h] <destination_host> <message> <Socket_application>\n",argv[0]);
    fprintf(stderr,"[-h]: optional help argument\n");
    fprintf(stderr,"<destination_host>: MIP addresses of ping target\n");
    fprintf(stderr,"<message>: message to send along with ping\n");
    fprintf(stderr,"<Socket_application>: name of socket for IPC with daemon\n");
    exit(EXIT_FAILURE);
  }

  char *endptr;
  ret = strtol(argv[1],&endptr,10);
  if(*endptr != '\0' || argv[1][0] == '\0' || ret > 255 || ret < 0){
    fprintf(stderr,"USAGE: %s [-h] <Socket_application> [MIP addresses ...]\n", argv[0]);
    fprintf(stderr,"[-h]: optional help argument\n");
    fprintf(stderr,"<Socket_application>: name of socket for IPC with application\n");
    fprintf(stderr,"[MIP addresses ...]: one unique MIP address per interface with a unique MAC address, in the form of a number between 0 and 255\n");
    exit(EXIT_FAILURE);
  }else dest_mip = ret;

  ping_msg = argv[2];
  un_sock_name = argv[3];

  //Close this
  un_sock = socket(AF_UNIX,SOCK_SEQPACKET,0);

  if(un_sock == -1){
    //ERROR_HANDLING
    perror("main: socket: un_sock");
    exit(EXIT_FAILURE);
  }

  struct timeval timeout = { 0 };
  timeout.tv_sec = 1;
  setsockopt(un_sock,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(struct timeval));


  struct sockaddr_un sockaddr;
  sockaddr.sun_family = AF_UNIX;
  strcpy(sockaddr.sun_path, un_sock_name);

  if (connect(un_sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
    perror("main: connect()");
    close(un_sock);
    exit(EXIT_FAILURE);
  }

  struct msghdr ping_msghdr = {0};
  struct iovec iov_ping[2];

  iov_ping[0].iov_base = &dest_mip;
  iov_ping[0].iov_len = sizeof(dest_mip);

  iov_ping[1].iov_base = ping_msg;
  iov_ping[1].iov_len = strlen(ping_msg)+1;

  ping_msghdr.msg_iov = iov_ping;
  ping_msghdr.msg_iovlen = 2;

  fprintf(stdout,"Pinging host [%d]\n",dest_mip);
  fprintf(stdout,"Message: \"%s\"\n",ping_msg);

  gettimeofday(&ping_start,NULL);
  if(sendmsg(un_sock,&ping_msghdr,0) == -1){
    //ERROR_HANDLING
    perror("main: sendmsg: un_sock");
    close(un_sock);
    exit(EXIT_FAILURE);
  }

  struct msghdr pong_msghdr = {0};

  struct iovec iov_pong[1];
  iov_pong[0].iov_base = pong_msg;
  iov_pong[0].iov_len = PONG_MSG_SIZE;

  pong_msghdr.msg_iov = iov_pong;
  pong_msghdr.msg_iovlen = 1;

  ret = recvmsg(un_sock,&pong_msghdr,0);
  if(ret == -1){
    if(errno == EAGAIN || errno == EWOULDBLOCK){
      fprintf(stderr,"Ping timed out\n");
    }else perror("main: recvmsg: un_sock");
    //shutdown(un_sock,SHUT_RDWR);
    close(un_sock);
    exit(EXIT_FAILURE);
  }else if(ret == 0){
    fprintf(stderr,"MIP daemon performed a shutdown while waiting for PONG response\n");
    close(un_sock);
    unlink(un_sock_name);
    exit(EXIT_FAILURE);
  }
  gettimeofday(&ping_end,NULL);

  //Calculate latency
  latency_s = ping_end.tv_sec - ping_start.tv_sec;
  if(latency_s > 0){
    latency_us = (1000000 - ping_start.tv_usec) + ping_end.tv_usec;
  }else latency_us = ping_end.tv_usec - ping_start.tv_usec;

  printf("Latency: %ld ms\n",latency_us/1000);

  close(un_sock);

  exit(EXIT_SUCCESS);



}
