#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <errno.h>
#include <inttypes.h>

#define PONG_MSG_SIZE 5 /* size of a pong message */
/* maximum size of a MIP message, not including headers */
#define MAX_MSG_SIZE 1496
/* timeout to wait for PONG message in milliseconds */
#define PONG_TIMEOUT_US 500

/* Based on code from group session
* https://github.uio.no/persun/inf3190/tree/master/plenum3 */

/* Server for receiving a ping with a ping message through communicating over
* IPC with a MIP daemon using a user specified socket name */

int main(int argc, char* argv[]){
  int un_sock; /* Socket to use for IPC */
  char *un_sock_name; /* Socket name to use for IPC */
  ssize_t ret;
  /* Start and end time of ping */
  struct timeval ping_start = { 0 }, ping_end = { 0 };
  struct timeval timeout = { 0 }; /* Timeout for waiting for PONG response */
  time_t latency_s; /* Latency in seconds */
  suseconds_t latency_us; /* Latency in microseconds */
  uint8_t dest_mip;
  char *ping_msg;

  /* Argument control */
  if(argc<4){
    if(argc>1){
      if(strcmp(argv[1],"[-h]")){
        printf("print HELP");
        exit(EXIT_FAILURE);
      }
    }
    fprintf(stderr,"USAGE: %s [-h] <destination_host> <message> "
        "<Socket_application>\n",argv[0]);
    fprintf(stderr,"[-h]: optional help argument\n");
    fprintf(stderr,"<destination_host>: MIP addresses of ping target\n");
    fprintf(stderr,"<message>: message to send along with ping\n");
    fprintf(stderr,"<Socket_application>: name of socket for IPC with "
        "daemon\n");
    exit(EXIT_FAILURE);
  }

  /* Get the MIP address from the input arguments */
  char *endptr;
  dest_mip = strtol(argv[1],&endptr,10);
  if(*endptr != '\0' || argv[1][0] == '\0' || dest_mip > 255 || dest_mip < 0){
    fprintf(stderr,"USAGE: %s [-h] <Socket_application> [MIP addresses ...]\n",
        argv[0]);
    fprintf(stderr,"[-h]: optional help argument\n");
    fprintf(stderr,"<Socket_application>: name of socket for IPC with "
        "application\n");
    fprintf(stderr,"[MIP addresses ...]: one unique MIP address per interface "
        "with a unique MAC address, in the form of a number between 0 and "
        "255\n");
    exit(EXIT_FAILURE);
  }


  ping_msg = argv[2];
  un_sock_name = argv[3];

  /* Using SOCK_SEQPACKET for a connection-oriented, sequence-preserving socket
   * that preserves message boundaries */
  un_sock = socket(AF_UNIX,SOCK_SEQPACKET,0);

  if(un_sock == -1){
    perror("main: socket: un_sock");
    exit(EXIT_FAILURE);
  }

  /* Set timeout for the socket */
  if(PONG_TIMEOUT_US >= 1000) timeout.tv_sec = PONG_TIMEOUT_US / 1000;
  timeout.tv_usec = PONG_TIMEOUT_US * 1000 - timeout.tv_sec * 1000;
  setsockopt(un_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
      sizeof(struct timeval));

  /* Connect to MIP daemon */
  struct sockaddr_un sockaddr;
  sockaddr.sun_family = AF_UNIX;
  strcpy(sockaddr.sun_path,un_sock_name);

  if(connect(un_sock,(struct sockaddr*)&sockaddr,sizeof(sockaddr)) == -1){
    perror("main: connect");
    close(un_sock);
    exit(EXIT_FAILURE);
  }

  /* Send the ping message and destination MIP address to the connected MIP
  * daemon */
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

  /* Timestamp before sending ping */
  gettimeofday(&ping_start,NULL);
  if(sendmsg(un_sock,&ping_msghdr,0) == -1){
    perror("main: sendmsg: un_sock");
    close(un_sock);
    exit(EXIT_FAILURE);
  }

  /* Wait for ping */
  for(;;){
    char pong_msg[MAX_MSG_SIZE] = { 0 };
    struct msghdr pong_msghdr = { 0 };
    struct iovec iov_pong[2];
    uint8_t src_mip;

    iov_pong[0].iov_base = &src_mip;
    iov_pong[0].iov_len = sizeof(src_mip);

    iov_pong[1].iov_base = pong_msg;
    iov_pong[1].iov_len = MAX_MSG_SIZE;

    pong_msghdr.msg_iov = iov_pong;
    pong_msghdr.msg_iovlen = 2;

    ret = recvmsg(un_sock, &pong_msghdr, 0);
    if(ret == -1){
      if(errno == EAGAIN || errno == EWOULDBLOCK){
        /* Timeout */
        fprintf(stderr,"Ping timed out\n");
      }
      else if(errno == EINTR){
        fprintf(stdout,"Received interrupt, exiting server.\n");
        close(un_sock);
        exit(EXIT_SUCCESS);
      }else perror("main: recvmsg: un_sock");
      close(un_sock);
      exit(EXIT_FAILURE);
    }else if(ret == 0){
      fprintf(stderr,"MIP daemon performed a shutdown while waiting for PONG "
          "response\n");
      close(un_sock);
      unlink(un_sock_name);
      exit(EXIT_FAILURE);
    }

    fprintf(stdout,"Received PONG response:\n\"%s\"\n\n",ping_msg);
    fprintf(stdout, "From host: %d\n",src_mip);

    /* Calculate how much time has been spent waiting */
    gettimeofday(&ping_end,NULL);

    /* Time in microseconds */
    latency_s = ping_end.tv_sec - ping_start.tv_sec;
    if(latency_s > 0){
      latency_us = (1000000 - ping_start.tv_usec) + ping_end.tv_usec;
    }else latency_us = ping_end.tv_usec - ping_start.tv_usec;

    /* Received PONG response */
    if(strcmp("PONG",pong_msg) == 0){
      /* Can't verify that the source is the same as the destination, because
       * the destination may have responded with a different MIP address as the
       * sourec */
      break;
    }

  }

  printf("Latency: %ld ms\n",latency_us/1000);

  close(un_sock);

  exit(EXIT_SUCCESS);

}
