#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <inttypes.h>

#define PONG_MSG_SIZE 5 /* size of a pong message */
/* maximum size of a MIP message, not including headers */
#define MAX_MSG_SIZE 1496

/* Based on code from group session
* https://github.uio.no/persun/inf3190/tree/master/plenum3 */

/* Server for receiving a ping with a ping message through communicating over
* IPC with a MIP daemon using a user specified socket name */

int main(int argc, char* argv[]){
  int un_sock; /* Socket to use for IPC */
  char *un_sock_name; /* Socket name to use for IPC */
  ssize_t ret;

  /* Argument control */
  if(argc < 2){
    fprintf(stderr,"USAGE: %s [-h] <Socket_application>\n",argv[0]);
    fprintf(stderr,"[-h]: optional help argument\n");
    fprintf(stderr,"<Socket_application>: name of socket for IPC with MIP "
        "daemon\n");
    exit(EXIT_FAILURE);
  }
  if(strcmp(argv[1],"-h") == 0){
    fprintf(stderr,"USAGE: %s [-h] <Socket_application>\n",argv[0]);
    fprintf(stderr,"[-h]: optional help argument\n");
    fprintf(stderr,"<Socket_application>: name of socket for IPC with MIP "
        "daemon\n");
    exit(EXIT_SUCCESS);
  }

  un_sock_name = argv[1];

  /* Using SOCK_SEQPACKET for a connection-oriented, sequence-preserving socket
   * that preserves message boundaries */
  un_sock = socket(AF_UNIX,SOCK_SEQPACKET,0);

  if(un_sock == -1){
    perror("main: socket: un_sock");
    exit(EXIT_FAILURE);
  }

  /* Connect to MIP daemon */
  struct sockaddr_un sockaddr;
  sockaddr.sun_family = AF_UNIX;
  strcpy(sockaddr.sun_path,un_sock_name);

  if(connect(un_sock,(struct sockaddr*)&sockaddr,sizeof(sockaddr)) == -1){
    perror("main: connect");
    close(un_sock);
    exit(EXIT_FAILURE);
  }

  /* Wait for ping */
  for(;;){
    char ping_msg[MAX_MSG_SIZE] = { 0 };
    struct msghdr ping_msghdr = { 0 };
    struct iovec iov_ping[2];
    uint8_t src_mip;

    iov_ping[0].iov_base = &src_mip;
    iov_ping[0].iov_len = sizeof(src_mip);

    iov_ping[1].iov_base = ping_msg;
    iov_ping[1].iov_len = MAX_MSG_SIZE;

    ping_msghdr.msg_iov = iov_ping;
    ping_msghdr.msg_iovlen = 2;

    ret = recvmsg(un_sock,&ping_msghdr,0);
    if(ret == -1){
      if(errno == EINTR){
        fprintf(stdout,"Received interrupt, exiting server.\n");
        close(un_sock);
        exit(EXIT_SUCCESS);
      }else perror("main: recvmsg: un_sock");
      close(un_sock);
      exit(EXIT_FAILURE);
    }else if(ret == 0){
      fprintf(stderr,"MIP daemon performed a shutdown, lost connection, "
          "aborting\n");
      close(un_sock);
      unlink(un_sock_name);
      exit(EXIT_FAILURE);
    }

    fprintf(stdout,"Received ping messsage:\n\"%s\"\n\n",ping_msg);

    char pong_msg[PONG_MSG_SIZE] = { 0 };
    struct msghdr pong_msghdr = { 0 };
    struct iovec iov_pong[2];

    /* Send PONG response */
    strncpy(pong_msg,"PONG",5);

    iov_pong[0].iov_base = &src_mip;
    iov_pong[0].iov_len = sizeof(src_mip);

    iov_pong[1].iov_base = pong_msg;
    iov_pong[1].iov_len = PONG_MSG_SIZE;

    pong_msghdr.msg_iov = iov_pong;
    pong_msghdr.msg_iovlen = 2;

    if(sendmsg(un_sock,&pong_msghdr,0) == -1){
      perror("main: sendmsg: un_sock");
      close(un_sock);
      exit(EXIT_FAILURE);
    }

  }

}
