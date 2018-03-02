#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define PONG_MSG_SIZE 5 /* size of a pong message */
#define MAX_MSG_SIZE 1496 /* maximum size of a MIP message, not including headers */

int main(int argc, char* argv[]){
  int un_sock;
  char *un_sock_name;
  ssize_t ret;

  if(argc < 2){
    fprintf(stderr,"USAGE: %s [-h] <Socket_application>\n",argv[0]);
    fprintf(stderr,"[-h]: optional help argument\n");
    fprintf(stderr,"<Socket_application>: name of socket for IPC with MIP daemon\n");
    exit(EXIT_FAILURE);
  }
  if(strcmp(argv[1],"-h") == 0){
    fprintf(stderr,"USAGE: %s [-h] <Socket_application>\n",argv[0]);
    fprintf(stderr,"[-h]: optional help argument\n");
    fprintf(stderr,"<Socket_application>: name of socket for IPC with MIP daemon\n");
    exit(EXIT_SUCCESS);
  }

  un_sock_name = argv[1];

  un_sock = socket(AF_UNIX,SOCK_SEQPACKET,0);

  if(un_sock == -1){
    //ERROR_HANDLING
    perror("main: socket: un_sock");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_un sockaddr;
  sockaddr.sun_family = AF_UNIX;
  strcpy(sockaddr.sun_path,un_sock_name);

  if(connect(un_sock,(struct sockaddr*)&sockaddr,sizeof(sockaddr)) == -1){
    perror("main: connect");
    close(un_sock);
    exit(EXIT_FAILURE);
  }

  for(;;){
    char ping_msg[MAX_MSG_SIZE] = { 0 };
    char pong_msg[PONG_MSG_SIZE] = { 0 };

    struct msghdr ping_msghdr = { 0 };
    struct msghdr pong_msghdr = { 0 };

    struct iovec iov_ping[1];
    struct iovec iov_pong[1];

    iov_ping[0].iov_base = ping_msg;
    iov_ping[0].iov_len = MAX_MSG_SIZE;

    ping_msghdr.msg_iov = iov_ping;
    ping_msghdr.msg_iovlen = 1;

    ret = recvmsg(un_sock,&ping_msghdr,0);
    if(ret == -1){
      if(errno == ECONNRESET){
        fprintf(stderr,"Lost connection with MIP daemon\n");
      }else perror("main: recvmsg: un_sock");
      close(un_sock);
      exit(EXIT_FAILURE);
    }else if(ret == 0){
      fprintf(stderr,"MIP daemon performed a shutdown, lost connection, aborting\n");
      close(un_sock);
      unlink(un_sock_name);
      exit(EXIT_FAILURE);
    }

    fprintf(stdout,"Received ping messsage:\n\"%s\"\n\n",ping_msg);

    strncpy(pong_msg,"PONG",5);

    iov_pong[0].iov_base = pong_msg;
    iov_pong[0].iov_len = PONG_MSG_SIZE;

    pong_msghdr.msg_iov = iov_pong;
    pong_msghdr.msg_iovlen = 1;

    if(sendmsg(un_sock,&pong_msghdr,0) == -1){
      perror("main: sendmsg: un_sock");
      close(un_sock);
      exit(EXIT_FAILURE);
    }

  }

}
