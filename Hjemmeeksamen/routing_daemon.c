#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <time.h>

#include "routing_daemon.h"

int init_routing_table(int un_route_sock, struct routing_table_entry *routing_table,uint8_t *local_mips){

  /* TODO: FREE */
  int num_local_mips,i;

  struct msghdr recv_msg = { 0 };
  struct iovec recv_iov[1];

  for(i = 0; i < MAX_MIP; i++){
    routing_table[i].dest_mip = 255;
    routing_table[i].next_hop = 255;
    routing_table[i].cost = 255;

    local_mips[i] = 255;
  }

  recv_iov[0].iov_base = local_mips;
  recv_iov[0].iov_len = MAX_MIP;

  recv_msg.msg_iov = recv_iov;
  recv_msg.msg_iovlen = 1;

  /* Receive an array of characters, each indicating a local MIP address */
  num_local_mips = recvmsg(un_route_sock,&recv_msg,0);

  if(num_local_mips == -1){
    if(errno == EINTR){
      return 0;
    }
    return -1;
  }else if(num_local_mips == 0){
    return -2;
  }

  for(i = 0; i < num_local_mips; i++){
    routing_table[i].dest_mip = local_mips[i];
    routing_table[i].next_hop = local_mips[i];
    routing_table[i].cost = 0;
  }

  struct msghdr send_msg = { 0 };
  struct iovec send_iov[1];

  send_iov[0].iov_base = routing_table;
  send_iov[0].iov_len = sizeof(struct routing_table_entry) * num_local_mips;

  send_msg.msg_iov = send_iov;
  send_msg.msg_iovlen = 1;



  if(sendmsg(un_route_sock,&send_msg,0) == -1){
    return -1;
  }

  return num_local_mips;
}


int main(int argc, char *argv[]){
  char const *usage = "./routing_daemon <Socket_route> <Socket_forwarding>";
  printf("%s\n",usage);

  if(argc<3){
    fprintf(stderr,"USAGE: %s\n",usage);
  }

  struct routing_table_entry routing_table[MAX_MIP];
  struct distance_table_entry distance_table[MAX_MIP] = { 0 };
  uint8_t local_mips[MAX_MIP] = { 0 };
  uint8_t neighbours[MAX_MIP] = { 0 };
  int num_local_mips;
  int num_neighbours = 0;

  int un_route_sock;
  int un_fwd_sock;
  int signal_fd;

  int route_sock_ind;
  int fwd_sock_ind;

  char* un_route_name;
  char* un_fwd_name;

  int epfd;
  int nfds;
  struct epoll_event events [MAX_EVENTS];
  struct epoll_event ep_route_ev = { 0 };
  struct epoll_event ep_fwd_ev = { 0 };
  struct epoll_event ep_sig_ev = { 0 };

  int last_update_timestamp = time(NULL);
  int timeout;

  int i,j,k,l;
  ssize_t ret;

  route_sock_ind = 1;
  fwd_sock_ind = 2;

  un_route_name = argv[route_sock_ind];
  un_fwd_name = argv[fwd_sock_ind];

  /* Create unix IPC routing and forwarding sockets */
  struct sockaddr_un route_addr = { 0 };
  struct sockaddr_un fwd_addr = { 0 };

  un_route_sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if(un_route_sock == -1){
    perror("main: socket: un_route_sock");
    exit(EXIT_FAILURE);
  }
  un_fwd_sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if(un_fwd_sock == -1){
    perror("main: socket: un_fwd_sock");
    close(un_route_sock);
    exit(EXIT_FAILURE);
  }

  route_addr.sun_family = AF_UNIX;
  strncpy(route_addr.sun_path, un_route_name, sizeof(route_addr.sun_path));
  fwd_addr.sun_family = AF_UNIX;
  strncpy(fwd_addr.sun_path, un_fwd_name, sizeof(fwd_addr.sun_path));

  if(connect(un_route_sock, (struct sockaddr *) &route_addr,
      sizeof(struct sockaddr_un)) == -1){
    perror("main: connect: un_route_sock");
    close(un_route_sock);
    close(un_fwd_sock);
    exit(EXIT_FAILURE);
  }
  if(connect(un_fwd_sock, (struct sockaddr *) &fwd_addr,
      sizeof(struct sockaddr_un)) == -1){
    perror("main: connect: un_fwd_sock");
    close(un_route_sock);
    close(un_fwd_sock);
    exit(EXIT_FAILURE);
  }


  /* Create an epoll instance for the sockets */
  epfd = epoll_create(1);

  ep_route_ev.data.fd = un_route_sock;
  ep_route_ev.events = EPOLLIN;
  ep_fwd_ev.data.fd = un_fwd_sock;
  ep_fwd_ev.events = EPOLLIN;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, un_route_sock, &ep_route_ev) == -1){
    perror("main: epoll_ctl: add un_route_sock");
    close(un_route_sock);
    close(un_fwd_sock);
    exit(EXIT_FAILURE);
  }
  if(epoll_ctl(epfd, EPOLL_CTL_ADD, un_fwd_sock, &ep_fwd_ev) == -1){
    perror("main: epoll_ctl: add un_fwd_sock");
    close(un_route_sock);
    close(un_fwd_sock);
    exit(EXIT_FAILURE);
  }

  /* Add a keyboard interrupt signal handler for the epoll instance */
  sigset_t mask;

  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGQUIT);

  sigprocmask(SIG_BLOCK, &mask, NULL);

  signal_fd = signalfd(-1, &mask, 0);
  if(signal_fd == -1){
    perror("main: signalfd");
    close(un_route_sock);
    close(un_fwd_sock);
    exit(EXIT_FAILURE);
  }

  ep_sig_ev.events = EPOLLIN | EPOLLERR;
  ep_sig_ev.data.fd = signal_fd;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, signal_fd, &ep_sig_ev) == -1){
    perror("main: epoll_ctl: add signal_fd");
    close(un_route_sock);
    close(un_fwd_sock);
    close(signal_fd);
    exit(EXIT_FAILURE);
  }

  /* Initialize routing tables */
  num_local_mips = init_routing_table(un_route_sock, routing_table, local_mips);

  for(i = 0; i < MAX_MIP; i++){
    distance_table[i].dest_mip = 255;
    distance_table[i].next_hop = NULL;
    distance_table[i].cost = NULL;
    distance_table[i].timestamp = NULL;

    neighbours[i] = 255;
  }


  for(;;){
    timeout = (UPDATE_WAIT - (time(NULL) - last_update_timestamp)) * 1000;
    if(timeout<0) timeout = 0;

    nfds = epoll_wait(epfd,events,MAX_EVENTS,timeout);

    if(nfds == -1){
      perror("main: epoll_wait");
      close(un_route_sock);
      close(un_fwd_sock);
      close(signal_fd);
      exit(EXIT_FAILURE);
    }

    /* If it has been at least 30 seconds since the last routing table update,
     * send a routing table update */
    if (nfds == 0){
      struct msghdr msg = { 0 };
      struct iovec iov[1];

      iov[0].iov_base = routing_table;
      iov[0].iov_len = sizeof(routing_table_entry)*num_local_mips;

      msg.msg_iov = iov;
      msg.msg_iovlen = 1;

      if(sendmsg(un_route_sock,&msg,0) == -1){
        perror("main: sendmsg: route update");
        close(un_route_sock);
        close(un_fwd_sock);
        close(signal_fd);
        exit(EXIT_FAILURE);
      }

      last_update_timestamp = time(NULL);
    }

    for(i = 0; i < nfds; i++){
      /* If a routing table update was received */
      if(events[i].data.fd == un_route_sock){
        struct msghdr msg = { 0 };
        struct iovec iov[2];

        uint8_t src_mip;
        struct routing_table_entry recv_route_table[MAX_MIP] = { 0 };

        iov[0].iov_base = &src_mip;
        iov[0].iov_len = sizeof(src_mip);

        iov[1].iov_base = recv_route_table;
        iov[1].iov_len = sizeof(recv_route_table);

        msg.msg_iov = iov;
        msg.msg_iovlen = 2;

        ret = recvmsg(events[i].data.fd,&msg,0);

        if(ret == -1){
          close(un_route_sock);
          close(un_fwd_sock);
          close(signal_fd);
          if(errno == EINTR){
            fprintf(stdout,"Received interrupt, exiting router.");
            exit(EXIT_SUCCESS);
          }
          perror("main: recvmsg: un_route_sock");
          exit(EXIT_FAILURE);
        }else if(ret == 0){
          fprintf(stderr,"MIP daemon performed a shutdown, lost connection, "
              "aborting\n");
          close(un_route_sock);
          close(un_fwd_sock);
          close(signal_fd);
          unlink(un_route_name);
          unlink(un_fwd_name);
          exit(EXIT_FAILURE);
        }

        for(j = 0; j < num_neighbours; j++){
          if(src_mip == neighbours[i]) break;
          if(j == num_neighbours-1){
            neighbours[j+1] = src_mip;
            for(k = 0; k < MAX_MIP; k++){
              void *tmp;

              tmp = distance_table[k].next_hop;
              distance_table[k].next_hop = (uint8_t *) malloc(num_neighbours+1);
              memcpy(distance_table[k].next_hop,tmp,num_neighbours);
              distance_table[k].next_hop[num_neighbours] = src_mip;
              free(tmp);

              tmp = distance_table[k].cost;
              distance_table[k].cost = (uint8_t *) malloc(num_neighbours+1);
              memcpy(distance_table[k].cost,tmp,num_neighbours);
              distance_table[k].cost[num_neighbours] = 16;
              free(tmp);

              tmp = distance_table[k].timestamp;
              distance_table[k].timestamp = (time_t *) malloc(sizeof(time_t) * (num_neighbours + 1));
              memcpy(distance_table[k].timestamp,tmp,sizeof(time_t) * num_neighbours);
              distance_table[k].timestamp[num_neighbours] = time(NULL);
              free(tmp);
            }
          }
        }

        /* Number of rows in the routing table received */
        ret--;
        ret /= 3;

        for(j = ret; j < ret; j++){

          int goes_through_this = 0;
          for(k = 0; k < num_local_mips; k++){
            if(recv_route_table[j].next_hop == local_mips[k]){
              goes_through_this = 1;
            }
          }
          if(goes_through_this) continue;

          for(k = 0; k < MAX_MIP; k++){
            if(recv_route_table[j].dest_mip == distance_table[k].dest_mip){
              
            }
            for(l = 0; l < num_neighbours; l++){
            }
          }
        }


      }
      else if(events[i].data.fd == un_fwd_sock){

      }
    }
  }

}
