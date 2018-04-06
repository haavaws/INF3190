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


int main(int argc, char *argv[]){
  char const *usage = "./routing_daemon [-d] <Socket_route> "
      "<Socket_forwarding>";

  struct routing_data routing_data_container = { 0 };
  struct sockets sock_container = { 0 };

  /* Entries in the distance and routing table for the local MIP addresses on
   * this node are handled specially, they are never updated after being
   * initialized, and any data received from other routers regarding those MIP
   * addresses is ignored */
  struct routing_table_entry routing_table[MAX_MIP];
  struct distance_table_entry distance_table[MAX_MIP];
  uint8_t local_mips[MAX_MIP];
  uint8_t neighbours[MAX_MIP];
  time_t last_neighbour_update[MAX_MIP] = { 0 };
  int num_local_mips;
  int num_neighbours = 0;

  int un_route_sock;
  int un_fwd_sock;
  int signal_fd;

  int debug;
  int route_sock_ind;
  int fwd_sock_ind;
  char* un_route_name;
  char* un_fwd_name;

  int epfd;
  int nfds;
  struct epoll_event events [MAX_EVENTS];

  time_t last_update_timestamp = time(NULL);
  time_t timeout;
  time_t now = time(NULL);

  int i;
  ssize_t ret;

  /* Add routing data to routing data container */
  routing_data_container.routing_table = routing_table;
  routing_data_container.distance_table = distance_table;
  routing_data_container.last_neighbour_update = last_neighbour_update;
  routing_data_container.local_mips = local_mips;
  routing_data_container.num_local_mips = &num_local_mips;
  routing_data_container.neighbours = neighbours;
  routing_data_container.num_neighbours = &num_neighbours;
  routing_data_container.last_update_timestamp = &last_update_timestamp;

  /* Add sockets to socket container */
  sock_container.un_route_sock = &un_route_sock;
  sock_container.un_fwd_sock = &un_fwd_sock;
  sock_container.signal_fd = &signal_fd;


  if(argc<3){
    fprintf(stderr,"USAGE: %s\n",usage);
    exit(EXIT_FAILURE);
  }


  route_sock_ind = 1;
  fwd_sock_ind = 2;

  if(strcmp(argv[1],"-d") == 0){
    if(argc<4){
      fprintf(stderr,"USAGE: %s\n",usage);
    }

    debug = 1;
    route_sock_ind++;
    fwd_sock_ind++;

    if(debug){
      fprintf(stdout, "-------------------Debug mode activated.--------------------\n");
    }
  }

  /* Create the unix sockets for communication with the MIP daemon, as well as
   * a signal handler */
  un_route_name = argv[route_sock_ind];
  un_fwd_name = argv[fwd_sock_ind];

  if(create_sockets(sock_container, un_route_name, un_fwd_name) < 0){
    perror("main: create_sockets");
    close_sockets(sock_container, 0);
    exit(EXIT_FAILURE);
  }

  /* Create the epoll instance listening for events on the sockets */
  epfd = create_epoll_instance(sock_container);

  if(epfd < 0){
    perror("main: create_epoll_instance");
    close_sockets(sock_container, 0);
    exit(EXIT_FAILURE);
  }

  /* Initialize routing tables */
  num_local_mips = init_routing_data(sock_container, routing_data_container, debug);

  if(num_local_mips == -1){
    perror("main: init_routing_data");
    close_sockets(sock_container, 0);
    exit(EXIT_FAILURE);
  }else if(num_local_mips == -2){
    fprintf(stderr, "No local MIP addresses supplied from MIP daemon.\n");
    close_sockets(sock_container, 0);
    exit(EXIT_FAILURE);
  }

  for(;;){
    timeout = scheduled_update(sock_container, routing_data_container, now, debug);

    if(timeout == -1){
      perror("main: scheduled_update");
      close_sockets(sock_container, 0);
      free_distance_table(distance_table);
      exit(EXIT_FAILURE);
    }

    nfds = epoll_wait(epfd, events, MAX_EVENTS, timeout);

    if(nfds == -1){
      perror("main: epoll_wait");
      close_sockets(sock_container, 0);
      free_distance_table(distance_table);
      exit(EXIT_FAILURE);
    }

    now = time(NULL);

    for(i = 0; i < nfds; i++){
      /* A keyboard interrupt was signaled */
      if(events[i].data.fd == signal_fd){
        if(keyboard_signal(events[i].data.fd) == 0){
          close_sockets(sock_container, 0);
          free_distance_table(distance_table);
          exit(EXIT_SUCCESS);
        }
      }/* Keyboard signal END */

      /* If a data was received on the routing socket */
      if(events[i].data.fd == un_route_sock){

        ret = recv_routing_update(sock_container, routing_data_container, now, debug);

        if(ret == -1){
          perror("main: recv_routing_update");
          close_sockets(sock_container, 0);
          free_distance_table(distance_table);
        }else if(ret == -2){
          fprintf(stderr,"MIP daemon performed a shutdown, lost connection, "
              "aborting\n");
          close_sockets(sock_container, 1);
          free_distance_table(distance_table);
          exit(EXIT_FAILURE);
        }
      } /* Receive data on routing socket END */

      else if(events[i].data.fd == un_fwd_sock){
        recv_fwd_req(sock_container, routing_data_container, now, debug);

        if(ret == -1){
          perror("main: recv_fwd_req");
          close_sockets(sock_container, 0);
          free_distance_table(distance_table);
        }else if(ret == -2){
          fprintf(stderr,"MIP daemon performed a shutdown, lost connection, "
              "aborting\n");
          close_sockets(sock_container, 1);
          free_distance_table(distance_table);
          exit(EXIT_FAILURE);
        }
      } /* Receive data on forward socket END */
    }
  }
}
