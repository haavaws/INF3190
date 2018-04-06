#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <errno.h>
#include "mip_daemon.h"

/* Global variables and functions declared in mip_daemon.h */

/* Daemon used for network layer communication using the Mininet
* Interconnection Protocol (MIP). Allows a client application to ping, through
* this MIP daemon, a host directly connected to this MIP daemon over ethernet.
* Also allows for a connected server application, through this daemon, to
* receive a ping message over ethernet from a host connected directly to the
* host running this MIP daemon. */

int main(int argc, char *argv[]){
  /* Variable container */
  struct sockets sock_container = { 0 };
  struct packet_queues queue_container = { 0 };

  /* MIP-ARP table and local interface MIP-ARP */
  struct mip_arp_entry mip_arp_table[MAX_ARP_SIZE] = { 0 };
  struct mip_arp_entry local_mip_mac_table[MAX_ARP_SIZE] = { 0 };

  /* Epoll */
  struct epoll_event events[MAX_EVENTS];
  int epfd,nfds;

  /* Sockets */
  int num_eth_sds = 0;
  int un_sock = -1;
  int un_route_sock = -1;
  int un_fwd_sock = -1;

  /* Connected sockets, from application and router */
  /* -1 indicates no connection */
  int un_sock_conn = -1;
  int un_route_conn = -1;
  int un_fwd_conn = -1;

  int signal_fd = -1;

  /* Arguments */
  int debug;
  char* un_sock_name;
  char* un_route_name;
  char* un_fwd_name;
  int mip_start_ind;
  int sock_name_ind;
  int route_name_ind;
  int fwd_name_ind;

  /* Packet queue */
  struct packet_queue *first_packet = NULL;
  struct packet_queue *last_packet = first_packet;
  struct packet_queue *first_broadcast_packet = NULL;
  struct packet_queue *last_broadcast_packet = first_broadcast_packet;

  /* Extra */
  int i,j;
  ssize_t ret;

  /* Add all sockets to the socket container */
  sock_container.un_sock = &un_sock;
  sock_container.un_route_sock = &un_route_sock;
  sock_container.un_fwd_sock = &un_fwd_sock;
  sock_container.un_sock_conn = &un_sock_conn;
  sock_container.un_route_conn = &un_route_conn;
  sock_container.un_fwd_conn = &un_fwd_conn;
  sock_container.signal_fd = &signal_fd;
  sock_container.local_mip_mac_table = local_mip_mac_table;
  sock_container.num_eth_sds = &num_eth_sds;

  /* Add packet queues to the packet queue container */
  queue_container.first_packet = &first_packet;
  queue_container.last_packet = &last_packet;
  queue_container.first_broadcast_packet = &first_broadcast_packet;
  queue_container.last_broadcast_packet = &last_broadcast_packet;




  /* Argument control */
  if(argc<5){
    print_help(argv[0]);
    exit(EXIT_FAILURE);
  }

  if(strcmp(argv[1],"-h") == 0){
    print_help(argv[0]);
    exit(EXIT_SUCCESS);
  }
  else if(strcmp(argv[1],"-d") == 0){
    if (argc<6){
      print_help(argv[0]);
      exit(EXIT_FAILURE);
    }
    fprintf(stdout,"--- Starting MIP daemon in debug mode ---\n\n");
    debug = 1;
    sock_name_ind = 2;
    route_name_ind = 3;
    fwd_name_ind = 4;
    mip_start_ind = 5;
  }
  else{
    debug = 0;
    sock_name_ind = 1;
    route_name_ind = 2;
    fwd_name_ind = 3;
    mip_start_ind = 4;
  }

  un_sock_name = argv[sock_name_ind]; /* <Socket_application */
  un_route_name = argv[route_name_ind]; /* <Socket_route> */
  un_fwd_name = argv[fwd_name_ind]; /* <Socket_forwarding> */

  /* Store MIP addresses in the MIP-ARP for local interfaces */
  int num_mip_addrs = argc-4;
  if(debug) num_mip_addrs --;
  for(i = 0; i < num_mip_addrs; i++){
    char *endptr;
    long int check = strtol(argv[mip_start_ind+i],&endptr,10);
    if(*endptr != '\0' || argv[mip_start_ind+i][0] == '\0'
        || check > 255 || check < 0){
      print_help(argv[0]);
      exit(EXIT_FAILURE);
    }
    local_mip_mac_table[i].mip_addr = check;
    for(j = 0;j < i; j++){
      if(local_mip_mac_table[i].mip_addr == local_mip_mac_table[j].mip_addr){
        print_help(argv[0]);
        exit(EXIT_FAILURE);
      }
    }
  }

  /* Setup the unix IPC sockets */
  un_sock = setup_unix_socket(un_sock_name);
  un_route_sock = setup_unix_socket(un_route_name);
  un_fwd_sock = setup_unix_socket(un_fwd_name);

  if(un_sock == -1 || un_route_sock == -1 || un_fwd_sock == -1){
    perror("main: setup_unix_socket, socket() un_sock");
    exit(EXIT_FAILURE);
  }
  else if (un_sock == -2|| un_route_sock == -2 || un_fwd_sock == -2){
    perror("main: setup_unix_socket, bind un_sock");
    close_sockets(sock_container);
    free_queues(queue_container);
    exit(EXIT_FAILURE);
  }
  else if (un_sock == -3|| un_route_sock == -3 || un_fwd_sock == -3){
    perror("main: setup_unix_socket, listen() un_sock");
    close_sockets(sock_container);
    free_queues(queue_container);
    exit(EXIT_FAILURE);
  }

  /* Setup the raw ethernet sockets */
  num_eth_sds = setup_eth_sockets(local_mip_mac_table, num_mip_addrs, debug);

  if(num_eth_sds < 0){
    perror("main: setup_eth_sockets");
    close_sockets(sock_container);
    free_queues(queue_container);
    exit(EXIT_FAILURE);
  }

  /* Control number of supplied MIP addresses vs. number of raw interfaces */
  if(num_eth_sds > num_mip_addrs || num_mip_addrs > num_eth_sds){
    /* Number of MIP addresses did not match number of ethernet sockets */
    fprintf(stderr,"Number of supplied MIP addresses did not match the number "
        "of interfaces requiring a MIP address...\n");
    fprintf(stderr,"Number of supplied MIP addresses: %d\n", num_mip_addrs);
    fprintf(stderr,"Number of interfaces which require MIP addresses: %d\n",
        num_eth_sds);
    close_sockets(sock_container);
    free_queues(queue_container);
    exit(EXIT_FAILURE);
  }

  signal_fd = setup_signal_fd();

  if(signal_fd == -1){
    perror("main: setup_signal_fd");
    close_sockets(sock_container);
    free_queues(queue_container);
    exit(EXIT_FAILURE);
  }

  /* Create an epoll instance with the unix and ethernet sockets */
  epfd = create_epoll_instance(sock_container);

  if (epfd < 0){
    perror("main: create_epoll_instance():");
    close_sockets(sock_container);
    free_queues(queue_container);
    exit(EXIT_FAILURE);
  }


  /* Poll the sockets for events until a keyboard interrupt is signaled */
  for(;;){

    nfds = epoll_wait(epfd,events,MAX_EVENTS,-1);

    if(nfds == -1){
      perror("main: epoll_wait()");
      close_sockets(sock_container);
      free_queues(queue_container);
      exit(EXIT_FAILURE);
    }

    /* Iterate through the triggered events */
    for (i = 0; i < nfds; i++){

      /* A keyboard interrupt was signaled */
      if(events[i].data.fd == signal_fd){
        if(keyboard_signal(events[i].data.fd) == 0){
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_SUCCESS);
        }
      }

      /* An application has connected to the MIP daemon */
      else if(events[i].data.fd == un_sock){
        un_sock_conn = new_connection(events[i].data.fd, epfd);

        if(un_sock_conn == -1){
          perror("main: un_sock: new_connection");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }

        if(debug){
          fprintf(stdout,"Connection to application established.\n\n");
        }
      }

      /* A router has connected to the MIP daemon, on the routing socket */
      else if(events[i].data.fd == un_route_sock){
        un_route_conn = new_connection(events[i].data.fd, epfd);

        if(un_route_conn == -1){
          perror("main: un_sock: new_connection");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }

        if(debug){
          fprintf(stdout,"Connection to router established on routing socket.\n\n");
        }

        printf("num_eth_sds: %d\n",num_eth_sds);

        /* Initialize the router */
        if(init_router(un_route_conn, local_mip_mac_table, num_eth_sds) == -1){
          perror("main: init_router");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }
      }

      /* A router has connected to the MIP daemon, on the forwarding socket */
      else if(events[i].data.fd == un_fwd_sock){

        un_fwd_conn = new_connection(events[i].data.fd, epfd);

        if(un_fwd_conn == -1){
          perror("main: un_fwd_sock: new_connection");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }

        if(debug){
          fprintf(stdout,"Connection to router established on forwarding socket.\n\n");
        }
      }

      /* Incoming data over IPC from the routing daemon on the routing
      * socket */
      else if(events[i].data.fd == un_route_conn){
        ret = send_route_update(epfd, sock_container, queue_container, mip_arp_table, debug);

        if(ret == -1){
          perror("main: send_route_update");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }
      }

      /* Incoming data over IPC from the routing daemon on the forwarding
      * socket */
      else if(events[i].data.fd == un_fwd_conn){
        ret = forward_mip_packet(epfd, sock_container, queue_container, mip_arp_table, debug);
        if(ret == -1){
          perror("main: forward_mip_packet");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }
      }

      /* Incoming data over IPC from connected application */
      else if(events[i].data.fd == un_sock_conn){
        recv_app_msg(epfd, sock_container, queue_container, debug);

        if(ret == -1){
          perror("main: recv_app_msg");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }

      } /* Communication over IPC with connected application END */



      /* Incoming data over ethernet */
      else{
        /* The source MIP address of the received packet will be stored in
        * src_mip, and the message will be stored in buf */
        ret = recv_mip_packet(mip_arp_table, events[i].data.fd, sock_container,
            queue_container, debug);

        if(ret == -1){
          perror("main: recv_mip_packet");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }

      } /* Received data over ethernet END */

    } /* Iterating through events triggered in the main loop END */

  } /* Polling sockets for event until keyboard interrupt END */

} /* int main() END */
