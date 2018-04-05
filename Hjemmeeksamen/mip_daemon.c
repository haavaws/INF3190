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
  int num_packet = 0;
  struct packet_queue *first_broadcast_packet = NULL;
  struct packet_queue *last_broadcast_packet = first_broadcast_packet;
  int num_bpacket = 0;

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

  struct epoll_event ep_app_conn_ev = { 0 };
  struct epoll_event ep_route_conn_ev = { 0 };
  struct epoll_event ep_fwd_conn_ev = { 0 };

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
        struct signalfd_siginfo sig_info;
        ssize_t sig_size;

        sig_size = read(events[i].data.fd, &sig_info,
            sizeof(struct signalfd_siginfo));
        if(sig_size == 0){
          perror("\nCtrl-d: Received EOF signal from keyboard, stopping\n");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_SUCCESS);
        }
        if(sig_info.ssi_signo == SIGINT){
          /* Close all sockets and close stop the daemon */
          fprintf(stderr,"\nCtrl-c: Received interrupt from keyboard,"
              "stopping daemon\n");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_SUCCESS);
        }
        else if(sig_info.ssi_signo == SIGQUIT){
          /* Close all sockets and close stop the daemon */
          fprintf(stderr,"\nCtrl-\\: Received interrupt from keyboard,"
              "stopping daemon\n");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_SUCCESS);
        }
      }/* Keyboard signal END */




      /* An application has connected to the MIP daemon */
      else if(events[i].data.fd == un_sock){

        struct sockaddr_un un_sock_conn_addr = { 0 };
        socklen_t size_un_sock_conn_addr = sizeof(un_sock_conn_addr);

        /* Store the socket for the connected application for later use */
        un_sock_conn = accept(un_sock, (struct sockaddr *) &un_sock_conn_addr,
            &size_un_sock_conn_addr);

        if(debug){
          fprintf(stdout,"Connection to application established.\n\n");
        }

        /* Using EPOLLONESHOT to make sure the socket may only be triggered
        * in the main loop of the MIP daemon */
        ep_app_conn_ev.events = EPOLLIN;
        ep_app_conn_ev.data.fd = un_sock_conn;

        if(epoll_ctl(epfd, EPOLL_CTL_ADD, un_sock_conn, &ep_app_conn_ev) == -1){
          perror("main: epoll_ctl(): add un_sock_conn");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }
      } /* Incoming application connection END */




      /* A router has connected to the MIP daemon, on the routing socket */
      else if(events[i].data.fd == un_route_sock){

        struct sockaddr_un un_route_conn_addr = { 0 };
        socklen_t size_un_route_conn_addr = sizeof(un_route_conn_addr);

        /* Store the routing socket for the connected routing daemon for later
        * use */
        un_route_conn = accept(un_route_sock,
            (struct sockaddr *) &un_route_conn_addr, &size_un_route_conn_addr);

        if(debug){
          fprintf(stdout,"Connection to router on routing socket established.\n\n");
        }

        /* Using EPOLLONESHOT to make sure the socket may only be triggered
        * in the main loop of the MIP daemon */
        ep_route_conn_ev.events = EPOLLIN;
        ep_route_conn_ev.data.fd = un_route_conn;

        if(epoll_ctl(epfd, EPOLL_CTL_ADD, un_route_conn, &ep_route_conn_ev) == -1){
          perror("main: epoll_ctl(): add un_route_conn");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }

        /* Send the local MIP addresses to the router for initialization */
        struct msghdr msg = { 0 };
        struct iovec iov[1];

        uint8_t local_mips[256];
        for(j = 0; j < num_eth_sds; j++){
          local_mips[j] = local_mip_mac_table[j].mip_addr;
        }

        iov[0].iov_base = local_mips;
        iov[0].iov_len = num_eth_sds;

        msg.msg_iov = iov;
        msg.msg_iovlen = 1;

        if(sendmsg(un_route_conn,&msg,0) == -1){
          perror("main: sendmsg: un_route_sock");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }
      } /* Incoming routing connection END */




      /* A router has connected to the MIP daemon, on the forwarding socket */
      else if(events[i].data.fd == un_fwd_sock){

        struct sockaddr_un un_fwd_conn_addr = { 0 };
        socklen_t size_un_fwd_conn_addr = sizeof(un_fwd_conn_addr);

        /* Store the forwarding socket for the connected routing daemon for
        * later use */
        un_fwd_conn = accept(un_fwd_sock,
          (struct sockaddr *) &un_fwd_conn_addr, &size_un_fwd_conn_addr);

        if(debug){
          fprintf(stdout,"Connection to router on forwarding socket established.\n\n");
        }

        /* Using EPOLLONESHOT to make sure the socket may only be triggered
        * in the main loop of the MIP daemon */
        ep_fwd_conn_ev.events = EPOLLIN;
        ep_fwd_conn_ev.data.fd = un_fwd_conn;

        if(epoll_ctl(epfd, EPOLL_CTL_ADD, un_fwd_conn, &ep_fwd_conn_ev) == -1){
          perror("main: epoll_ctl(): add un_sock_conn");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }
      } /* Incoming forwarding connection END */




      /* Incoming data over IPC from the routing daemon on the routing
      * socket */
      else if(events[i].data.fd == un_route_conn){

        if(debug){
          fprintf(stdout, "Receiving data on routing socket.\n");
        }

        struct msghdr route_msg = { 0 };
        struct iovec route_iov[2];

        uint8_t dest_mip;
        void *routing_table = malloc(MAX_MSG_SIZE);
        memset(routing_table, 255, MAX_MSG_SIZE);

        route_iov[0].iov_base = &dest_mip;
        route_iov[0].iov_len = sizeof(dest_mip);

        route_iov[1].iov_base = routing_table;
        route_iov[1].iov_len = MAX_MSG_SIZE;

        route_msg.msg_iov = route_iov;
        route_msg.msg_iovlen = 2;

        ret = recvmsg(events[i].data.fd, &route_msg, 0);

        if(ret == -1){
          perror("main: recvmsg: un_route_conn");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }
        else if(ret == 0){

          if(debug){
            fprintf(stdout,"Connection to router terminated.\n\n\n");
          }

          /* Remove the connected routing socket from the epoll instance */
          if(epoll_ctl(epfd, EPOLL_CTL_DEL, events[i].data.fd, &events[i])
              == -1){
            perror("main: epoll_ctl: del un_route_conn");
            close_sockets(sock_container);
            free_queues(queue_container);
            exit(EXIT_FAILURE);
          }

          close(events[i].data.fd);
          un_route_conn = -1; /* Indicates no router is connected */

          /* Rearm the routing socket listening for incoming connections from
           * a router */
          struct epoll_event ep_route_ev = { 0 };
          ep_route_ev.events = EPOLLIN | EPOLLONESHOT;
          ep_route_ev.data.fd = un_route_sock;

          epoll_ctl(epfd, EPOLL_CTL_MOD, un_route_sock, &ep_route_ev);

          continue;

        }

        if(debug){
          for(j = 0; j < MAX_MSG_SIZE; j++){
            if((uint8_t)((char *) routing_table)[j] == 255){
              break;
            }
          }
          fprintf(stdout, "Received %ld bytes from router.\n", ret);
          fprintf(stdout, "Destination for routing data: %d\n", dest_mip);
          fprintf(stdout, "First instance of 255 in the received data: %d\n", j);
        }

        /* If the destination of the routing update is 255, broadcast the
         * routing table on all network interfaces */
        if(dest_mip == 255){

          if(debug){
            fprintf(stdout, "Destination was broadcast address, broadcasting routing data.\n");
          }
          for(j = 0; j < num_eth_sds; j++){
            send_mip_packet(mip_arp_table, local_mip_mac_table, dest_mip,
                dest_mip, routing_table, ret - 1, 0b010,
                local_mip_mac_table[j].socket, debug);

            if(ret == -1){
              perror("main: un_route_conn: broadcast route table");
              close_sockets(sock_container);
              free_queues(queue_container);
              exit(EXIT_FAILURE);
            }

            /* The payload of the packet was too large */
            else if(ret == -2){
              if(debug){
                fprintf(stdout,"Payload exceeds max length. Aborted send.\n");
              }
            }
          }

          if(debug){
            fprintf(stdout, "Broadcasted to %d nodes.\n", j);
          }

          continue;
        }

        if(debug){
          fprintf(stdout, "Sending routing data to MIP address %d\n", dest_mip);
        }

        ret = send_mip_packet(mip_arp_table, local_mip_mac_table, dest_mip,
            dest_mip, routing_table, ret - 1, 0b010, 0, debug);

        if(ret == -1){
          perror("main: send_mip_packet: un_fwd_conn: send_mip_packet");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }

        /* The payload of the packet was too large */
        else if(ret == -2){
          if(debug){
            fprintf(stdout,"Payload exceeds max length. Aborted send.\n");
          }
        }

        /* The MIP address indicated by the client was not cached in the
         * MIP-ARP table */
        else if(ret == -3){
          if(debug){
            fprintf(stdout,"MIP address %d not in MIP-ARP table.\n",
              dest_mip);
            fprintf(stdout, "Sending a MIP-ARP broadcast to find the destination.\n");
          }

          /* Send out a MIP-ARP broadcast to attempt to find the host indicated
          * by the client */
          ret = send_mip_broadcast(mip_arp_table, num_eth_sds,
              local_mip_mac_table, dest_mip, debug);

          if(ret == -1){
            perror("main: send_mip_broadcast: un_fwd_conn");
            close_sockets(sock_container);
            free_queues(queue_container);
            exit(EXIT_FAILURE);
          }

          if(debug){
            fprintf(stdout,"Broadcast sent.\n");
            fprintf(stdout, "Adding the routing update to the packet queue waiting for broadcast responses.\n");
          }

          struct packet_queue *broadcast_packet = (struct packet_queue *)
              malloc(sizeof(struct packet_queue));
          broadcast_packet->is_packet = 0;
          broadcast_packet->buf = routing_table;
          broadcast_packet->dest_mip = dest_mip;
          broadcast_packet->next_packet = NULL;
          broadcast_packet->next_hop = dest_mip;
          broadcast_packet->payload_len = ret - 1;
          broadcast_packet->tra = 0b010;

          if(first_broadcast_packet == NULL){
            first_broadcast_packet = broadcast_packet;
            last_broadcast_packet = first_broadcast_packet;
          }else {
            last_broadcast_packet->next_packet = broadcast_packet;
            last_broadcast_packet = last_broadcast_packet->next_packet;
          }

          num_bpacket++;


          if(debug){
            fprintf(stdout, "Number of packets waiting for broadcasts: %d\n",num_bpacket);
          }

          continue;
        }

        if(debug){
          fprintf(stdout, "%ld bytes sent to MIP address %d\n", ret, dest_mip);
        }
      }/* Incoming routing data END */




      /* Incoming data over IPC from the routing daemon on the forwarding
      * socket */
      else if(events[i].data.fd == un_fwd_conn){

        if(debug){
          fprintf(stdout, "Received data on forward socket.\n");
        }

        struct msghdr fwd_msg = { 0 };
        struct iovec fwd_iov[1];
        uint8_t next_hop;

        fwd_iov[0].iov_base = &next_hop;
        fwd_iov[0].iov_len = sizeof(next_hop);

        fwd_msg.msg_iov = fwd_iov;
        fwd_msg.msg_iovlen = 1;

        ret = recvmsg(events[i].data.fd, &fwd_msg, 0);

        if(ret == -1){
          perror("main: recvmsg: un_fwd_conn");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }
        else if(ret == 0){

          if(debug){
            fprintf(stdout,"Connection to router terminated.\n\n\n");
          }

          /* Remove the connected forward socket from the epoll instance */
          if(epoll_ctl(epfd,EPOLL_CTL_DEL,events[i].data.fd,&events[i]) == -1){
            perror("main: epoll_ctl: del un_fwd_conn");
            close_sockets(sock_container);
            free_queues(queue_container);
            exit(EXIT_FAILURE);
          }

          close(events[i].data.fd);
          un_fwd_conn = -1; /* Indicates no router is connected */

          /* Rearm the forward socket listening for incoming connections from
           * a router */
          struct epoll_event ep_fwd_ev = { 0 };
          ep_fwd_ev.events = EPOLLIN | EPOLLONESHOT;
          ep_fwd_ev.data.fd = un_fwd_sock;

          epoll_ctl(epfd, EPOLL_CTL_MOD, un_fwd_sock, &ep_fwd_ev);

          continue;

        }

        if(debug){
          fprintf(stdout, "Received next hop address was %d\n", next_hop);
          fprintf(stdout, "Checking if received next hop is a local address.\n");
        }

        /* Check if the packet was inteded for this host */
        for(j = 0; j < num_eth_sds; j++){
          if(next_hop == local_mip_mac_table[j].mip_addr){
            if(debug){
              fprintf(stdout, "Received next hop address %d was a local MIP address.\n", next_hop);
            }

            if(un_sock_conn == -1){
              break;
            }

            /* TODO: Send to router or application */
            /* Packet will be a complete MIP transport packet */
            struct msghdr transport_msg = { 0 };
            struct iovec transport_iov[2];

            void *payload = ((struct ethernet_frame *) first_packet->buf)->payload.payload;

            transport_iov[0].iov_base = &first_packet->src_mip;
            transport_iov[0].iov_len = sizeof(first_packet->src_mip);

            transport_iov[1].iov_base = payload;
            transport_iov[1].iov_len = strlen((char *) payload) + 1;

            transport_msg.msg_iov = transport_iov;
            transport_msg.msg_iovlen = 2;

            ret = sendmsg(un_sock_conn, &transport_msg, 0);

            if(ret == -1){
              perror("main: un_fwd_conn: message to application failure");
              close_sockets(sock_container);
              free_queues(queue_container);
              exit(EXIT_FAILURE);
            }

            break;
          }
        }
        /* If j < num_eth_sds, the packet was sent to the application */

        /* If the next hop MIP address received from the router was 255, the
         * destination has no known route, or the packet was sent to the
         * connected application */
        if(next_hop == 255 || j < num_eth_sds){
          if(debug){
            fprintf(stdout, "Next hop address was invalid, discard packet.\n");
          }
          /* Remove the querying packet from the front of the queue of packets
           * waiting for forwarding, and free the data */
          struct packet_queue *tmp = first_packet;
          first_packet = first_packet->next_packet;
          if(first_packet == NULL){
            last_packet = first_packet;
          }

          free(tmp->buf);
          free(tmp);

          num_packet--;

          if(debug){
            fprintf(stdout, "Number of packets waiting for forwarding: %d\n", num_packet);
          }
          continue;
        }
        /* Else, attempt to forward the first packet in the queue */
        else{
          if(debug){
            fprintf(stdout, "Forwarding packet with next hop received from router.\n");
          }
          if(first_packet->is_packet == 1){
            ret = forward_mip_packet(mip_arp_table, local_mip_mac_table,
                next_hop,
                (struct ethernet_frame *) first_packet->buf,
                first_packet->payload_len, debug);
          }else{
            ret = send_mip_packet(mip_arp_table, local_mip_mac_table,
                first_packet->dest_mip, next_hop, first_packet->buf,
                strlen((char *) first_packet->buf) + 1, 0b100, 0, debug);
          }
        }


        if(ret == -1){
          perror("main: un_fwd_conn: forward MIP packet");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }

        /* The payload of the packet was too large */
        else if(ret == -2){
          if(debug){
            fprintf(stdout,"Payload exceeds max length. Aborted send.\n");
          }
        }

        /* The MIP address indicated by the client was not cached in the
         * MIP-ARP table */
        else if(ret == -3){
          if(debug){
            fprintf(stdout,"Next hop address %d not in MIP-ARP table.\n",
              next_hop);
            fprintf(stdout, "Sending MIP-ARP broadcast to find destination.\n");
          }

          /* Send out a MIP-ARP broadcast to attempt to find the next hop MIP
           * address indicated by the router */
          if(send_mip_broadcast(mip_arp_table, num_eth_sds,
              local_mip_mac_table, next_hop, debug) == -1){
            perror("main: send_mip_broadcast: un_fwd_conn");
            close_sockets(sock_container);
            free_queues(queue_container);
            exit(EXIT_FAILURE);
          }

          if(debug){
            fprintf(stdout,"Broadcast sent.\n");
            fprintf(stdout, "Moving packet to packet queue waiting for broadcast responses.\n");
          }


          /* Move the packet from the queue of packets awaiting forwarding to
           * the queue of packets awaiting a broadcast response */
          first_packet->next_hop = next_hop;

          if(first_broadcast_packet == NULL){
            first_broadcast_packet = first_packet;
            last_broadcast_packet = first_broadcast_packet;
          }else {
            last_broadcast_packet->next_packet = first_packet;
            last_broadcast_packet = last_broadcast_packet->next_packet;
          }

          first_packet = first_packet->next_packet;
          if(first_packet == NULL) last_packet = NULL;

          num_packet--;
          num_bpacket++;


          if(debug){
            fprintf(stdout,"Current number in forward queue: %d\n", num_packet);
            fprintf(stdout, "Current number in broadcast queue: %d\n",num_bpacket);
          }

          continue;
        }

        if(debug){
          fprintf(stdout,"%ld bytes sent to destination %d\n", ret, next_hop);
          fprintf(stdout, "Removing packet from packet queue.\n");
        }

        /* If the packet was successfully forwarded, remove the packet from the
         * queue, and free the data */
        struct packet_queue *tmp = first_packet;
        first_packet = first_packet->next_packet;
        if(first_packet == NULL){
          last_packet = first_packet;
        }
        free(tmp->buf);
        free(tmp);
        num_packet--;

        if(debug){
          fprintf(stdout,"Number of packets in queue: %d\n", num_packet);
        }

      }/* Incoming forwarding data END */




      /* Incoming data over IPC from connected application */
      else if(events[i].data.fd == un_sock_conn){
        if(debug){
          fprintf(stdout,"Incoming data from application.\n");
        }

        /* Unix communication based on code from group session
         * https://github.uio.no/persun/inf3190/tree/master/plenum3 */

        /* Receive data from the connected application over IPC */
        char *msg_buf = (char *) calloc(MAX_MSG_SIZE, sizeof(char));
        uint8_t dest_mip_addr;

        struct msghdr msg = { 0 };
        struct iovec iov[2];

        iov[0].iov_base = &dest_mip_addr;
        iov[0].iov_len = sizeof(dest_mip_addr);

        iov[1].iov_base = msg_buf;
        iov[1].iov_len = sizeof(char) * MAX_MSG_SIZE;

        msg.msg_iov = iov;
        msg.msg_iovlen = 2;

        ret = recvmsg(events[i].data.fd,&msg,0);

        if(ret == -1){
          perror("main: recvmsg: un_sock_conn");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }
        /* Application has terminated the connection to the MIP daemon */
        else if (ret == 0){

          if(debug){
            fprintf(stdout,"Connection to application terminated.\n\n\n");
          }

          /* Remove the connected unix socket from the epoll instance */
          if(epoll_ctl(epfd,EPOLL_CTL_DEL,events[i].data.fd,&events[i]) == -1){
            perror("main: epoll_ctl: del un_sock_conn");
            close_sockets(sock_container);
            free_queues(queue_container);
            exit(EXIT_FAILURE);
          }

          close(events[i].data.fd);
          un_sock_conn = -1; /* Indicates no application is connected */

          /* Rearm the unix socket listening for incoming connections from
          * applications */
          struct epoll_event ep_un_ev = { 0 };
          ep_un_ev.events = EPOLLIN | EPOLLONESHOT;
          ep_un_ev.data.fd = un_sock;

          epoll_ctl(epfd, EPOLL_CTL_MOD, un_sock, &ep_un_ev);

          continue;
        }

        /* The received data was an outgoing packet */
        if(debug){
          fprintf(stdout,"Received %ld bytes from client:\n",ret);
          fprintf(stdout,"Destination MIP address: %d\n",dest_mip_addr);
          fprintf(stdout,"Message: \"%s\"\n\n",msg_buf);
          fprintf(stdout,"Requesting next hop for destination from router.\n");
        }

        struct msghdr lookup_msg = { 0 };
        struct iovec lookup_iov[1];

        lookup_iov[0].iov_base = &dest_mip_addr;
        lookup_iov[0].iov_len = sizeof(dest_mip_addr);

        lookup_msg.msg_iov = lookup_iov;
        lookup_msg.msg_iovlen = 1;

        if(sendmsg(un_fwd_conn, &lookup_msg, 0) == -1){
          perror("main: sendmsg: un_sock_conn");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }

        if(debug) print_arp_table(mip_arp_table);

        if(debug){
          fprintf(stdout, "Adding packet to packet queue awaiting forward response from router.\n");
        }

        /* TODO: FREE */
        struct packet_queue *packet = (struct packet_queue *)
            malloc(sizeof(struct packet_queue));
        packet->is_packet = 0;
        packet->buf = msg_buf;
        packet->dest_mip = dest_mip_addr;
        packet->next_packet = NULL;
        packet->payload_len = ret - 1;
        packet->tra = 0b100;

        if(first_packet == NULL){
          first_packet = packet;
          last_packet = packet;
        }else{
          last_packet->next_packet = packet;
          last_packet = last_packet->next_packet;
        }
        num_packet++;

        if(debug){
          fprintf(stdout, "Number of packets in queue: %d\n", num_packet);
        }

      } /* Communication over IPC with connected application END */



      /* Incoming data over ethernet */
      else{

        if(debug){
          fprintf(stdout, "Receiving data over ethernet.\n");
        }
        /* The source MIP address of the received packet will be stored in
        * src_mip, and the message will be stored in buf */
        ret = recv_mip_packet(mip_arp_table, events[i].data.fd, sock_container,
            queue_container, debug, &num_packet, &num_bpacket);

        if(ret == -1){
          perror("main: recv: eth socket");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }
        /* The received packet was not intended for this host */
        else if(ret == -2){

          if(debug){
            fprintf(stdout, "Received packet was not intended for this host. Discarding it.\n");
          }
          /* Discard it */
          continue;
        }
        /* The received packet needed to be forwarded, but no router was
         * was connected to handle forwarding */
        else if(ret == -3){
          if(debug){
            fprintf(stdout, "Received packet needed to be forwarded, but no router was connected to handle forwarding.\n");
          }
        }
        /* The received packet needed to be forwarded, but the its TTL reached
         * -1 */
        else if(ret == -4){
          if(debug){
            fprintf(stdout, "Received packet needed to be forwarded, but its TTL reached -1.\n");
          }
        }
        /* Error when sending forward request to router */
        else if(ret == -5){
          perror("main: recv_eth: forward failure");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }
        /* Error when attempting to forward packets waiting for a broadcast */
        else if(ret == -6){
          perror("main: recv_eth: broadcast forward failure");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }
        /* No connected application to receive transport packet */
        else if(ret == -7){
          if(debug){
            fprintf(stdout, "No application connected. Discarding packet.\n");
          }
          /* Discarding the packet */
          continue;
        }
        /* Error when attempting to send message from transport packet to
         * connected application */
        else if(ret == -8){
          perror("main: recv_eth: message to application failure");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }
        /* No router connected to receive routing packet */
        else if(ret == -9){
          if(debug){
            fprintf(stdout, "No routing daemon connected. Discarding "
                "packet\n");
          }
          continue;
        }
        /* Error when attempting to send data from routing packet to connected
         * router */
        else if(ret == -10){
          perror("main: recv_eth: data to router failure");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }
        /* Error when attempting to respond to MIP-ARP broadcast */
        else if(ret == -11){
          perror("main: recv_eth: MIP-ARP response failure");
          close_sockets(sock_container);
          free_queues(queue_container);
          exit(EXIT_FAILURE);
        }

      } /* Received data over ethernet END */

    } /* Iterating through events triggered in the main loop END */

  } /* Polling sockets for event until keyboard interrupt END */

} /* int main() END */
