#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <signal.h>
#include <sys/signalfd.h>

#include "routing_daemon.h"




/**
 * Prints usage information to stderr for the user
 *
 * @param file_name Filename of the user executed, argv[0]
 * @return          none
 */
void print_help(char *file_name){
  fprintf(stderr,"USAGE: %s [-h] [-d] <Socket_route> <Socket_forwarding>\n",
    file_name);
  fprintf(stderr,"[-h]: optional help argument\n");
  fprintf(stderr,"[-d]: optional debug argument, prints debugging "
    "information\n");
  fprintf(stderr,"<Socket_route>: name of socket for IPC of routing data with "
    "the MIP daemon\n");
  fprintf(stderr,"<Socket_forwarding>: name of socket for IPC of forwarding "
    "lookup with the MIP daemon\n");
  exit(EXIT_FAILURE);
}




/**
 * Prints the destination MIPs in the provided routing table.
 *
 * @param routing_table   The routing table whose destinations are to be
 *                        printed
 * @return                None
 */
void print_rout_dest(struct routing_table_entry *routing_table){
  int i;
  for(i = 0; i < MAX_MIP; i++){
    if(routing_table[i].dest_mip == 255){
      break;
    }
    fprintf(stdout, "%d\t",routing_table[i].dest_mip);
  }
}




/**
 * Closes the sockets in the provided socks struct, and unlinks their paths if
 * free_path is set to 1.
 *
 * @param socks     Data structure whose sockets are to be closed.
 * @param free_path Decides if the paths of the sockets should be unlinked.
 * @return          None
 */
void close_sockets(struct sockets socks, int free_path){
  /* Closes the sockets in socks */
  struct sockaddr_un un_route_addr = { 0 };
  socklen_t route_addrlen = sizeof(un_route_addr);
  getsockname(*socks.un_route_sock, (struct sockaddr*) &un_route_addr,
      &route_addrlen);
  close(*socks.un_route_sock);

  /* Unlink if specified */
  if(free_path == 1) unlink(un_route_addr.sun_path);

  struct sockaddr_un un_fwd_addr = { 0 };
  socklen_t fwd_addrlen = sizeof(un_fwd_addr);
  getsockname(*socks.un_fwd_sock, (struct sockaddr*) &un_fwd_addr,
    &fwd_addrlen);
  close(*socks.un_fwd_sock);

  /* Unlink if specified */
  if(free_path == 1) unlink(un_fwd_addr.sun_path);

  close(*socks.signal_fd);

}




/**
 * Frees the data stored in the distance table provided.
 *
 * @param distance_table  Distance table whose data is to be freed.
 * @return                None
 */
void free_distance_table(struct distance_table_entry *distance_table){
  int i;
  /* Iterate through all non-empty entries of the distance table and free
   * their entries */
  for(i = 0; i < MAX_MIP; i++){
    if(distance_table[i].dest_mip == BAD_MIP){
      break;
    }
    free(distance_table[i].next_hop);
    free(distance_table[i].cost);
    free(distance_table[i].timestamp);
  }

}




/**
 * Initializes the routing and distance table of the routing daemon by
 * receiving the local MIP addresses of the MIP daemon the router is connected
 * to, and then sending a broadcast routing update to the MIP daemon for
 * neighbour discovery.
 *
 * @param socks         Structure containing the sockets of the routing daemon.
 *                      Used for receiving data from the MIP daemon and sending
 *                      a routing broadcast to the MIP daemon.
 * @param rd            Structure containing the data of the routing daemon.
 *                      Contains the routing and distance tables as well as
 *                      other structures. Used for containing the initialized
 *                      data.
 * @param debug         Variable specifying whether or not debug messages
 *                      should be written to the terminal.
 * @return              Returns the number of local mip addresses received from
 *                      the routing daemon on success, -2  if the routing
 *                      daemon shut down, and -1 on error.
 */
int init_routing_data(struct sockets socks, struct routing_data rd, int debug){

  int num_local_mips,i;

  struct msghdr recv_msg = { 0 };
  struct iovec recv_iov[1];

  /* Initialize the tables to invalid data. An invalid MIP address signifies an
   * empty entry */
  for(i = 0; i < MAX_MIP; i++){
    rd.routing_table[i].dest_mip = BAD_MIP;
    rd.routing_table[i].next_hop = BAD_MIP;
    rd.routing_table[i].cost = UNREACHABLE;
  }
  memset(rd.local_mips, BAD_MIP, MAX_MIP);
  memset(rd.neighbours, BAD_MIP, MAX_MIP);


  /* Receive the local MIP addresses from the MIP daemon */
  recv_iov[0].iov_base = rd.local_mips;
  recv_iov[0].iov_len = MAX_MIP;

  recv_msg.msg_iov = recv_iov;
  recv_msg.msg_iovlen = 1;

  /* Receive an array of characters, each indicating a local MIP address */
  num_local_mips = recvmsg(*socks.un_route_sock, &recv_msg, 0);

  if(num_local_mips == -1){
    return -1;
  }else if(num_local_mips == 0){
    return -2;
  }

  if(debug){
    fprintf(stdout, "Received %d bytes of data from MIP daemon.\n",
        num_local_mips);
    fprintf(stdout, "Local MIP addresses received:\n");
  }

  /* Create entries for the local MIP addresses in the routing and distance
   * tables */
  for(i = 0; i < num_local_mips; i++){

    if(debug){
      fprintf(stdout, "%d\n",rd.local_mips[i]);
    }

    rd.routing_table[i].dest_mip = rd.local_mips[i];
    rd.routing_table[i].next_hop = rd.local_mips[i];
    rd.routing_table[i].cost = 0;
  }

  for(i = 0; i < MAX_MIP; i++){
    if(i < num_local_mips){
     rd.distance_table[i].dest_mip = rd.local_mips[i];
    }
    /* Initialize the rest to invalid values */
    else{
      rd.distance_table[i].dest_mip = BAD_MIP;
    }

    rd.distance_table[i].next_hop = NULL;
    rd.distance_table[i].cost = NULL;
    rd.distance_table[i].timestamp = NULL;
  }

  /* Broadcast the local MIP addresses to all neighbours */
  struct msghdr send_msg = { 0 };
  struct iovec send_iov[2];

  /* A MIP address of 255 indicates that the MIP daemon should broadcast the
   * routing table on all network interfaces */
  uint8_t broadcast_mip = BROADCAST_MIP;

  send_iov[0].iov_base = &broadcast_mip;
  send_iov[0].iov_len = sizeof(broadcast_mip);

  send_iov[1].iov_base = rd.routing_table;
  send_iov[1].iov_len = sizeof(struct routing_table_entry) * num_local_mips;

  send_msg.msg_iov = send_iov;
  send_msg.msg_iovlen = 2;

  ssize_t ret = sendmsg(*socks.un_route_sock, &send_msg, 0);

  if(ret == -1){
    return -1;
  }

  return num_local_mips;
}




/**
 * Sends a routing update with the routing table contained in the rd struct,
 * to all neighbours contained in the rd struct.
 *
 * @param socks         Structure containing the sockets of the routing daemon.
 *                      Used for sending updates to the routing daemon.
 * @param rd            Structure containing the data of the routing daemon.
 *                      Contains the routing and distance tables as well as
 *                      other structures. Used for sending the routing data
 *                      in the routing table contained in this struct to the
 *                      neighbours in the neighbours array contained in this
 *                      struct.
 * @param debug         Variable specifying whether or not debug messages
 *                      should be written to the terminal.
 * @return              Returns 0 on success, -1 on error.
 */
int send_routing_table_update(struct sockets socks, struct routing_data rd,
    int debug){

  int i,j;
  ssize_t ret;

  for(i = 0; i < *rd.num_neighbours; i++){
    struct routing_table_entry send_table[MAX_MIP];
    uint8_t dest_neighbour = rd.neighbours[i];
    int num_entries = 0;

    for(j = 0; j < MAX_MIP; j++){
      if(rd.routing_table[j].dest_mip == BAD_MIP) break;

      if(rd.routing_table[j].next_hop != dest_neighbour){
        send_table[num_entries].next_hop = rd.routing_table[j].next_hop;
        send_table[num_entries].dest_mip = rd.routing_table[j].dest_mip;
        send_table[num_entries].cost = rd.routing_table[j].cost;
        num_entries++;
      }
    }

    struct msghdr msg = { 0 };
    struct iovec iov[2];

    iov[0].iov_base = &dest_neighbour;
    iov[0].iov_len = sizeof(dest_neighbour);

    iov[1].iov_base = send_table;
    iov[1].iov_len = num_entries * sizeof(struct routing_table_entry);

    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    ret = sendmsg(*socks.un_route_sock, &msg, 0);

    if(ret == -1){
      return -1;
    }

    if(debug){
      fprintf(stdout, "Sent %ld bytes to MIP daemon for MIP %d\n", ret,
          dest_neighbour);
    }


  }

  if(debug) fprintf(stdout, "\n");


  return 0;
}




/**
 * Cleans up expired entries in the distance table contained in the provided
 * rd struct. Any expired entry will have its cost set to UNREACHABLE, and the
 * routing table will be updated to reflect the changes in the distance table.
 * If a neighbour only has expired entries in the distance table, the neighbour
 * is removed from it, but not from the routing table. A destination with only
 * expired entries in the destination table will result in the destination in
 * the routing table becoming UNREACHABLE, but it will not be removed, so that
 * an update can be sent to neighbours that the destination is unreachable.
 *
 * @param rd            Structure containing the data of the routing daemon.
 *                      Contains the routing and distance tables as well as
 *                      other structures. Used for updating the routing and
 *                      distance tables.
 * @param now           The current time. Used for checking timestamps in the
 *                      distance table.
 * @return              Returns 1 if the routing table is updated, 0 if not.
 */
int clean_dist_route(struct routing_data rd, time_t now){
  int i,j,k;
  int updated = 0;

  /* If a neighbour has been silent for the time between routing updates
   * specified in UPDATE_WAIT, a number of times specified in
   * WAIT_NUM_TIMEOUT, remove the neighbour and its corresponding entries in
   * the distance table */
  for(i = 0; i < *rd.num_neighbours; i++){
    if(now - rd.last_neighbour_update[i] > UPDATE_WAIT * WAIT_NUM_TTL){
      uint8_t neighbour = rd.neighbours[i];
      for(j = *rd.num_local_mips; j < MAX_MIP; j++){

        /* Stop if an empty entry was reached */
        if(rd.distance_table[j].dest_mip == BAD_MIP) break;

        /* Remove the entries for the neighbour and resort the values for next
         * hop, cost and timestamp */
        for(k = i; k < *rd.num_neighbours-1; k++){
          rd.distance_table[j].next_hop[k] =
              rd.distance_table[j].next_hop[k+1];
          rd.distance_table[j].cost[k] = rd.distance_table[j].cost[k+1];
          rd.distance_table[j].timestamp[k] =
              rd.distance_table[j].timestamp[k+1];
        }

        /* Reallocate memory */
        rd.distance_table[j].next_hop =
          (uint8_t *) realloc(rd.distance_table[j].next_hop,
              *rd.num_neighbours - 1);

        rd.distance_table[j].cost =
          (uint8_t *) realloc(rd.distance_table[j].cost,
              *rd.num_neighbours - 1);

        rd.distance_table[j].timestamp =
          (time_t *) realloc(rd.distance_table[j].timestamp,
          sizeof(time_t) * (*rd.num_neighbours - 1));
      }

      /* Remove the neighbour from the neighbours data structure */
      for(j = i; j < *rd.num_neighbours-1; j++){
        rd.neighbours[j] = rd.neighbours[j+1];
        rd.neighbours[j+1] = BAD_MIP;
        rd.last_neighbour_update[j] = rd.last_neighbour_update[j+1];
        rd.last_neighbour_update[j+1] = 0;
      }

      (*rd.num_neighbours)--;

      /* Update the entry in the routing table for any destination whose
       * route's next hop was the removed neighbour */
      for(j = 0; j < MAX_MIP; j++){
        if(rd.routing_table[j].next_hop == neighbour){
          updated = 1;

          rd.routing_table[j].cost = UNREACHABLE;

          for(k = 0; k < *rd.num_neighbours; k++){
            if(rd.distance_table[j].cost[k] < rd.routing_table[j].cost){
              rd.routing_table[j].next_hop = rd.distance_table[j].next_hop[k];
              rd.routing_table[j].cost = rd.distance_table[j].cost[k];
            }
          }
        }
      }
    }
  }

  /* Set expired entries in the distance table to unreachable */
  for(i = 0; i < *rd.num_neighbours; i++){
    /* Don't update entries for local MIP addresses */
    for(j = *rd.num_local_mips; j < MAX_MIP; j++){
      /* Stop if an empty entry was reached */
      if(rd.distance_table[j].dest_mip == BAD_MIP) break;

      /* If the destination is already unreachable through the neighbour,
       * the entry has been previously updated */
      if(rd.distance_table[j].cost[i] == UNREACHABLE) continue;

      /* Expired entry */
      if(now - rd.distance_table[j].timestamp[i] > UPDATE_WAIT * WAIT_NUM_TTL){

        rd.distance_table[j].cost[i] = UNREACHABLE;

        /* Update the cost of the route if the next hop of the route was the
         * same as the next hop of the expired entry */
        if(rd.routing_table[j].next_hop == rd.distance_table[j].next_hop[i]){
          rd.routing_table[j].cost = rd.distance_table[j].cost[i];

          updated = 1;
        }

        /* Update the next hop of the route to the next hop with the cheapest
         * route */
        for(k = 0; k < *rd.num_neighbours; k++){
          if(rd.distance_table[j].cost[k] < rd.routing_table[j].cost){
            rd.routing_table[j].next_hop = rd.distance_table[j].next_hop[k];
            rd.routing_table[j].cost = rd.distance_table[j].cost[k];

            updated = 1;
          }
        }
      }
    }
  }

  return updated;
}




/**
 * Removes UNREACHABLE destination MIP addresses from the routing and distance
 * tables.
 *
 * @param rd            Structure containing the data of the routing daemon.
 *                      Contains the routing and distance tables as well as
 *                      other structures. Used for updating the routing and
 *                      distance tables.
 * @return              Returns the amount of entries removed from the routing
 *                      and distance tables.
 */
int rm_empty_route_dist(struct routing_data rd){

  int i,j;

  int removed = 0;

  /* If the next hop of a route for a destination MIP address is an invalid
   * MIP address, remove the entry for that destination MIP address from both
   * the distance and routing tables */
  for(i = 0; i < MAX_MIP; i++){
    if(rd.routing_table[i].dest_mip == BAD_MIP) break;
    if(rd.routing_table[i].cost == UNREACHABLE){

      removed ++;
      free(rd.distance_table[i].next_hop);
      free(rd.distance_table[i].cost);
      free(rd.distance_table[i].timestamp);

      for(j = i; j < MAX_MIP-1; j++){
        if(rd.routing_table[j].dest_mip == BAD_MIP) break;

        rd.routing_table[j] = rd.routing_table[j+1];
        rd.routing_table[j+1].next_hop = BAD_MIP;
        rd.routing_table[j+1].dest_mip = BAD_MIP;
        rd.routing_table[j+1].cost = UNREACHABLE;

        rd.distance_table[j] = rd.distance_table[j+1];
        rd.distance_table[j+1].dest_mip = BAD_MIP;
        rd.distance_table[j+1].next_hop = NULL;
        rd.distance_table[j+1].cost = NULL;
        rd.distance_table[j+1].timestamp = NULL;
      }
    }
  }

  return removed;
}




/**
 * Creates the routing and forwarding unix sockets used for communication with
 * the MIP daemon. Binds them to the paths in the provided arguments. Also sets
 * up the signal handler for keyboard interrupts.
 *
 * @param socks         Structure containing the sockets of the router. Used
 *                      for connecting to the MIP daemon.
 * @param un_route_name Path of the routing socket. Used to connect to the MIP
 *                      daemon.
 * @param un_fwd_name   Path of the forwarding socket. Used to connect to the
 *                      MIP daemon.
 * @return              Returns 0 on success and a negative number on error.
 */
int create_sockets(struct sockets socks, char* un_route_name,
    char* un_fwd_name){

  /* Create unix IPC routing and forwarding sockets */
  struct sockaddr_un route_addr = { 0 };
  struct sockaddr_un fwd_addr = { 0 };

  *socks.un_route_sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if(*socks.un_route_sock == -1){
    return -1;
  }

  *socks.un_fwd_sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if(*socks.un_fwd_sock == -1){
    return -2;
  }

  /* Bind them to the paths and connect to the MIP daemon */
  route_addr.sun_family = AF_UNIX;
  strncpy(route_addr.sun_path, un_route_name, sizeof(route_addr.sun_path));
  fwd_addr.sun_family = AF_UNIX;
  strncpy(fwd_addr.sun_path, un_fwd_name, sizeof(fwd_addr.sun_path));

  if(connect(*socks.un_route_sock, (struct sockaddr *) &route_addr,
      sizeof(struct sockaddr_un)) == -1){
    return -3;
  }

  if(connect(*socks.un_fwd_sock, (struct sockaddr *) &fwd_addr,
      sizeof(struct sockaddr_un)) == -1){
    return -4;
  }

  /* Add a keyboard interrupt signal handler for the epoll instance */
  sigset_t mask;

  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGQUIT);

  sigprocmask(SIG_BLOCK, &mask, NULL);

  *socks.signal_fd = signalfd(-1, &mask, 0);
  if(*socks.signal_fd == -1){
    return -5;
  }

  return 0;

}




/**
 * Creates the epoll instance for the router, and adds events for the routing,
 * forward and signal handler descriptors.
 *
 * @param socks         Structure containing the sockets of the router. Used
 *                      Adding said sockets to the epoll instance.
 * @return              Returns the epoll file descriptor on success and a
 *                      negative number on failure.
 */
int create_epoll_instance(struct sockets socks){
  struct epoll_event ep_route_ev = { 0 };
  struct epoll_event ep_fwd_ev = { 0 };
  struct epoll_event ep_sig_ev = { 0 };

  /* Create an epoll instance for the sockets */
  int epfd = epoll_create(1);

  /* Add the unix sockets */
  ep_route_ev.data.fd = *socks.un_route_sock;
  ep_route_ev.events = EPOLLIN;
  ep_fwd_ev.data.fd = *socks.un_fwd_sock;
  ep_fwd_ev.events = EPOLLIN;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, *socks.un_route_sock, &ep_route_ev) == -1){
    return -1;
  }
  if(epoll_ctl(epfd, EPOLL_CTL_ADD, *socks.un_fwd_sock, &ep_fwd_ev) == -1){
    return -2;
  }

  /* Add the signal handler */
  ep_sig_ev.events = EPOLLIN | EPOLLERR;
  ep_sig_ev.data.fd = *socks.signal_fd;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, *socks.signal_fd, &ep_sig_ev) == -1){
    return -3;
  }

  return epfd;
}




/**
 * Prints the entries in the provided routing table.
 *
 * @param routing_table Routing table whose entries are to be printed.
 * @return              None
 */
void print_routing_table(struct routing_table_entry *routing_table){
  int i;
  fprintf(stdout, "Current routing table:\n");
  for(i = 0; i < MAX_MIP; i++){
    if(routing_table[i].dest_mip == 255) break;
    fprintf(stdout, "Dest mip: %d\tNext hop: %d\tCost: %d\n",
        routing_table[i].dest_mip, routing_table[i].next_hop,
        routing_table[i].cost);
  }
  fprintf(stdout,"\n");
}




/**
 * Prints the neighbours in the provided neighbour data structure.
 *
 * @param neighbours      Neighbours to be printed.
 * @param num_neighbours  Number of neighbours in neighbours.
 * @return                None
 */
void print_neighbours(uint8_t *neighbours, int num_neighbours){
  int i;
  fprintf(stdout, "Current neighbours:\n");
  for(i = 0; i < num_neighbours; i++){
    fprintf(stdout, "#%d\t%d\n", i, neighbours[i]);
  }
  fprintf(stdout,"\n");
}




/**
 * Sends a routing update to all neighbours if the time since the last update
 * has exceeded the time limit specified in UPDATE_WAIT
 *
 * @param socks   Data structure containing the sockets of the router. Used for
 *                sending routing updates to the MIP daemon so it can send it
 *                to the neighbours.
 * @param rd      Structure containing the data of router. Contains the routing
 *                table which is what will be sent, as well as the neighbours,
 *                which is who the routing update will be sent to.
 * @param now     The current time.
 * @param debug   Variable specifiying whether debug messages should be written
 *                to the console.
 * @return        None
 */
time_t scheduled_update(struct sockets socks, struct routing_data rd,
    time_t now, int debug){
  /* How long the timeout should be for the call to epoll_wait */
  time_t timeout = (UPDATE_WAIT - (now - *rd.last_update_timestamp)) * 1000;

  /* If it has been at least a number of seconds specified in UPDATE_WAIT
   * since the last routing table update, send a routing table update */
  if(timeout <= 0){

    if(debug){
      fprintf(stdout, "Sending scheduled update.\n");
    }

    /* Clean the distance and routing tables first */
    clean_dist_route(rd, now);

    if(debug) print_routing_table(rd.routing_table);
    if(debug) print_neighbours(rd.neighbours, *rd.num_neighbours);

    if(send_routing_table_update(socks, rd, debug) == -1){
      return -1;
    }

    /* Only remove unreachable destinations after telling neighbours that
     * the destinations are unreachable */
    rm_empty_route_dist(rd);

    *rd.last_update_timestamp = now;
    timeout = UPDATE_WAIT * 1000;
  }

  return timeout;
}




/**
 * Handler for receiving a signal on the provided signal_fd
 *
 * @param signal_fd       The descriptor which received the signal.
 * @return                Returns 0 if the signal was a keyboard interrupt, 0
 *                        otherwise.
 */
int keyboard_signal(int signal_fd){
  struct signalfd_siginfo sig_info;
  ssize_t sig_size;

  sig_size = read(signal_fd, &sig_info, sizeof(struct signalfd_siginfo));

  /* Close all sockets and close stop the daemon */
  if(sig_size == 0){
    perror("\nCtrl-d: Received EOF signal from keyboard, stopping\n");
    return 0;
  }
  if(sig_info.ssi_signo == SIGINT){
    fprintf(stderr,"\nCtrl-c: Received interrupt from keyboard,"
        "stopping daemon\n");
    return 0;
  }
  else if(sig_info.ssi_signo == SIGQUIT){
    fprintf(stderr,"\nCtrl-\\: Received interrupt from keyboard,"
        "stopping daemon\n");
    return 0;
  }

  return 1;
}




/**
 * Checks if a MIP address is a new neighbour, and adds it to the neighbour
 * list and expands the distance table if it is.
 *
 * @param rd            Structure containing the data of the router. Used when
 *                      checking if the neighbour is new, as well as adding the
 *                      new neighbour and expanding the distance table.
 * @param src_mip       The address to check if is a new neighbour.
 * @param now           The current time.
 * @param debug         Variable specifying whether or not to write debug
 *                      messages to the terminal.
 * @return              Returns 1 if the neighbour was previously unknown and 0
 *                      otherwise.
 */
int new_neighbour(struct routing_data rd, int src_mip, time_t now, int debug){
  int new_neighbour = 1;
  int i;

  for(i = 0; i < *rd.num_neighbours; i++){
    if(src_mip == rd.neighbours[i]){
      new_neighbour = 0;
      rd.last_neighbour_update[i] = now;
      break;
    }
  }

  /* If the routing update was received from a previously unknown
   * neighbour, expand the distance table to make room for the new
   * neighbour */
  if(new_neighbour == 1){
    rd.neighbours[*rd.num_neighbours] = src_mip;
    rd.last_neighbour_update[*rd.num_neighbours] = now;

    /* Never update entries for local MIP addresses */
    for(i = *rd.num_local_mips; i < MAX_MIP; i++){

      /* Stop if an empty entry was reached */
      if(rd.distance_table[i].dest_mip == BAD_MIP) break;

      /* Reallocate memory to make room for the new neighbour */
      rd.distance_table[i].next_hop = (uint8_t *)
        realloc(rd.distance_table[i].next_hop, *rd.num_neighbours + 1);
      rd.distance_table[i].next_hop[*rd.num_neighbours] = src_mip;

      rd.distance_table[i].cost =
        (uint8_t *) realloc(rd.distance_table[i].cost, *rd.num_neighbours + 1);
      rd.distance_table[i].cost[*rd.num_neighbours] = UNREACHABLE;

      rd.distance_table[i].timestamp =
        (time_t *) realloc(rd.distance_table[i].timestamp, sizeof(time_t) *
        (*rd.num_neighbours + 1));
      rd.distance_table[i].timestamp[*rd.num_neighbours] = 0;
    }

    (*rd.num_neighbours)++;
  }

  return new_neighbour;
}




/**
 * Updates the routing and distance tables in the rd data structure with the
 * data in the provided routing update.
 *
 * @param rd            Structure containing the data of the router. Used to
 *                      update the routing and distance tables contained in the
 *                      structure with the data in route_update.
 * @param route_update  Routing update to be used to update the routing and
 *                      distance tables contained in the rd data structure.
 * @param src_mip       The source of the routing update.
 * @param recv_size     Used to calculate the amount of entries in the routing
 *                      update
 * @param now           The current time.
 * @param debug         Variable specifying whether or not to write debug
 *                      messages to the terminal.
 * @return              Returns 1 if the routing table was updated, and 0
 *                      otherwise
 */
int update_tables(struct routing_data rd,
    struct routing_table_entry *route_update, uint8_t src_mip,
    ssize_t recv_size, time_t now, int debug){

  int updated = 0;
  int i,j,k;

  /* Number of rows in the routing table received */
  int num_entries = (recv_size - 1) / 3; /* next hop, destination, cost */

  /* Update the distance table */
  for(i = 0; i < num_entries; i++){

    /* Ignore entry if the route's next hop is this node */
    int goes_through_this = 0;
    for(j = 0; j < *rd.num_local_mips; j++){
      if(route_update[i].next_hop == rd.local_mips[j]){
        goes_through_this = 1;
      }
    }
    if(goes_through_this) continue;


    for(j = 0; j < MAX_MIP; j++){
      /* Existing destionation MIP */
      if(route_update[i].dest_mip == rd.distance_table[j].dest_mip){
        if(j < *rd.num_local_mips){
          /* Ignore entry if the destination is one of the local MIP
           * addresses */
          break;
        }

        for(k = 0; k < *rd.num_neighbours; k++){
          if(rd.neighbours[k] == src_mip){
            /* Update entry for the neighbour that the routing data was
             * received from */
            rd.distance_table[j].next_hop[k] = rd.neighbours[k];
            rd.distance_table[j].cost[k] = route_update[i].cost + 1;
            if(rd.distance_table[j].cost[k] > UNREACHABLE){
              rd.distance_table[j].cost[k] = UNREACHABLE;
            }
            rd.distance_table[j].timestamp[k] = now;

            /* Update the routing table if the new cost is cheaper than the
             * current cost, or if the old next hop was this neighbour and the
             * new cost is HIGHER than the previous one */
            if((rd.distance_table[j].cost[k] < rd.routing_table[j].cost)
                || (rd.distance_table[j].next_hop[k]
                == rd.routing_table[j].next_hop && rd.distance_table[j].cost[k]
                > rd.routing_table[j].cost)){

              if(debug){
                fprintf(stdout, "Entry for MIP %d updated.\n",
                    rd.routing_table[j].dest_mip);
                fprintf(stdout, "Previous values, Next hop: %d\tCost: %d\n",
                    rd.routing_table[j].next_hop, rd.routing_table[j].cost);
              }

              rd.routing_table[j].next_hop = rd.distance_table[j].next_hop[k];
              rd.routing_table[j].cost = rd.distance_table[j].cost[k];

              if(debug){
                fprintf(stdout, "New values, Next hop: %d\tCost: %d\n",
                    rd.routing_table[j].next_hop, rd.routing_table[j].cost);
              }

              updated = 1;
            }

            break;
          }
        }
        break;
      }
      /* New destination MIP */
      else if(rd.distance_table[j].dest_mip == BAD_MIP){

        /* Initialize values for all neighbours */
        rd.distance_table[j].dest_mip = route_update[i].dest_mip;
        rd.distance_table[j].next_hop = (uint8_t *) malloc(*rd.num_neighbours);
        rd.distance_table[j].cost = (uint8_t *) malloc(*rd.num_neighbours);
        rd.distance_table[j].timestamp = (time_t *) malloc(*rd.num_neighbours);

        for(k = 0; k < *rd.num_neighbours; k++){
          if(rd.neighbours[k] == src_mip){
            /* Update entry for the neighbour that the routing data was
             * received from */
            rd.distance_table[j].next_hop[k] = rd.neighbours[k];
            rd.distance_table[j].cost[k] = route_update[i].cost + 1;
            if(rd.distance_table[j].cost[k] > UNREACHABLE){
              rd.distance_table[j].cost[k] = UNREACHABLE;
            }
            rd.distance_table[j].timestamp[k] = now;

            /* Make new entry for the destination MIP address in the
             * routing table */
            rd.routing_table[j].dest_mip = rd.distance_table[j].dest_mip;
            rd.routing_table[j].next_hop = rd.distance_table[j].next_hop[k];
            rd.routing_table[j].cost = rd.distance_table[j].cost[k];

            if(debug){
              fprintf(stdout, "New entry for MIP %d. Next hop: %d\tCost: %d\n",
                  rd.routing_table[j].dest_mip, rd.routing_table[j].next_hop,
                  rd.routing_table[j].cost);
            }
          }
          else {
            /* Values indicating no data for other neighbours */
            rd.distance_table[j].next_hop[k] = rd.neighbours[k];
            rd.distance_table[j].cost[k] = UNREACHABLE;
            rd.distance_table[j].timestamp[k] = 0;
          }
        }

        updated = 1;

        break;
      }
    }
  }

  return updated;
}




/**
 * Receives a routing update from the MIP daemon and uses it to update the
 * routing and distance tables contained in the rd data structure, as well as
 * updating the neighbours if the sender was a previously unknown neighbour.
 *
 * @param socks         Structure containing the sockets of the router. Used
 *                      when receiving the routing update from the MIP daemon.
 * @param rd            Structure containing the data of the router. Used to
 *                      update the routing and distance tables contained in the
 *                      structure with the data in route_update, and the
 *                      neighbours.
 * @param now           The current time.
 * @param debug         Variable specifying whether or not to write debug
 *                      messages to the terminal.
 * @return              Returns 1 if the routing table was updated, if it
 *                      wasn't, -2 if the MIP daemon terminated the connection
 *                      to the router and -1 on error.
 */
int recv_routing_update(struct sockets socks, struct routing_data rd,
    time_t now, int debug){

  /* Receive routing update from MIP daemon */
  int updated = 0;
  ssize_t ret;

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

  ret = recvmsg(*socks.un_route_sock, &msg,0);

  if(ret == -1){
    return -1;
  }else if(ret == 0){
    return -2;
  }

  if(debug){
    fprintf(stdout, "Received %ld bytes from MIP daemon on routing socket, "
        "with source MIP %d.\n", ret, src_mip);
  }

  /* Check if the source is a new neighbour, and add the neighbour if it is */
  new_neighbour(rd, src_mip, now, debug);

  /* Update the routing and distance tables with the routing update */
  updated = update_tables(rd, recv_route_table, src_mip, ret, now, debug);

  /* If the routing update led to the routing table changing, send an
   * update to neighbours */
  if(updated == 1){
    /* Clean expire entries first */
    clean_dist_route(rd, now);

    if(debug){
      fprintf(stdout, "Routing table was updated, sending update to "
          "neighbours.\n");
      print_routing_table(rd.routing_table);
      print_neighbours(rd.neighbours, *rd.num_neighbours);
    }

    /* Send the update */
    if(send_routing_table_update(socks, rd, debug) == -1){
      return -1;
    }

    /* Only remove unreachable destinations after telling neighbours that
     * the destinations are unreachable */
    rm_empty_route_dist(rd);
  }

  return updated;
}




/**
 * Receives a destination MIP address as a forward request, and responds with
 * the next hop of the route if it is known, and an invalid MIP address if it
 * is unknown. Before responding, the distane and routing tables are cleaned
 * of expired entries. If the cleaning lead to an update in the routing table
 * a routing update is sent to all neighbours. Afterwards any UNREACHABLE
 * destinations are removed from the tables.
 *
 * @param socks         Structure containing the sockets of the router. Used
 *                      when receiving the forward request from the MIP daemon.
 * @param rd            Structure containing the data of the router. Used to
 *                      look up the next hop of the route of the received
 *                      destination MIP address.
 * @param now           The current time.
 * @param debug         Variable specifying whether or not to write debug
 *                      messages to the terminal.
 * @return              Returns the next hop of the route of the received
 *                      destination MIP address on success, -2 if the MIP
 *                      daemon terminated the connection and -1 on error.
 */
int recv_fwd_req(struct sockets socks, struct routing_data rd, time_t now,
    int debug){
  ssize_t ret;
  int i;

  struct msghdr recv_msg = { 0 };
  struct iovec recv_iov[1];

  uint8_t dest_mip;

  recv_iov[0].iov_base = &dest_mip;
  recv_iov[0].iov_len = sizeof(dest_mip);

  recv_msg.msg_iov = recv_iov;
  recv_msg.msg_iovlen = 1;

  /* Receive destination MIP address */
  ret = recvmsg(*socks.un_fwd_sock, &recv_msg,0);

  if(ret == -1){
    return -1;
  }else if(ret == 0){
    return -2;
  }

  if(debug){
    fprintf(stdout, "Received request for next hop for destination MIP %d\n",
        dest_mip);
  }

  struct msghdr send_msg = { 0 };
  struct iovec send_iov[1];

  /* An invalid MIP address indicates no route was found for the MIP
   * address */
  uint8_t next_hop = BAD_MIP;

  send_iov[0].iov_base = &next_hop;
  send_iov[0].iov_len = sizeof(next_hop);

  send_msg.msg_iov = send_iov;
  send_msg.msg_iovlen = 1;

  /* Clean up the routing and distance tables before looking up the next
   * hop for the route */
  if(clean_dist_route(rd, now) == 1){
    if(debug){
      fprintf(stdout, "Routing table was updated while cleaning before "
          "responding to forwarding request. Sending update to neighbours.\n");
      print_routing_table(rd.routing_table);
      print_neighbours(rd.neighbours, *rd.num_neighbours);
    }

    /* Id clean-up changed the routing table, send an update to
     * neighbours */
    if(send_routing_table_update(socks, rd, debug) == -1){
      return -1;
    }

    /* Only remove unreachable entries after telling neighbours that the
     * destinations are unreachable */
    rm_empty_route_dist(rd);

    *rd.last_update_timestamp = now;
  }

  for(i = 0; i < MAX_MIP; i++){
    if(rd.routing_table[i].dest_mip == dest_mip){
      next_hop = rd.routing_table[i].next_hop;
    }else if(rd.routing_table[i].dest_mip == BAD_MIP) break;
  }

  if(debug){
    if(next_hop == BAD_MIP){
      fprintf(stdout, "No next hop found for request destination.\n");
      fprintf(stdout, "Responding with %d\n",BAD_MIP);
    }else{
      fprintf(stdout, "Next hop for desination %d: %d\n",dest_mip, next_hop);
    }
  }

  /* Send the next hop of the received destination MIP address to the MIP
   * daemon. */
  ret = sendmsg(*socks.un_fwd_sock, &send_msg, 0);

  if(ret == -1){
    return -1;
  }

  if(debug){
    fprintf(stdout, "Sent %ld bytes to MIP daemon.\n", ret);
  }

  return next_hop;
} /* recv_fwd_req() END */
