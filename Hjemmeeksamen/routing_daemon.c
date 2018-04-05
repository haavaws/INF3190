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

void print_rout_dest(struct routing_table_entry *routing_table){
  int i;
  for(i = 0; i < MAX_MIP; i++){
    if(routing_table[i].dest_mip == 255){
      break;
    }
    fprintf(stdout, "%d\t",routing_table[i].dest_mip);
  }
}

void free_distance_table(struct distance_table_entry *distance_table){
  int i;
  for(i = 0; i < MAX_MIP; i++){
    if(distance_table[i].dest_mip == BAD_MIP){
      break;
    }
    free(distance_table[i].next_hop);
    free(distance_table[i].cost);
    free(distance_table[i].timestamp);
  }

}

int init_routing_data(int un_route_sock,
    struct routing_table_entry *routing_table,
    struct distance_table_entry *distance_table, uint8_t *neighbours,
    uint8_t *local_mips, int debug){

  int num_local_mips,i;

  struct msghdr recv_msg = { 0 };
  struct iovec recv_iov[1];

  /* An invalid MIP address signifies an empty entry */
  for(i = 0; i < MAX_MIP; i++){
    routing_table[i].dest_mip = BAD_MIP;
    routing_table[i].next_hop = BAD_MIP;
    routing_table[i].cost = UNREACHABLE;
  }
  memset(local_mips, BAD_MIP, MAX_MIP);
  memset(neighbours, BAD_MIP, MAX_MIP);

  recv_iov[0].iov_base = local_mips;
  recv_iov[0].iov_len = MAX_MIP;

  recv_msg.msg_iov = recv_iov;
  recv_msg.msg_iovlen = 1;

  /* Receive an array of characters, each indicating a local MIP address */
  num_local_mips = recvmsg(un_route_sock, &recv_msg, 0);


  if(debug){
    fprintf(stdout, "Received %d local MIPs from the MIP daemon.\n",num_local_mips);
  }

  if(num_local_mips == -1){
    return -1;
  }else if(num_local_mips == 0){
    return -2;
  }

  /* Create entries for the local MIP addresses in the routing and distance
   * tables */
  for(i = 0; i < num_local_mips; i++){
    routing_table[i].dest_mip = local_mips[i];
    routing_table[i].next_hop = local_mips[i];
    routing_table[i].cost = 0;
  }

  for(i = 0; i < MAX_MIP; i++){
     if(i < num_local_mips){
       distance_table[i].dest_mip = local_mips[i];
     }
    else{
      distance_table[i].dest_mip = BAD_MIP;
    }

    distance_table[i].next_hop = NULL;
    distance_table[i].cost = NULL;
    distance_table[i].timestamp = NULL;
  }

  if(debug){
    for(i = 0; i < num_local_mips; i++){
      fprintf(stdout, "Local MIP address %d: %d\n", i, routing_table[i].dest_mip);
    }
  }

  if(debug){
    fprintf(stdout,"Broadcasting initial routing data.\n");
  }
  /* Broadcast the local MIP addresses to all neighbours */
  struct msghdr send_msg = { 0 };
  struct iovec send_iov[2];

  /* A MIP address of 255 indicates that the MIP daemon should broadcast the
   * routing table on all network interfaces */
  uint8_t broadcast_mip = BROADCAST_MIP;

  send_iov[0].iov_base = &broadcast_mip;
  send_iov[0].iov_len = sizeof(broadcast_mip);

  send_iov[1].iov_base = routing_table;
  send_iov[1].iov_len = sizeof(struct routing_table_entry) * num_local_mips;

  send_msg.msg_iov = send_iov;
  send_msg.msg_iovlen = 2;

  ssize_t ret = sendmsg(un_route_sock, &send_msg, 0);

  if(ret == -1){
    return -1;
  }

  if(debug){
    fprintf(stdout,"Sent %ld bytes to MIP daemon.\n", ret);
  }

  return num_local_mips;
}

int send_routing_table_update(int un_route_sock,
    struct routing_table_entry *routing_table, uint8_t *neighbours,
    int num_neighbours, int debug){

  int i,j;
  ssize_t ret;

  if(debug){
    fprintf(stdout, "Sending update to %d neighbours.\n", num_neighbours);
  }

  for(i = 0; i < num_neighbours; i++){
    struct routing_table_entry send_table[MAX_MIP];
    uint8_t dest_neighbour = neighbours[i];
    int num_entries = 0;

    for(j = 0; j < MAX_MIP; j++){
      if(routing_table[j].dest_mip == BAD_MIP) break;

      if(routing_table[j].next_hop != dest_neighbour){
        send_table[num_entries].next_hop = routing_table[j].next_hop;
        send_table[num_entries].dest_mip = routing_table[j].dest_mip;
        send_table[num_entries].cost = routing_table[j].cost;
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

    ret = sendmsg(un_route_sock, &msg, 0);

    if(ret == -1){
      return -1;
    }

    if(debug){
      fprintf(stdout, "%ld bytes sent to neighbour with MIP address %d.\n", ret, dest_neighbour);
    }


  }


  return 0;
}

int clean_dist_route(struct distance_table_entry *distance_table,
    struct routing_table_entry *routing_table, uint8_t *neighbours,
    time_t *last_neighbour_update, int *num_neighbours, int num_local_mips){

  time_t now = time(NULL);
  int i,j,k;
  int updated = 0;

  /* If a neighbour has been silent for the time between routing updates
   * specified in UPDATE_WAIT, a number of times specified in
   * WAIT_NUM_TIMEOUT, remove the neighbour and its corresponding entries in
   * the distance table */
  for(i = 0; i < *num_neighbours; i++){
    if(now - last_neighbour_update[i] > UPDATE_WAIT * WAIT_NUM_TTL){
      uint8_t neighbour = neighbours[i];
      for(j = num_local_mips; j < MAX_MIP; j++){

        /* Stop if an empty entry was reached */
        if(distance_table[j].dest_mip == BAD_MIP) break;

        /* Remove the entries for the neighbour and resort the values for next
         * hop, cost and timestamp */
        for(k = i; k < *num_neighbours-1; k++){
          distance_table[j].next_hop[k] = distance_table[j].next_hop[k+1];
          distance_table[j].cost[k] = distance_table[j].cost[k+1];
          distance_table[j].timestamp[k] = distance_table[j].timestamp[k+1];
        }

        /* Reallocate memory */
        distance_table[j].next_hop =
          (uint8_t *) realloc(distance_table[j].next_hop, *num_neighbours - 1);

        distance_table[j].cost =
          (uint8_t *) realloc(distance_table[j].cost, *num_neighbours - 1);

        distance_table[j].timestamp =
          (time_t *) realloc(distance_table[j].timestamp,
          sizeof(time_t) * (*num_neighbours - 1));
      }

      for(j = i; j < *num_neighbours-1; j++){
        neighbours[j] = neighbours[j+1];
        neighbours[j+1] = BAD_MIP;
        last_neighbour_update[j] = last_neighbour_update[j+1];
        last_neighbour_update[j+1] = 0;
      }

      (*num_neighbours)--;

      /* Update the entry in the routing table for any destination whose
       * route's next hop was the removed neighbour */
      for(j = 0; j < MAX_MIP; j++){
        if(routing_table[j].next_hop == neighbour){
          updated = 1;

          routing_table[j].cost = UNREACHABLE;

          for(k = 0; k < *num_neighbours; k++){
            if(distance_table[j].cost[k] < routing_table[j].cost){
              routing_table[j].next_hop = distance_table[j].next_hop[k];
              routing_table[j].cost = distance_table[j].cost[k];
            }
          }
        }
      }
    }
  }

  /* Set expired entries in the distance table to unreachable */
  for(i = 0; i < *num_neighbours; i++){
    /* Don't update entries for local MIP addresses */
    for(j = num_local_mips; j < MAX_MIP; j++){
      /* Stop if an empty entry was reached */
      if(distance_table[j].dest_mip == BAD_MIP) break;

      /* If the destination is already unreachable through the neighbour,
       * the entry has been previously updated */
      if(distance_table[j].cost[i] == UNREACHABLE) continue;

      /* Expired entry */
      if(now - distance_table[j].timestamp[i] > UPDATE_WAIT * WAIT_NUM_TTL){

        distance_table[j].cost[i] = UNREACHABLE;

        /* Update the cost of the route if the next hop of the route was the
         * same as the next hop of the expired entry */
        if(routing_table[j].next_hop == distance_table[j].next_hop[i]){
          routing_table[j].cost = distance_table[j].cost[i];

          updated = 1;
        }

        /* Update the next hop of the route to the next hop with the cheapest
         * route */
        for(k = 0; k < *num_neighbours; k++){
          if(distance_table[j].cost[k] < routing_table[j].cost){
            routing_table[j].next_hop = distance_table[j].next_hop[k];
            routing_table[j].cost = distance_table[j].cost[k];

            updated = 1;
          }
        }
      }
    }
  }

  return updated;
}

int rm_empty_route_dist(struct distance_table_entry *distance_table,
    struct routing_table_entry *routing_table, int debug){

  int i,j;

  int removed = 0;

  /* If the next hop of a route for a destination MIP address is an invalid
   * MIP address, remove the entry for that destination MIP address from both
   * the distance and routing tables */
  for(i = 0; i < MAX_MIP; i++){
    if(routing_table[i].dest_mip == BAD_MIP) break;
    if(routing_table[i].cost == UNREACHABLE){

      if(debug){
        fprintf(stdout, "Destination MIP %d removed from routing and distance table.\n", routing_table[i].dest_mip);
      }

      removed ++;
      free(distance_table[i].next_hop);
      free(distance_table[i].cost);
      free(distance_table[i].timestamp);

      for(j = i; j < MAX_MIP-1; j++){
        if(routing_table[j].dest_mip == BAD_MIP) break;

        routing_table[j] = routing_table[j+1];
        routing_table[j+1].next_hop = BAD_MIP;
        routing_table[j+1].dest_mip = BAD_MIP;
        routing_table[j+1].cost = UNREACHABLE;

        distance_table[j] = distance_table[j+1];
        distance_table[j+1].dest_mip = BAD_MIP;
        distance_table[j+1].next_hop = NULL;
        distance_table[j+1].cost = NULL;
        distance_table[j+1].timestamp = NULL;
      }
    }
  }

  return removed;
}


int main(int argc, char *argv[]){
  char const *usage = "./routing_daemon [-d] <Socket_route> "
      "<Socket_forwarding>";

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
  struct epoll_event ep_route_ev = { 0 };
  struct epoll_event ep_fwd_ev = { 0 };
  struct epoll_event ep_sig_ev = { 0 };

  int last_update_timestamp = time(NULL);
  time_t timeout;
  time_t now = time(NULL);

  int i,j,k,l;
  ssize_t ret;


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
      fprintf(stdout, "----------------------------------Debug mode activated.------------------------------------------------\n");
    }
  }


  un_route_name = argv[route_sock_ind];
  un_fwd_name = argv[fwd_sock_ind];

  /* Create unix IPC routing and forwarding sockets */
  struct sockaddr_un route_addr = { 0 };
  struct sockaddr_un fwd_addr = { 0 };

  if(debug){
    fprintf(stdout, "Setting up unix sockets\n");
  }

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

  if(debug){
    fprintf(stdout, "Routing socket set up to path: %s\n",un_route_name);
  }

  if(connect(un_fwd_sock, (struct sockaddr *) &fwd_addr,
      sizeof(struct sockaddr_un)) == -1){
    perror("main: connect: un_fwd_sock");
    close(un_route_sock);
    close(un_fwd_sock);
    exit(EXIT_FAILURE);
  }

  if(debug){
    fprintf(stdout, "Forwarding socket set up to path: %s\n",un_fwd_name);
  }

  if(debug){
    fprintf(stdout, "Creating epoll instance.\n");
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

  if(debug){
    fprintf(stdout, "Epoll instance created.\n");
  }

  if(debug){
    fprintf(stdout, "Initializing routing data.\n");
  }
  /* Initialize routing tables */
  num_local_mips = init_routing_data(un_route_sock, routing_table,
    distance_table, neighbours, local_mips, debug);

  if(num_local_mips == -1){
    perror("main: init_routing_data");
    close(un_route_sock);
    close(un_fwd_sock);
    close(signal_fd);
    exit(EXIT_FAILURE);
  }

  if(debug){
    fprintf(stdout, "Routing data initialized.\n");
  }

  if(debug){
    fprintf(stdout, "Beginning routing.\n");
  }

  for(;;){
    /* How long the timeout should be for the call to epoll_wait */
    timeout = (UPDATE_WAIT - (now - last_update_timestamp)) * 1000;


    if(debug){
      fprintf(stdout, "Timeout: %ld.\n",timeout);
    }

    /* If it has been at least 30 seconds since the last routing table update,
     * send a routing table update */
    if(timeout <= 0){


      if(debug){
        fprintf(stdout, "At least 30 seconds since last update, sending routing update.\n");
        fprintf(stdout, "Cleaning distance and routing tables.\n");
      }

      /* Clean the distance and routing tables first */
      ret = clean_dist_route(distance_table, routing_table, neighbours,
          last_neighbour_update, &num_neighbours, num_local_mips);

      if(debug){
        if(ret == 1){
          fprintf(stdout, "Tables cleaned, but there was no update\n");
        }else{
          fprintf(stdout, "Tables cleaned and updated.\n");
        }
        fprintf(stdout, "Sending routing update.\n");
      }

      if(send_routing_table_update(un_route_sock, routing_table, neighbours,
          num_neighbours, debug) == -1){
        perror("main: send_routing_table_update");
        close(un_route_sock);
        close(un_fwd_sock);
        close(signal_fd);
        free_distance_table(distance_table);
        exit(EXIT_FAILURE);
      }

      if(debug){
        fprintf(stdout, "Routing update sent.\n");
        fprintf(stdout, "Removing empty entries in the routing and distance tables.\n");
      }

      /* Only remove unreachable destinations after telling neighbours that
       * the destinations are unreachable */
      ret = rm_empty_route_dist(distance_table, routing_table, debug);

      if(debug){
        if(ret > 0){
          fprintf(stdout, "%ld entries were removed.\n", ret);
        }else{
          fprintf(stdout, "No entries were removed.\n");
        }
      }

      last_update_timestamp = now;
      timeout = UPDATE_WAIT * 1000;
    }

    if(debug){
      fprintf(stdout, "Waiting for events.\n");
    }

    nfds = epoll_wait(epfd, events, MAX_EVENTS, timeout);

    if(nfds == -1){
      perror("main: epoll_wait");
      close(un_route_sock);
      close(un_fwd_sock);
      close(signal_fd);
      free_distance_table(distance_table);
      exit(EXIT_FAILURE);
    }

    now = time(NULL);

    for(i = 0; i < nfds; i++){
      /* A keyboard interrupt was signaled */
      if(events[i].data.fd == signal_fd){
        struct signalfd_siginfo sig_info;
        ssize_t sig_size;

        sig_size = read(events[i].data.fd, &sig_info,
            sizeof(struct signalfd_siginfo));

        /* Close all sockets and close stop the daemon */
        if(sig_size == 0){
          perror("\nCtrl-d: Received EOF signal from keyboard, stopping\n");
          close(un_route_sock);
          close(un_fwd_sock);
          close(signal_fd);
          free_distance_table(distance_table);
          exit(EXIT_SUCCESS);
        }
        if(sig_info.ssi_signo == SIGINT){
          fprintf(stderr,"\nCtrl-c: Received interrupt from keyboard,"
              "stopping daemon\n");
          close(un_route_sock);
          close(un_fwd_sock);
          close(signal_fd);
          free_distance_table(distance_table);
          exit(EXIT_SUCCESS);
        }
        else if(sig_info.ssi_signo == SIGQUIT){
          fprintf(stderr,"\nCtrl-\\: Received interrupt from keyboard,"
              "stopping daemon\n");
          close(un_route_sock);
          close(un_fwd_sock);
          close(signal_fd);
          free_distance_table(distance_table);
          exit(EXIT_SUCCESS);
        }
      }/* Keyboard signal END */

      /* If a data was received on the routing socket */
      if(events[i].data.fd == un_route_sock){

        if(debug){
          fprintf(stdout, "Received data on routing socket.\n");
        }

        int updated = 0;

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
        perror("main: recvmsg: un_route_sock");
          close(un_route_sock);
          close(un_fwd_sock);
          close(signal_fd);
          free_distance_table(distance_table);
          exit(EXIT_FAILURE);
        }else if(ret == 0){
          fprintf(stderr,"MIP daemon performed a shutdown, lost connection, "
              "aborting\n");
          close(un_route_sock);
          close(un_fwd_sock);
          close(signal_fd);
          unlink(un_route_name);
          unlink(un_fwd_name);
          free_distance_table(distance_table);
          exit(EXIT_FAILURE);
        }

        if(debug){
          fprintf(stdout, "Received %ld data on routing socket.\n", ret);
        }

        int new_neighbour = 1;

        for(j = 0; j < num_neighbours; j++){
          if(src_mip == neighbours[j]){
            new_neighbour = 0;
            last_neighbour_update[j] = now;
            break;
          }
        }

        /* If the routing update was received from a previously unknown
         * neighbour, expand the distance table to make room for the new
         * neighbour */
        if(new_neighbour == 1){

          if(debug){
            fprintf(stdout, "Data was from a previously unknown neighbour, with MIP address: %d.\n", src_mip);
            fprintf(stdout, "Current number of neighbours: %d\n", num_neighbours+1);
          }
          neighbours[num_neighbours] = src_mip;
          last_neighbour_update[num_neighbours] = now;

          if(debug){
            fprintf(stdout, "Expanding distance table to make room for new neighbour.\n");
          }

          /* Never update entries for local MIP addresses */
          for(j = num_local_mips; j < MAX_MIP; j++){

            /* Stop if an empty entry was reached */
            if(distance_table[j].dest_mip == BAD_MIP) break;

            /* Reallocate memory to make room for the new neighbour */
            distance_table[j].next_hop = (uint8_t *)
              realloc(distance_table[j].next_hop, num_neighbours + 1);
            distance_table[j].next_hop[num_neighbours] = src_mip;

            distance_table[j].cost =
              (uint8_t *) realloc(distance_table[j].cost, num_neighbours + 1);
            distance_table[j].cost[num_neighbours] = UNREACHABLE;

            distance_table[j].timestamp =
              (time_t *) realloc(distance_table[j].timestamp, sizeof(time_t) *
              (num_neighbours + 1));
            distance_table[j].timestamp[num_neighbours] = 0;
          }

          num_neighbours++;
        }

        /* Number of rows in the routing table received */
        int num_entries = (ret - 1) / 3; /* next hop, destination, cost */

        if(debug){
          fprintf(stdout, "Number of rows in routing update received: %d.\n", num_entries);
          fprintf(stdout, "Update distance and routing tables with the received data.\n");
        }

        /* Update the distance table */
        for(j = 0; j < num_entries; j++){

          /* Ignore entry if the route's next hop is this node */
          int goes_through_this = 0;
          for(k = 0; k < num_local_mips; k++){
            if(recv_route_table[j].next_hop == local_mips[k]){
              goes_through_this = 1;
              if(debug){
                fprintf(stdout, "GOES THROUGH THIS.\n");
              }
            }
          }
          if(goes_through_this) continue;


          for(k = 0; k < MAX_MIP; k++){
            /* Existing destionation MIP */
            if(recv_route_table[j].dest_mip == distance_table[k].dest_mip){
              if(k < num_local_mips){
                /* Ignore entry if the destination is one of the local MIP
                 * addresses */
                break;
              }

              for(l = 0; l < num_neighbours; l++){
                if(neighbours[l] == src_mip){
                  /* Update entry for the neighbour that the routing data was
                   * received from */
                  distance_table[k].next_hop[l] = neighbours[l];
                  distance_table[k].cost[l] = recv_route_table[j].cost + 1;
                  if(distance_table[k].cost[l] > UNREACHABLE){
                    distance_table[k].cost[l] = UNREACHABLE;
                  }
                  distance_table[k].timestamp[l] = now;

                  if((distance_table[k].cost[l] < routing_table[k].cost)
                      || (distance_table[k].next_hop[l]
                      == routing_table[k].next_hop && distance_table[k].cost[l]
                      > routing_table[k].cost)){

                    if(debug){
                      fprintf(stdout, "Update for destination MIP %d, previous: next_hop: %d, cost: %d.\n", routing_table[k].dest_mip, routing_table[k].next_hop, routing_table[k].cost);
                    }
                    routing_table[k].next_hop = distance_table[k].next_hop[l];
                    routing_table[k].cost = distance_table[k].cost[l];

                    if(debug){
                      fprintf(stdout, "New: next_hop: %d, cost: %d.\n", routing_table[k].next_hop, routing_table[k].cost);
                    }

                    updated = 1;
                  }

                  break;
                }
              }
              break;
            }
            /* New destination MIP */
            else if(distance_table[k].dest_mip == BAD_MIP){

              if(debug){
                fprintf(stdout, "Destination was previously unknown.\n");
              }

              /* Initialize values for all neighbours */
              distance_table[k].dest_mip = recv_route_table[j].dest_mip;
              distance_table[k].next_hop = (uint8_t *) malloc(num_neighbours);
              distance_table[k].cost = (uint8_t *) malloc(num_neighbours);
              distance_table[k].timestamp = (time_t *) malloc(num_neighbours);

              for(l = 0; l < num_neighbours; l++){
                if(neighbours[l] == src_mip){
                  /* Update entry for the neighbour that the routing data was
                   * received from */
                  distance_table[k].next_hop[l] = neighbours[l];
                  distance_table[k].cost[l] = recv_route_table[j].cost + 1;
                  if(distance_table[k].cost[l] > UNREACHABLE){
                    distance_table[k].cost[l] = UNREACHABLE;
                  }
                  distance_table[k].timestamp[l] = now;

                  /* Make new entry for the destination MIP address in the
                   * routing table */
                  routing_table[k].dest_mip = distance_table[k].dest_mip;
                  routing_table[k].next_hop = distance_table[k].next_hop[l];
                  routing_table[k].cost = distance_table[k].cost[l];

                  if(debug){
                    fprintf(stdout, "Received update for previously unknown destination MIP: %d, next_hop: %d, cost: %d\n",routing_table[k].dest_mip, routing_table[k].next_hop, routing_table[k].cost);
                  }
                }
                else {
                  /* Values indicating no data for other neighbours */
                  distance_table[k].next_hop[l] = neighbours[l];
                  distance_table[k].cost[l] = UNREACHABLE;
                  distance_table[k].timestamp[l] = 0;
                }
              }

              updated = 1;

              break;
            }
          }
        }

        /* If the routing update led to the routing table changing, send an
         * update to neighbours */
        if(updated == 1){
          if(debug){
            fprintf(stdout, "Routing table was updated by the received update.\n");
            fprintf(stdout, "Cleaning distance and routing tables.");
          }
          clean_dist_route(distance_table, routing_table, neighbours,
              last_neighbour_update, &num_neighbours, num_local_mips);

          if(debug){
            fprintf(stdout, "Tables cleaned.\n");
            fprintf(stdout, "Sending update to all neighbours.\n");
          }

          if(send_routing_table_update(un_route_sock, routing_table,
              neighbours, num_neighbours, debug) == -1){
            perror("main: send_routing_table_update");
            close(un_route_sock);
            close(un_fwd_sock);
            close(signal_fd);
            free_distance_table(distance_table);
            exit(EXIT_FAILURE);
          }

          if(debug){
            fprintf(stdout, "Updates sent.\n");
            fprintf(stdout, "Removing empty entries in the routing and distance tables.\n");
          }

          /* Only remove unreachable destinations after telling neighbours that
           * the destinations are unreachable */
          rm_empty_route_dist(distance_table,routing_table, debug);

          if(debug){
            fprintf(stdout, "Entries removed.\n");
          }
        }
      } /* Receive data on routing socket END */

      else if(events[i].data.fd == un_fwd_sock){

        if(debug){
          fprintf(stdout, "Received data on forwarding socket.\n");
          fprintf(stdout, "Forwarding socket: %d\n",events[i].data.fd);
        }
        struct msghdr recv_msg = { 0 };
        struct iovec recv_iov[1];

        uint8_t dest_mip;

        recv_iov[0].iov_base = &dest_mip;
        recv_iov[0].iov_len = sizeof(dest_mip);

        recv_msg.msg_iov = recv_iov;
        recv_msg.msg_iovlen = 1;

        /* Receive destination MIP address */
        ret = recvmsg(events[i].data.fd,&recv_msg,0);

        if(ret == -1){
          close(un_route_sock);
          close(un_fwd_sock);
          close(signal_fd);
          free_distance_table(distance_table);
          if(errno == EINTR){
            fprintf(stdout,"Received interrupt, exiting router.");
            exit(EXIT_SUCCESS);
          }
          perror("main: recvmsg: un_fwd_sock");
          exit(EXIT_FAILURE);
        }else if(ret == 0){
          fprintf(stderr,"MIP daemon performed a shutdown, lost connection, "
              "aborting\n");
          close(un_route_sock);
          close(un_fwd_sock);
          close(signal_fd);
          unlink(un_route_name);
          unlink(un_fwd_name);
          free_distance_table(distance_table);
          exit(EXIT_FAILURE);
        }else if(ret != 1){
          /* Received unexpected data, do nothing */
          continue;
        }

        if(debug){
          fprintf(stdout, "Received %ld bytes.\n", ret);
          fprintf(stdout, "Received request for next hop MIP address for destination MIP address: %d\n", dest_mip);
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

        if(debug){
          fprintf(stdout, "Cleaning tables before responding to request.\n");
        }

        /* Clean up the routing and distance tables before looking up the next
         * hop for the route */
        if(clean_dist_route(distance_table, routing_table, neighbours,
            last_neighbour_update, &num_neighbours, num_local_mips) == 1){

          if(debug){
            fprintf(stdout, "Tables cleaned.\n");
            fprintf(stdout, "There was an update, sending routing update before continuing.\n");
          }

          /* If clean-up changed the routing table, send an update to
           * neighbours */
          if(send_routing_table_update(un_route_sock, routing_table,
              neighbours, num_neighbours, debug) == -1){
            perror("main: send_routing_table_update: un_fwd_sock");
            close(un_route_sock);
            close(un_fwd_sock);
            close(signal_fd);
            free_distance_table(distance_table);
            exit(EXIT_FAILURE);
          }

          if(debug){
            fprintf(stdout, "Update sent.\n");
            fprintf(stdout, "Removing empty entries in the tables.\n");
          }

          /* Only remove unreachable entries after telling neighbours that the
           * destinations are unreachable */
          rm_empty_route_dist(distance_table,routing_table, debug);

          if(debug){
            fprintf(stdout, "Empty entries removed.\n");
          }

          last_update_timestamp = now;
        }else{
          if(debug){
            fprintf(stdout, "Tables cleaned, no update.\n");
          }
        }

        for(j = 0; j < MAX_MIP; j++){
          if(routing_table[j].dest_mip == dest_mip){
            next_hop = routing_table[j].next_hop;
          }else if(routing_table[j].dest_mip == BAD_MIP) break;
        }

        if(debug){
          if(next_hop == 255){
            fprintf(stdout, "Couldn't find a route for the request destination MIP address.\n");
          }else{
            fprintf(stdout, "Next hop for destination MIP addres %d is %d\n", dest_mip, next_hop);
          }
          fprintf(stdout, "Responding to MIP daemon.\n");
          fprintf(stdout, "Forwarding socket: %d\n", events[i].data.fd);
        }

        if(sendmsg(events[i].data.fd, &send_msg, 0) == -1){
          perror("main: sendmsg: un_fwd_sock");
          close(un_route_sock);
          close(un_fwd_sock);
          close(signal_fd);
          free_distance_table(distance_table);
          exit(EXIT_FAILURE);
        }

        if(debug){
          fprintf(stdout, "Response sent.\n");
        }
      } /* Receive data on forward socket END */
    }
  }
}
