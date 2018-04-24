#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <signal.h>
#include "mip_daemon.h"



/**
 * Closes all sockets and unlinks the name bound to the listening unix socket
 *
 * @param un_sock             Unix socket listening for connections from
 *                            applications
 * @param un_sock_name        Name un_sock is bound to
 * @param un_sock_conn        Socket for IPC with connected application,
 *                            ignored if -1
 * @param signal_fd           Socket handling signals, ignored if -1
 * @param local_mip_mac_table MIP-ARP table storing all local ethernet sockets
 * @param num_eth_sds         Number of sockets stored in local_mip_mac_table
 * @return                    none
 */
void close_sockets(struct sockets sock_container){
  int i;
  for (i = 0; i < *sock_container.num_eth_sds; i++){
    close(sock_container.local_mip_mac_table[i].socket);
  }
  struct sockaddr_un un_addr = { 0 };
  socklen_t addrlen = sizeof(un_addr);
  getsockname(*sock_container.un_sock, (struct sockaddr*) &un_addr, &addrlen);
  close(*sock_container.un_sock);
  unlink(un_addr.sun_path);

  struct sockaddr_un un_route_addr = { 0 };
  socklen_t route_addrlen = sizeof(un_route_addr);
  getsockname(*sock_container.un_route_sock, (struct sockaddr*) &un_route_addr,
    &route_addrlen);
  close(*sock_container.un_route_sock);
  unlink(un_route_addr.sun_path);

  struct sockaddr_un un_fwd_addr = { 0 };
  socklen_t fwd_addrlen = sizeof(un_fwd_addr);
  getsockname(*sock_container.un_fwd_sock, (struct sockaddr*) &un_fwd_addr,
    &fwd_addrlen);
  close(*sock_container.un_fwd_sock);
  unlink(un_fwd_addr.sun_path);

  close(*sock_container.un_sock_conn);
  close(*sock_container.un_route_conn);
  close(*sock_container.un_fwd_conn);
  close(*sock_container.signal_fd);
}



/**
 * Sets up a unix socket and binds it to the provided name, and listens to it
 *
 * @param un_sock_name Name to bind the unix socket to
 * @return             Returns the socket descriptor of the new unix socket on
 *                     success, -1 if socket() fails, -2 if bind() fails, -3 if
 *                     listen() fails
 *
 * Global variables: LISTEN_BACKLOG_UNIX
 */
int setup_unix_socket(char* un_sock_name){
  /* Using SOCK_SEQPACKET for a connection-oriented, sequence-preserving socket
   * that preserves message boundaries */
  int un_sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);

  if (un_sock == -1){
    return -1;
  }

  /* Based on code from 'man 2 bind' */

  struct sockaddr_un un_sock_addr;
  memset(&un_sock_addr, 0, sizeof(struct sockaddr_un));

  un_sock_addr.sun_family = AF_UNIX;

  strncpy(un_sock_addr.sun_path,un_sock_name,sizeof(un_sock_addr.sun_path));


  if(bind (un_sock, (struct sockaddr*)&un_sock_addr,
  sizeof(struct sockaddr_un)) == -1)
  {
    return -2;
  }

  if(listen(un_sock, LISTEN_BACKLOG_UNIX) == -1){
    return -3;
  }

  return un_sock;
} /* setup_unix_socket() END */



/**
 * Sets up an ethernet socket for each network interface of type AF_PACKET,
 * and associates each with MIP by storing it in the provided MIP-ARP table
 * along with the MIP addresses already stored there address stored in the
 * provided MIP-ARP table
 *
 * @param local_mip_mac_table MIP-ARP table containing MIP addresses
 * @param num_mip_addrs       Number of MIP addresses stored in
 *                            local_mip_mac_table
 * @param debug               Variable indicating whether or not debug messages
 *                            should be logged to the console, 1 indicating
 *                            yes, and 0 indicating no
 * @return                    Returns the number of network interfaces of type
 *                            AF_PACKET, -1 if getifaddrs() fails, -2 if
 *                            socket() fails, -3 if ioctl() fails, -4 if bind()
 *                            fails
 *
 * Global variables: ETH_P_MIP
 *                   MAC_SIZE
 */
int setup_eth_sockets(struct mip_arp_entry *local_mip_mac_table,
    int num_mip_addrs, int debug){
  /* ifaddrs code based on code from 'man 3 getifaddrs' and group session
  * https://github.uio.no/persun/inf3190/blob/master/get_interface_names.c */

  //List of interfaces
  struct ifaddrs *ifaddr, *ifa;

  /* Ethernet socket */
  int eth_sd;
  int eth_ptcl; /* Ethernet protocol */
  int num_eth_sds = 0; /* Number of raw network interfaces found so far */
  int i;

  /* Using the local experimental protocol for ethernet communication */
  eth_ptcl = htons(ETH_P_MIP);

  /* Get a list of all network interfaces */
  if (getifaddrs (&ifaddr) == -1){
    return -1;
  }

  if(debug){
    fprintf(stdout,"Local Ethernet Interface%s:\n",num_mip_addrs>1 ? "s" : "");
  }

  /* Set up all raw network interfaces (AF_PACKET) for ethernet communication
  * and associate them and their MAC addresses with the MIP addresses stored in
  * local_mip_mac_table */
  for (ifa = ifaddr; ifa != NULL; ifa = ifa -> ifa_next){
    if (ifa -> ifa_addr == NULL) continue;

    /* Ignore the local loopback interface */
    if (strcmp (ifa -> ifa_name, "lo") == 0) continue;

    int family = ifa -> ifa_addr -> sa_family;

    /* Only raw network interfaces */
    if(family == AF_PACKET){
      if(++num_eth_sds>num_mip_addrs){
        /* If the number of raw interfaces is greater than the number of MIP
        * addresses which was supplied at startup, count them */
        continue;
      }

      eth_sd = socket (AF_PACKET, SOCK_RAW, eth_ptcl);
      if (eth_sd == -1){
        for (i = 0; i < num_eth_sds-1; i++){
          close(local_mip_mac_table[i].socket);
        }
        freeifaddrs(ifaddr);

        return -2;
      }

      /* Store the raw socket together with the MIP address it is associated
      * with */
      local_mip_mac_table[num_eth_sds-1].socket = eth_sd;

      /* Get the MAC address of the interface */
      struct ifreq dev;
      strcpy(dev.ifr_name, ifa->ifa_name);
      if(ioctl(eth_sd, SIOCGIFHWADDR, &dev) == -1){
        /* Close all sockets and free the interfaces struct */
        for(int i = 0; i < num_eth_sds; i++){
          close(local_mip_mac_table[i].socket);
        }
        freeifaddrs(ifaddr);

        return -3;
      }

      /* Store the MAC address of the interface with the MIP address it is
      * associated with */
      memcpy(local_mip_mac_table[num_eth_sds-1].mac_addr,
          dev.ifr_hwaddr.sa_data, MAC_SIZE);


      /* Bind the socket */
      struct sockaddr_ll eth_sockaddr;
      memset(&eth_sockaddr, 0, sizeof(eth_sockaddr));
      eth_sockaddr.sll_family = AF_PACKET;
      eth_sockaddr.sll_protocol = eth_ptcl;
      eth_sockaddr.sll_ifindex = if_nametoindex(ifa -> ifa_name);

      if (bind (eth_sd, (struct sockaddr*) &eth_sockaddr,
      sizeof(eth_sockaddr)) == -1)
      {
        for(int i = 0; i < num_eth_sds; i++){
          close(local_mip_mac_table[i].socket);
        }
        freeifaddrs(ifaddr);

        return -4;
      }

      if(debug){
        fprintf(stdout,"%s:\t",ifa->ifa_name);
        print_mac(local_mip_mac_table[num_eth_sds-1].mac_addr);
        fprintf(stdout,"\t%d\n",local_mip_mac_table[num_eth_sds-1].mip_addr);
      }
    }
  } /* Set up raw sockets END */

  if(debug) fprintf(stdout,"\n");

  freeifaddrs(ifaddr);

  return num_eth_sds;
} /* setup_eth_sockets END */



/**
 * Creates a signal handler which can be used to handle keyboard interrupts
 * when waiting for events in the epoll instance
 *
 * @returns       Returns a descriptor for a signal handler on success and -1
 *                on error.
 */
int setup_signal_fd(){
  /* Create a signal handler to be used when waiting for the epoll instance */
  int signal_fd;

  sigset_t mask;

  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGQUIT);

  sigprocmask(SIG_BLOCK, &mask, NULL);

  signal_fd = signalfd(-1, &mask, 0);
  if(signal_fd == -1){
    return -1;
  }

  return signal_fd;
}



/**
 * Handles an incoming connection on the supplied socket, creates a new
 * connected socket and adds it to the supplied epoll instance.
 *
 * @param un_sock Socket which received a new connection.
 * @param epfd    File descriptor for epoll instance to add the new connected
 *                socket to.
 * @returns       Returns the socket descriptor for the new connected socket
 *                on success, and -1 on error.
 */
int new_connection(int un_sock, int epfd){
  int un_sock_conn;
  struct sockaddr_un un_sock_conn_addr = { 0 };
  socklen_t size_un_sock_conn_addr = sizeof(un_sock_conn_addr);

  /* Accept and return the socket */
  un_sock_conn = accept(un_sock, (struct sockaddr *) &un_sock_conn_addr,
      &size_un_sock_conn_addr);

  /* Add the socket to the epoll instance */
  struct epoll_event ep_conn_ev = { 0 };
  ep_conn_ev.events = EPOLLIN;
  ep_conn_ev.data.fd = un_sock_conn;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, un_sock_conn, &ep_conn_ev) == -1){
    return -1;
  }

  return un_sock_conn;
}


/**
 * Creates an epoll instance and adds all sockets provided as arguments to the
 * instance
 *
 * @param un_sock             Unix socket listening for connections from
 *                            applications
 * @param local_mip_mac_table MIP-ARP table containing sockets for all local
 *                            network interfaces
 * @param num_eth_sds         Number of sockets stored in local_mip_mac_table
 * @return                    Returns the file descriptor for the created epoll
 *                            instance, -1 if epoll_create() fails, -2 if
 *                            epoll_ctl() fails for the unix socket, and -3 if
 *                            epoll_ctl() fails for an ethernet socket.
 */
int create_epoll_instance(struct sockets sock_container){

  /* Code concerning epoll is based on code from 'man 7 epoll' and group
  * session https://github.uio.no/persun/inf3190/blob/master/plenum3/epoll.c */

  int i;

  int epfd = epoll_create(1);

  if (epfd == -1){
    return -1;
  }

  /* Add the unix socket used to listen for connections from applications to
  * the MIP daemon.
  * Using EPOLLONESHOT to make sure events for connections to the MIP daemon
  * from an application is only triggered in the main loop of the MIP daemon */
  struct epoll_event ep_un_ev = { 0 };
  ep_un_ev.events = EPOLLIN | EPOLLONESHOT;
  ep_un_ev.data.fd = *sock_container.un_sock;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, *sock_container.un_sock, &ep_un_ev) == -1){
    return -2;
  }

  struct epoll_event ep_route_ev = { 0 };
  ep_route_ev.events = EPOLLIN | EPOLLONESHOT;
  ep_route_ev.data.fd = *sock_container.un_route_sock;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, *sock_container.un_route_sock,
      &ep_route_ev) == -1){
    return -2;
  }

  struct epoll_event ep_fwd_ev = { 0 };
  ep_fwd_ev.events = EPOLLIN | EPOLLONESHOT;
  ep_fwd_ev.data.fd = *sock_container.un_fwd_sock;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, *sock_container.un_fwd_sock, &ep_fwd_ev)
      == -1){
    return -2;
  }

  /* Add the ethernet sockets to the epoll instance */
  for(i=0;i<*sock_container.num_eth_sds;i++){
    struct epoll_event ep_eth_ev = { 0 };
    ep_eth_ev.events = EPOLLIN;
    ep_eth_ev.data.fd = sock_container.local_mip_mac_table[i].socket;

    if(epoll_ctl(epfd, EPOLL_CTL_ADD,
        sock_container.local_mip_mac_table[i].socket, &ep_eth_ev) == -1 ){
      return -3;
    }
  }

  struct epoll_event ep_sig_ev = { 0 };
  ep_sig_ev.events = EPOLLIN | EPOLLERR;
  ep_sig_ev.data.fd = *sock_container.signal_fd;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, *sock_container.signal_fd, &ep_sig_ev)
      == -1){
    return -4;
  }

  return epfd;
} /* create_epoll_instance() END */
