#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/signalfd.h>
#include <signal.h>

// use the local experimental protocol for ethernet communication
#define ETH_P_MIP 0x88B5
// only accept connections from one application at a time
#define LISTEN_BACKLOG_UNIX 1
#define MAX_EVENTS 1 /* only handle one epoll event at a time */
#define MAX_MSG_SIZE 1496 /* ethernet MTU not including MIP header */
#define MAX_ETH_FRAME_SIZE 1514 /* max message size plus ethernet and mip headers */
#define MAX_ARP_SIZE 256 /* the maximum size of the MIP-ARP table */
#define MIP_ARP_TTL 300 /* seconds a MIP-ARP entry is valid */
#define PING_TIMEOUT 100 /* timout for waiting for ping in milliseconds */
#define MAC_SIZE 6 /* size of a mac address */
#define IPC_PONG_RSP_SIZE 5 /* message size of an IPC PONG response */

//TODO: debug-mode / logging
//TODO: error-handling function

void print_help(char *file_name){
  fprintf(stderr,"USAGE: %s [-h][-d] <Socket_application> [MIP addresses ...]\n", file_name);
  fprintf(stderr,"[-h]: optional help argument\n");
  fprintf(stderr,"[-d]: optional debug argument, prints communication information\n");
  fprintf(stderr,"<Socket_application>: name of socket for IPC with application\n");
  fprintf(stderr,"[MIP addresses ...]: one unique MIP address per interface with a unique MAC address, in the form of a number between 0 and 255\n");
  exit(EXIT_FAILURE);
}

void print_mac(uint8_t *mac){
  for(int i = 0; i < MAC_SIZE; i++){
    fprintf(stdout,"%x:",mac[i]);
  }fprintf(stdout,"%x",mac[5]);
}


//ARP:
struct mip_arp_entry {
  uint8_t mip_addr; /* MIP address of the host */
  uint8_t mac_addr[6]; /* MAC address of the host */
  int socket; /* Socket the interface connected to the MIP address is bound to */
  /* The time at which the entry was stored, timestamp is 0, entry is empty */
  time_t timestamp;
};

void print_arp_table(struct mip_arp_entry *arp_table){
  fprintf(stdout,"MIP-ARP table entries:\n");
  time_t now = time(NULL);
  for(int i = 0; i < MAX_ARP_SIZE; i++){
    if(now-arp_table[i].timestamp < MIP_ARP_TTL){
      fprintf(stdout,"MIP: %d\t",arp_table[i].mip_addr);
      fprintf(stdout,"MAC: "); print_mac(arp_table[i].mac_addr);
      fprintf(stdout,"\n");
    }
  }
}

struct mip_frame{
  uint8_t header_bytes[4]; /* mip header as specified in the mandatory assignment */
  char payload[]; /* payload of the MIP packet */
} __attribute__((packed));

struct ethernet_frame {
  uint8_t destination[6];
  uint8_t source[6];
  uint16_t protocol;
  struct mip_frame payload;
} __attribute__((packed));

uint8_t get_mip_tra(struct mip_frame *frame){
  return frame->header_bytes[0] >> 5;
}

uint8_t get_mip_dest(struct mip_frame *frame){
  uint8_t destination = 0;
  destination |= frame->header_bytes[0] << 3;
  destination |= frame->header_bytes[1] >> 5;
  return destination;
}

uint8_t get_mip_src(struct mip_frame *frame){
  uint8_t source = 0;
  source |= frame->header_bytes[1] << 3;
  source |= frame->header_bytes[2] >> 5;
  return source;
}

int update_mip_arp (struct mip_arp_entry *arp_table,uint8_t mip,uint8_t *mac,int socket,int debug){
  //Will contain entry in the MIP-ARP table to insert the MIP-MAC mapping
  struct mip_arp_entry *first_free_entry = NULL;
  time_t now = time(NULL); /* timestamp */
  //Index of where the entry was stored in the MIP-ARP table, -1 if the table
  //is full
  int ret = -1;

  //Check if MIP address has an entry in the MIP-ARP table, and remove expired
  //entries during lookup
  for(int i = 0; i < MAX_ARP_SIZE; i++){
    //If entry is empty
    if(arp_table[i].timestamp == 0){

      //Store the entry if the was the first one found
      if(!first_free_entry){
        first_free_entry = &arp_table[i];
        ret = i;
      }
    }

    //If the entry has expired
    else if(now - arp_table[i].timestamp > MIP_ARP_TTL){
      //Remove the entry
      memset(&arp_table[i],0,sizeof(struct mip_arp_entry));

      //Store it if the was the first one found
      if(!first_free_entry) first_free_entry = &arp_table[i];
    }

    //If an unexpired entry for the MIP address was found
    else if(arp_table[i].mip_addr == mip){
      //Return the index in the MIP-ARP table at which the entry was found
      return i;
    }
  }

  //If an empty entry was found
  if(first_free_entry){
    //Update the entry with the MIP-MAC mapping, and the socket it is connected to
    first_free_entry->mip_addr = mip;
    memcpy(first_free_entry->mac_addr,mac,MAC_SIZE);
    first_free_entry->socket = socket;
    if(debug){
      fprintf(stdout,"Entry added to MIP-ARP cache table:\n");
      fprintf(stdout,"MAC: "); print_mac(mac);
      fprintf(stdout,"\tMIP: %d\t\n\n",mip);
    }
  }

  return ret;
}

void close_sockets(int un_sock,char* un_sock_name,int un_sock_conn,int signal_fd,struct mip_arp_entry *local_mip_mac_table,int num_eth_sds){
  int i;
  for (i = 0; i < num_eth_sds; i++){
    close(local_mip_mac_table[i].socket);
  }
  close(un_sock);
  unlink(un_sock_name);
  if(un_sock_conn != -1) close(un_sock_conn);
  if(signal_fd != -1) close(signal_fd);
}

int construct_mip_packet(struct mip_frame* frame,uint8_t destination,uint8_t source,uint8_t tra,char* payload,int payload_len){
  int msg_len;
  if (payload) msg_len = strlen(payload);
  else msg_len = payload_len;
  //Pads the end of the message with 0-bytes
  memset(frame,0,sizeof(struct mip_frame)+payload_len);

  //Insert the different fields into the header conforming to the specification
  frame->header_bytes[0] |= tra << 5;
  frame->header_bytes[0] |= destination >> 3;
  frame->header_bytes[1] |= destination << 5;
  frame->header_bytes[1] |= source >> 3;
  frame->header_bytes[2] |= source << 5;
  frame->header_bytes[2] |= (payload_len/4) >> 4;
  frame->header_bytes[3] |= (payload_len/4) << 5;
  //TTL is always the maximum possible value:
  frame->header_bytes[3] |= 0b1111;
  memcpy(frame->payload,payload,msg_len);

  return 0;
}

//Send a mip packet to the supplied dest_mip address with TRA bits tra,
//and payload as the message
ssize_t send_mip_packet(struct mip_arp_entry *arp_table,struct mip_arp_entry *local_mip_mac_table,uint8_t dest_mip,char* payload,uint8_t tra,int send_sd,int debug){
  struct ethernet_frame *frame;
  uint8_t dest_mac[6];
  uint8_t src_mac[6];
  uint8_t src_mip;
  uint16_t eth_ptcl;
  int i;
  int msg_len;
  ssize_t ret;


  //ARP response has no payload
  if(tra == 0b000 || tra == 0b001) msg_len = 0;
  else{
    //Message length plus padding
    msg_len = strlen(payload)+1;
    msg_len += msg_len % 4;
  }

  //Error if message size exceeds specification limit
  if(msg_len > MAX_MSG_SIZE) return -2;


  if(tra == 0b001){
    memcpy(dest_mac,"\xff\xff\xff\xff\xff\xff",MAC_SIZE);
  }else{
    //Find the destination MAC
    for(i = 0; i < MAX_ARP_SIZE; i++){
      if(arp_table[i].mip_addr == dest_mip){
        memcpy(dest_mac,arp_table[i].mac_addr,MAC_SIZE);
        send_sd = arp_table[i].socket;
        break;
      }
      else if (i == MAX_ARP_SIZE-1){
        //Error, no MIP-ARP entry was found for the supplied MIP address
        return -3;
      }
    }
  }

  //Find the source MIP and MAC address
  for(i = 0; i < MAX_ARP_SIZE; i++){
      if(local_mip_mac_table[i].socket == send_sd){
        memcpy(src_mac,local_mip_mac_table[i].mac_addr,MAC_SIZE);
        src_mip = local_mip_mac_table[i].mip_addr;
      }
  }

  //Use the local experimental protocol for communication
  eth_ptcl = htons(ETH_P_MIP);

  //Construct the ethernet frame
  frame = (struct ethernet_frame *) malloc (sizeof(struct ethernet_frame) + msg_len);

  memcpy(frame->destination,dest_mac,MAC_SIZE);
  memcpy(frame->source,src_mac,MAC_SIZE);
  frame->protocol = eth_ptcl;

  //Construct the MIP packet
  construct_mip_packet(&frame->payload,dest_mip,src_mip,tra,payload,msg_len);

  if (debug){
    fprintf(stdout,"Destination MAC: "); print_mac(frame->destination);
    fprintf(stdout,"\tDestination MIP: %d\n",get_mip_dest(&frame->payload));
    fprintf(stdout,"Source Mac: "); print_mac(frame->source);
    fprintf(stdout,"\tSource MIP: %d\n",get_mip_src(&frame->payload));
  }

  //Send the MIP packet
  ret = send(send_sd,frame,sizeof(struct ethernet_frame) + msg_len,0);

  if(debug) fprintf(stdout,"Bytes sent: %ld\n\n",ret);

  free(frame);

  return ret;


}

int recv_mip_packet(struct mip_arp_entry *mip_arp_table,struct mip_arp_entry *local_mip_mac_table,int socket,uint8_t *src_mip_buf,char *buf,int debug){

  struct mip_arp_entry *local_entry;
  char eth_buf[MAX_ETH_FRAME_SIZE];
  struct ethernet_frame *recv_eth_frame;
  uint8_t src_mac[MAC_SIZE];
  uint8_t mip_tra;
  uint8_t src_mip;
  uint8_t dest_mip;
  ssize_t ret;
  int i;


  for(i = 0; i < MAX_ARP_SIZE; i++){
    if(local_mip_mac_table[i].socket == socket){
      local_entry = &local_mip_mac_table[i];
    }
  }

  ret = recv(socket,eth_buf,MAX_ETH_FRAME_SIZE,0);

  if(ret == -1){
    //ERROR_HANDLING
    return -1;
  }

  recv_eth_frame = (struct ethernet_frame *) eth_buf;

  memcpy(src_mac,recv_eth_frame->source,MAC_SIZE);
  mip_tra = get_mip_tra(&recv_eth_frame->payload);
  src_mip = get_mip_src(&recv_eth_frame->payload);
  dest_mip = get_mip_dest(&recv_eth_frame->payload);

  if(debug){
    if(mip_tra == 0b100) fprintf(stdout,"Received transport packet.\n");
    else if(mip_tra == 0b001) fprintf(stdout,"Received MIP-ARP broadcast.\n");
    else if(mip_tra == 0b000) fprintf(stdout,"Received MIP-ARP response.\n");
    fprintf(stdout,"Destination MAC: "); print_mac(recv_eth_frame->destination);
    fprintf(stdout,"\tDestination MIP: %d\n",dest_mip);
    fprintf(stdout,"Source MAC: "); print_mac(recv_eth_frame->source);
    fprintf(stdout,"\tSource MIP: %d\n",src_mip);
    if(mip_tra == 0b100) fprintf(stdout,"Message: \"%s\"\n", recv_eth_frame->payload.payload);
    fprintf(stdout,"Bytes received: %ld\n\n",ret);
  }

  //Check that the destination is right
  if(local_entry->mip_addr != dest_mip){
    //Packet was not intended for this MIP daemon:
    //Discard the packet
    if(debug){
      fprintf(stdout,"Destination and host MIP do not match.\n");
    }

    return -2;
  }

  //Update the MIP-ARP table if necessary
  update_mip_arp(mip_arp_table,src_mip,src_mac,socket,debug);

  if(buf) memcpy(buf, recv_eth_frame->payload.payload, strlen(recv_eth_frame->payload.payload) + 1);
  if (src_mip_buf) *src_mip_buf = src_mip;

  if (mip_tra == 0b001){
    //Respond normally to the MIP address that sent the MIP broadcast
    ret = send_mip_packet(mip_arp_table, local_mip_mac_table, src_mip, NULL, 0b000, 0, debug);
  }

  return mip_tra;
}

int send_mip_broadcast(int epoll_fd,struct mip_arp_entry *mip_arp_table,int num_eth_sds,struct mip_arp_entry *local_mip_mac_table,uint8_t dest_mip,int debug){
  int i;
  int nfds_bcast;
  struct epoll_event bcast_events[MAX_EVENTS];
  uint8_t tra;

  if(debug){
    fprintf(stdout,"Sending MIP ARP broadcast on all interfaces.\n");
  }
  //Broacast on every ethernet interface
  for(i = 0; i < num_eth_sds; i++){
    if(send_mip_packet(mip_arp_table,local_mip_mac_table,dest_mip,NULL,0b001,local_mip_mac_table[i].socket,debug) == -1){
      //ERROR_HANDLING
      return -1;
    }
  }

  //Wait for respose from broadcast, or timeout
  for(;;){
    nfds_bcast = epoll_wait(epoll_fd,bcast_events,MAX_EVENTS,PING_TIMEOUT);

    if(nfds_bcast == -1){
      //ERROR_HANDLING
      perror("main: epoll_wait: un_sock_conn: arp response");
      return -1;
    }
    //If no response within the timeout
    else if(nfds_bcast==0) {
      if(debug){
        fprintf(stdout,"Timeout.\n");
      }
      return -2;
    }

    //Ignore any packet payloads, but update the MIP-ARP table
    for (i = 0;i<nfds_bcast;i++){
      tra = recv_mip_packet(mip_arp_table, local_mip_mac_table, bcast_events[i].data.fd, NULL, NULL, debug);
    } /* Go through events (for(i<nfds_bcast)) END */

    //If the expected ARP response was received, stop waiting
    if(tra == 0b000) break;

  } /* Wait for ARP response for(;;) END */

  return 0;
}

int setup_unix_socket(char* un_sock_name){
  //Setup a unix domain socket to receive communication over IPC
  //Using SOCK_SEQPACKET for connection-oriented, sequence-preserving socket
  //that preserves message boundaries (man 7 unix)
  int un_sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);

  //Error handling
  if (un_sock == -1){
    return -1;
  }

  //Based on example code from 'man 2 bind'
  //Set the address for the receiving UNIX socket
  struct sockaddr_un un_sock_addr;
  memset(&un_sock_addr, 0, sizeof(struct sockaddr_un));

  un_sock_addr.sun_family = AF_UNIX;
  //right copying?
  memcpy(un_sock_addr.sun_path,un_sock_name,sizeof(un_sock_addr.sun_path));


  //bind the socket to the name specified in the command line
  if(bind (un_sock, (struct sockaddr*)&un_sock_addr,
  sizeof(struct sockaddr_un)) == -1)
  {
    return -2;
  }

  //listen for connections on the socket
  if(listen(un_sock, LISTEN_BACKLOG_UNIX) == -1){
    return -3;
  }

  return un_sock;
}


int setup_eth_sockets(struct mip_arp_entry *local_mip_mac_table,int num_mip_addrs,int debug){
  //Based on code from 'man getifaddrs'

  //List of interfaces
  struct ifaddrs *ifaddr, *ifa;
  int eth_sd;
  int eth_sds[MAX_ARP_SIZE];
  int eth_ptcl; //The protocol to be used for ethernet
  int num_eth_sds = 0;
  int i;

  //Use the local experimental ETH_P_MIP protocol for communication
  eth_ptcl = htons(ETH_P_MIP);

  //Get all interface addresses
  if (getifaddrs (&ifaddr) == -1){
    //Error handling
    return -1;
  }
  if(debug) fprintf(stdout,"Local Ethernet Interface%s:\n",num_mip_addrs>1?"s":"");

  //Set up all raw interfaces except the local loopback as sockets for
  //receiving packets over ethernet
  for (ifa = ifaddr; ifa != NULL; ifa = ifa -> ifa_next){
    if (ifa -> ifa_addr == NULL) continue;

    //Ignore local loopback
    if (strcmp (ifa -> ifa_name, "lo") == 0) continue;

    int family = ifa -> ifa_addr -> sa_family;

    //Only raw interfaces
    if(family == AF_PACKET){
      if(++num_eth_sds>num_mip_addrs){
        continue;
      }

      //Setup a raw socket to receive packets over ethernet
      eth_sd = socket (AF_PACKET, SOCK_RAW, eth_ptcl);
      if (eth_sd == -1){
        //Error handling
        //Close all sockets (not including the most recent one)
        //and free the list of interface addresses
        for (i = 0; i < num_eth_sds-1; i++){
          close(eth_sds[i]);
        }
        freeifaddrs(ifaddr);

        return -2;
      }

      //Add the new socket to the descriptor container
      eth_sds[num_eth_sds-1] = eth_sd;

      //Get MAC address
      struct ifreq dev;
      strcpy(dev.ifr_name, ifa->ifa_name);
      if(ioctl(eth_sd,SIOCGIFHWADDR,&dev) == -1){
        //Close all sockets and free the interfaces struct
        for(int i = 0; i < num_eth_sds; i++){
          close(eth_sds[i]);
        }
        freeifaddrs(ifaddr);

        return -3;
      }

      //Associate an interface with a MIP address by adding an entry in a
      //MIP-ARP table for local interfaces, and store the socket it's bound to
      memcpy(local_mip_mac_table[num_eth_sds-1].mac_addr,dev.ifr_hwaddr.sa_data, MAC_SIZE);
      local_mip_mac_table[num_eth_sds-1].socket = eth_sd;

      //Set up the address to bind the socket to the interface
      struct sockaddr_ll eth_sockaddr;
      memset(&eth_sockaddr, 0, sizeof(eth_sockaddr));
      eth_sockaddr.sll_family = AF_PACKET;
      eth_sockaddr.sll_protocol = eth_ptcl;
      eth_sockaddr.sll_ifindex = if_nametoindex(ifa -> ifa_name);

      //Bind the socket to the interface
      if (bind (eth_sd, (struct sockaddr*) &eth_sockaddr,
      sizeof(eth_sockaddr)) == -1)
      {
        //ERROR HANDLING
        //Close all sockets and free the interfaces struct
        for(int i = 0; i < num_eth_sds; i++){
          close(eth_sds[i]);
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

  //Return the number of sockets that were created
  return num_eth_sds;
}

int create_epoll_instance(int un_sock,struct mip_arp_entry *local_mip_mac_table,int num_eth_sds){
  int i;
  //Create the epoll instance
  int epfd = epoll_create(1);

  if (epfd == -1){
    //ERROR_HANDLING
    return -1;
  }

  struct epoll_event ep_un_ev = { 0 };
  //TODO:why not edge-triggered
  //Only accept one connection at a time
  ep_un_ev.events = EPOLLIN;
  ep_un_ev.data.fd = un_sock;

  //Add the unix communication socket to the epoll instance
  if(epoll_ctl(epfd, EPOLL_CTL_ADD, un_sock, &ep_un_ev) == -1){
    //ERROR_HANDLING
    return -2;
  }

  //Add the ethernet sockets to the epoll instance
  for(i=0;i<num_eth_sds;i++){

    struct epoll_event ep_eth_ev = { 0 };
    //TODO: Maybe edge-triggered? Why?
    ep_eth_ev.events = EPOLLIN;
    ep_eth_ev.data.fd = local_mip_mac_table[i].socket;

    if (epoll_ctl (epfd, EPOLL_CTL_ADD, local_mip_mac_table[i].socket, &ep_eth_ev) == -1 ){
      //ERROR_HANDLING
      return -3;
    }

  }

  return epfd;
}


int main(int argc, char *argv[]){
  struct mip_arp_entry mip_arp_table[MAX_ARP_SIZE] = { 0 };
  struct mip_arp_entry local_mip_mac_table[MAX_ARP_SIZE] = { 0 };

  struct epoll_event events[MAX_EVENTS];
  int epfd,nfds;

  int num_eth_sds;
  int un_sock,un_sock_conn;
  int signal_fd;

  int debug;
  char* un_sock_name;
  int mip_start_ind;
  int sock_name_ind;

  int i,j;
  ssize_t ret;

  if(argc<3){
    print_help(argv[0]);
    exit(EXIT_FAILURE);
  }

  if(strcmp(argv[1],"-h") == 0){
    print_help(argv[0]);
    exit(EXIT_SUCCESS);
  }else if(strcmp(argv[1],"-d") == 0){
    if (argc<4){
      print_help(argv[0]);
      exit(EXIT_SUCCESS);
    }
    fprintf(stdout,"--- Starting MIP daemon in debug mode ---\n\n");
    //Setting the index at which the MIP daemon arguments are in argv
    debug = 1;
    sock_name_ind = 2;
    mip_start_ind = 3;
  }else{
    debug = 0;
    sock_name_ind = 1;
    mip_start_ind = 2;
  }

  //The name of the socket used for host-communication
  un_sock_name = argv[sock_name_ind];

  //Make entries in for each supplied MIP address in a local MIP-MAC table
  int num_mip_addrs = argc-2;
  if(debug) num_mip_addrs --;
  for(i=0;i<num_mip_addrs;i++){
    char *endptr;
    long int check = strtol(argv[mip_start_ind+i],&endptr,10);
    if(*endptr != '\0' || argv[mip_start_ind+i][0] == '\0' || check>255 || check < 0){
      print_help(argv[0]);
      exit(EXIT_FAILURE);
    }
    local_mip_mac_table[i].mip_addr = check;
    for(j=0;j<i;j++){
      if(local_mip_mac_table[i].mip_addr==local_mip_mac_table[j].mip_addr){
        print_help(argv[0]);
        exit(EXIT_FAILURE);
      }
    }
  }

  //Setup a unix socket for accepting application connections
  un_sock = setup_unix_socket(un_sock_name);

  if(un_sock == -1){
    perror("main: setup_unix_socket, socket() un_sock");
    exit(EXIT_FAILURE);
  }else if (un_sock == -2){
    perror("main: setup_unix_socket, bind un_sock");
    close_sockets(un_sock,NULL,-1,-1,NULL,0);
    exit(EXIT_FAILURE);
  }else if (un_sock == -3){
    perror("main: listen() un_sock");
    close_sockets(un_sock,un_sock_name,-1,-1,NULL,0);
    exit(EXIT_FAILURE);
  }

  num_eth_sds =  setup_eth_sockets(local_mip_mac_table,num_mip_addrs,debug);

  if(num_eth_sds == -1){
    //ERROR_HANDLING
    perror("main: setup_eth_sockets: getifaddrs");
    close_sockets(un_sock,un_sock_name,-1,-1,NULL,0);
    exit(EXIT_FAILURE);
  }else if(num_eth_sds == -2){
    perror("main: setup_eth_sockets: socket");
    close_sockets(un_sock,un_sock_name,-1,-1,NULL,0);
    exit(EXIT_FAILURE);
  }else if(num_eth_sds == -3){
    perror("main: setup_eth_sockets: ioctl");
    close_sockets(un_sock,un_sock_name,-1,-1,NULL,0);
    exit(EXIT_FAILURE);
  }else if(num_eth_sds == -4){
    perror("main: setup_eth_sockets: bind");
    close_sockets(un_sock,un_sock_name,-1,-1,NULL,0);
    exit(EXIT_FAILURE);
  }

  //Check if the correct number of MIP addresses was supplied to the MIP daemon
  //on startup
  if(num_eth_sds > num_mip_addrs || num_mip_addrs > num_eth_sds){
    //Number of MIP addresses did not match number of ethernet sockets
    fprintf(stderr,"Number of supplied MIP addresses did not match the number of interfaces requiring a MIP address...\n");
    fprintf(stderr,"Number of supplied MIP addresses: %d\n", num_mip_addrs);
    fprintf(stderr,"Number of interfaces which require MIP addresses: %d\n", num_eth_sds);
    close_sockets(un_sock,un_sock_name,-1,-1,local_mip_mac_table,num_mip_addrs > num_eth_sds ? num_eth_sds : num_mip_addrs);
    exit(EXIT_FAILURE);
  }

  //Code concerning epoll is based on code from 'man 7 epoll' and plenumstime 3
  epfd = create_epoll_instance(un_sock,local_mip_mac_table,num_eth_sds);

  if (epfd == -1){
    //ERROR_HANDLING
    perror("main: create_epoll_instance(): epoll_create");
    close_sockets(un_sock,un_sock_name,-1,-1,local_mip_mac_table,num_eth_sds);
    exit(EXIT_FAILURE);
  }else if(epfd == -2){
    //ERROR_HANDLING
    perror("main: create_epoll_instance: epoll_ctl(): add un_sock");
    close_sockets(un_sock,un_sock_name,-1,-1,local_mip_mac_table,num_eth_sds);
    exit(EXIT_FAILURE);
  }else if(epfd == -3){
    //ERROR_HANDLING
    perror("main: epoll_ctl: add local_mip_mac_table[i].socket");
    close_sockets(un_sock,un_sock_name,-1,-1,local_mip_mac_table,num_eth_sds);
    exit(EXIT_FAILURE);
  }

  //Add signal handler to the epoll instance
  sigset_t mask;

  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGQUIT);

  sigprocmask(SIG_BLOCK, &mask, NULL);

  signal_fd = signalfd(-1, &mask, 0);
  if(signal_fd == -1){
    //ERROR_HANDLING
    perror("main: signalfd");
    close_sockets(un_sock,un_sock_name,-1,-1,local_mip_mac_table,num_eth_sds);
    exit(EXIT_FAILURE);
  }

  struct epoll_event ep_sig_ev = { 0 };
  ep_sig_ev.events = EPOLLIN | EPOLLERR;
  ep_sig_ev.data.fd = signal_fd;

  if(epoll_ctl(epfd,EPOLL_CTL_ADD,signal_fd,&ep_sig_ev) == -1){
    //ERROR_HANDLING
    perror("main: epoll_ctl: add signal_fd");
    close_sockets(un_sock,un_sock_name,-1,signal_fd,local_mip_mac_table,num_eth_sds);
    exit(EXIT_FAILURE);
  }


  un_sock_conn = -1; //no connection when un_sock_conn is -1

  struct epoll_event ep_ev = { 0 };
  //Poll the sockets for events using epoll
  for(;;){

    nfds = epoll_wait(epfd,events,MAX_EVENTS,-1);
    if(nfds == -1){
      //ERROR_HANDLING
      perror("main: epoll_wait()");
      close_sockets(un_sock,un_sock_name,un_sock_conn,signal_fd,local_mip_mac_table,num_eth_sds);
      exit(EXIT_FAILURE);
    }

    //Handle all triggered events
    for (i = 0; i < nfds; i++){

      //Received interrupt signal
      if(events[i].data.fd == signal_fd){
        struct signalfd_siginfo sig_info;
        ssize_t sig_size;

        sig_size = read(events[i].data.fd,&sig_info,sizeof(struct signalfd_siginfo));
        if(sig_size == 0){
          perror("\nCtrl-d: Received EOF signal from keyboard, stopping\n");
          close_sockets(un_sock,un_sock_name,un_sock_conn,signal_fd,local_mip_mac_table,num_eth_sds);
          exit(EXIT_SUCCESS);
        }
        if(sig_info.ssi_signo == SIGINT){
          //Close all sockets and close stop the daemon
          fprintf(stderr,"\nCtrl-c: Received interrupt from keyboard, stopping daemon\n");
          close_sockets(un_sock,un_sock_name,un_sock_conn,signal_fd,local_mip_mac_table,num_eth_sds);
          exit(EXIT_SUCCESS);
        }
        else if(sig_info.ssi_signo == SIGQUIT){
          //Close all sockets and close stop the daemon
          fprintf(stderr,"\nCtrl-\\: Received interrupt from keyboard, stopping daemon\n");
          close_sockets(un_sock,un_sock_name,un_sock_conn,signal_fd,local_mip_mac_table,num_eth_sds);
          exit(EXIT_SUCCESS);
        }
      }
      //Incoming connection from an application
      else if(events[i].data.fd == un_sock){

        struct sockaddr_un un_sock_conn_addr = { 0 };
        socklen_t size_un_sock_conn_addr = sizeof(un_sock_conn_addr);

        //Accept incoming connection from the application
        un_sock_conn = accept(un_sock,(struct sockaddr *)&un_sock_conn_addr,
        &size_un_sock_conn_addr);

        if(debug){
          fprintf(stdout,"Connection to application established.\n");
        }

        //Only recelive one message from the application at a time
        ep_ev.events = EPOLLIN|EPOLLONESHOT;
        ep_ev.data.fd = un_sock_conn;

        if(epoll_ctl(epfd, EPOLL_CTL_ADD, un_sock_conn, &ep_ev) == -1){
          //ERROR_HANDLING
          perror("main: epoll_ctl(): add un_sock_conn");
          close_sockets(un_sock,un_sock_name,un_sock_conn,signal_fd,local_mip_mac_table,num_eth_sds);
          exit(EXIT_FAILURE);
        }
      } /* incoming application connection END */

      //Incoming data from client on local unix socket
      else if(events[i].data.fd == un_sock_conn){

        char msg_buf[MAX_MSG_SIZE] = { 0 }; /* to hold zero terminated message */
        uint8_t dest_mip_addr;

        struct msghdr msg = { 0 };
        struct iovec iov[2];

        iov[0].iov_base = &dest_mip_addr;
        iov[0].iov_len = sizeof(int);

        iov[1].iov_base = msg_buf;
        iov[1].iov_len = sizeof(msg_buf);

        msg.msg_iov = iov;
        msg.msg_iovlen = 2;

        //un_sock_conn is set to 0 why?

        ret = recvmsg(events[i].data.fd,&msg,0);

        //Need this to fix above...
        un_sock_conn = events[i].data.fd;

        if(ret == -1){
          //ERROR_HANDLING
          perror("main: recvmsg: un_sock_conn");
          close_sockets(un_sock,un_sock_name,un_sock_conn,signal_fd,local_mip_mac_table,num_eth_sds);
          exit(EXIT_FAILURE);
        }
        else if (ret == 0){
          //Application terminated connection

          if(debug){
            fprintf(stdout,"Connection to application terminated.\n");
          }

          //Remove the unix connected socket from the epoll instance
          if(epoll_ctl(epfd,EPOLL_CTL_DEL,events[i].data.fd,&events[i]) == -1){
            //ERROR_HANDLING
            perror("main: epoll_ctl: del un_sock_conn");
            close_sockets(un_sock,un_sock_name,un_sock_conn,signal_fd,local_mip_mac_table,num_eth_sds);
            exit(EXIT_FAILURE);
          }

          //Close the connected unix socket
          close(events[i].data.fd);
          un_sock_conn = -1;

          struct epoll_event ep_un_ev = { 0 };
          ep_un_ev.events = EPOLLIN;
          ep_un_ev.data.fd = un_sock;

          //Rearm the unix socket listening for connections
          epoll_ctl(epfd,EPOLL_CTL_MOD,un_sock,&ep_un_ev);

          //Discard other events and start over
          break;
        }

        if(debug){
          fprintf(stdout,"Received %ld bytes from client:\n",ret);
          fprintf(stdout,"Destination MIP address: %d\n",dest_mip_addr);
          fprintf(stdout,"Message: \"%s\"\n\n",msg_buf);
          fprintf(stdout,"Sending ping.\n");
        }

        //Attempt to send the ping message
        ret = send_mip_packet(mip_arp_table, local_mip_mac_table, dest_mip_addr, msg_buf, 0b100, 0, debug);

        if(ret == -1){
          //ERROR_HANDLING
          perror("main: send_mip_packet: un_sock_conn: send ping");
          close_sockets(un_sock,un_sock_name,un_sock_conn,signal_fd,local_mip_mac_table,num_eth_sds);
          exit(EXIT_FAILURE);
        }
        else if(ret == -2){
          //Max message length exceeded
          if(debug){
            fprintf(stdout,"Ping message exceeds max length. Aborted send.\n");
          }
          continue;
        }
        else if(ret == -3){
          //MIP not cached
          if(debug){
            fprintf(stdout,"MIP address %d not in MIP-ARP table.\n",dest_mip_addr);
            print_arp_table(mip_arp_table);
          }

          ret = send_mip_broadcast(epfd, mip_arp_table, num_eth_sds, local_mip_mac_table, dest_mip_addr,debug);

          if(ret == -1){
            perror("main: send_mip_broadcast: un_sock_conn: send ping broadcast");
            close_sockets(un_sock,un_sock_name,un_sock_conn,signal_fd,local_mip_mac_table,num_eth_sds);
            exit(EXIT_FAILURE);
          }
          else if(ret == -2){
            //Timeout
            //Rearm the connected unix socket and keep iterating through events
            epoll_ctl(epfd,EPOLL_CTL_MOD,un_sock_conn,&ep_ev);
            continue;
          }

          if(debug){
            fprintf(stdout,"Re-sending ping.\n");
          }
          ret = send_mip_packet(mip_arp_table, local_mip_mac_table, dest_mip_addr, msg_buf, 0b100, 0, debug);
        }


        int ping_nfds;
        int pong = 0; /* check if received PONG response */
        struct epoll_event ping_events[MAX_EVENTS];
        char buf[MAX_MSG_SIZE];
        uint8_t src_mip;
        int tra;

        //Wait for PONG response
        for(;;){
          //If received a PONG response the previous iteration, break
          if(pong == 1){
            //Rearm the connected unix socket
            epoll_ctl(epfd,EPOLL_CTL_MOD,un_sock_conn,&ep_ev);
            break;
          }

          ping_nfds = epoll_wait(epfd,ping_events,MAX_EVENTS,PING_TIMEOUT);

          if(ping_nfds == -1){
            //ERROR_HANDLING
            perror("main: epoll_wait: un_sock_conn: PONG response");
            close_sockets(un_sock,un_sock_name,un_sock_conn,signal_fd,local_mip_mac_table,num_eth_sds);
            exit(EXIT_FAILURE);
          } else if(ping_nfds == 0){
            //Timeout
            if(debug){
              fprintf(stdout,"Timeout.\n");
            }
            //Rearm connected unix socket
            epoll_ctl(epfd,EPOLL_CTL_MOD,un_sock_conn,&ep_ev);
            break;
          }

          for(j = 0; j < ping_nfds; j++){
            //Receive MIP packet, MIP payload written to buf
            tra = recv_mip_packet(mip_arp_table, local_mip_mac_table, ping_events[j].data.fd,&src_mip, buf,debug);
            if(tra == -1){
              //ERROR_HANDLING
              perror("main: recv: un_sock_conn: PONG response");
              close_sockets(un_sock,un_sock_name,un_sock_conn,signal_fd,local_mip_mac_table,num_eth_sds);
              exit(EXIT_FAILURE);
            }else if(tra == -2){
              //Packet was not for this host, discard it
              continue;
            }

            if(tra == 0b100){
              //Frame was a Transport message

              if(strcmp(buf,"PONG") != 0){
                //Packet was not the PONG response that was expected,
                //discard the packet
                continue;
              }

              if(debug){
                fprintf(stdout,"Packet was a PONG response.\n");
              }

              char pong_buf[IPC_PONG_RSP_SIZE] = { 0 }; /* to hold the PONG response */

              struct msghdr msg = { 0 };
              struct iovec iov[1];

              iov[0].iov_base = pong_buf;
              iov[0].iov_len = sizeof(pong_buf);

              msg.msg_iov = iov;
              msg.msg_iovlen = sizeof(iov);

              ret = sendmsg(un_sock_conn,&msg,0);

              if(ret == -1){
                //ERROR_HANDLING
                perror("main: sendmsg: un_sock_conn: PONG response");
                close_sockets(un_sock,un_sock_name,un_sock_conn,signal_fd,local_mip_mac_table,num_eth_sds);
                exit(EXIT_FAILURE);
              }

              if(debug){
                fprintf(stdout,"Sent %ld bytes to client.\n",ret);
              }

              //Stop waiting for a PONG response next iteration
              pong = 1;

              break;
            }

          } /* for(j < ping_fds) END */

        } /* for (;;) END */

      } /* Local unix communcation END */

      //Incoming data on ethernet sockets
      else{
        int tra;
        char buf[MAX_MSG_SIZE];
        uint8_t src_mip;

        tra = recv_mip_packet(mip_arp_table, local_mip_mac_table,events[i].data.fd,&src_mip,buf,debug);

        if(tra == -1){
          //ERROR_HANDLING
          perror("main: recv: eth socket");
          close_sockets(un_sock,un_sock_name,un_sock_conn,signal_fd,local_mip_mac_table,num_eth_sds);
          exit(EXIT_FAILURE);
        } else if(tra == -2){
          //Packet was not for this host
          continue;
        }

        //If the received packet was a ping message
        if(tra == 0b100){
          //If no server is connected, ignore the packet
          if(un_sock_conn == -1){
            if(debug){
              fprintf(stdout,"No server connected. Discarding packet.\n");
            }
            continue;
          }

          if(debug){
            fprintf(stdout,"Packet was a ping.\n");
          }

          //Set up the sending data structure
          struct msghdr ping_msg = { 0 };
          struct iovec ping_iov[1];

          ping_iov[0].iov_base = buf;
          ping_iov[0].iov_len = strlen(buf)+1;

          ping_msg.msg_iov = ping_iov;
          ping_msg.msg_iovlen = 1;

          ret = sendmsg(un_sock_conn,&ping_msg,0);

          //Send the message
          if(ret == -1){
            //ERROR_HANDLING
            perror("main: sendmsg: un_sock_conn receive ping");
            close_sockets(un_sock,un_sock_name,un_sock_conn,signal_fd,local_mip_mac_table,num_eth_sds);
            exit(EXIT_FAILURE);
          }

          if(debug){
            fprintf(stdout,"Sent %ld bytes to server.\n",ret);
          }

          uint8_t pong_tra = 0b100;

          //Set up the receiving data structure
          char pong_buf[IPC_PONG_RSP_SIZE];

          struct msghdr pong_msg = { 0 };
          struct iovec pong_iov[1];


          pong_iov[0].iov_base = pong_buf;
          pong_iov[0].iov_len = IPC_PONG_RSP_SIZE;

          pong_msg.msg_iov = pong_iov;
          pong_msg.msg_iovlen = 1;

          ret = recvmsg(un_sock_conn,&pong_msg,0);

          //Receive the PONG response
          if(ret == -1){
            //ERROR_HANDLING
            perror("main: recvmsg: un_sock_conn send pong");
            close_sockets(un_sock,un_sock_name,un_sock_conn,signal_fd,local_mip_mac_table,num_eth_sds);
            exit(EXIT_FAILURE);
          }

          if(debug){
            fprintf(stdout,"Received %ld bytes from server:\n",ret);
            fprintf(stdout,"Message: \"%s\"\n",pong_buf);
          }

          if(debug){
            fprintf(stdout,"Sending pong response.\n");
          }

          //Send a MIP packet with the PONG response to the pinging host
          ret = send_mip_packet(mip_arp_table, local_mip_mac_table, src_mip,pong_buf, pong_tra, 0,debug);

          if(ret == -1){
            //ERROR_HANDLING
            perror("main: send_mip_packet: un_sock_conn send pong");
            close_sockets(un_sock,un_sock_name,un_sock_conn,signal_fd,local_mip_mac_table,num_eth_sds);
            exit(EXIT_FAILURE);
          }

        } /* Received ping END */

      } /* receive on ethernet END */

    } /* Iterate over events (for(i < nfds)) END */

  } /* Wait for epoll events main loop (for(;;)) END */

} /* int main() END */
