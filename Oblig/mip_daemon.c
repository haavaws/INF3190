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
//TODO: MIP-ARP


//ARP:
struct mip_arp_entry {
  uint8_t mip_addr; /* MIP address of the host */
  uint8_t mac_addr[6]; /* MAC address of the host */
  int socket; /* Socket the interface connected to the MIP address is bound to */
  /* The time at which the entry was stored, timestamp is 0, entry is empty */
  time_t timestamp;
};

int mac_cmp(uint8_t *mac_a, uint8_t *mac_b){
  int i,mac_len;
  mac_len = 6;
  for(i = 0; i < mac_len; i++){
    if(mac_a[i] != mac_b[i]) return -1;
  }
  return 0;
}


struct mip_frame{
  uint8_t header_bytes[4];
  char payload[];

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




//Based on code from plenumstime 2
struct ethernet_frame {
  uint8_t destination[6];
  uint8_t source[6];
  uint16_t protocol;
  struct mip_frame payload;
} __attribute__((packed));


//Listen to all available ethernet adapters and put their
//descriptors into fds.
//Return number of
int listen_eth_sockets(int *fds){
  return 0;
}

int construct_mip_header(struct mip_frame* frame,uint8_t destination,uint8_t source,uint8_t tra,char* payload,int payload_len){
  memset(frame,0,sizeof(struct mip_frame));
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

  return 0;

}


int main(int argc, char *argv[]){
  int i,j,k; /* index for loops */
  struct mip_arp_entry mip_arp_table[MAX_ARP_SIZE] = { 0 };
  struct mip_arp_entry* local_mip_mac_table;

  //TEST DATA
  //int mip_addr = 0;

  if(argc<3){
    fprintf(stderr,"USAGE: %s <Socket_application> [MIP addresses ...]\n"
    "<Socket_application>: name of the socket to be used for communicating "
    "with the application\n"
    "[MIP addresses ...]: one unique MIP address for each interface with a unique "
    "MAC address, in the form of a number between 0 and 255\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  //The name of the socket used for host-communication
  char* un_sock_name = argv[1];

  //Make entries in for each supplied MIP address in a local MIP-MAC table
  int num_mip_addrs = argc-2;
  local_mip_mac_table = (struct mip_arp_entry*) calloc(num_mip_addrs, sizeof(struct mip_arp_entry));
  for(i=0;i<num_mip_addrs;i++){
    char *endptr;
    long int check = strtol(argv[2+i],&endptr,10);
    if(*endptr != '\0' || argv[2+i][0] == '\0' || check>255 || check < 0){
      fprintf(stderr,"USAGE: %s <Socket_application> [MIP addresses ...]\n"
      "<Socket_application>: name of the socket to be used for communicating "
      "with the application\n"
      "[MIP addresses ...]: one unique MIP address for each interface with a unique "
      "MAC address, in the form of a number between 0 and 255\n", argv[0]);
      exit(EXIT_FAILURE);
    }
    local_mip_mac_table[i].mip_addr = check;
    for(j=0;j<i;j++){
      if(local_mip_mac_table[i].mip_addr==local_mip_mac_table[j].mip_addr){
        fprintf(stderr,"USAGE: %s <Socket_application> [MIP addresses ...]\n"
        "<Socket_application>: name of the socket to be used for communicating "
        "with the application\n"
        "[MIP addresses ...]: one unique MIP address for each interface with a unique "
        "MAC address, in the form of a number between 0 and 255\n", argv[0]);
        exit(EXIT_FAILURE);
      }
    }
  }



  //Setup a unix domain socket to receive communication over IPC
  //Using SOCK_SEQPACKET for connection-oriented, sequence-preserving socket
  //that preserves message boundaries (man 7 unix)
  int un_sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);

  //Error handling
  if (un_sock == -1){
    perror("main: socket() un_sock");
    exit(EXIT_FAILURE);
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
    //TODO: ERROR HANDLING
    perror("main: bind() un_sock");
    close(un_sock);
    exit(EXIT_FAILURE);
  }

  //listen for connections on the socket
  if(listen(un_sock, LISTEN_BACKLOG_UNIX) == -1){
    //TODO: ERROR HANDLING
    perror("main: listen() un_sock");
    close(un_sock);
    unlink(un_sock_name);
    exit(EXIT_FAILURE);
  }

  //temp accept code
  //TODO: USE EPOLL!!


  //Close the socket and unlink the path
  close(un_sock);
  unlink(un_sock_name);









  //Based on code from 'man getifaddrs'

  //List of interfaces
  //TODO: Remember to free
  struct ifaddrs *ifaddr, *ifa;
  //TODO: Remember to free
  int *eth_sds; //Descriptors for all ethernet sockets
  int num_eth_sds,eth_sd;
  int eth_ptcl; //The protocol to be used for ethernet

  //Use the local experimental ETH_P_MIP protocol for communication
  eth_ptcl = htons(ETH_P_MIP);

  //TODO: remove conversion, which was used to stop linter complaining
  //Socket descriptors for all interfaces with a unique MAC address
  eth_sds = (int *) calloc (num_mip_addrs, sizeof(int));

  //TODO: Remember to free
  //Get all interface addresses
  if (getifaddrs (&ifaddr) == -1){
    //Error handling
    perror("main: getiffaddrs()");
    free(eth_sds);
    exit(EXIT_FAILURE);
  }

  num_eth_sds = 0;

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
      fprintf(stdout,"%s",ifa -> ifa_name);

      //Broadcast address: 255:255:255:255:255:255
      //Evt. subnet x.x.x.255

      //Setup a raw socket to receive packets over ethernet
      eth_sd = socket (AF_PACKET, SOCK_RAW, eth_ptcl);
      if (eth_sd == -1){
        //Error handling
        perror("main: socket: eth_sd");
        //Close all sockets (not including the most recent one)
        //and free the list of interface addresses
        for (i = 0; i < num_eth_sds-1; i++){
          close(eth_sds[i]);
        }
        free(eth_sds);
        freeifaddrs(ifaddr);

        exit(EXIT_FAILURE);
      }

      //Add the new socket to the descriptor container
      eth_sds[num_eth_sds-1] = eth_sd;

      //Add the MAC address of the interface to an entry in the local
      //MIP-MAC table, along with the socket it is bound to
      struct ifreq dev;
      strcpy(dev.ifr_name, ifa->ifa_name);
      if(ioctl(eth_sd,SIOCGIFHWADDR,&dev) == -1){
        perror("main: ioctl");
        exit(EXIT_FAILURE);
      }
      memcpy(dev.ifr_hwaddr.sa_data,local_mip_mac_table[num_eth_sds-1].mac_addr, sizeof(local_mip_mac_table[num_eth_sds-1]));
      local_mip_mac_table[num_eth_sds-1].socket = eth_sd;

      //Set up the address for communication
      struct sockaddr_ll eth_sockaddr;
      memset(&eth_sockaddr, 0, sizeof(eth_sockaddr));
      eth_sockaddr.sll_family = AF_PACKET;
      eth_sockaddr.sll_protocol = eth_ptcl;
      eth_sockaddr.sll_ifindex = if_nametoindex(ifa -> ifa_name);

      //Bind the socket
      if (bind (eth_sd, (struct sockaddr*) &eth_sockaddr,
      sizeof(eth_sockaddr)) == -1)
      {
        //ERROR HANDLING
        perror("main: bind: eth_sd");
        //Close all sockets and free the interfaces struct
        for(int i = 0; i < num_eth_sds; i++){
          close(eth_sds[i]);
        }
        free(eth_sds);
        freeifaddrs(ifaddr);

        exit(EXIT_FAILURE);
      }
    }
  }

  //Check if the number of interfaces with a MAC addresses is greater
  //than the number of supplied MIP addresses
  if(num_eth_sds > num_mip_addrs){
    fprintf(stderr,"USAGE: %s <Socket_application> [MIP addresses ...]\n"
    "<Socket_application>: name of the socket to be used for communicating "
    "with the application\n"
    "[MIP addresses ...]: one MIP address for each interface with a unique "
    "MAC address, in the form of a number between 0 and 255\n", argv[0]);
    fprintf(stderr,"Number of supplied MIP addresses: %d\n"
    "Number of interfaces which require MIP addresses: %d\n",
    num_mip_addrs,num_eth_sds);

    //Free up resources
    for(i = 0;i<num_eth_sds;i++){
      close(eth_sds[i]);
    }
    free(eth_sds);
    freeifaddrs(ifaddr);

    exit(EXIT_FAILURE);
  }



  //Free up all resources
  for(i = 0;i<num_eth_sds;i++){
    close(eth_sds[i]);
  }
  free(eth_sds);
  freeifaddrs(ifaddr);








  //Code concerning epoll is based on code from 'man 7 epoll' and plenumstime 3

  //Epoll descriptor
  int epfd,nfds;
  int un_sock_conn;
  un_sock_conn = -1; //no connection when un_sock_conn is -1
  struct epoll_event events[MAX_EVENTS];

  //Create the epoll instance
  epfd = epoll_create(1);

  if (epfd == -1){
    //ERROR_HANDLING
    perror("main: epoll_create()");
    exit(EXIT_FAILURE);
  }

  struct epoll_event ep_un_ev = { 0 };
  //TODO:why not edge-triggered
  //Only accept one connection at a time
  ep_un_ev.events = EPOLLIN|EPOLLONESHOT;
  ep_un_ev.data.fd = un_sock;

  //Add the unix communication socket to the epoll instance
  if(epoll_ctl(epfd, EPOLL_CTL_ADD, un_sock, &ep_un_ev) == -1){
    //ERROR_HANDLING
    perror("main: epoll_ctl(): add un_sock");
    exit(EXIT_FAILURE);
  }


  //Add the events for the ethernet sockets to the epoll instance
  for(i=0;i<num_eth_sds;i++){

    struct epoll_event ep_eth_ev = { 0 };
    //TODO: Maybe edge-triggered? Why?
    ep_eth_ev.events = EPOLLIN;
    ep_eth_ev.data.fd = eth_sds[i];

    if (epoll_ctl (epfd, EPOLL_CTL_ADD, eth_sds[i], &ep_eth_ev) == -1 ){
      //ERROR_HANDLING
      perror("main: epoll_ctl: add eth_sds[i]");
      exit(EXIT_FAILURE);
    }

  }


  //Poll the sockets for events using epoll
  for(;;){
    struct epoll_event ep_ev = { 0 };
    //TODO: Handle signals
    nfds = epoll_wait(epfd,events,MAX_EVENTS,-1);
    if(nfds == -1){
      //ERROR_HANDLING
      perror("main: epoll_wait()");
      exit(EXIT_FAILURE);
    }

    //Handle all triggered events
    for (i = 0; i < nfds; i++){

      //Incoming connection from an application
      if(events[i].data.fd == un_sock){
        struct sockaddr_un un_sock_conn_addr = { 0 };
        socklen_t size_un_sock_conn_addr = sizeof(un_sock_conn_addr);

        //TODO: Refuse connection if a client is already connected
        if (un_sock_conn != -1) continue;

        //Accept incoming connection from the application
        un_sock_conn = accept(un_sock,(struct sockaddr *)&un_sock_conn_addr,
        &size_un_sock_conn_addr);

        //TODO: edge-triggered maybe??? why?
        //Only recelive one message from the application at a time
        ep_ev.events = EPOLLIN|EPOLLONESHOT;
        ep_ev.data.fd = un_sock_conn;

        if(epoll_ctl(epfd, EPOLL_CTL_ADD, un_sock_conn, &ep_ev) == -1){
          //ERROR_HANDLING
          perror("main: epoll_ctl(): add un_sock_conn");
          exit(EXIT_FAILURE);
        }
      }
      //Incoming data from client
      else if(events[i].data.fd == un_sock_conn){
        char msg_buf[MAX_MSG_SIZE] = { 0 }; /* to hold zero terminated message */
        uint8_t dest_mip_addr;
        uint8_t src_mip_addr;

        struct msghdr msg = { 0 };
        struct iovec iov[2];

        iov[0].iov_base = &dest_mip_addr;
        iov[0].iov_len = sizeof(int);

        iov[1].iov_base = msg_buf;
        iov[1].iov_len = sizeof(msg_buf);

        msg.msg_iov = iov;
        msg.msg_iovlen = sizeof(iov);

        ssize_t ret = recvmsg(events[i].data.fd,&msg,0);

        if(ret == -1){
          //ERROR_HANDLING
          perror("main: recvmsg: un_sock_conn");
          exit(EXIT_FAILURE);
        } else if (ret == 0){
          //Application terminated connection

          //Remove the unix connected socket from the epoll instance
          if(epoll_ctl(epfd,EPOLL_CTL_DEL,events[i].data.fd,&events[i]) == -1){
            //ERROR_HANDLING
            perror("main: epoll_ctl: del un_sock_conn");
            exit(EXIT_FAILURE);
          }

          //Close the connected unix socket
          close(events[i].data.fd);
          un_sock_conn = -1;

          //Rearm the unix socket listening for connections
          epoll_ctl(epfd,EPOLL_CTL_MOD,un_sock,&ep_un_ev);

          //Discard other events and start over
          break;
        }


        //TODO: Transmit message via ethernet to the given MIP address
        //Length include terminating byte
        int msg_len = strlen(msg_buf)+1;

        //Make sure message size conforms to specifications, and add padding
        //if necessary
        if(msg_len % 4 != 0){

          //Pad the message with 0-bytes
          for(j = 0; j < msg_len % 4; j++){
            msg_buf[strlen(msg_buf)+1+j] = '\0';
          }

          //Correct the message length
          msg_len += msg_len % 4;
        }

        int broadcast = 1; /* indicates if a MIP-ARP broadcast is required */
        //Construct ethernet header:
        struct ethernet_frame *eth_frame;
        eth_frame = (struct ethernet_frame *) malloc(sizeof(eth_frame)+msg_len);

        eth_frame->protocol = eth_ptcl;

        //Check if destination MIP is cached in the MIP-ARP table
        for(j = 0;j<MAX_ARP_SIZE;j++){
          if(mip_arp_table[j].mip_addr == dest_mip_addr){
            //If it is, set the corresponding MAC address as the destination
            //in the ethernet frame, unless the entry has exceeded the
            //MIP_ARP_TTL time limit
            if(time(NULL) - mip_arp_table[j].timestamp > MIP_ARP_TTL){
              memset(&mip_arp_table[j],0,sizeof(mip_arp_table[j]));
            }else{
              memcpy(eth_frame->destination,mip_arp_table[j].mac_addr, MAC_SIZE);
              broadcast = 0;
            }
            break;
          }
        }

        //
        int timeout = 0;
        if(broadcast == 1){
          //Broacast on every ethernet interface
          for(j = 0; j < num_eth_sds; j++){
            //Construct brocast ethernet header for each interface
            struct ethernet_frame bcast_frame = { 0 };
            memcpy(bcast_frame.destination,"\xff\xff\xff\xff\xff\xff", MAC_SIZE);
            memcpy(bcast_frame.source,local_mip_mac_table[j].mac_addr, MAC_SIZE);
            bcast_frame.protocol = eth_ptcl;

            //Construct MIP header:
            uint8_t tra;
            char bcast_mip_msg;
            //Will send an ARP broacast message
            tra = 0b001;
            bcast_mip_msg = '\0';
            ret = construct_mip_header(&bcast_frame.payload,dest_mip_addr, local_mip_mac_table[j].mip_addr,tra,&bcast_mip_msg,0);
            if(ret == -1){
              //ERROR_HANDLING
              fprintf(stderr,"Message size exceeds limit");
              //TODO: do something?
            }else if (ret == -2){
              //ERROR_HANDLING
              fprintf(stderr,"Message was not a multiple of 4");
              //TODO: do something??
            }

            //TODO: Maybe need to use epoll???
            if(send(local_mip_mac_table[j].socket,&bcast_frame,sizeof(struct mip_frame), 0) == -1){
              perror("main: send: ARP broadcast");
              exit(EXIT_FAILURE);
            }



          }
          int nfds_bcast;
          struct epoll_event bcast_events[MAX_EVENTS];
          char buf[MAX_ETH_FRAME_SIZE];
          struct ethernet_frame *recv_bcast_frame;
          int ret;
          uint8_t tra;

          //Wait for respose from broadcast
          for(;;){
            //Repeat this process until either the timeout is reached in an
            //epoll_wait call, or the MIP-ARP response is received

            //Neither the unix socket awaiting connections and the unix socket
            //connecting the application to the daemon is monitored
            //due to the EPOLLONESHOT event associated with them
            nfds_bcast = epoll_wait(epfd,bcast_events,MAX_EVENTS,PING_TIMEOUT);

            if(nfds_bcast == -1){
              //ERROR_HANDLING
              perror("main: epoll_wait: un_sock_conn: arp response");
            }
            //If no response within the timeout
            else if(nfds_bcast==0) {
              timeout=1;
              break;
            }

            //Receive data over ethernet interfaces that have sent data
            //and handle any unexpected data
            for (j = 0;j<nfds_bcast;j++){
              ret = recv(bcast_events[j].data.fd, &buf, sizeof(struct ethernet_frame) + MAX_MSG_SIZE, 0);
              if(ret == -1){
                perror("main: recv: ARP response");
                exit(EXIT_FAILURE);
              }
              recv_bcast_frame = (struct ethernet_frame *) buf;




              struct mip_arp_entry *entry;

              //Check if the ethernet frame was intended for this MIP daemon
              //Lookup this host's interface
              for(k = 0; k < num_eth_sds; k++){
                if(local_mip_mac_table[k].socket == bcast_events[j].data.fd){
                  entry = &local_mip_mac_table[k];
                }
              }

              //Check if the package was sent to the right interface
              if(get_mip_dest(&recv_bcast_frame->payload) != entry->mip_addr) continue;

              tra = get_mip_tra(&recv_bcast_frame->payload);
              uint8_t mip_src = get_mip_src(&recv_bcast_frame->payload);
              time_t now = time(NULL);

              //Check if it is the ARP resonse that was expected
              if(tra == 0b000){

                //Register the MIP and MAC address in the MIP-ARP table
                for(k = 0; k < MAX_ARP_SIZE; k++){

                  if(mip_arp_table[k].timestamp == 0 || now - mip_arp_table[k].timestamp > MIP_ARP_TTL){

                    //Overwrite an expired entry if its TTL was exceeded,
                    //or create new entry if there were no expired entries
                    mip_arp_table[k].mip_addr = mip_src;
                    memcpy(mip_arp_table[k].mac_addr,recv_bcast_frame->source,MAC_SIZE);
                    mip_arp_table[k].socket = bcast_events[j].data.fd;
                    mip_arp_table[k].timestamp = now;

                    break;
                  }
                }
              }
              //If the packet was a transport message, not the ARP response
              //that was expected
              else if(tra == 0b100){

                //Discard the package but update the MIP-ARP table if necessary
                for(k = 0; k < MAX_ARP_SIZE; k++){

                  //If the mip address exists as an entry or an empty entry
                  //was reached
                  if(mip_arp_table[k].mip_addr == mip_src || mip_arp_table[k].timestamp == 0){

                    //Check if the previous entry with the source MIP address
                    //has expired or the entry was empty, update the entry
                    if(now - mip_arp_table[k].timestamp > MIP_ARP_TTL){
                      mip_arp_table[k].mip_addr = mip_src;
                      memcpy(mip_arp_table[k].mac_addr,recv_bcast_frame->source,MAC_SIZE);
                      mip_arp_table[k].socket = bcast_events[j].data.fd;
                      mip_arp_table[k].timestamp = now;
                    }

                    break;
                  }
                }
              }
              //If the packet was an ARP broadcast message, not the APR response
              //that was expected
              else if(tra == 0b001){
                //Respond to the broadcast normally anyway, and update the
                //MIP-ARP table if necessary

                //Update MIP-ARP table:
                for(k = 0; k < MAX_ARP_SIZE; k++){

                  //If the mip address exists as an entry or an empty entry
                  //was reached
                  if(mip_arp_table[k].mip_addr == mip_src || mip_arp_table[k].timestamp == 0){

                    //Check if the previous entry with the source MIP address
                    //has expired
                    if(now - mip_arp_table[k].timestamp > MIP_ARP_TTL){
                      mip_arp_table[k].mip_addr = mip_src;
                      memcpy(mip_arp_table[k].mac_addr,recv_bcast_frame->source,MAC_SIZE);
                      mip_arp_table[k].socket = bcast_events[j].data.fd;
                      mip_arp_table[k].timestamp = now;
                    }

                    break;
                  }
                }


                //Respond to the broadcast with a normal MIP-ARP response
                struct ethernet_frame arp_resp_frame = { 0 };
                uint8_t arp_resp_tra;
                char arp_resp_payload;

                arp_resp_tra = 0b000;
                arp_resp_payload = '\0';

                memcpy(arp_resp_frame.destination,recv_bcast_frame->source, MAC_SIZE);
                memcpy(arp_resp_frame.source,entry->mac_addr, MAC_SIZE);
                arp_resp_frame.protocol = eth_ptcl;

                //If the packet was an ARP broadcast, respond normally
                construct_mip_header(&arp_resp_frame.payload,mip_src,entry->mip_addr,arp_resp_tra,&arp_resp_payload,0);

                if(send(bcast_events[j].data.fd,&arp_resp_frame,sizeof(arp_resp_frame),0) == -1){
                  //ERROR_HANDLING
                  perror("main: ping broadcast: send: arp response");
                  exit(EXIT_FAILURE);
                }
              }
            }
            if(tra == 0b000) break;
          }

          //Do something if there was a timeout and the MIP-ARP table was not
          //updated
          if(timeout == 1){
            //TODO: handle timeout
            continue;
          }


          //MIP-ARP table was updated, add the destination to the ethernet frame
          for(j = 0; j < MAX_ARP_SIZE; j++){
            if(mip_arp_table[j].mip_addr == dest_mip_addr){
              memcpy(eth_frame->destination,mip_arp_table[j].mac_addr,MAC_SIZE);
            }
          }
        }

        struct mip_arp_entry *entry;
        //Find the source MIP and MAC address, and add the MAC to the ethernet frame
        for(j = 0; j < num_eth_sds; j++){
          if(local_mip_mac_table[j].socket == events[i].data.fd){
            memcpy(eth_frame->source,local_mip_mac_table[j].mac_addr, MAC_SIZE);
            entry = &local_mip_mac_table[j];
            break;
          }
        }

        src_mip_addr = entry->mip_addr;

        //Construct MIP header:
        construct_mip_header(&eth_frame->payload,dest_mip_addr,src_mip_addr,0b100,msg_buf,msg_len);

        if(send(events[i].data.fd,eth_frame, sizeof(struct ethernet_frame) + msg_len,0) == -1){
          //ERROR_HANDLING
          perror("main: send: un_sock_conn: ping message");
          exit(EXIT_FAILURE);
        }



        int ping_nfds;
        int pong = 0; /* check if received PONG response */
        struct epoll_event ping_events[MAX_EVENTS];
        struct ethernet_frame *ping_recv_frame = { 0 };
        char buf[MAX_ETH_FRAME_SIZE];
        timeout = 0;

        //Wait for PONG response
        for(;;){
          //If received a pong response the previous iteration, break
          if(pong == 1) break;

          ping_nfds = epoll_wait(epfd,ping_events,MAX_EVENTS,PING_TIMEOUT);

          if(ping_nfds == -1){
            //ERROR_HANDLING
            perror("main: epoll_wait: un_sock_conn: PONG response");
            exit(EXIT_FAILURE);
          } else if(ping_nfds == 0){
            //TODO: timeout
            timeout=1;
            break;
          }

          for(j = 0; j < ping_nfds; j++){
            ret = recv(ping_events[j].data.fd,buf,MAX_ETH_FRAME_SIZE,0);
            if(ret == -1){
              //ERROR_HANDLING
              perror("main: recv: un_sock_conn: PONG response");
              exit(EXIT_FAILURE);
            }
            ping_recv_frame = (struct ethernet_frame*) buf;

            struct mip_arp_entry *local_arp_entry;

            //Get this interface's MIP address:
            for(k = 0; k < num_eth_sds; k++){
              if(local_mip_mac_table[k].socket == ping_events[j].data.fd){
                local_arp_entry = &local_mip_mac_table[k];
              }
            }

            //Was frame for this daemon?
            uint8_t dest_mip = get_mip_dest(&ping_recv_frame->payload);
            uint8_t src_mip = get_mip_src(&ping_recv_frame->payload);
            uint8_t tra = get_mip_tra(&ping_recv_frame->payload);
            time_t now = time(NULL);


            if(dest_mip != local_arp_entry->mip_addr){
              //Not for this daemon, discard packet
              continue;
            }

            if(tra == 0b100){
              //Frame was a Transport message

              if(strcmp(ping_recv_frame->payload.payload,"PONG") != 0){
                //Packet was not the PONG response that was expected,
                //update the MIP-ARP table and discard the packet
                for(k = 0; k < MAX_ARP_SIZE; k++){
                  if(mip_arp_table[k].mip_addr == src_mip || mip_arp_table[k].timestamp == 0){
                    if(now - mip_arp_table[k].timestamp > MIP_ARP_TTL){
                      mip_arp_table[k].mip_addr = src_mip;
                      memcpy(mip_arp_table[k].mac_addr,ping_recv_frame->source,MAC_SIZE);
                      mip_arp_table[k].socket = ping_events[j].data.fd;
                      mip_arp_table[k].timestamp = now;
                    }
                    break;
                  }
                }
                continue;
              }


              char msg_buf[IPC_PONG_RSP_SIZE] = { 0 }; /* to hold the PONG response */

              struct msghdr msg = { 0 };
              struct iovec iov[1];

              iov[1].iov_base = msg_buf;
              iov[1].iov_len = sizeof(msg_buf);

              msg.msg_iov = iov;
              msg.msg_iovlen = sizeof(iov);

              if(sendmsg(un_sock_conn,&msg,0) == -1){
                //ERROR_HANDLING
                perror("main: sendmsg: un_sock_conn: PONG response");
                exit(EXIT_FAILURE);
              }

              pong = 1;

              break;
            }
            //If the packet was an ARP broadcast message, not the APR response
            //that was expected
            else if(tra == 0b001){
              //Respond to the broadcast normally anyway, and update the
              //MIP-ARP table if necessary

              //Update MIP-ARP table:
              for(k = 0; k < MAX_ARP_SIZE; k++){

                //If the mip address exists as an entry or an empty entry
                //was reached
                if(mip_arp_table[k].mip_addr == src_mip || mip_arp_table[k].timestamp == 0){

                  //Check if the previous entry with the source MIP address
                  //has expired
                  if(now - mip_arp_table[k].timestamp > MIP_ARP_TTL){
                    mip_arp_table[k].mip_addr = src_mip;
                    memcpy(mip_arp_table[k].mac_addr,ping_recv_frame->source,MAC_SIZE);
                    mip_arp_table[k].socket = ping_events[j].data.fd;
                    mip_arp_table[k].timestamp = now;
                  }

                  break;
                }
              }


              //Respond to the broadcast with a normal MIP-ARP response
              struct ethernet_frame arp_resp_frame = { 0 };
              uint8_t arp_resp_tra;
              char arp_resp_payload;

              arp_resp_tra = 0b000;
              arp_resp_payload = '\0';

              memcpy(arp_resp_frame.destination,ping_recv_frame->source, MAC_SIZE);
              memcpy(arp_resp_frame.source,local_arp_entry->mac_addr, MAC_SIZE);
              arp_resp_frame.protocol = eth_ptcl;

              //If the packet was an ARP broadcast, respond normally
              construct_mip_header(&arp_resp_frame.payload,src_mip,local_arp_entry->mip_addr,arp_resp_tra,&arp_resp_payload,0);

              if(send(ping_events[j].data.fd,&arp_resp_frame,sizeof(arp_resp_frame),0) == -1){
                //ERROR_HANDLING
                perror("main: send: un_sock_conn: PONG response");
                exit(EXIT_FAILURE);
              }
            }
          }
        }

        //Delete the unix socket communicating with the daemon from the epoll instance
        if(epoll_ctl(epfd,EPOLL_CTL_DEL,events[i].data.fd,NULL) == -1){
          //ERROR_HANDLING
          perror("main: epoll_ctl: EPOLL_CTL_DEL un_sock_conn ping");
          exit(EXIT_FAILURE);
        }

        //Close the socket
        close(un_sock_conn);

        //Rearm the unix socket listening for connections
        if(epoll_ctl(epfd,EPOLL_CTL_MOD,un_sock,&ep_un_ev) == -1){
          //ERROR_HANDLING
          perror("main: epoll_ctl: EPOLL_CTL_MOD un_sock ping");
        }

        //Discard remaining events and listen for new connections
        break;
      }
      //Incoming data on ethernet sockets
      else{
        struct mip_arp_entry *local_entry;
        char buf[MAX_ETH_FRAME_SIZE];
        struct ethernet_frame *eth_recv_frame;
        uint8_t mip_tra;
        uint8_t src_mip;
        uint8_t dest_mip;

        for(j = 0; j < num_eth_sds; j++){
          if(local_mip_mac_table[j].socket == events[i].data.fd){
            local_entry = &local_mip_mac_table[j];
          }
        }

        if(recv(events[i].data.fd,buf,MAX_ETH_FRAME_SIZE,0) == -1){
          //ERROR_HANDLING
          perror("main: recv: eth socket");
          exit(EXIT_FAILURE);
        }
        eth_recv_frame = (struct ethernet_frame *) buf;

        mip_tra = get_mip_tra(&eth_recv_frame->payload);
        src_mip = get_mip_src(&eth_recv_frame->payload);
        dest_mip = get_mip_dest(&eth_recv_frame->payload);

        //Check that the destination is right
        if(local_entry->mip_addr != dest_mip){
          //Packet was not intended for this MIP daemon:
          //Discard the packet
          continue;
        }

        if(mip_tra == 0b100){
          struct msghdr msg = { 0 };
          struct iovec iov[1];
          iov[0].iov_base = eth_recv_frame->payload.payload;
          iov[0].iov_len = sizeof(eth_recv_frame->payload.payload);

          msg.msg_iov = iov;
          msg.msg_iovlen = 1;

          if(sendmsg(un_sock_conn,&msg,0) == -1){
            //ERROR_HANDLING
            perror("main: sendmsg: un_sock_conn receive ping");
            exit(EXIT_FAILURE);
          }

          


        }

      }
    }
  }


}
