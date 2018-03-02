#include <string.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <stdlib.h>
#include "mip_daemon.h"

/**
 * Extracts TRA value from the provided MIP packet
 *
 * @param frame MIP packet to extract TRA from
 * @return      Returns the TRA value in frame
 */
uint8_t get_mip_tra(struct mip_frame *frame){
  return frame->header_bytes[0] >> 5;
}

/**
 * Extracts the destination MIP address from the provided MIP packet
 *
 * @param frame MIP packet to extract destination MIP address from
 * @return      Returns the destination MIP address in frame
 */
uint8_t get_mip_dest(struct mip_frame *frame){
  uint8_t destination = 0;
  destination |= frame->header_bytes[0] << 3;
  destination |= frame->header_bytes[1] >> 5;
  return destination;
}

/**
 * Extracts the source MIP address from the provided MIP packet
 *
 * @param frame MIP packet to extract source MIP address from
 * @return      Returns the source MIP address in frame
 */
uint8_t get_mip_src(struct mip_frame *frame){
  uint8_t source = 0;
  source |= frame->header_bytes[1] << 3;
  source |= frame->header_bytes[2] >> 5;
  return source;
}

/**
 * Updates the MIP-ARP table provided with an entry for the provided MIP
 * adress, MAC address, and socket
 *
 * @param arp_table MIP-ARP table to update
 * @param mip       MIP address to add entry for in arp_table
 * @param mac       MAC address to add entry for in arp_table
 * @param socket    Socket descriptor of network interface connected to the
 *                  host with the provided MIP and MAC address
 * @param debug     Indicates if debug messages should be logged to console
 * @return          Returns the index at which the entry for the provided MIP
 *                  and MAC address is stored in the MIP-ARP table, or -1 if
 *                  the entry could not be added to the MIP-ARP table because
 *                  it was full
 *
 * Global variables: MAX_ARP_SIZE
 *                   MIP_ARP_TTL
 *                   MAC_SIZE
 */
int update_mip_arp (struct mip_arp_entry *arp_table, uint8_t mip,
    uint8_t *mac, int socket, int debug){

  struct mip_arp_entry *first_free_entry = NULL; /* in arp_table */
  time_t now = time(NULL); /* timestamp */
  int ret = -1; /* index of first_free_entry in arp_table */

  /* Check for MIP addres mip in arp_table, and remove expired entries,
  * and store the first available entry in first_free_entry */
  for(int i = 0; i < MAX_ARP_SIZE; i++){
    if(now - arp_table[i].timestamp > MIP_ARP_TTL){
      /* An entry has expired (time since storage greater than MIP_ARP_TTL) */
      if(arp_table[i].timestamp == 0){
        memset(&arp_table[i],0,sizeof(struct mip_arp_entry));
      }

      if(!first_free_entry){
        first_free_entry = &arp_table[i];
        ret = i;
      }
    }
    /* If the MIP address has an unexpired entry in arp_table */
    else if(arp_table[i].mip_addr == mip){
      return i;
    }
  }

  /* If no entry was found for the MIP address, and an available entry to store
  * it was found */
  if(first_free_entry){
    memcpy(first_free_entry->mac_addr,mac,MAC_SIZE);
    first_free_entry->mip_addr = mip;
    first_free_entry->socket = socket;
    first_free_entry->timestamp = now;
    if(debug){
      fprintf(stdout,"Entry added to MIP-ARP cache table:\n");
      fprintf(stdout,"MAC: "); print_mac(mac);
      fprintf(stdout,"\tMIP: %d\t\n\n",mip);
    }
  }

  return ret;
} /* update_mip_arp() END */

/**
 * Constructs a MIP packet by bit shifiting the variables provided as arguments
 * into the header of the MIP packet provided, and copying the provided message
 * into the payload of the provided MIP packet
 *
 * @param frame MIP packet in which to store the variables and message
 * @param destination Destination MIP address of frame
 * @param source      Source MIP address of frame
 * @param tra         TRA bits of the frame
 * @param payload     Message of the frame
 * @param payload_len Length of payload
 * @return            none
 */
void construct_mip_packet(struct mip_frame* frame, uint8_t destination,
    uint8_t source, uint8_t tra, char* payload, int payload_len){
  int msg_len;
  if (payload) msg_len = strlen(payload);
  else msg_len = payload_len;
  /* Pads the end of the MIP packet payload with 0-bytes */
  memset(frame,0,sizeof(struct mip_frame)+payload_len);

  /* Construct the MIP header by bitshifting the variables into their
  * appropriate positions */
  frame->header_bytes[0] |= tra << 5;
  frame->header_bytes[0] |= destination >> 3;
  frame->header_bytes[1] |= destination << 5;
  frame->header_bytes[1] |= source >> 3;
  frame->header_bytes[2] |= source << 5;
  frame->header_bytes[2] |= (payload_len/4) >> 4;
  frame->header_bytes[3] |= (payload_len/4) << 5;
  frame->header_bytes[3] |= 0b1111;
  /* Copy the message into the payload of the packet */
  memcpy(frame->payload,payload,msg_len);
}

/**
 * Construct a MIP packet using the provided arguments and send it to the MIP
 * address provided as destination
 *
 * @param arp_table           MIP-ARP table in which to lookup MIP addresses
 * @param local_mip_mac_table MIP-ARP table for local network interfaces
 * @param dest_mip            The destination MIP address of the packet
 * @param payload             The message to be sent with the packet
 * @param tra                 The TRA bits of the packet
 * @param send_sd             The socket of the network local interface to send
 *                            the packet on
 * @param debug               Indicates if debug messages should be logged to
 *                            the console
 * @return                    Returns amount of bytes sent on success, and -1
 *                            if send() fails, -2 if message was large, and -3
 *                            if MIP address didn't have an entry in arp_table
 *
 * Global variables: MAX_MSG_SIZE
 *                   MAC_SIZE
 *                   ETH_P_MIP
 */
ssize_t send_mip_packet(struct mip_arp_entry *arp_table,
    struct mip_arp_entry *local_mip_mac_table, uint8_t dest_mip, char* payload,
    uint8_t tra, int send_sd, int debug){

  struct ethernet_frame *frame;
  uint8_t dest_mac[6];
  uint8_t src_mac[6];
  uint8_t src_mip;
  uint16_t eth_ptcl; /* Ethernet communication protocol */
  int i;
  int msg_len;
  ssize_t ret;


  /* MIP-ARP broadcast and broadcast responses have no payload */
  if(tra == 0b000 || tra == 0b001) msg_len = 0;
  else{
    /* Message length plus padding */
    msg_len = strlen(payload)+1;
    msg_len += msg_len % 4;
  }

  /* If the message is to large */
  if(msg_len > MAX_MSG_SIZE) return -2;

  /* If the packet is a MIP-ARP broadcast packet, set the MAC destination to
  * the MAC broadcast address, otherwise look up the MAC address and the socket
  * to send the packet on using the destination MIP address in the MIP-ARP
  * table */
  if(tra == 0b001){
    memcpy(dest_mac, "\xff\xff\xff\xff\xff\xff", MAC_SIZE);
  }else{
    for(i = 0; i < MAX_ARP_SIZE; i++){
      if(arp_table[i].mip_addr == dest_mip){
        memcpy(dest_mac, arp_table[i].mac_addr, MAC_SIZE);
        send_sd = arp_table[i].socket;
        break;
      }
      else if (i == MAX_ARP_SIZE-1){
        return -3;
      }
    }
  }

  /* Lookup the source MIP and MAC address using the socket found above */
  for(i = 0; i < MAX_ARP_SIZE; i++){
      if(local_mip_mac_table[i].socket == send_sd){
        memcpy(src_mac, local_mip_mac_table[i].mac_addr, MAC_SIZE);
        src_mip = local_mip_mac_table[i].mip_addr;
      }
  }

  /* Use the local experimental protocol for ethernet communication */
  eth_ptcl = htons(ETH_P_MIP);

  /* Construct the ethernet frame and MIP packet and send it */
  frame = (struct ethernet_frame *) malloc (sizeof(struct ethernet_frame) +
    msg_len);

  memcpy(frame->destination, dest_mac, MAC_SIZE);
  memcpy(frame->source, src_mac, MAC_SIZE);
  frame->protocol = eth_ptcl;

  construct_mip_packet(&frame->payload,dest_mip,src_mip,tra,payload,msg_len);

  if (debug){
    fprintf(stdout,"Destination MAC: "); print_mac(frame->destination);
    fprintf(stdout,"\tDestination MIP: %d\n", get_mip_dest(&frame->payload));
    fprintf(stdout,"Source Mac: "); print_mac(frame->source);
    fprintf(stdout,"\tSource MIP: %d\n", get_mip_src(&frame->payload));
  }

  ret = send(send_sd,frame,sizeof(struct ethernet_frame) + msg_len,0);

  if(debug) fprintf(stdout,"Bytes sent: %ld\n\n",ret);

  free(frame);

  return ret;
} /* send_mip_packet() END */

/**
 * Receives a MIP packet on the socket provided, and copies its message to the
 * provided character buffer, and its source MIP address to the provided byte
 * buffer
 *
 * @param mip_arp_table       MIP-ARP table to update with the source MIP
 *                            address of the received MIP packet if necessary
 * @param local_mip_mac_table MIP-ARP table of the local network interfaces to
 *                            check if the packet was intended for this host
 * @param socket              Socket to receive the MIP packet on
 * @param src_mip_buf         Byte buffer in which to store the source MIP
 *                            address of the received packet
 * @param buf                 Character buffer in which to store the message of
 *                            the received packet
 * @param debug               Indicates if debug messages should be logged to
 *                            console
 *
 * Global variables: MAX_ETH_FRAME_SIZE
 *                   MAC_SIZE
 *                   MAX_ARP_SIZE
 */
int recv_mip_packet(struct mip_arp_entry *mip_arp_table,
    struct mip_arp_entry *local_mip_mac_table, int socket,
    uint8_t *src_mip_buf, char *buf, int debug){
  /* MIP-ARP data for the socket that received the frame */
  struct mip_arp_entry *local_entry;
  char eth_buf[MAX_ETH_FRAME_SIZE];
  struct ethernet_frame *recv_eth_frame;
  uint8_t src_mac[MAC_SIZE];
  uint8_t mip_tra;
  uint8_t src_mip;
  uint8_t dest_mip;
  ssize_t ret;
  int i;

  /* Lookup MIP-ARP data for the socket that received the frame */
  for(i = 0; i < MAX_ARP_SIZE; i++){
    if(local_mip_mac_table[i].socket == socket){
      local_entry = &local_mip_mac_table[i];
    }
  }

  /* Receive the frame */
  ret = recv(socket, eth_buf, MAX_ETH_FRAME_SIZE, 0);

  if(ret == -1){
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
    fprintf(stdout,"Destination MAC: ");print_mac(recv_eth_frame->destination);
    fprintf(stdout,"\tDestination MIP: %d\n",dest_mip);
    fprintf(stdout,"Source MAC: "); print_mac(recv_eth_frame->source);
    fprintf(stdout,"\tSource MIP: %d\n",src_mip);
    if(mip_tra == 0b100){
      fprintf(stdout,"Message: \"%s\"\n",recv_eth_frame->payload.payload);
    }
    fprintf(stdout,"Bytes received: %ld\n\n",ret);
  }

  /* Verify that the packet was for this host, otherwise discard it */
  if(local_entry->mip_addr != dest_mip){
    if(debug){
      fprintf(stdout,"Destination and host MIP do not match.\n");
    }

    return -2;
  }

  update_mip_arp(mip_arp_table, src_mip, src_mac, socket, debug);

  /* Store the message in buf and the source MIP address in src_mip_buf */
  if(buf) memcpy(buf, recv_eth_frame->payload.payload,
    strlen(recv_eth_frame->payload.payload) + 1);
  if (src_mip_buf) *src_mip_buf = src_mip;

  /* Respond if the packet was a MIP-ARP broadcast */
  if (mip_tra == 0b001){
    ret = send_mip_packet(mip_arp_table, local_mip_mac_table, src_mip, NULL,
      0b000, 0, debug);
  }

  return mip_tra;
} /* recv_mip_packet END */

/**
 * Sends a MIP broadcast packet on all local network interfaces whose socket
 * descriptors are in the provided local MIP-ARP table, and waits for response
 *
 * @param epoll_fd            Descriptor for the epoll instance which handles
 *                            events for the sockets to broadcast on
 * @param mip_arp_table       MIP-ARP table to be updated as a result of the
 *                            MIP-ARP broadcast
 * @param num_eth_sds         Number of sockets stored in the local MIP-ARP
 *                            table
 * @param local_mip_mac_table MIP-ARP table storing MIP-ARp entries for local
 *                            network interfaces
 * @param dest_mip            MIP address to be located by the broadcast
 * @param debug               Indicates of debug messages should be logged to
 *                            console
 * @return                    Returns 0 on success, -1 if send() fails in
 *                            send_mip_packet(), -2 if there is a timeout while
 *                            waiting for a MIP-ARP broadcast response
 *
 * Global variables: MAX_EVENTS
 *                   PING_TIMEOUT
 */
int send_mip_broadcast(int epoll_fd, struct mip_arp_entry *mip_arp_table,
    int num_eth_sds, struct mip_arp_entry *local_mip_mac_table,
    uint8_t dest_mip, int debug){

  int i;
  int nfds_bcast;
  struct epoll_event bcast_events[MAX_EVENTS];
  uint8_t tra;

  if(debug){
    fprintf(stdout,"Sending MIP ARP broadcast on all interfaces.\n\n");
  }

  /* Send a broadcast message for dest_mip on every ethernet socket */
  for(i = 0; i < num_eth_sds; i++){
    if(send_mip_packet(mip_arp_table, local_mip_mac_table, dest_mip, NULL,
        0b001, local_mip_mac_table[i].socket, debug) == -1){
      return -1;
    }
  }

  /* Wait for respose from broadcast, or until timeout, specified by
  * PING_TIMEOUT */
  for(;;){
    nfds_bcast = epoll_wait(epoll_fd,bcast_events,MAX_EVENTS,PING_TIMEOUT);

    if(nfds_bcast == -1){
      perror("main: epoll_wait: un_sock_conn: arp response");
      return -1;
    }
    /* Timeout */
    else if(nfds_bcast==0) {
      if(debug){
        fprintf(stdout,"Timeout.\n");
      }
      return -2;
    }

    /* Discard all packets, but update the MIP-ARP table */
    for (i = 0;i<nfds_bcast;i++){
      tra = recv_mip_packet(mip_arp_table, local_mip_mac_table,
        bcast_events[i].data.fd, NULL, NULL, debug);
    }

    /* Stop waiting if the MIP-ARP response was received */
    if(tra == 0b000) break;

  }

  return 0;
} /* send_mip_broadcast() END */
