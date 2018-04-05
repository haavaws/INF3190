#include <string.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <stdlib.h>
#include "mip_daemon.h"


void free_queues(struct packet_queues queue_container){
  struct packet_queue *packet = *queue_container.first_packet;
  while(packet != NULL){
    struct packet_queue *tmp = packet->next_packet;
    free(packet->buf);
    free(packet);
    packet = tmp;
  }
  packet = *queue_container.first_broadcast_packet;
  while(packet != NULL){
    struct packet_queue *tmp = packet->next_packet;
    free(packet->buf);
    free(packet);
    packet = tmp;
  }
}




int mac_eql(uint8_t *mac1, uint8_t *mac2){
  int i;
  for(i = 0; i < MAC_SIZE; i++){
    if(mac1[i] != mac2[i]){
      return 0;
    }
  }
  return 1;
}

int is_broadcast_mac(uint8_t *mac){
  int i;
  for(i = 0; i < MAC_SIZE; i++){
    if(mac[i] != 255){
      return 0;
    }
  }
  return 1;
}


uint16_t get_mip_payload_len(struct mip_frame *frame){
  uint16_t payload_len = 0;
  payload_len |= (frame->header_bytes[2] & 0b00011111) << 4;
  payload_len |= frame->header_bytes[3] >> 4;
  return payload_len;
}

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

uint8_t get_mip_ttl(struct mip_frame *frame){
  return frame->header_bytes[3] | 0b1111;
}

void set_mip_ttl(struct mip_frame *frame, uint8_t ttl){
  frame->header_bytes[3] &= 0b11110000;
  frame->header_bytes[3] |= ttl;
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

      if(debug){
        fprintf(stdout, "MIP was already in cache.\n");
      }
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
    uint8_t source, uint8_t tra, void* payload, int payload_len){

  /* Construct the MIP header by bitshifting the variables into their
  * appropriate positions */
  frame->header_bytes[0] |= tra << 5;
  frame->header_bytes[0] |= destination >> 3;
  frame->header_bytes[1] |= destination << 5;
  frame->header_bytes[1] |= source >> 3;
  frame->header_bytes[2] |= source << 5;
  frame->header_bytes[2] |= (payload_len/4) >> 4;
  frame->header_bytes[3] |= (payload_len/4) << 4;
  frame->header_bytes[3] |= 0b1111;
  /* Copy the message into the payload of the packet */
  memcpy(frame->payload, payload, payload_len);
}



/**
 * Constructs a MIP packet using the provided arguments and sends it to the MIP
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
 *                            if the destination MIP address didn't have an
 *                            entry in the provided MIP-ARP table
 *
 * Global variables: MAX_MSG_SIZE
 *                   MAC_SIZE
 *                   ETH_P_MIP
 */
ssize_t send_mip_packet(struct mip_arp_entry *arp_table,
    struct mip_arp_entry *local_mip_mac_table, uint8_t dest_mip,
    uint8_t next_hop, void* payload, int payload_len, uint8_t tra, int send_sd,
    int debug){

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
  else if (tra == 0b100 || tra == 0b010) {
    /* Message length plus padding */
    msg_len = payload_len;
    if(msg_len % 4 != 0) msg_len += 4 - (msg_len % 4);
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
    if(dest_mip == 255){
      memcpy(dest_mac, "\xff\xff\xff\xff\xff\xff", MAC_SIZE);
    }else {
      for(i = 0; i < MAX_ARP_SIZE; i++){
        if(arp_table[i].mip_addr == next_hop){
          memcpy(dest_mac, arp_table[i].mac_addr, MAC_SIZE);
          send_sd = arp_table[i].socket;
          break;
        }
        else if (i == MAX_ARP_SIZE-1){
          return -3;
        }
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
  frame = (struct ethernet_frame *) calloc (sizeof(struct ethernet_frame) +
    msg_len, 1);

  memcpy(frame->destination, dest_mac, MAC_SIZE);
  memcpy(frame->source, src_mac, MAC_SIZE);
  frame->protocol = eth_ptcl;

  construct_mip_packet(&frame->payload, dest_mip, src_mip, tra, payload,
      msg_len);

    if(debug){
      fprintf(stdout, "Payload length of sent data: %d\n", get_mip_payload_len(&frame->payload)*4);
    }

  if (debug){
    fprintf(stdout, "Destination MAC: "); print_mac(frame->destination);
    fprintf(stdout, "\tDestination MIP: %d\n", get_mip_dest(&frame->payload));
    fprintf(stdout, "Source Mac: "); print_mac(frame->source);
    fprintf(stdout, "\tSource MIP: %d\n", get_mip_src(&frame->payload));
  }

  ret = send(send_sd, frame, sizeof(struct ethernet_frame) + msg_len, 0);

  if(debug) fprintf(stdout,"Bytes sent: %ld\n\n",ret);

  free(frame);

  return ret;
} /* send_mip_packet() END */






int forward_mip_packet(struct mip_arp_entry *arp_table,
    struct mip_arp_entry *local_mip_mac_table, uint8_t next_hop,
    struct ethernet_frame *frame, int frame_size, int debug){

  uint8_t dest_mac[6];
  uint8_t src_mac[6];
  uint16_t eth_ptcl; /* Ethernet communication protocol */
  int i;
  int send_sd;
  ssize_t ret;

  for(i = 0; i < MAX_ARP_SIZE; i++){
    if(arp_table[i].mip_addr == next_hop){
      memcpy(dest_mac, arp_table[i].mac_addr, MAC_SIZE);
      send_sd = arp_table[i].socket;
      break;
    }
    else if (i == MAX_ARP_SIZE-1){
      return -3;
    }
  }

  /* Lookup the source MIP and MAC address using the socket found above */
  for(i = 0; i < MAX_ARP_SIZE; i++){
    if(local_mip_mac_table[i].socket == send_sd){
      memcpy(src_mac, local_mip_mac_table[i].mac_addr, MAC_SIZE);
    }
  }

  /* Use the local experimental protocol for ethernet communication */
  eth_ptcl = htons(ETH_P_MIP);

  memcpy(frame->destination, dest_mac, MAC_SIZE);
  memcpy(frame->source, src_mac, MAC_SIZE);
  frame->protocol = eth_ptcl;


  ret = send(send_sd, frame, frame_size, 0);

  return ret;

}/* forward_mip_packet() END */






/**
 * Receives a MIP packet on the socket provided, and copies its message to the
 * provided character buffer, and its source MIP address to the provided byte
 * buffer. In addition it updates the provided MIP-ARP table with the
 * information from the received packet, and responds if the received packet
 * was a MIP-ARP broadcast intended for the network interface that received the
 * packet.
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
 * @returns                   Returns the binary value of the TRA bits of the
 *                            received packet on success, -1 if recv() fails,
 *                            and -2 if the destination MIP address of the
 *                            received packet did not match the MIP address of
 *                            the network interface that received it
 *
 * Global variables: MAX_ETH_FRAME_SIZE
 *                   MAC_SIZE
 *                   MAX_ARP_SIZE
 */
int recv_mip_packet(struct mip_arp_entry *mip_arp_table, int socket,
    struct sockets sock_container, struct packet_queues queue_container,
    int debug, int *num_packet, int *num_bpacket){
  /* MIP-ARP data for the socket that received the frame */
  struct mip_arp_entry local_entry;
  void *eth_buf = malloc(MAX_ETH_FRAME_SIZE);
  struct ethernet_frame *recv_eth_frame;
  uint8_t src_mac[MAC_SIZE];
  uint8_t mip_tra;
  uint8_t src_mip;
  uint8_t dest_mip;
  uint8_t mip_ttl;
  void *mip_payload;
  int payload_len;
  ssize_t ret;
  int i;

  /* Lookup MIP-ARP data for the socket that received the frame */
  for(i = 0; i < MAX_ARP_SIZE; i++){
    if(sock_container.local_mip_mac_table[i].socket == socket){
      local_entry = sock_container.local_mip_mac_table[i];
      break;
    }
  }

  /* Receive the frame */
  ret = recv(socket, eth_buf, MAX_ETH_FRAME_SIZE, 0);

  if(ret == -1){
    free(eth_buf);
    return -1;
  }

  recv_eth_frame = (struct ethernet_frame *) eth_buf;

  memcpy(src_mac, recv_eth_frame->source, MAC_SIZE);
  mip_tra = get_mip_tra(&recv_eth_frame->payload);
  src_mip = get_mip_src(&recv_eth_frame->payload);
  dest_mip = get_mip_dest(&recv_eth_frame->payload);
  mip_ttl = get_mip_ttl(&recv_eth_frame->payload);
  mip_payload = recv_eth_frame->payload.payload;
  payload_len = get_mip_payload_len(&recv_eth_frame->payload) * 4;
  if(debug){
    fprintf(stdout, "Payload length of received packet: %d\n", payload_len);
  }

  if(debug){
    if(mip_tra == 0b100) fprintf(stdout,"Received transport packet.\n");
    else if(mip_tra == 0b001) fprintf(stdout,"Received MIP-ARP broadcast.\n");
    else if(mip_tra == 0b000) fprintf(stdout,"Received MIP-ARP response.\n");
    else if(mip_tra == 0b010) fprintf(stdout,"Received routing packet.\n");
    fprintf(stdout,"Destination MAC: ");print_mac(recv_eth_frame->destination);
    fprintf(stdout,"\tDestination MIP: %d\n",dest_mip);
    fprintf(stdout,"Source MAC: "); print_mac(recv_eth_frame->source);
    fprintf(stdout,"\tSource MIP: %d\n",src_mip);
    if(mip_tra == 0b100){
      fprintf(stdout,"Message: \"%s\"\n",recv_eth_frame->payload.payload);
    }
    fprintf(stdout,"Bytes received: %ld\n\n",ret);
  }

  if(debug){
    fprintf(stdout, "Checking if the packet was intended for this host.\n");
  }

  /* Verify that the packet was for this host, otherwise discard it */
  if(mac_eql(local_entry.mac_addr, recv_eth_frame->destination) != 1
      && is_broadcast_mac(recv_eth_frame->destination) != 1){
    /* The destination MAC address in the ethernet header did not match the
     * MAC address of the receiving interface */
     free(eth_buf);
     return -2;
  }

  if(debug){
    fprintf(stdout, "Packet was intended for this host.\n");
    fprintf(stdout, "Checking if the packet is to be forwarded.\n");
  }

  /* Check if the packet needs to be forwarded */
  if(local_entry.mip_addr != dest_mip && dest_mip != 255){

    /* If there is no connected router, discard the packet */
    if(*sock_container.un_fwd_conn == -1){
      free(eth_buf);
      return -3;
    }

    if(debug){
    fprintf(stdout, "Packet needs to be forwarded.\n");
    fprintf(stdout, "Requesting next hop for destination from router.\n");
    }

    /* If the packet's TTL will reach -1 on forwarding */
    if(mip_ttl == 0){
      /* Discard the packet */
      free(eth_buf);
      return -4;
    }

    set_mip_ttl(&recv_eth_frame->payload, mip_ttl - 1);

    /* Ask the routing daemon for the next hop */
    struct msghdr lookup_msg = { 0 };
    struct iovec lookup_iov[1];

    lookup_iov[0].iov_base = &dest_mip;
    lookup_iov[0].iov_len = sizeof(dest_mip);

    lookup_msg.msg_iov = lookup_iov;
    lookup_msg.msg_iovlen = 1;

    if(sendmsg(*sock_container.un_fwd_conn, &lookup_msg, 0) == -1){
      free(eth_buf);
      return -5;
    }

    if(debug){
      fprintf(stdout, "Adding packet to packet queue awaiting forwarding response from router.\n");
    }


    /* Store the packet in the packet queue and forward it when a response is
     * received from the routing daemon */
    struct packet_queue *packet = (struct packet_queue *)
        malloc(sizeof(struct packet_queue));

    if(debug){
      fprintf(stdout, "SEGFAULT 0\n");
    }

    packet->is_packet = 1;
    packet->buf = eth_buf;
    packet->src_mip = src_mip;
    packet->next_packet = NULL;
    packet->payload_len = ret;

    if(*queue_container.first_packet == NULL){
      *queue_container.first_packet = packet;
      *queue_container.last_packet = *queue_container.last_packet;
    }else{
      (*queue_container.last_packet)->next_packet = packet;
      *queue_container.last_packet =
          (*queue_container.last_packet)->next_packet;
    }

    (*num_packet)++;

    return 0;
  }

  if(debug){
    fprintf(stdout, "Packet doesn't need to be forwarded.\n");
    fprintf(stdout, "Checking the packet can be used to update the MIP-ARP cache.\n");
  }

  /* Packet was originated from a neighbour */
  if(mip_tra == 0b000 || mip_tra == 0b010 || mip_tra == 0b001){

    if(debug){
      fprintf(stdout, "It can, updating cache.\n");
    }

    /* Update the MIP-ARP cache with data from the received packet */
    update_mip_arp(mip_arp_table, src_mip, src_mac, socket, debug);

    if(debug){
      fprintf(stdout, "Cache updated.\n");
      fprintf(stdout, "Checking if any of the packets in the queue waiting for broadcasts now can be forwarded.\n");
    }


    /* Iterate over all packets waiting for a broadcast to see if the received
     * packet was from a neighbour that the waiting packets are to be forwarded
     * to, so that they now can be forwarded to that neighbour */
    struct packet_queue *packet = *queue_container.first_broadcast_packet;
    struct packet_queue *previous_packet = NULL;

    while(packet != NULL){
      /* If the packet can now be sent, send it and remove it from the queue */
      if(packet->next_hop == src_mip){

        if(debug){
          fprintf(stdout, "Packet with next hop %d can be forwarded.\n", src_mip);
          fprintf(stdout, "Forwarding.\n");
        }

        /* If the packet is an entire packet received from another node, to be
         * forwarded as is */
        if(packet->is_packet == 1){
          ret = forward_mip_packet(mip_arp_table,
              sock_container.local_mip_mac_table, packet->next_hop,
              (struct ethernet_frame *) packet->buf, packet->payload_len,
              debug);
        }

        /* If the packet is from a connected application or router, so that the
         * packet needs to be constructed before sending */
        else{
          ret = send_mip_packet(mip_arp_table,
              sock_container.local_mip_mac_table, packet->dest_mip,
              packet->next_hop, packet->buf, packet->payload_len, packet->tra,
              0, debug);
        }

        if(ret == -1){
          free(eth_buf);
          return -6;
        }

        if(debug){
          fprintf(stdout, "Sent %ld bytes to MIP address %d\n", ret, src_mip);
        }
        struct packet_queue *tmp = packet;

        /* If this is the first packet in the queue */
        if(previous_packet == NULL){
          /* Set the next packet to be the new first packet */
          *queue_container.first_broadcast_packet = packet->next_packet;
        }
        else{
          /* Link the previous packet and the next packet */
          previous_packet->next_packet = packet->next_packet;
        }

        /* If this was the last packet in the queue */
        if(packet->next_packet == NULL){
          /* Set the previous packet to be the new last packet */
          *queue_container.last_broadcast_packet = previous_packet;
        }

        /* Set the next packet to be the current packet */
        packet = packet->next_packet;

        /* Free the data of the sent packet */
        free(tmp->buf);
        free(tmp);

        (*num_bpacket)--;

        if(debug){
          fprintf(stdout, "Number of packets in queue: %d\n", *num_bpacket);
        }
      }
      /* Else, iterate */
      else{
        previous_packet = packet;
        packet = packet->next_packet;
      }
    }
  }


  /* Send the message to the connected application if the packet was a
   * transport packet */
  if(mip_tra == 0b100){
    /* Discard the packet if no application is connected to the MIP
     * daemon */
    if(*sock_container.un_sock_conn == -1){
      free(eth_buf);
      return -7;
    }

    if(debug){
      fprintf(stdout,"Sending transport packet to connected application.\n");
    }

    /* Unix communication based on code from group session
    * https://github.uio.no/persun/inf3190/tree/master/plenum3 */

    /* Forward the ping message to the connected server application */
    struct msghdr transport_msg = { 0 };
    struct iovec transport_iov[2];

    transport_iov[0].iov_base = &src_mip;
    transport_iov[0].iov_len = sizeof(src_mip);

    transport_iov[1].iov_base = mip_payload;
    transport_iov[1].iov_len = strlen((char *) mip_payload) + 1;

    transport_msg.msg_iov = transport_iov;
    transport_msg.msg_iovlen = 2;

    ret = sendmsg(*sock_container.un_sock_conn, &transport_msg, 0);

    if(ret == -1){
      free(eth_buf);
      return -8;
    }

    if(debug){
      fprintf(stdout,"Sent %ld bytes to connected application.\n",ret);
    }

    free(eth_buf);

  }
  /* Send the message to the connected routing daemon if the packet was a
   * routing packet */
  else if(mip_tra == 0b010){
    /* Discard the packet if no routing daemon is connected to the MIP
     * daemon */
    if(*sock_container.un_route_conn == -1){
      free(eth_buf);
      return -9;
    }

    /* Remove any padding */
    for(i = 0; i < payload_len; i++){
      if((uint8_t)((char *) mip_payload)[i] == 255){
        payload_len = i;
        break;
      }
    }

    if(debug){
      fprintf(stdout,"Sending routing packet to connected router.\n");
    }

    struct msghdr routing_msg = { 0 };
    struct iovec routing_iov[2];

    routing_iov[0].iov_base = &src_mip;
    routing_iov[0].iov_len = sizeof(src_mip);

    routing_iov[1].iov_base = mip_payload;
    routing_iov[1].iov_len = payload_len;

    routing_msg.msg_iov = routing_iov;
    routing_msg.msg_iovlen = 2;

    ret = sendmsg(*sock_container.un_route_conn, &routing_msg, 0);

    if(ret == -1){
      return -10;
    }

    if(debug){
      fprintf(stdout,"Sent %ld bytes to connected router.\n", ret);
    }

    free(eth_buf);
  }
  /* Respond if the packet was a MIP-ARP broadcast */
  else if(mip_tra == 0b001){

    if(debug){
      fprintf(stdout,"Responding to MIP-ARP broadcast.\n");
    }
    if(send_mip_packet(mip_arp_table, sock_container.local_mip_mac_table,
      src_mip, src_mip, NULL, 0, 0b000, 0, debug) == -1){
        free(eth_buf);
        return -11;
      }

    if(debug){
      fprintf(stdout,"Sent %ld bytes to MIP address %d\n", ret, src_mip);
    }
    free(eth_buf);
  }

  return mip_tra;
} /* recv_mip_packet END */


/* TODO: FIX THIS */
/**
 * Sends a MIP broadcast packet on all local network interfaces whose socket
 * descriptors are in the provided local MIP-ARP table, waits for response and
 * updates the provided MIP-ARP table with information from all packets
 * received while waiting for the MIP-ARP response.
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
int send_mip_broadcast(struct mip_arp_entry *mip_arp_table,
    int num_eth_sds, struct mip_arp_entry *local_mip_mac_table,
    uint8_t dest_mip, int debug){

  int i;
  // int nfds_bcast;
  // struct epoll_event bcast_events[MAX_EVENTS];
  // uint8_t tra;

  if(debug){
    fprintf(stdout,"Sending MIP ARP broadcast on all interfaces.\n\n");
  }

  /* TODO: CHECK THIS */
  /* Send a broadcast message for dest_mip on every ethernet socket */
  for(i = 0; i < num_eth_sds; i++){
    if(send_mip_packet(mip_arp_table, local_mip_mac_table, dest_mip, dest_mip,
        NULL, 0, 0b001, local_mip_mac_table[i].socket, debug) == -1){
      return -1;
    }
  }

  return 0;
} /* send_mip_broadcast() END */
