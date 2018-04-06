#include <string.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/signalfd.h>
#include <signal.h>
#include "mip_daemon.h"



/**
 * Frees the data in the queues in the queue container provided.
 *
 * @param queue_container Queue container whose queues are to be freed
 * @return                None
 */
void free_queues(struct packet_queues queue_container){
  /* Iterate through both queues contained in the container and free them */
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



/**
 * Checks if the provided mac addresses are equal to each other
 *
 * @param mac1  The first MAC address to check
 * @param mac2  The second MAC address to check
 * @returns     Returns 1 on equal, 0 on not equal
 */
int mac_eql(uint8_t *mac1, uint8_t *mac2){
  int i;
  for(i = 0; i < MAC_SIZE; i++){
    if(mac1[i] != mac2[i]){
      return 0;
    }
  }
  return 1;
}



/**
 * Checks if the provided mac is the broadcast MAC address
 *
 * @param frame MAC to check
 * @return      1 on true, 0 on false
 */
int is_broadcast_mac(uint8_t *mac){
  int i;
  for(i = 0; i < MAC_SIZE; i++){
    if(mac[i] != 255){
      return 0;
    }
  }
  return 1;
}



/**
 * Extracts the payload length of the provided MIP packet
 *
 * @param frame MIP packet to extract the payload length from
 * @return      Returns the payload length of the packet
 */
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



/**
 * Extracts the TTL from the provided MIP packet
 *
 * @param frame MIP packet to extract TTL from
 * @return      Returns the TTL in the packet
 */
uint8_t get_mip_ttl(struct mip_frame *frame){
  return frame->header_bytes[3] | 0b1111;
}



/**
 * Sets the TTL of a MIP packet
 *
 * @param frame MIP packet to change the TTL of
 * @param ttl   The TTL to set the TTL of the frame to
 * @return      None
 */
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





/**
 * Takes a complete MIP packet, changes the ethernet header to match the next
 * hop address, and sends it to the next hop address.
 *
 * @param arp_table           MIP-ARP cache, used for looking up where to send
 *                            the packet based on the next hop address.
 * @param local_mip_mac_table Data structure containing local MIP addresses and
 *                            their network interfaces. Used for looking up
 *                            where to send the packet based on the next hop
 *                            address.
 * @param next_hop            Next hop MIP address to send the packet to.
 * @param frame               The MIP packet to send to the next hop address.
 * @param frame_size          Size of the MIP packet, used for determining how
 *                            many bytes to send to the next hop address.
 * @param debug               Variable to determine whether or not debug
 *                            messages should be written to the terminal.
 * @returns                   Returns the amount of bytes sent on success, -3
 *                            if the next hop address couldn't be found in the
 *                            MIP-ARP cache, and -1 on error.
 */
int send_complete_packet(struct mip_arp_entry *arp_table,
    struct mip_arp_entry *local_mip_mac_table, uint8_t next_hop,
    struct ethernet_frame *frame, int frame_size, int debug){

  uint8_t dest_mac[6];
  uint8_t src_mac[6];
  uint16_t eth_ptcl; /* Ethernet communication protocol */
  int i;
  int send_sd;
  ssize_t ret;

  /* Look up which MAC address to set as destination in the ethernet header,
   * and which network interface to send the packet on. */
  for(i = 0; i < MAX_ARP_SIZE; i++){
    if(arp_table[i].mip_addr == next_hop){
      memcpy(dest_mac, arp_table[i].mac_addr, MAC_SIZE);
      send_sd = arp_table[i].socket;
      break;
    }
    /* Didn't find the next hop address in the MIP-ARP cache */
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

  /* Change the ethernet header to match the source and destination MAC
   * addresses. */
  memcpy(frame->destination, dest_mac, MAC_SIZE);
  memcpy(frame->source, src_mac, MAC_SIZE);
  frame->protocol = eth_ptcl;

  /* Send the packet */
  ret = send(send_sd, frame, frame_size, 0);

  return ret;

}/* send_complete_packet() END */



/**
 * Sends a MIP broadcast packet on all local network interfaces whose socket
 * descriptors are in the provided local MIP-ARP table.
 *
 * @param mip_arp_table       MIP-ARP table to be updated as a result of the
 *                            MIP-ARP broadcast
 * @param num_eth_sds         Number of sockets stored in the local MIP-ARP
 *                            table
 * @param local_mip_mac_table MIP-ARP table storing MIP-ARP entries for local
 *                            network interfaces
 * @param dest_mip            MIP address to be located by the broadcast
 * @param debug               Indicates of debug messages should be logged to
 *                            console
 * @return                    Returns 0 on success, -1 on error
 */
int send_mip_broadcast(struct mip_arp_entry *mip_arp_table,
    int num_eth_sds, struct mip_arp_entry *local_mip_mac_table,
    uint8_t dest_mip, int debug){

  int i;

  if(debug){
    fprintf(stdout,"Sending MIP ARP broadcast on all interfaces.\n\n");
  }


  /* Send a broadcast message for dest_mip on every ethernet socket */
  for(i = 0; i < num_eth_sds; i++){
    if(send_mip_packet(mip_arp_table, local_mip_mac_table, dest_mip, dest_mip,
        NULL, 0, 0b001, local_mip_mac_table[i].socket, debug) == -1){
      return -1;
    }
  }

  return 0;
} /* send_mip_broadcast() END */






/**
 * Receives a MIP packet on the network interface specified in the socket
 * parameter. It updates the MIP-ARP cache if the packet's source is a routing,
 * broadcast or broadcast response packet. The packet is queued for forwarding
 * if its destination was not the interface on which it was received, unless
 * its TTL reached -1, in which case the packet is discarded. If its
 * destination is the same as the interface on which it was received, the
 * payload of the packet is sent to a connected application if the packet was a
 * transport packet and there exists a connected application, and to a
 * connected router if the packet was a routing packet and there exists a
 * connected router. The packet is discarded if the application or router is
 * not connected. If the packet was a MIP-ARP broadcast, a MIP-ARP response is
 * sent to the source MIP address.
 *
 * @param mip_arp_table       MIP-ARP table to update with the source MIP
 *                            address of the received MIP packet if necessary
 * @param socket              Socket to receive the MIP packet on
 * @param sock_container      Contains all sockets, to be able to send data to
 *                            connected application and router depending on the
 *                            received packet, and to respond to MIP-ARP
 *                            broadcasts.
 * @param queue_container     Contains the packet queues, to allow new received
 *                            packets to be added to the packet queues if
 *                            necessary.
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
    int debug){
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

  /* Read data from the MIP packet */
  recv_eth_frame = (struct ethernet_frame *) eth_buf;

  memcpy(src_mac, recv_eth_frame->source, MAC_SIZE);
  mip_tra = get_mip_tra(&recv_eth_frame->payload);
  src_mip = get_mip_src(&recv_eth_frame->payload);
  dest_mip = get_mip_dest(&recv_eth_frame->payload);
  mip_ttl = get_mip_ttl(&recv_eth_frame->payload);
  mip_payload = recv_eth_frame->payload.payload;
  payload_len = get_mip_payload_len(&recv_eth_frame->payload) * 4;

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

  /* Verify that the packet was for this host, otherwise discard it */
  if(mac_eql(local_entry.mac_addr, recv_eth_frame->destination) != 1
      && is_broadcast_mac(recv_eth_frame->destination) != 1){
    /* The destination MAC address in the ethernet header did not match the
     * MAC address of the receiving interface */
     if(debug){
       fprintf(stdout, "Received packet was not intended for this host. "
          "Discarding it.\n");
     }
     free(eth_buf);
     return -2;
  }

  /* Check if the packet needs to be forwarded */
  if(local_entry.mip_addr != dest_mip && dest_mip != 255){

    /* If there is no connected router, discard the packet */
    if(*sock_container.un_fwd_conn == -1){
      if(debug){
        fprintf(stdout, "Received packet needed to be forwarded, but no "
            "router was connected to handle forwarding.\n");
      }
      free(eth_buf);
      return -3;
    }

    if(debug){
    fprintf(stdout, "Packet needs to be forwarded.\n");
    }

    /* If the packet's TTL will reach -1 on forwarding */
    if(mip_ttl == 0){
      /* Discard the packet */
      if(debug){
        fprintf(stdout, "Received packet needed to be forwarded, but its TTL "
            "reached -1.\n");
      }
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
      return -1;
    }

    if(debug){
      fprintf(stdout, "Sent forward request for destination %d to router.\n",
          dest_mip);
    }


    /* Store the packet in the packet queue and forward it when a response is
     * received from the routing daemon */
    struct packet_queue *packet = (struct packet_queue *)
        malloc(sizeof(struct packet_queue));

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

    return 0;
  }

  /* Packet originated from a neighbour */
  if(mip_tra == 0b000 || mip_tra == 0b010 || mip_tra == 0b001){

    /* Update the MIP-ARP cache with data from the received packet */
    update_mip_arp(mip_arp_table, src_mip, src_mac, socket, debug);


    /* Iterate over all packets waiting for a broadcast to see if the received
     * packet was from a neighbour that the waiting packets are to be forwarded
     * to, so that they now can be forwarded to that neighbour */
    struct packet_queue *packet = *queue_container.first_broadcast_packet;
    struct packet_queue *previous_packet = NULL;

    while(packet != NULL){
      /* If the packet can now be sent, send it and remove it from the queue */
      if(packet->next_hop == src_mip){

        if(debug){
          fprintf(stdout, "Packet with next hop %d can now be forwarded.\n",
              src_mip);
        }

        /* If the packet is an entire packet received from another node, to be
         * forwarded as is */
        if(packet->is_packet == 1){
          ret = send_complete_packet(mip_arp_table,
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
          return -1;
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
      if(debug){
        fprintf(stdout, "No application connected. Discarding packet.\n");
      }
      free(eth_buf);
      return -5;
    }

    /* Send the ping message to the connected application */
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
      return -1;
    }

    if(debug){
      fprintf(stdout,"Sent %ld bytes to connected application.\n",ret);
    }

    free(eth_buf);

  }
  /* Send the routing update to the connected routing daemon if the packet was
   * a routing packet */
  else if(mip_tra == 0b010){
    /* Discard the packet if no routing daemon is connected to the MIP
     * daemon */
    if(*sock_container.un_route_conn == -1){
      if(debug){
        fprintf(stdout, "No routing daemon connected. Discarding "
            "packet\n");
      }
      free(eth_buf);
      return -6;
    }

    /* Don't send any padding to the router */
    for(i = 0; i < payload_len; i++){
      if((uint8_t)((char *) mip_payload)[i] == 255){
        payload_len = i;
        break;
      }
    }

    /* Send the routing update */
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
      return -1;
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

    ret = send_mip_packet(mip_arp_table, sock_container.local_mip_mac_table,
        src_mip, src_mip, NULL, 0, 0b000, 0, debug);
    if(ret == -1){
      free(eth_buf);
      return -1;
    }
    free(eth_buf);
  }

  return mip_tra;
} /* recv_mip_packet END */








/**
 * Receives a routing update from the connected router and sends it to the
 * MIP address neighbour specified in the first byte of the received data.
 * The routing update is padded with bytes with value 255 if it does not
 * conform to the standard of its size in bytes being divisible by four. If the
 * destination specified by the router is not in the MIP-ARP cache, a MIP-ARP
 * broadcast for the destination is added, and the update is added to the queue
 * of packets waiting for a response to broadcasts. If the destination MIP
 * specified by the router is 255, the update is instead broadcasted on all
 * network interfaces. If the router has performed an oderly shutdown, the
 * routing accept socket is rearmed to again be listening for a connection from
 * a new router.
 *
 * @param epfd              Epoll file descriptor, used to be able to modify
 *                          the epoll instance when the router has performed an
 *                          orderly shutdown.
 * @param socks             Struct containing the sockets of the MIP daemon,
 *                          used for receiving the update from the router,
 *                          modifying the epoll instance, sending the routing
 *                          update and sending MIP-ARP broadcasts.
 * @param queues            Struct containing the packet queues for packets
 *                          awaiting forward responses from the router, and
 *                          packets awaiting MIP-ARP broadcast responses. Used
 *                          to add the routing update to the queue awaiting
 *                          broadcast responses if its destination wasn't found
 *                          in the MIP-ARP cache.
 * @param mip_arp_table     The MIP-ARP cache. Used to look up the destination
 *                          MIP address of the routing update.
 * @param debug             Variable signifying whether or not to print debug
 *                          messages.
 * @returns                 Function returns amount of bytes sent over ethernet
 *                          on normal operation, -4 if the update was
 *                          broadcasted, -3 if the update exceeded the maximum
 *                          size allowed by MIP, -2 if the router performed an
 *                          orderly shutdown, -1 on error and 0 if the
 *                          destination MIP wasn't found in the MIP-ARP cache,
 *                          a MIP-ARP broadcast was sent and the update was
 *                          added to the packet queue awaiting broadcast
 *                          responses.
 */
int send_route_update(int epfd, struct sockets socks,
    struct packet_queues queues, struct mip_arp_entry *mip_arp_table,
    int debug){

  /* Receive routing update from connected router */
  struct msghdr route_msg = { 0 };
  struct iovec route_iov[2];
  ssize_t ret;
  int i;

  uint8_t dest_mip;
  void *routing_table = malloc(MAX_MSG_SIZE);
  memset(routing_table, 255, MAX_MSG_SIZE);

  route_iov[0].iov_base = &dest_mip;
  route_iov[0].iov_len = sizeof(dest_mip);

  route_iov[1].iov_base = routing_table;
  route_iov[1].iov_len = MAX_MSG_SIZE;

  route_msg.msg_iov = route_iov;
  route_msg.msg_iovlen = 2;

  ret = recvmsg(*socks.un_route_conn, &route_msg, 0);

  if(ret == -1){
    free(routing_table);
    return -1;
  }
  else if(ret == 0){
    /* The router has performed an orderly shutdown */
    free(routing_table);

    if(debug){
      fprintf(stdout,"Connection to router terminated.\n\n\n");
    }

    /* Remove the connected routing socket from the epoll instance */
    if(epoll_ctl(epfd, EPOLL_CTL_DEL, *socks.un_route_conn, NULL)
        == -1){
      return -1;
    }

    close(*socks.un_route_conn);
    *socks.un_route_conn = -1; /* Indicates no router is connected */

    /* Rearm the routing socket listening for incoming connections from
     * a router */
    struct epoll_event ep_route_ev = { 0 };
    ep_route_ev.events = EPOLLIN | EPOLLONESHOT;
    ep_route_ev.data.fd = *socks.un_route_sock;

    if(epoll_ctl(epfd, EPOLL_CTL_MOD, *socks.un_route_sock, &ep_route_ev)
        == -1){
      return -1;
    }

    return -2;

  }

  if(debug){
    fprintf(stdout, "Received %ld bytes from router.\n", ret);
    fprintf(stdout, "Destination for routing data: %d\n", dest_mip);
  }

  /* If the destination of the routing update is 255, broadcast the
   * routing table on all network interfaces */
  if(dest_mip == 255){

    if(debug){
      fprintf(stdout, "Broadcasting routing data.\n");
    }
    for(i = 0; i < *socks.num_eth_sds; i++){
      ret = send_mip_packet(mip_arp_table, socks.local_mip_mac_table, dest_mip,
          dest_mip, routing_table, ret - 1, 0b010,
          socks.local_mip_mac_table[i].socket, debug);

      if(ret == -1){
        free(routing_table);
        return -1;
      }

      /* The routing update exceeded the maximum size allowed by MIP */
      else if(ret == -2){
        if(debug){
          fprintf(stdout,"Payload exceeds max length. Aborted send.\n");
        }
        free(routing_table);
        return -3;
      }
    }
    free(routing_table);

    return -4;
  }

  /* Send the routing update */
  ret = send_mip_packet(mip_arp_table, socks.local_mip_mac_table, dest_mip,
      dest_mip, routing_table, ret - 1, 0b010, 0, debug);

  if(ret == -1){
    free(routing_table);
    return -1;
  }

  /* The routing update exceeded the maximum size allowed by MIP */
  else if(ret == -2){
    if(debug){
      fprintf(stdout,"Payload exceeds max length. Aborted send.\n");
    }
    free(routing_table);
    return -3;
  }

  /* The MIP address indicated by the client was not cached in the
   * MIP-ARP table */
  else if(ret == -3){
    if(debug){
      fprintf(stdout,"MIP address %d not in MIP-ARP table.\n",
        dest_mip);
      fprintf(stdout, "Sending a MIP-ARP broadcast.\n");
    }

    /* Send out a MIP-ARP broadcast to attempt to find the host indicated
    * by the client */
    ret = send_mip_broadcast(mip_arp_table, *socks.num_eth_sds,
        socks.local_mip_mac_table, dest_mip, debug);

    if(ret == -1){
      free(routing_table);
      return -1;
    }

    /* Store the routing update in the packet queue awaiting broadcast
     * responses */
    struct packet_queue *broadcast_packet = (struct packet_queue *)
        malloc(sizeof(struct packet_queue));
    broadcast_packet->is_packet = 0;
    broadcast_packet->buf = routing_table;
    broadcast_packet->dest_mip = dest_mip;
    broadcast_packet->next_packet = NULL;
    broadcast_packet->next_hop = dest_mip;
    broadcast_packet->payload_len = ret - 1;
    broadcast_packet->tra = 0b010;

    if(*queues.first_broadcast_packet == NULL){
      *queues.first_broadcast_packet = broadcast_packet;
      *queues.last_broadcast_packet = *queues.first_broadcast_packet;
    }else {
      (*queues.last_broadcast_packet)->next_packet = broadcast_packet;
      *queues.last_broadcast_packet =
          (*queues.last_broadcast_packet)->next_packet;
    }

    return 0;
  }

  free(routing_table);

  return ret;

} /* send_route_update() END */



/**
 * Receives a next hop address from the router and uses this address to forward
 * the first packet in the queue of packets awaiting a forwarding respons from
 * the router. If the next hop received from the router is a local MIP address,
 * the packet is sent to the connected application if it exists and is
 * otherwise discarded. If the next hop is a local MIP address, but the packet
 * originated from this host, the packet is also discarded. If the next hop MIP
 * is 255, the destination of the packet has no known route, and the packet is
 * discarded. If the next hop is not found in the MIP-ARP cache, a MIP-ARP
 * broadcast is sent for the next hop and the packet is added to the queue of
 * packets awaiting a broadcast response. If the router has performed an
 * orderly shutdown, the socket listening for connections is rearmed.
 *
 * @param epfd                File descriptor for the epoll instance. Used to
 *                            modifying the epoll instance when the router has
 *                            performed an orderly shutdown.
 * @param socks               Struct containing the sockets of the MIP daemon.
 *                            Used to receive data on the forwarding socket,
 *                            modify the epoll instance, send the message to
 *                            the connected application if necessary, forward
 *                            the packet to another host and send a MIP-ARP
 *                            broadcast if necessary.
 * @param queues              Struct containing the queues of packets awaiting
 *                            forward responses and broadcast responses. Used
 *                            to get the packet that is to be forwarded. Also
 *                            used to move the packet awaiting a forwarding
 *                            response to the queue of packets awaiting
 *                            broadcast responses.
 * @param debug               Variable signifying whether or not debug messages
 *                            should be written to the terimnal.
 * @returns                   Returns amount of bytes sent to the next hop on
 *                            normal operation, -5 if a MIP-ARP broadcast was
 *                            was sent and the packet was moved to the queue
 *                            awaiting broadcast responses, -4 if the payload
 *                            of the MIP packet exceeded the maximum size
 *                            allowed by MIP, -3 if the next hop was either
 *                            invalid or a local MIP address, -2 if the router
 *                            performed an orderly shutdown and -1 on error.
 */

int forward_mip_packet(int epfd, struct sockets socks,
    struct packet_queues queues, struct mip_arp_entry *mip_arp_table,
    int debug){
  ssize_t ret;
  int i;

  /* Receive a next hop address from the connected router */
  struct msghdr fwd_msg = { 0 };
  struct iovec fwd_iov[1];
  uint8_t next_hop;

  fwd_iov[0].iov_base = &next_hop;
  fwd_iov[0].iov_len = sizeof(next_hop);

  fwd_msg.msg_iov = fwd_iov;
  fwd_msg.msg_iovlen = 1;

  ret = recvmsg(*socks.un_fwd_conn, &fwd_msg, 0);

  if(ret == -1){
    return -1;
  }
  else if(ret == 0){
    /* If the router has performed an orderly shutdown */

    if(debug){
      fprintf(stdout,"Connection to router terminated.\n\n\n");
    }

    /* Remove the connected forward socket from the epoll instance */
    if(epoll_ctl(epfd, EPOLL_CTL_DEL, *socks.un_fwd_conn, NULL) == -1){
      return -1;
    }

    close(*socks.un_fwd_conn);
    *socks.un_fwd_conn = -1; /* Indicates no router is connected */

    /* Rearm the forward socket listening for incoming connections from
     * a router */
    struct epoll_event ep_fwd_ev = { 0 };
    ep_fwd_ev.events = EPOLLIN | EPOLLONESHOT;
    ep_fwd_ev.data.fd = *socks.un_fwd_sock;

    epoll_ctl(epfd, EPOLL_CTL_MOD, *socks.un_fwd_sock, &ep_fwd_ev);

    return -2;

  }

  if(debug){
    fprintf(stdout, "Received next hop address from router: %d\n", next_hop);
  }

  /* Check if the packet was inteded for this host */
  for(i = 0; i < *socks.num_eth_sds; i++){
    if(next_hop == socks.local_mip_mac_table[i].mip_addr){
      if(debug){
        fprintf(stdout, "Adress is a local MIP address.\n");
      }

      /* Discard packet if no application is connected to receive it */
      if(*socks.un_sock_conn == -1){
        if(debug){
          fprintf(stdout, "No connected application, discarding packet.\n");
        }
        break;
      }

      /* Discard the packet if it originated from this host */
      if((*queues.first_packet)->is_packet != 1){
        break;
      }

      /* Packet will be a complete MIP transport packet since no other packet
       * types are forwarded.
       * Send the payload of the packet to the connected application */
      struct msghdr transport_msg = { 0 };
      struct iovec transport_iov[2];

      void *payload = ((struct ethernet_frame *)
          (*queues.first_packet)->buf)->payload.payload;

      transport_iov[0].iov_base = &(*queues.first_packet)->src_mip;
      transport_iov[0].iov_len = sizeof((*queues.first_packet)->src_mip);

      transport_iov[1].iov_base = payload;
      transport_iov[1].iov_len = strlen((char *) payload) + 1;

      transport_msg.msg_iov = transport_iov;
      transport_msg.msg_iovlen = 2;

      ret = sendmsg(*socks.un_sock_conn, &transport_msg, 0);

      if(ret == -1){
        return -1;
      }

      if(debug){
        fprintf(stdout, "Sent %ld bytes to connected application.\n", ret);
      }

      break;
    }
  }
  /* If i < num_eth_sds, the packet was sent to the application */

  /* If the next hop MIP address received from the router was 255, the
   * destination has no known route, or the packet was sent to the
   * connected application */
  if(next_hop == 255 || i < *socks.num_eth_sds){
    if(debug){
      if(next_hop == 255) fprintf(stdout, "Next hop address was invalid, "
          "discard packet.\n");
    }
    /* Remove the querying packet from the front of the queue of packets
     * waiting for forwarding, and free the data */
    struct packet_queue *tmp = *queues.first_packet;
    *queues.first_packet = (*queues.first_packet)->next_packet;
    if(*queues.first_packet == NULL){
      *queues.last_packet = *queues.first_packet;
    }

    free(tmp->buf);
    free(tmp);

    return -3;
  }
  /* Else, attempt to forward the first packet in the queue */
  else{
    if((*queues.first_packet)->is_packet == 1){
      ret = send_complete_packet(mip_arp_table, socks.local_mip_mac_table,
          next_hop,
          (struct ethernet_frame *) (*queues.first_packet)->buf,
          (*queues.first_packet)->payload_len, debug);
    }else{
      ret = send_mip_packet(mip_arp_table, socks.local_mip_mac_table,
          (*queues.first_packet)->dest_mip, next_hop,
          (*queues.first_packet)->buf,
          strlen((char *) (*queues.first_packet)->buf) + 1, 0b100, 0, debug);
    }
  }

  if(ret == -1){
    return -1;
  }
  /* The payload of the packet was too large */
  else if(ret == -2){
    if(debug){
      fprintf(stdout,"Payload exceeds max length. Aborted send.\n");
    }
    return -4;
  }
  /* The MIP address indicated by the client was not cached in the
   * MIP-ARP table */
  else if(ret == -3){
    if(debug){
      fprintf(stdout,"Next hop address %d not in MIP-ARP table.\n",
        next_hop);
      fprintf(stdout, "Sending MIP-ARP broadcast.\n");
    }

    /* Send out a MIP-ARP broadcast to attempt to find the next hop MIP
     * address indicated by the router */
    if(send_mip_broadcast(mip_arp_table, *socks.num_eth_sds,
        socks.local_mip_mac_table, next_hop, debug) == -1){
      return -1;
    }


    /* Move the packet from the queue of packets awaiting forwarding to
     * the queue of packets awaiting a broadcast response */
    (*queues.first_packet)->next_hop = next_hop;

    if(*queues.first_broadcast_packet == NULL){
      *queues.first_broadcast_packet = *queues.first_packet;
      *queues.last_broadcast_packet = *queues.first_broadcast_packet;
    }else {
      (*queues.last_broadcast_packet)->next_packet = *queues.first_packet;
      *queues.last_broadcast_packet =
          (*queues.last_broadcast_packet)->next_packet;
    }

    *queues.first_packet = (*queues.first_packet)->next_packet;
    if(*queues.first_packet == NULL) *queues.last_packet = NULL;

    return -5;
  }

  /* If the packet was successfully forwarded, remove the packet from the
   * queue, and free the data */
  struct packet_queue *tmp = *queues.first_packet;
  *queues.first_packet = (*queues.first_packet)->next_packet;
  if(*queues.first_packet == NULL){
    *queues.last_packet = *queues.first_packet;
  }
  free(tmp->buf);
  free(tmp);

  return ret;

} /* forward_mip_packet() END */



/**
 * Receives a message and destination from the connected application, sends a
 * forward request to the connected application and adds the message to the
 * queue of packets awaiting a forward response from the router. If no router
 * is connected, the message is discarded instead. Rearms the socket listening
 * for connections from applications if the connected application has performed
 * an orderly shutdown.
 *
 * @param epfd                  File descriptor for the epoll instance. Used
 *                              to modify the epoll instance when the connected
 *                              application has performed an orderly shutdown.
 * @param socks                 Struct containing the sockets of the MIP
 *                              daemon. Used when receiving data from the
 *                              connected application, when modifying the epoll
 *                              instance and when sending the forward request
 *                              to the connected router.
 * @param queues                Struct containing the queues of packet awaiting
 *                              forward and broadcast responses. Used to add
 *                              the message received from the connected
 *                              application to the queue of packets awaiting
 *                              forward responses from the router.
 * @param debug                 Variable signifying whether or not debug
 *                              messages should be written to the terminal.
 * @returns                     Returns number of bytes received from the
 *                              connected application on normal operation, -3
 *                              if no router is connected to receive the
 *                              forward request for the received message, -2 if
 *                              the connected application has performed an
 *                              orderly shutdown and -1 on error.
 */

int recv_app_msg(int epfd, struct sockets socks, struct packet_queues queues,
    int debug){
  ssize_t ret;

  /* Receive data from the connected application */
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

  ret = recvmsg(*socks.un_sock_conn,&msg,0);

  if(ret == -1){
    free(msg_buf);
    return -1;
  }
  /* Application has terminated the connection to the MIP daemon */
  else if (ret == 0){

    if(debug){
      fprintf(stdout,"Connection to application terminated.\n\n\n");
    }

    /* Remove the connected unix socket from the epoll instance */
    if(epoll_ctl(epfd, EPOLL_CTL_DEL, *socks.un_sock_conn, NULL) == -1){
      free(msg_buf);
      return -1;
    }

    close(*socks.un_sock_conn);
    *socks.un_sock_conn = -1; /* Indicates no application is connected */

    /* Rearm the unix socket listening for incoming connections from
    * applications */
    struct epoll_event ep_un_ev = { 0 };
    ep_un_ev.events = EPOLLIN | EPOLLONESHOT;
    ep_un_ev.data.fd = *socks.un_sock;

    epoll_ctl(epfd, EPOLL_CTL_MOD, *socks.un_sock, &ep_un_ev);

    free(msg_buf);
    return -2;
  }

  /* The received data was an outgoing packet */
  if(debug){
    fprintf(stdout,"Received %ld bytes from client:\n",ret);
    fprintf(stdout,"Destination MIP address: %d\n",dest_mip_addr);
    fprintf(stdout,"Message: \"%s\"\n\n",msg_buf);
    fprintf(stdout,"Requesting next hop for destination from router.\n");
  }

  /* Discard the packet if no router was connected to receive the forwarding
   * request */
  if(*socks.un_fwd_conn == -1){
    free(msg_buf);
    return -3;
  }

  /* Send a forwarding request to the connected router */
  struct msghdr lookup_msg = { 0 };
  struct iovec lookup_iov[1];

  lookup_iov[0].iov_base = &dest_mip_addr;
  lookup_iov[0].iov_len = sizeof(dest_mip_addr);

  lookup_msg.msg_iov = lookup_iov;
  lookup_msg.msg_iovlen = 1;

  if(sendmsg(*socks.un_fwd_conn, &lookup_msg, 0) == -1){
    free(msg_buf);
    return -1;
  }

  /* Add the message received from the connected application to the queue of
   * packets awaiting a forwarding response from the connected router */
  struct packet_queue *packet = (struct packet_queue *)
      malloc(sizeof(struct packet_queue));
  packet->is_packet = 0;
  packet->buf = msg_buf;
  packet->dest_mip = dest_mip_addr;
  packet->next_packet = NULL;
  packet->payload_len = ret - 1;
  packet->tra = 0b100;

  if(*queues.first_packet == NULL){
    *queues.first_packet = packet;
    *queues.last_packet = packet;
  }else{
    (*queues.last_packet)->next_packet = packet;
    *queues.last_packet = (*queues.last_packet)->next_packet;
  }

  return ret;
} /* recv_app_msg() END */





/**
 * Handles a signal received on the signal_fd descriptor.
 *
 * @param signal_fd       The descriptor to read the signal from.
 * @returns               Returns 0 if an interrupt signal was received, -1
 *                        otherwise.
 */
int keyboard_signal(int signal_fd){
  /* Read the signal */
  struct signalfd_siginfo sig_info;
  ssize_t sig_size;

  sig_size = read(signal_fd, &sig_info, sizeof(struct signalfd_siginfo));

  /* Write to terminal what signal was received if it was an interrupt */
  if(sig_size == 0){
    fprintf(stderr,"\nCtrl-d: Received EOF signal from keyboard, stopping\n");
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

}/* keyboard_signal() END */




/**
 * Initializes the routing table of the connected router with the local MIP
 * addresses of the MIP daemon.
 *
 * @param un_route_conn           The routing socket connected to the router.
 *                                Used for sending the local MIP address to the
 *                                router.
 * @param local_mip_mac_table     Data structure containing the local MIP
 *                                addresses of the MIP daemon. Used to find the
 *                                local MIP addresses to send to the router.
 * @param num_mips                The number of MIP addresses stored in
 *                                local_mip_mac_table.
 * @returns                       Returns 0 on success and -1 on error.
 */
int init_router(int un_route_conn, struct mip_arp_entry *local_mip_mac_table,
    int num_mips){
  int i;

  /* Send the local MIP addresses to the router for initialization */
  struct msghdr msg = { 0 };
  struct iovec iov[1];

  uint8_t local_mips[256];
  for(i = 0; i < num_mips; i++){
    local_mips[i] = local_mip_mac_table[i].mip_addr;
    printf("Local_mips: %d\n",local_mips[i]);
  }

  iov[0].iov_base = local_mips;
  iov[0].iov_len = num_mips;

  msg.msg_iov = iov;
  msg.msg_iovlen = 1;

  printf("i: %d\n",i);

  int ret = sendmsg(un_route_conn, &msg, 0);

  printf("Sent: %d\n",ret);

  if(ret == -1){
    return -1;
  }

  return 0;
} /* init_router() END */
