#include <string.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <stdlib.h>
#include "mip_daemon.h"

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
}


int construct_mip_packet(struct mip_frame* frame, uint8_t destination,
    uint8_t source, uint8_t tra, char* payload, int payload_len){
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
    fprintf(stdout,"Destination MAC: ");print_mac(recv_eth_frame->destination);
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
    fprintf(stdout,"Sending MIP ARP broadcast on all interfaces.\n\n");
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
