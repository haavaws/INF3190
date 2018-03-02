#ifndef CONSTANTS
#define CONSTANTS

#include <inttypes.h>
#include <time.h>
#include <sys/types.h>

/* use the local experimental protocol for ethernet communication */
#define ETH_P_MIP 0x88B5
#define LISTEN_BACKLOG_UNIX 100 /* number of pending connections allowed */
#define MAX_EVENTS 1 /* only handle one epoll event at a time */
#define MAX_MSG_SIZE 1496 /* ethernet MTU not including MIP header */
#define MAX_ETH_FRAME_SIZE 1514 /* max message size plus ethernet and mip headers */
#define MAX_ARP_SIZE 256 /* the maximum size of the MIP-ARP table */
#define MIP_ARP_TTL 300 /* seconds a MIP-ARP entry is valid */
#define PING_TIMEOUT 100 /* timout for waiting for ping in milliseconds */
#define MAC_SIZE 6 /* size of a mac address */
#define IPC_PONG_RSP_SIZE 5 /* message size of an IPC PONG response */


struct mip_arp_entry {
  uint8_t mip_addr; /* MIP address of the host */
  uint8_t mac_addr[6]; /* MAC address of the host */
  int socket; /* Socket the interface connected to the MIP address is bound to */
  /* The time at which the entry was stored, timestamp is 0, entry is empty */
  time_t timestamp;
};

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



void print_help(char *file_name);

void print_mac(uint8_t *mac);

void print_arp_table(struct mip_arp_entry *arp_table);



void close_sockets(int un_sock,char* un_sock_name,int un_sock_conn,int signal_fd,struct mip_arp_entry *local_mip_mac_table,int num_eth_sds);

int setup_unix_socket(char* un_sock_name);

int setup_eth_sockets(struct mip_arp_entry *local_mip_mac_table,int num_mip_addrs,int debug);

int create_epoll_instance(int un_sock,struct mip_arp_entry *local_mip_mac_table,int num_eth_sds);



uint8_t get_mip_tra(struct mip_frame *frame);

uint8_t get_mip_dest(struct mip_frame *frame);

uint8_t get_mip_src(struct mip_frame *frame);



int update_mip_arp (struct mip_arp_entry *arp_table,uint8_t mip,uint8_t *mac,int socket,int debug);

int construct_mip_packet(struct mip_frame* frame,uint8_t destination,uint8_t source,uint8_t tra,char* payload,int payload_len);



ssize_t send_mip_packet(struct mip_arp_entry *arp_table,struct mip_arp_entry *local_mip_mac_table,uint8_t dest_mip,char* payload,uint8_t tra,int send_sd,int debug);

int recv_mip_packet(struct mip_arp_entry *mip_arp_table,struct mip_arp_entry *local_mip_mac_table,int socket,uint8_t *src_mip_buf,char *buf,int debug);

int send_mip_broadcast(int epoll_fd,struct mip_arp_entry *mip_arp_table,int num_eth_sds,struct mip_arp_entry *local_mip_mac_table,uint8_t dest_mip,int debug);



#endif
