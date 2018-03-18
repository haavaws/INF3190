#ifndef GLOBALVARS
#define GLOBALVARS

#include <inttypes.h>
#include <time.h>
#include <sys/types.h>

/* use the local experimental protocol for ethernet communication */
#define ETH_P_MIP 0x88B5
#define LISTEN_BACKLOG_UNIX 100 /* number of pending connections allowed */
#define MAX_EVENTS 1 /* only handle one epoll event at a time */
#define MAX_MSG_SIZE 1496 /* ethernet MTU not including MIP header */
/* max message size plus ethernet and mip headers */
#define MAX_ETH_FRAME_SIZE 1514
#define MAX_ARP_SIZE 256 /* the maximum size of the MIP-ARP table */
#define MIP_ARP_TTL 300 /* seconds a MIP-ARP entry is valid */
#define PING_TIMEOUT 100 /* timout for waiting for ping in milliseconds */
#define MAC_SIZE 6 /* size of a mac address */
#define IPC_PONG_RSP_SIZE 5 /* message size of an IPC PONG response */


/* Entries to make up a MIP-ARP table */
struct mip_arp_entry {
  uint8_t mip_addr; /* MIP address of the host */
  uint8_t mac_addr[6]; /* MAC address of the host */
  /* Socket the interface connected to the MIP address is bound to */
  int socket;
  /* The time at which the entry was stored, timestamp is 0, entry is empty */
  time_t timestamp;
};

/* Data structure for a MIP packet */
struct mip_frame{
  /* Bytes for storing the MIP header as specified in the assignment text */
  uint8_t header_bytes[4];
  char payload[]; /* Payload of the MIP packet */
} __attribute__((packed));

/* Data structure for an ethernet frame */
struct ethernet_frame {
  /* Standard ethernet header */
  uint8_t destination[6];
  uint8_t source[6];
  uint16_t protocol;
  struct mip_frame payload; /* A MIP packet as a payload */
} __attribute__((packed));

struct sockets {
  int *un_sock;
  int *un_route_sock;
  int *un_fwd_sock;
  int *un_sock_conn;
  int *un_route_conn;
  int *un_fwd_conn;
  int *signal_fd;
  struct mip_arp_entry *local_mip_mac_table;
  int *num_eth_sds;
};

/* Functions are documented where they are defined */

/* Defined in debug.c */
void print_help(char *file_name);

void print_mac(uint8_t *mac);

int print_arp_table(struct mip_arp_entry *arp_table);


/* Defined in sockets.c */
void close_sockets(struct sockets sock_container);

int setup_unix_socket(char* un_sock_name);

int setup_eth_sockets(struct mip_arp_entry *local_mip_mac_table,
  int num_mip_addrs, int debug);

int create_epoll_instance(struct sockets sock_container);


/* Defined in mip.c */
uint8_t get_mip_tra(struct mip_frame *frame);

uint8_t get_mip_dest(struct mip_frame *frame);

uint8_t get_mip_src(struct mip_frame *frame);

int update_mip_arp (struct mip_arp_entry *arp_table, uint8_t mip, uint8_t *mac,
  int socket, int debug);

void construct_mip_packet(struct mip_frame* frame, uint8_t destination,
  uint8_t source, uint8_t tra, char* payload, int payload_len);

ssize_t send_mip_packet(struct mip_arp_entry *arp_table,
  struct mip_arp_entry *local_mip_mac_table, uint8_t dest_mip, char* payload,
  uint8_t tra, int send_sd, int debug);

int recv_mip_packet(struct mip_arp_entry *mip_arp_table,
  struct mip_arp_entry *local_mip_mac_table, int socket, uint8_t *src_mip_buf,
  char *buf, int debug);

int send_mip_broadcast(int epoll_fd, struct mip_arp_entry *mip_arp_table,
  int num_eth_sds, struct mip_arp_entry *local_mip_mac_table, uint8_t dest_mip,
  int debug);


#endif
