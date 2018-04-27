#include <inttypes.h>
#include <time.h>
#include <stdio.h>

#define LISTEN_BACKLOG_UNIX 100 /* number of pending connections allowed */
#define MAX_EVENTS 10 /* only handle one epoll event at a time */
#define MAX_PACKET_SIZE 1496 /* maximum size of a transport packet */
#define MAX_PAYLOAD_SIZE 1492 /* maximum size of the payload of a packet */
#define PACKET_HDR_SIZE 4 /* size of the header in a transport packet */
#define WINDOW_SIZE 10 /* Size of the sliding window */
#define SEQ_NUM_MAX 65535 /* The largest possible sequence number */

struct transport_packet{
  /* The two first bits of the pad_and_port array are for the padding length,
   * while the remaining 14 are for the port */
  uint8_t pad_and_port[2];
  uint16_t seq_num; /* Sequence number stored in network-byte-order */
  uint8_t payload[]; /* Payload of the packet, including padding */
} __attribute__((packed));

/* For a connected server application, only the mip, sock and port fields are
 * used */
struct conn_app{
  int sock; /* Socket the application is conneceted to */
  /* MIP address the application is sending to (invalid, i.e. 255, if the
   * application is a server) */
  uint8_t mip;
  uint16_t port; /* Port communicated on */
  /* Sequence number of last packet sent (initialized to SEQ_NUM_MAX) */
  uint16_t seq_num;
  /* Total amount of bytes of payload received by the intended recipient */
  ssize_t payload_bytes_sent;
  struct transport_packet *sent_packets[10]; /* Packet window */
  int packet_size[10]; /* Size of the packets in the packet window */
  int packet_pad[10]; /* Padding length of the packets in the packet window */
  /* Time the packets in the packet window were sent */
  time_t packet_timestamp[10];
  int num_ack_queue; /* Number of packets awaiting ack */
};

/* Remote connection sessions */
struct connection_data{
  uint16_t *seq_nums; /* Sequence numbers of the next expected packets */
  uint16_t *port_conns; /* Ports that are being communicated on */
  uint8_t *mip_conns; /* Source MIP address of the sessions */
  int num_sessions; /* Number of sessions */
};

/* Local connection data */
struct socket_container{
  int epfd; /* Epoll instance */
  int app; /* Socket listening for application connections */
  int mip; /* Socket connected to the MIP daemon */
  struct conn_app *app_conns; /* Connected applications */
  int num_apps; /* Number of connected applications */
  int signal; /* Signal handler */
};

/* Functions defined in transport.c */
int setup_listen_socket(char* un_sock_name);
void print_help(char *file_name);
void close_sockets(struct socket_container *socks, int unlink_mip_path);
int setup_signal_fd();
int connect_socket(char* socket_name);
int create_epoll_instance(struct socket_container *socks);
void free_conn_data(struct connection_data *conn_data);
int keyboard_signal(int signal_fd);
int is_conn(int sock, struct conn_app *app_conns, int sock_len);
int recv_transport_packet(struct socket_container *socks,
    struct connection_data *conn_data, int debug);
int resend_packets(struct conn_app *app_conn, struct socket_container *socks);
int recv_from_app(int app_sock, uint32_t epoll_events,
    struct socket_container *socks, int debug);
int init_app(struct conn_app *app_conn, int epfd);
