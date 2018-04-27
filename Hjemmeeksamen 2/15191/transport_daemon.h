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
struct app_data{
  int sock; /* Socket the application is conneceted to */
  /* MIP address the application is sending to (invalid, i.e. 255, if the
   * application is a server) */
  uint8_t mip;
  uint16_t port; /* Port communicated on */
  /* Sequence number of last packet sent (initialized to SEQ_NUM_MAX) */
  uint16_t seq_num;
  /* Total amount of bytes of payload received by the intended recipient */
  ssize_t payload_bytes_sent;
  struct transport_packet *packet_window[WINDOW_SIZE]; /* Packet window */
  int packet_size[WINDOW_SIZE]; /* Size of the packets in the packet window */
  int packet_pad[WINDOW_SIZE]; /* Padding length of the packets in the packet window */
  /* Time the packets in the packet window were sent */
  time_t packet_timestamp[WINDOW_SIZE];
  uint16_t packet_seq_num[WINDOW_SIZE];
  int packet_acked[WINDOW_SIZE];
  int num_ack_queue; /* Number of packets awaiting ack */
};

/* Remote connection sessions */
struct session_data{
  uint16_t seq_num; /* Sequence numbers of the next expected packets */
  uint16_t port_conn; /* Ports that are being communicated on */
  uint8_t mip_conn; /* Source MIP address of the sessions */
  struct transport_packet *packet_window[WINDOW_SIZE]; /* Window buffer for a session */
  int packet_payload_len[WINDOW_SIZE];
  int num_buffered;
};

/* Structure containing connection data */
struct data_container{
  int epfd; /* Epoll instance */
  int app; /* Socket listening for application connections */
  int mip; /* Socket connected to the MIP daemon */
  int signal; /* Signal handler */
  struct app_data **app_conns; /* Connected applications */
  struct session_data **sessions; /* Remote incoming sessions */
  int num_apps; /* Number of connected applications */
  int num_sessions; /* Number of sessions */
};

/* Functions defined in transport.c */
int setup_listen_socket(char* un_sock_name);
void print_help(char *file_name);
void close_sockets(struct data_container *data, int unlink_mip_path);
int setup_signal_fd();
int connect_socket(char* socket_name);
int create_epoll_instance(struct data_container *data);
int keyboard_signal(int signal_fd);
int is_conn(int sock, struct data_container *data);
int recv_transport_packet(struct data_container *data, int debug);
int resend_packets(struct app_data *app_conn, struct data_container *data, int debug);
int recv_from_app(int app_sock, uint32_t epoll_events,
    struct data_container *data, int debug);
int init_app(struct data_container *data, struct app_data *app_conn, int epfd);
