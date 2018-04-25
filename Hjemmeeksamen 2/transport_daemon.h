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
  uint8_t pad_and_port[2];
  uint16_t seq_num;
  uint8_t payload[];
} __attribute__((packed));

struct conn_app{
  int sock;
  uint8_t mip;
  uint16_t port;
  uint16_t seq_num;
  ssize_t payload_bytes_sent;
  struct transport_packet *sent_packets[10];
  int packet_size[10];
  time_t packet_timestamp[10];
  int num_ack_queue;
};

struct connection_data{
  uint16_t *seq_nums;
  uint16_t *port_conns;
  uint8_t *mip_conns;
  int num_sessions;
};

struct socket_container{
  int epfd;
  int app;
  int mip;
  struct conn_app *app_conns;
  int num_apps;
  int signal;
};

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
    struct connection_data *conn_data);
int resend_packets(struct conn_app *app_conn, struct socket_container *socks);
int recv_from_app(int app_sock, struct socket_container *socks,
    struct connection_data *conn_data, int debug);
int init_app(struct conn_app *app_conn, struct socket_container *socks,
    int epfd);
