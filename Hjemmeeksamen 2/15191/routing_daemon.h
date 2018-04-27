#include <time.h>
#include <inttypes.h>
#include <unistd.h>

#define TTL 15 /* Max TTL of any MIP packet */
#define UNREACHABLE 16 /* Cost indicating unreachable destination */
#define MAX_EVENTS 1
#define MAX_MIP 256
#define BROADCAST_MIP 255 /* Broadcast MIP address */
#define BAD_MIP 255 /* Value indicating an invalid MIP address */
#define UPDATE_WAIT 30 /* Max seconds to wait between routing updates */
/* Number of times to wait before invalidating an entry in the distance
 * table */
#define WAIT_NUM_TTL 6

struct routing_table_entry{
  uint8_t next_hop;
  uint8_t dest_mip;
  uint8_t cost;
} __attribute__((packed));

struct distance_table_entry{
  uint8_t dest_mip;
  /* Will have one member per neighbour */
  uint8_t *next_hop;
  uint8_t *cost;
  time_t *timestamp;
};

struct routing_data{
  /* Routing table of the router */
  struct routing_table_entry *routing_table;
  /* Distance table of the router */
  struct distance_table_entry *distance_table;
  /* The last time an update was received from a neighbour corresponding to the
   * neighbours array */
  time_t *last_neighbour_update;
  /* The local mip addresses supplied by the MIP daemon */
  uint8_t *local_mips;
  /* Number of local mip addresses */
  int *num_local_mips;
  /* Current neighbours */
  uint8_t *neighbours;
  /* Number of current neighbours */
  int *num_neighbours;
  /* Last time an update was sent */
  time_t *last_update_timestamp;

};

struct sockets{
  int *un_route_sock;
  int *un_fwd_sock;
  int *signal_fd;
};

/* Functions declared in routing.c */
void print_help(char *file_name);

void print_rout_dest(struct routing_table_entry *routing_table);

void close_sockets(struct sockets socks, int free_path);

void free_distance_table(struct distance_table_entry *distance_table);

int init_routing_data(struct sockets socks, struct routing_data rd, int debug);

int send_routing_table_update(struct sockets socks, struct routing_data rd,
    int debug);

int clean_dist_route(struct routing_data rd, time_t now);

int rm_empty_route_dist(struct routing_data rd);

int create_sockets(struct sockets socks, char* un_route_name,
    char* un_fwd_name);

int create_epoll_instance(struct sockets socks);

void print_routing_table(struct routing_table_entry *routing_table);

void print_neighbours(uint8_t *neighbours, int num_neighbours);

time_t scheduled_update(struct sockets socks, struct routing_data rd,
    time_t now, int debug);

int keyboard_signal(int signal_fd);

int new_neighbour(struct routing_data rd, int src_mip, time_t now, int debug);

int update_tables(struct routing_data rd,
    struct routing_table_entry *route_update, uint8_t src_mip,
    ssize_t recv_size, time_t now, int debug);

int recv_routing_update(struct sockets socks, struct routing_data rd,
    time_t now, int debug);

int recv_fwd_req(struct sockets socks, struct routing_data rd, time_t now,
    int debug);
