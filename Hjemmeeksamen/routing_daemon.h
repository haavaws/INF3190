#define TTL 15 /* Max TTL of any MIP packet */
#define MAX_EVENTS 1
#define MAX_MIP 256
#define UPDATE_WAIT 30 /* Max time to wait between routing updates */

struct routing_table_entry{
  char next_hop;
  char dest_mip;
  char cost;
} __attribute__((packed));

struct distance_table_entry{
  char dest_mip;
  char *next_hop;
  char *cost;
};
