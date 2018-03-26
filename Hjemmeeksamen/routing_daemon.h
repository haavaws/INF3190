#include <time.h>
#include <inttypes.h>

#define TTL 15 /* Max TTL of any MIP packet */
#define MAX_EVENTS 1
#define MAX_MIP 256
#define UPDATE_WAIT 30 /* Max time to wait between routing updates */

struct routing_table_entry{
  uint8_t next_hop;
  uint8_t dest_mip;
  uint8_t cost;
} __attribute__((packed));

struct distance_table_entry{
  uint8_t dest_mip;
  uint8_t *next_hop;
  uint8_t *cost;
  time_t *timestamp;
};
