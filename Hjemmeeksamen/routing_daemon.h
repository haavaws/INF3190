#include <time.h>
#include <inttypes.h>

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
  uint8_t *next_hop;
  uint8_t *cost;
  time_t *timestamp;
};
