#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include "mip_daemon.h"


/**
 * Prints usage information to stderr for the user
 *
 * @param file_name Filename of the user executed, argv[0]
 * @return          none
 */
void print_help(char *file_name){
  fprintf(stderr,"USAGE: %s [-h][-d] <Socket_application> "
    "[MIP addresses ...]\n", file_name);
  fprintf(stderr,"[-h]: optional help argument\n");
  fprintf(stderr,"[-d]: optional debug argument, prints communication "
    "information\n");
  fprintf(stderr,"<Socket_application>: name of socket for IPC with "
    "application\n");
  fprintf(stderr,"[MIP addresses ...]: one unique MIP address per interface "
    "with a unique MAC address, in the form of a number between 0 and 255\n");
  exit(EXIT_FAILURE);
}



/**
 * Prints out the provided MAC address to console
 *
 * @param mac MAC address to be printed
 * @return    none
 *
 * Global variables: MAC_SIZE
 */
void print_mac(uint8_t *mac){
  for(int i = 0; i < MAC_SIZE; i++){
    fprintf(stdout,"%x:",mac[i]);
  }fprintf(stdout,"%x",mac[5]);
}



/**
 * Prints all unexpired entries of the MIP-ARP table provided
 *
 * @param arp_table MIP-ARP table whose entries are to be printed
 * @return          Returns number of entries printed
 *
 * Global variables: MAX_ARP_SIZE
 *                   MIP_ARP_TTL
 */
int print_arp_table(struct mip_arp_entry *arp_table){
  int num_entries = 0;
  fprintf(stdout,"\nMIP-ARP table:\n");
  time_t now = time(NULL);
  for(int i = 0; i < MAX_ARP_SIZE; i++){
    if(now-arp_table[i].timestamp < MIP_ARP_TTL){
      fprintf(stdout,"MIP: %d\t",arp_table[i].mip_addr);
      fprintf(stdout,"MAC: "); print_mac(arp_table[i].mac_addr);
      fprintf(stdout,"\n");
      num_entries++;
    }
  }
  if(num_entries == 0) fprintf(stdout,"EMPTY\n");
  fprintf(stdout,"\n");

  return num_entries;
}
