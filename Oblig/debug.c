#ifndef DEBUG
#define DEBUG

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include "mip_daemon.h"

void print_help(char *file_name){
  fprintf(stderr,"USAGE: %s [-h][-d] <Socket_application> [MIP addresses ...]\n", file_name);
  fprintf(stderr,"[-h]: optional help argument\n");
  fprintf(stderr,"[-d]: optional debug argument, prints communication information\n");
  fprintf(stderr,"<Socket_application>: name of socket for IPC with application\n");
  fprintf(stderr,"[MIP addresses ...]: one unique MIP address per interface with a unique MAC address, in the form of a number between 0 and 255\n");
  exit(EXIT_FAILURE);
}

void print_mac(uint8_t *mac){
  for(int i = 0; i < MAC_SIZE; i++){
    fprintf(stdout,"%x:",mac[i]);
  }fprintf(stdout,"%x",mac[5]);
}


void print_arp_table(struct mip_arp_entry *arp_table){
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
}

#endif
