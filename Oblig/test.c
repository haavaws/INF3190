#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

struct test_struct {
  int testa;
};


int main(int argc, char *argv[]){
  struct test_struct testarr[10] = {0};
  if(&testarr[0] == NULL){
    printf("null");
  }else printf("not null");

}
