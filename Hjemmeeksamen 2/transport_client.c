#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>

#define MAX_FILE_SIZE 65535 /* Maximum allowed file size */
#define MAX_PAYLOAD_SIZE 1492 /* Maximum size of a payload */


/**
 * Prints usage information to stderr for the user
 *
 * @param file_name Filename of the user executed, argv[0]
 * @return          none
 */
void print_help(char *file_name){
  fprintf(stderr,"USAGE: %s [-h][-d] <Socket_application> <MIP address> "
      "<Port> <File_name>\n", file_name);
  fprintf(stderr,"[-h]: optional help argument\n");
  fprintf(stderr,"<MIP address>: the MIP address to send the file to, between "
      "0 and 254.\n");
  fprintf(stderr,"<Port>: port to send the file through.\n");
  fprintf(stderr,"<File_name>: name of the file to send, which is smaller "
      "than 64 KiB.\n");
}


int main(int argc, char* argv[]){
  int un_sock;
  uint8_t dest_mip;
  uint16_t dest_port;

  char* sock_name;
  char* file_name;

  struct timeval start = { 0 };
  struct timeval end = { 0 };
  time_t transfer_time_s;
  time_t transfer_time_u;

  FILE *fp;
  uint16_t file_size;
  ssize_t sent_bytes = -2;
  ssize_t ret;
  int i;


  /* ARGUMENT HANDLING */
  if(argc >= 2){
    if(strcmp(argv[1], "-h") == 0){
      print_help(argv[0]);
      exit(EXIT_SUCCESS);
    }
  }

  if(argc < 5){
    print_help(argv[0]);
    exit(EXIT_FAILURE);
  }

  sock_name = argv[1];

  char *endptr;
  dest_mip = strtol(argv[2],&endptr,10);
  if(*endptr != '\0' || argv[1][0] == '\0'){
    print_help(argv[0]);
    exit(EXIT_FAILURE);
  }
  if(dest_mip == 255){
    print_help(argv[0]);
    exit(EXIT_FAILURE);
  }

  dest_port = strtol(argv[3],&endptr,10);
  if(*endptr != '\0' || argv[1][0] == '\0'){
    print_help(argv[0]);
    exit(EXIT_FAILURE);
  }

  file_name = argv[4];


  un_sock = socket(AF_UNIX,SOCK_SEQPACKET,0);

  if(un_sock == -1){
    perror("main: socket()");
    exit(EXIT_FAILURE);
  }

  /* Connect to MIP daemon */
  struct sockaddr_un sockaddr;
  sockaddr.sun_family = AF_UNIX;
  strcpy(sockaddr.sun_path, sock_name);

  if(connect(un_sock, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) == -1){
    perror("main: connect()");
    close(un_sock);
    exit(EXIT_FAILURE);
  }

  fp = fopen(file_name, "rb");

  if(!fp){
    perror("main: fopen()");
    close(un_sock);
    exit(EXIT_FAILURE);
  }

  /* Check file size */
  ssize_t actual_size = 0;
  if(fseek(fp, 0, SEEK_END) == -1){
    perror("main: fseek(): SEEK_END");
    close(un_sock);
    exit(EXIT_FAILURE);
  }

  actual_size = ftell(fp);
  if(actual_size == -1){
    perror("main: ftell()");
    close(un_sock);
    exit(EXIT_FAILURE);
  }

  if(fseek(fp, 0, SEEK_SET) == -1){
    perror("main: fseek(): SEEK_SET");
    close(un_sock);
    exit(EXIT_FAILURE);
  }

  if(actual_size > MAX_FILE_SIZE){
    fprintf(stderr, "Size of the file to send was not under the 64 KiB limit, "
        "aborting.\n");
    fprintf(stderr, "File size: %ld\tMax size: %d\n",
        actual_size, MAX_FILE_SIZE);
    close(un_sock);
    exit(EXIT_FAILURE);
  }

  file_size = actual_size;

  /* Send the destination MIP address and port to the transport daemon */
  struct msghdr init_msg = { 0 };
  struct iovec init_iov[2];

  init_iov[0].iov_base = &dest_mip;
  init_iov[0].iov_len = sizeof(dest_mip);

  init_iov[1].iov_base = &dest_port;
  init_iov[1].iov_len = sizeof(dest_port);

  init_msg.msg_iov = init_iov;
  init_msg.msg_iovlen = 2;

  if(sendmsg(un_sock, &init_msg, 0) == -1){
    perror("main: sendmsg(): init_msg");
    close(un_sock);
    exit(EXIT_FAILURE);
  }

  gettimeofday(&start, NULL);
  /* Send the file to the transport daemon */
  for(;;){
    uint8_t file_segment[MAX_PAYLOAD_SIZE];
    int offset = 0;

    if(sent_bytes < 0){
      file_segment[0] = file_size >> 8;
      file_segment[1] = (uint8_t) file_size;
      offset = 2;
      sent_bytes += 2;
    }

    ret = fread(&file_segment[offset], 1, MAX_PAYLOAD_SIZE - offset, fp);

    if(ret == 0) break;

    struct msghdr segment_msg = { 0 };
    struct iovec segment_iov[1];

    segment_iov[0].iov_base = file_segment;
    segment_iov[0].iov_len = ret + offset;

    segment_msg.msg_iov = segment_iov;
    segment_msg.msg_iovlen = 1;

    if(sendmsg(un_sock, &segment_msg, 0) == -1){
      perror("main: sendmsg(): segment_msg");
      close(un_sock);
      exit(EXIT_FAILURE);
    }

    sent_bytes += ret;

    if(ret < MAX_PAYLOAD_SIZE - offset) break;
  }

  if(sent_bytes != file_size){
    fprintf(stderr, "Finished sending file to transfer daemon, but amount "
        "did not match file size, aborting.\n");
    close(un_sock);
    exit(EXIT_FAILURE);
  }

  sent_bytes = -2;

  fprintf(stdout, "Transferring file \"%s\" of %d bytes:\n", file_name,
      file_size);

  i = file_size;
  int num_digits;
  for(num_digits = 0; i / 10 > 0; num_digits++) i /= 10;


  /* Wait for progress updates from transport daemon */
  for(;;){

    /* Print progress */
    fprintf(stdout, "\rBytes sent: %*ld of %d\t",
        num_digits, sent_bytes >= 0 ? sent_bytes : 0, file_size);
    fprintf(stdout, "|");
    for(i = 0;
        i < (int)((double) sent_bytes / file_size * (40 - (num_digits * 2)));
        i++){
      fprintf(stdout, "=");
    }
    for(; i < 40 - (num_digits * 2); i++){
      fprintf(stdout, " ");
    }
    fprintf(stdout, "| %3d%%\n", sent_bytes >= 0 ? (int)((double)sent_bytes / file_size * 100) : 0);
    fflush(stdout);



    struct msghdr update_msg = { 0 };
    struct iovec update_iov[1];

    update_iov[0].iov_base = &ret;
    update_iov[0].iov_len = sizeof(ret);

    update_msg.msg_iov = update_iov;
    update_msg.msg_iovlen = 1;

    ret = recvmsg(un_sock, &update_msg, 0);

    if(ret == -1){
      perror("\nmain: recvmsg()");
      close(un_sock);
      exit(EXIT_FAILURE);
    }else if(ret == 0){
      /* Transport daemon disconnected */
      fprintf(stdout, "\nDisconnected from the trasnport daemon, shutting "
          "down.\n");
      close(un_sock);
      unlink(file_name);
      exit(EXIT_FAILURE);
    }

    sent_bytes += ret;

    if(sent_bytes == file_size) break;
  }

  gettimeofday(&end, NULL);

  transfer_time_s = end.tv_sec - start.tv_sec;
  if(start.tv_usec > end.tv_usec){
    transfer_time_s--;
    transfer_time_u = 1000000 - start.tv_usec + end.tv_sec;
  }
  else transfer_time_u = end.tv_sec - start.tv_usec;

  fprintf(stdout, "\nTransfer completed in %ld.%03ld s.\n",transfer_time_s,
      transfer_time_u / 1000);


}
