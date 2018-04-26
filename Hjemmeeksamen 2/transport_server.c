#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#define MAX_FILE_SIZE 65535 /* Maximum allowed file size */
#define MAX_PORT 16383 /* Largest possible port number */
#define MAX_PAYLOAD_SIZE 1492 /* Maximum size of a payload */
#define SAVE_NAME "receivedFile"

void ignore(int moo){

}


/**
 * Prints usage information to stderr for the user
 *
 * @param file_name Filename of the user executed, argv[0]
 * @return          none
 */
void print_help(char *file_name){
  fprintf(stderr,"USAGE: %s [-h] <Socket_application> <Port>\n",
      file_name);
  fprintf(stderr,"[-h]: optional help argument\n");
  fprintf(stderr,"<MIP address>: the MIP address to send the file to, between "
      "0 and 254.\n");
  fprintf(stderr,"<Port>: port to send the file through.\n");
  fprintf(stderr,"<File_name>: name of the file to send, which is smaller "
      "than 64 KiB.\n");
}

FILE *open_next_available(int *file_counter, char **file_name){
  int i,j;
  FILE *fp;

  int save_name_len;

  for(save_name_len = 0; SAVE_NAME[save_name_len] != '\0'; save_name_len++);


  for(i = *file_counter; i > 0; i++){

    int num_digits;
    for(j = *file_counter; j / 10 > 0; j /= 10) num_digits++;

    (*file_name) = (char *) malloc(save_name_len + num_digits + 1);
    strncpy((*file_name), SAVE_NAME, save_name_len);
    sprintf(&(*file_name)[save_name_len], "%d", *file_counter);

    fp = fopen((*file_name), "r");

    if(fp){
      fclose(fp);
      (*file_counter)++;
      free((*file_name));
      continue;
    }else{
      fp = fopen((*file_name), "wb");

      if(!fp){
        (*file_counter)++;
        free((*file_name));
        continue;
      }

      break;
    }
  }

  return fp;

}


void prepare_shutdown(FILE **files, char **file_names, uint16_t *file_sizes,
    uint16_t *bytes_received, uint8_t *src_mips, int num_files){

  int i;
  for(i = 0; i < num_files; i++){
    fclose(files[i]);
    free(file_names[i]);
  }

  free(files);
  free(file_names);
  free(file_sizes);
  free(bytes_received);
  free(src_mips);

}


int remove_session(FILE ***files, char ***file_names, uint16_t **file_sizes,
    uint16_t **bytes_received, uint8_t **src_mips, int *num_receiving,
    uint8_t src_mip){

  int ret = 0;
  int i;

  for(i = 0; i < (*num_receiving); i++){
    if((*src_mips)[i] == src_mip){
      fclose((*files)[i]);

      /* Remove and reorder the data */
      for(; i < (*num_receiving) - 1; i++){
        (*files)[i] = (*files)[i + 1];
        (*file_names)[i] = (*file_names)[i + 1];
        (*file_sizes)[i] = (*file_sizes)[i + 1];
        (*bytes_received)[i] = (*bytes_received)[i + 1];
        (*src_mips)[i] = (*src_mips) [i + 1];
      }

      (*num_receiving)--;

      /* Reallocate space for the data */
      (*files) =
          (FILE **) realloc((*files), (*num_receiving) * sizeof((*files)));
      (*file_names) =
          (char **) realloc((*file_names), (*num_receiving) * sizeof(char));
      (*file_sizes) = (uint16_t *)
          realloc((*file_sizes), (*num_receiving) * sizeof(uint16_t));
      (*bytes_received) = (uint16_t *)
          realloc((*bytes_received), (*num_receiving) * sizeof(uint16_t));
      (*src_mips) =
          (uint8_t *) realloc((*src_mips), (*num_receiving) * sizeof(uint8_t));

      ret = 1;

      break;
    }
  }

  return ret;
}



int new_transfer(FILE ***files, char ***file_names, uint16_t **file_sizes,
    uint16_t **bytes_received, uint8_t **src_mips, int *file_counter,
    int *num_receiving, uint16_t file_size, uint8_t src_mip){

  char *file_name;

  int ret = remove_session(files, file_names, file_sizes, bytes_received, src_mips,
      num_receiving, src_mip);

  (*num_receiving)++;

  (*files) = (FILE **) realloc((*files), (*num_receiving) * sizeof((*files)));
  (*file_names) =
      (char **) realloc((*file_names), (*num_receiving) * sizeof(char));
  (*file_sizes) =
      (uint16_t *) realloc((*file_sizes), (*num_receiving) * sizeof(uint16_t));
  (*bytes_received) = (uint16_t *)
      realloc((*bytes_received), (*num_receiving) * sizeof(uint16_t));
  (*src_mips) =
      (uint8_t *) realloc((*src_mips), (*num_receiving) * sizeof(uint8_t));

  (*files)[(*num_receiving) - 1] =
      open_next_available(file_counter, &file_name);
  (*file_names)[(*num_receiving) - 1] = file_name;
  (*file_sizes)[(*num_receiving) - 1] = file_size;
  (*bytes_received)[(*num_receiving) - 1] = 0;
  (*src_mips)[(*num_receiving) - 1] = src_mip;

  if(!(*files)[(*num_receiving) - 1]){
    return -1;
  }

  return ret;

}


int main(int argc, char* argv[]){
  int un_sock;
  uint16_t listen_port;

  FILE **receiving_files = NULL;
  char **file_names = NULL;
  uint16_t *file_sizes = NULL;
  uint16_t *bytes_received = NULL;
  uint8_t *src_mips = NULL;
  int file_counter = 0;
  int num_receiving = 0;

  char* sock_name;

  ssize_t ret;
  int i;
  size_t check;


  /* ARGUMENT HANDLING */
  if(argc > 1){
    if(strcmp(argv[1], "-h") == 0){
      print_help(argv[0]);
      exit(EXIT_SUCCESS);
    }
  }

  if(argc < 3){
    print_help(argv[0]);
    exit(EXIT_FAILURE);
  }

  sock_name = argv[1];

  char *endptr;
  check = strtol(argv[2],&endptr,10);
  if(*endptr != '\0' || argv[1][0] == '\0'){
    print_help(argv[0]);
    exit(EXIT_FAILURE);
  }
  if(check > MAX_PORT){
    print_help(argv[0]);
    exit(EXIT_FAILURE);
  }
  listen_port = check;


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

  /* Catch keyboard interrupts */

  struct sigaction sa = { 0 };

  sa.sa_handler = ignore;

  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGQUIT, &sa, NULL);

  /* Send the destination MIP address and port to the transport daemon */
  uint8_t invalid_mip = 255;
  struct msghdr init_msg = { 0 };
  struct iovec init_iov[2];

  init_iov[0].iov_base = &invalid_mip;
  init_iov[0].iov_len = sizeof(invalid_mip);

  init_iov[1].iov_base = &listen_port;
  init_iov[1].iov_len = sizeof(listen_port);

  init_msg.msg_iov = init_iov;
  init_msg.msg_iovlen = 2;

  if(sendmsg(un_sock, &init_msg, 0) == -1){
    perror("main: sendmsg(): init_msg");
    close(un_sock);
    exit(EXIT_FAILURE);
  }


  for(;;){
    fprintf(stdout, "NOW LOOPING\n");
    ssize_t payload_size;
    int offset = 0;
    uint8_t src_mip;
    int new_session;
    uint8_t file_segment[MAX_PAYLOAD_SIZE];

    struct msghdr file_msg = { 0 };
    struct iovec file_iov[3];

    file_iov[0].iov_base = &src_mip;
    file_iov[0].iov_len = sizeof(src_mip);

    file_iov[1].iov_base = &new_session;
    file_iov[1].iov_len = sizeof(new_session),

    file_iov[2].iov_base = file_segment;
    file_iov[2].iov_len = MAX_PAYLOAD_SIZE;

    file_msg.msg_iov = file_iov;
    file_msg.msg_iovlen = 3;

    ret = recvmsg(un_sock, &file_msg, 0);

    if(ret == -1){
      close(un_sock);
      if(errno == EINTR){
        fprintf(stdout, "Received interrupt from keyboard, shutting down file server.\n");
        exit(EXIT_SUCCESS);
      }
      perror("main: recvmsg()");
      exit(EXIT_FAILURE);
    }else if(ret == 0){
      fprintf(stdout, "Transport daemon has performed an orderly shutdown, "
          "lost connection, aborting.\n");
      prepare_shutdown(receiving_files, file_names, file_sizes, bytes_received, src_mips, num_receiving);
      exit(EXIT_FAILURE);
    }

    payload_size = ret - sizeof(src_mip) - sizeof(new_session);

    /* If segment was the start of a new transfer */
    if(new_session == 1){
      uint16_t file_size = 0;

      file_size |= file_segment[0] << 8;
      file_size |= file_segment[1];

      offset = sizeof(file_size);
      payload_size -= offset;

      fprintf(stdout, "Received file segment was the start of a new transfer.\n");

      ret = new_transfer(&receiving_files, &file_names, &file_sizes, &bytes_received, &src_mips, &num_receiving, &file_counter, file_size, src_mip);

      if(ret == -1){
        fprintf(stderr, "No available file to store received data, aborting "
            "server.\n");
        prepare_shutdown(receiving_files, file_names, file_sizes, bytes_received, src_mips, num_receiving - 1);
        exit(EXIT_FAILURE);
      }
      else if(ret == 0){
        fprintf(stdout, "The new transfer had the same source as an ongoing trasnfer.\n");
        fprintf(stdout, "Aborting previous transfer.\n");
      }
    }

    /* Write the received data to file */
    for(i = 0; i < num_receiving; i++){
      if(src_mips[i] == src_mip){
        bytes_received[i] += payload_size;

        ret = fwrite(&file_segment[offset], sizeof(*file_segment),
            payload_size, receiving_files[i]);

        if(ret != payload_size){
          perror("main: fwrite()");
          prepare_shutdown(receiving_files, file_names, file_sizes, bytes_received, src_mips, num_receiving - 1);
          exit(EXIT_FAILURE);
        }

        if(bytes_received[i] > file_sizes[i]){
          fprintf(stderr, "Amount of bytes received exceeds the size of the file being transferred, aborting transfer.\n");
          remove_session(&receiving_files, &file_names, &file_sizes, &bytes_received, &src_mips, &num_receiving, src_mip);
        }else if(bytes_received[i] == file_sizes[i]){
          fprintf(stdout, "File transfer from MIP address %d of %d bytes has completed.", src_mip, file_sizes[i]);
        }

        break;
      }
    }


  }
}
