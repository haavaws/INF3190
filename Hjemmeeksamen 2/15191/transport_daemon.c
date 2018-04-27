#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "transport_daemon.h"






int main(int argc, char* argv[]){
  /* Structure for containing data about local connections, and outgoing
   * connection sessions */
  struct data_container *data = (struct data_container *)
      malloc(sizeof(struct data_container));

  /* Epoll data */
  int epfd,nfds;
  struct epoll_event events[MAX_EVENTS];

  /* Socket paths */
  char *app_name;
  char *mip_name;

  /* Timeout before resending un-acked packets */
  int timeout;
  /* Indicates if debug information should be logged to console */
  int debug = 0;

  int i;
  ssize_t ret;
  time_t now; /* Current time */

  data->app_conns = NULL;
  data->sessions = NULL;
  data->num_apps = 0;
  data->num_sessions = 0;



  /* Argument handling */

  if(argc > 1){
    /* Print help */
    if(strcmp(argv[1],"-h") == 0){
      print_help(argv[0]);
      exit(EXIT_SUCCESS);
    }
  }

  if(argc < 4){
    /* Not enough arguments */
    print_help(argv[0]);
    exit(EXIT_FAILURE);
  }

  if(strcmp(argv[1],"-d") == 0){
    /* Debug mode */
    if(argc<5){
      print_help(argv[0]);
      exit(EXIT_FAILURE);
    }
    fprintf(stdout,"------------ STARTING IN DEBUG MODE --------------\n");
    debug = 1;
  }

  /* Timeout value */
  char *endptr;
  timeout = strtol(argv[1 + debug],&endptr,10);
  if(*endptr != '\0' || argv[1 + debug][0] == '\0'){
    print_help(argv[0]);
    exit(EXIT_FAILURE);
  }

  /* Socket paths */
  mip_name = argv[2 + debug];
  app_name = argv[3 + debug];

  /* Listen for transport applications */
  data->app = setup_listen_socket(app_name);

  if(data->app == -1){
    perror("main: setup_listen_socket, socket()");
    exit(EXIT_FAILURE);
  }
  else if (data->app == -2){
    perror("main: setup_listen_socket, bind()");
    close_sockets(data,0);
    exit(EXIT_FAILURE);
  }
  else if (data->app == -3){
    perror("main: setup_listen_socket, listen()");
    close_sockets(data,0);
    exit(EXIT_FAILURE);
  }

  if(debug){
    fprintf(stdout, "Listening for incoming connections from applications on "
        "path \"%s\"\n", app_name);
  }

  /* Connect to the MIP daemon */
  data->mip = connect_socket(mip_name);

  if(data->mip == -1){
    perror("main: connect_socket, socket()");
    close_sockets(data,0);
    exit(EXIT_FAILURE);
  }
  if(data->mip == -2){
    perror("main: connect_socket, connect()");
    close_sockets(data,0);
    exit(EXIT_FAILURE);
  }

  if(debug){
    fprintf(stdout, "Connected to MIP daemon on path \"%s\"\n", mip_name);
  }

  /* Signal handler. Capturing keyboard interrupts: Ctrl-C and Ctrl-\ */
  data->signal = setup_signal_fd();

  if(data->signal == -1){
    perror("main: setup_signal_fd");
    close_sockets(data,0);
    exit(EXIT_FAILURE);
  }

  /* Create the epoll instance */
  epfd = create_epoll_instance(data);

  if (epfd < 0){
    perror("main: create_epoll_instance():");
    close_sockets(data,0);
    exit(EXIT_FAILURE);
  }

  data->epfd = epfd;

  if(debug){
    fprintf(stdout, "Waiting for incoming data from applications and MIP "
        "daemon.\n");
  }



  /* MAIN LOOP */
  /* Perform the transport layer functionality */
  for(;;){
    now = time(NULL);

    /* Wait for events, non-blocking */
    nfds = epoll_wait(epfd, events, MAX_EVENTS, 0);

    if(nfds == -1){
      perror("main: epoll_wait()");
      close_sockets(data,0);
      exit(EXIT_FAILURE);
    }

    if(nfds == 0){
      /* Check if any of the packets awaiting acks have timed out */
      /* Iterate through all connected applications */
      for(i = 0; i < data->num_apps; i++){
        /* If they have any packets awaiting acks */
        if(data->app_conns[i]->num_ack_queue > 0){
          /* Check if the first packet has timed out */
          if(now - data->app_conns[i]->packet_timestamp[0] > timeout){

            if(debug){
              fprintf(stdout, "Packet meant for MIP %d on port %d has timed "
                  "out while waiting for ack.\n", data->app_conns[i]->mip,
                  data->app_conns[i]->port);
              fprintf(stdout, "Resending all unacked packets.\n");
            }

            /* Resend the packets if there was a timeout */
            if(resend_packets(data->app_conns[i], data, debug) == -1){
              perror("main: resend_packets()");
              close_sockets(data,0);
              exit(EXIT_FAILURE);
            }
          }
        }
      }

    }


    /* Iterate through the triggered events */
    for (i = 0; i < nfds; i++){

      /* A keyboard interrupt was signaled, shutdown the transport daemon */
      if(events[i].data.fd == data->signal){
        if(keyboard_signal(events[i].data.fd) == 0){
          close_sockets(data, 1);
          exit(EXIT_SUCCESS);
        }
      }


      /* A new application connected to the MIP daemon */
      else if(events[i].data.fd == data->app){
        if(debug){
          fprintf(stdout, "\n");
        }
        struct app_data *new_conn = (struct app_data *) calloc(1, sizeof(struct app_data));

        /* Accept the new application */
        new_conn->sock = accept(data->app, NULL, NULL);

        if(new_conn->sock == -1){
          perror("main: accept(): data->app");
          close_sockets(data,0);
          exit(EXIT_FAILURE);
        }

        /* Initialize the connection data */
        ret = init_app(data, new_conn, epfd);

        if(ret == -1){
          perror("main: init_app()");
          free(new_conn);
          close_sockets(data,0);
          exit(EXIT_FAILURE);
        }else if(ret == -2){
          if(debug){
            fprintf(stdout, "Application already connected with that MIP "
                "MIP address and port, closing new connection.\n");
          }
          free(new_conn);
          continue;
        }else if(ret == 0){
          /* Communication error, disconnect */
          if(debug){
            fprintf(stdout, "Communication error with transport application, "
                "connection closed.\n\n");
          }
          free(new_conn);
          continue;
        }

        /* Add the connection to the structure containing data about local
         * connections */
        data->app_conns = (struct app_data **) realloc(data->app_conns,
            sizeof(struct app_data *) * (data->num_apps + 1));
        data->app_conns[data->num_apps] = new_conn;
        data->num_apps++;

        if(debug){
          fprintf(stdout, "Connection to transport application "
              "established.\n\n");
        }

      }



      /* Incoming data from the MIP daemon */
      else if(events[i].data.fd == data->mip){

        if(debug){
          fprintf(stdout, "\n");
        }

        /* Handle the data */
        ret = recv_transport_packet(data, debug);

        if(ret == -1){
          perror("main: recv_transport_packet()");
          close_sockets(data,0);
          exit(EXIT_FAILURE);
        }else if(ret == -2){
          /* MIP daemon has performed an orderly shutdown, quit */

          if(debug){
            fprintf(stdout, "MIP daemon has performed an orderly shutdown, "
                "shutting down.\n");
          }

          close_sockets(data,1);
          exit(EXIT_FAILURE);
        }

        if(debug){
          fprintf(stdout, "\n");
        }

      }



      /* Incoming data from a connected application */
      else if(is_conn(events[i].data.fd, data)
          != -1){

        if(debug){
          fprintf(stdout, "\n");
        }

        /* Handle the data */
        ret = recv_from_app(events[i].data.fd, events[i].events, data, debug);
        if(ret == -1){
          perror("main: recv_from_app()");
          close_sockets(data, 0);
          exit(EXIT_FAILURE);
        }

        if(debug){
          fprintf(stdout, "\n");
        }

      }
    }/* END EVENT HANDLING */
  }/* END MAIN LOOP */
}/* END MAIN FUNCTION */
