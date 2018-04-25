#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "transport_daemon.h"






int main(int argc, char* argv[]){
  struct connection_data *conn_data = (struct connection_data *)
      malloc(sizeof(struct connection_data));
  struct socket_container *socks = (struct socket_container *)
      malloc(sizeof(struct socket_container));

  int epfd,nfds;
  struct epoll_event events[MAX_EVENTS];

  char *app_name;
  char *mip_name;

  int timeout;
  int debug = 0;

  int i;
  ssize_t ret;
  time_t now;

  printf("%d\n",argc);

  /* Argument handling */
  if(argc >= 2){
    /* Print help */
    if(strcmp(argv[1],"-h") == 0){
      print_help(argv[0]);
      exit(EXIT_SUCCESS);
    }
  }

  if(argc<4){
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

  mip_name = argv[2 + debug];
  app_name = argv[3 + debug];

  /* Listen for transport applications */
  socks->app = setup_listen_socket(app_name);

  if(socks->app == -1){
    perror("main: setup_listen_socket, socket()");
    exit(EXIT_FAILURE);
  }
  else if (socks->app == -2){
    perror("main: setup_listen_socket, bind()");
    close_sockets(socks,0);
    exit(EXIT_FAILURE);
  }
  else if (socks->app == -3){
    perror("main: setup_listen_socket, listen()");
    close_sockets(socks,0);
    exit(EXIT_FAILURE);
  }

  /* Connect to the MIP daemon */
  socks->mip = connect_socket(mip_name);

  if(socks->mip == -1){
    perror("main: connect_socket, socket()");
    close_sockets(socks,0);
    exit(EXIT_FAILURE);
  }
  if(socks->mip == -2){
    perror("main: connect_socket, connect()");
    close_sockets(socks,0);
    exit(EXIT_FAILURE);
  }

  /* Signal handler */
  socks->signal = setup_signal_fd();

  if(socks->signal == -1){
    perror("main: setup_signal_fd");
    close_sockets(socks,0);
    exit(EXIT_FAILURE);
  }

  /* Epoll instance */
  epfd = create_epoll_instance(socks);

  if (epfd < 0){
    perror("main: create_epoll_instance():");
    close_sockets(socks,0);
    exit(EXIT_FAILURE);
  }

  socks->epfd = epfd;


  /* Handle events in the epoll instance */
  for(;;){
    now = time(NULL);
    nfds = epoll_wait(epfd, events, MAX_EVENTS, 0);

    if(nfds == -1){
      perror("main: epoll_wait()");
      close_sockets(socks,0);
      free_conn_data(conn_data);
      exit(EXIT_FAILURE);
    }

    if(nfds == 0){
      /* Check for timeouts */
      for(i = 0; i < socks->num_apps; i++){
        if(socks->app_conns[i].num_ack_queue > 0){
          if(now - socks->app_conns[i].packet_timestamp[0] > timeout){
            /* Resend the packets if there was a timeout */
            if(resend_packets(&socks->app_conns[i], socks) == -1){
              perror("main: resend_packets()");
              close_sockets(socks,0);
              free_conn_data(conn_data);
              exit(EXIT_FAILURE);
            }
          }
        }
      }
    }

    /* Iterate through the triggered events */
    for (i = 0; i < nfds; i++){

      /* A keyboard interrupt was signaled */
      if(events[i].data.fd == socks->signal){
        if(keyboard_signal(events[i].data.fd) == 0){
          close_sockets(socks, 1);
          free_conn_data(conn_data);
          exit(EXIT_SUCCESS);
        }
      }


      else if(events[i].data.fd == socks->app){
        struct conn_app new_conn = { 0 };

        new_conn.sock = accept(socks->app, NULL, NULL);

        if(new_conn.sock == -1){
          perror("main: accept(): socks->app");
          close_sockets(socks,0);
          free_conn_data(conn_data);
          exit(EXIT_FAILURE);
        }

        ret = init_app(&new_conn, socks, epfd);

        if(ret == -1){
          perror("main: init_app()");
          close_sockets(socks,0);
          free_conn_data(conn_data);
          exit(EXIT_FAILURE);
        }else if(ret == 0){
          /* Communication error, disconnect */
          continue;
        }

        socks->app_conns = (struct conn_app *) realloc(socks->app_conns,
            sizeof(struct conn_app) * (socks->num_apps + 1));
        socks->app_conns[socks->num_apps] = new_conn;
        socks->num_apps++;

        if(debug){
          fprintf(stdout,"Connection to transport application "
              "established.\n\n");
        }

      }

      else if(events[i].data.fd == socks->mip){
        ret = recv_transport_packet(socks, conn_data);

        if(ret == -1){
          perror("main: recv_transport_packet()");
          close_sockets(socks,0);
          free_conn_data(conn_data);
          exit(EXIT_FAILURE);
        }else if(ret == -2){
          /* MIP daemon has performed an orderly shutdown, quit */
          if(debug){
            fprintf(stdout, "MIP daemon has performed an orderly shutdown, "
                "shutting down.\n");
          }
          close_sockets(socks,1);
          free_conn_data(conn_data);
          exit(EXIT_FAILURE);
        }

      }

      else if(is_conn(events[i].data.fd, socks->app_conns, socks->num_apps)
          == -1){
        ret = recv_from_app(events[i].data.fd, socks, conn_data, debug);
        if(ret == -1){
          perror("main: recv_from_app()");
          close_sockets(socks, 0);
          free_conn_data(conn_data);
          exit(EXIT_FAILURE);
        }

      }

    }

  }

}
