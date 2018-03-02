#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <errno.h>
#include "mip_daemon.h"

/* Global variables and functions declared in mip_daemon.h */

/* Daemon used for link layer network communication using the Mininet
* Interconnection Protocol (MIP). Allows a client application to ping, through
* this MIP daemon, a host directly connected to this MIP daemon over ethernet.
* Also allows for a connected server application, through this daemon, to
* receive a ping message over ethernet from a host connected directly to the
* host running this MIP daemon. */

int main(int argc, char *argv[]){
  /* MIP-ARP table and local interface MIP-ARP */
  struct mip_arp_entry mip_arp_table[MAX_ARP_SIZE] = { 0 };
  struct mip_arp_entry local_mip_mac_table[MAX_ARP_SIZE] = { 0 };

  /* Epoll */
  struct epoll_event events[MAX_EVENTS];
  int epfd,nfds;

  /* Sockets */
  int num_eth_sds;
  int un_sock,un_sock_conn;
  int signal_fd;

  /* Arguments */
  int debug;
  char* un_sock_name;
  int mip_start_ind;
  int sock_name_ind;

  /* Loops and return */
  int i,j;
  ssize_t ret;


  /* Argument control */
  if(argc<3){
    print_help(argv[0]);
    exit(EXIT_FAILURE);
  }

  if(strcmp(argv[1],"-h") == 0){
    print_help(argv[0]);
    exit(EXIT_SUCCESS);
  }
  else if(strcmp(argv[1],"-d") == 0){
    if (argc<4){
      print_help(argv[0]);
      exit(EXIT_SUCCESS);
    }
    fprintf(stdout,"--- Starting MIP daemon in debug mode ---\n\n");
    debug = 1;
    sock_name_ind = 2;
    mip_start_ind = 3;
  }
  else{
    debug = 0;
    sock_name_ind = 1;
    mip_start_ind = 2;
  }

  un_sock_name = argv[sock_name_ind]; /* <Socket_application */

  /* Store MIP addresses in the MIP-ARP for local interfaces */
  int num_mip_addrs = argc-2;
  if(debug) num_mip_addrs --;
  for(i = 0; i < num_mip_addrs; i++){
    char *endptr;
    long int check = strtol(argv[mip_start_ind+i],&endptr,10);
    if(*endptr != '\0' || argv[mip_start_ind+i][0] == '\0'
        || check > 255 || check < 0){
      print_help(argv[0]);
      exit(EXIT_FAILURE);
    }
    local_mip_mac_table[i].mip_addr = check;
    for(j = 0;j < i; j++){
      if(local_mip_mac_table[i].mip_addr == local_mip_mac_table[j].mip_addr){
        print_help(argv[0]);
        exit(EXIT_FAILURE);
      }
    }
  }

  un_sock = setup_unix_socket(un_sock_name);

  if(un_sock == -1){
    perror("main: setup_unix_socket, socket() un_sock");
    exit(EXIT_FAILURE);
  }
  else if (un_sock == -2){
    perror("main: setup_unix_socket, bind un_sock");
    close_sockets(un_sock, NULL, -1, -1, NULL, 0);
    exit(EXIT_FAILURE);
  }
  else if (un_sock == -3){
    perror("main: listen() un_sock");
    close_sockets(un_sock, un_sock_name, -1, -1, NULL, 0);
    exit(EXIT_FAILURE);
  }

  num_eth_sds =  setup_eth_sockets(local_mip_mac_table, num_mip_addrs, debug);

  if(num_eth_sds == -1){
    perror("main: setup_eth_sockets: getifaddrs");
    close_sockets(un_sock, un_sock_name, -1, -1, NULL, 0);
    exit(EXIT_FAILURE);
  }
  else if(num_eth_sds == -2){
    perror("main: setup_eth_sockets: socket");
    close_sockets(un_sock, un_sock_name, -1, -1, NULL, 0);
    exit(EXIT_FAILURE);
  }
  else if(num_eth_sds == -3){
    perror("main: setup_eth_sockets: ioctl");
    close_sockets(un_sock, un_sock_name, -1, -1, NULL, 0);
    exit(EXIT_FAILURE);
  }
  else if(num_eth_sds == -4){
    perror("main: setup_eth_sockets: bind");
    close_sockets(un_sock, un_sock_name, -1, -1, NULL, 0);
    exit(EXIT_FAILURE);
  }

  /* Control number of supplied MIP addresses vs. number of raw interfaces */
  if(num_eth_sds > num_mip_addrs || num_mip_addrs > num_eth_sds){
    //Number of MIP addresses did not match number of ethernet sockets
    fprintf(stderr,"Number of supplied MIP addresses did not match the number "
        "of interfaces requiring a MIP address...\n");
    fprintf(stderr,"Number of supplied MIP addresses: %d\n", num_mip_addrs);
    fprintf(stderr,"Number of interfaces which require MIP addresses: %d\n",
        num_eth_sds);
    close_sockets(un_sock,un_sock_name, -1, -1, local_mip_mac_table,
        num_mip_addrs > num_eth_sds ? num_eth_sds : num_mip_addrs);
    exit(EXIT_FAILURE);
  }

  /* Create an epoll instance with the unix and ethernet sockets */
  epfd = create_epoll_instance(un_sock, local_mip_mac_table, num_eth_sds);

  if (epfd == -1){
    //ERROR_HANDLING
    perror("main: create_epoll_instance(): epoll_create");
    close_sockets(un_sock,un_sock_name,-1,-1,local_mip_mac_table,num_eth_sds);
    exit(EXIT_FAILURE);
  }
  else if(epfd == -2){
    //ERROR_HANDLING
    perror("main: create_epoll_instance: epoll_ctl(): add un_sock");
    close_sockets(un_sock,un_sock_name,-1,-1,local_mip_mac_table,num_eth_sds);
    exit(EXIT_FAILURE);
  }
  else if(epfd == -3){
    //ERROR_HANDLING
    perror("main: epoll_ctl: add local_mip_mac_table[i].socket");
    close_sockets(un_sock,un_sock_name,-1,-1,local_mip_mac_table,num_eth_sds);
    exit(EXIT_FAILURE);
  }

  /* Add a keyboard interrupt signal handler for the epoll instance */
  sigset_t mask;

  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGQUIT);

  sigprocmask(SIG_BLOCK, &mask, NULL);

  signal_fd = signalfd(-1, &mask, 0);
  if(signal_fd == -1){
    //ERROR_HANDLING
    perror("main: signalfd");
    close_sockets(un_sock, un_sock_name, -1, -1, local_mip_mac_table,
        num_eth_sds);
    exit(EXIT_FAILURE);
  }

  struct epoll_event ep_sig_ev = { 0 };
  ep_sig_ev.events = EPOLLIN | EPOLLERR;
  ep_sig_ev.data.fd = signal_fd;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, signal_fd, &ep_sig_ev) == -1){
    //ERROR_HANDLING
    perror("main: epoll_ctl: add signal_fd");
    close_sockets(un_sock,un_sock_name, -1, signal_fd, local_mip_mac_table,
        num_eth_sds);
    exit(EXIT_FAILURE);
  }


  /* While un_sock_conn is -1, no application is connected to the MIP daemon */
  un_sock_conn = -1;

  struct epoll_event ep_ev = { 0 };

  /* Poll the sockets for events until a keyboard interrupt is signaled */
  for(;;){

    nfds = epoll_wait(epfd,events,MAX_EVENTS,-1);
    if(nfds == -1){
      //ERROR_HANDLING
      perror("main: epoll_wait()");
      close_sockets(un_sock, un_sock_name, un_sock_conn, signal_fd,
          local_mip_mac_table, num_eth_sds);
      exit(EXIT_FAILURE);
    }

    /* Iterate through the triggered events */
    for (i = 0; i < nfds; i++){

      /* A keyboard interrupt was signaled */
      if(events[i].data.fd == signal_fd){
        struct signalfd_siginfo sig_info;
        ssize_t sig_size;

        sig_size = read(events[i].data.fd, &sig_info,
            sizeof(struct signalfd_siginfo));
        if(sig_size == 0){
          perror("\nCtrl-d: Received EOF signal from keyboard, stopping\n");
          close_sockets(un_sock, un_sock_name, un_sock_conn, signal_fd,
              local_mip_mac_table, num_eth_sds);
          exit(EXIT_SUCCESS);
        }
        if(sig_info.ssi_signo == SIGINT){
          //Close all sockets and close stop the daemon
          fprintf(stderr,"\nCtrl-c: Received interrupt from keyboard,"
              "stopping daemon\n");
          close_sockets(un_sock, un_sock_name, un_sock_conn, signal_fd,
              local_mip_mac_table, num_eth_sds);
          exit(EXIT_SUCCESS);
        }
        else if(sig_info.ssi_signo == SIGQUIT){
          //Close all sockets and close stop the daemon
          fprintf(stderr,"\nCtrl-\\: Received interrupt from keyboard,"
              "stopping daemon\n");
          close_sockets(un_sock, un_sock_name, un_sock_conn, signal_fd,
              local_mip_mac_table, num_eth_sds);
          exit(EXIT_SUCCESS);
        }
      }
      /* An application has connected to the MIP daemon */
      else if(events[i].data.fd == un_sock){

        struct sockaddr_un un_sock_conn_addr = { 0 };
        socklen_t size_un_sock_conn_addr = sizeof(un_sock_conn_addr);

        /* Store the socket for the connected application for later use */
        un_sock_conn = accept(un_sock, (struct sockaddr *) &un_sock_conn_addr,
            &size_un_sock_conn_addr);

        if(debug){
          fprintf(stdout,"Connection to application established.\n\n");
        }

        /* Using EPOLLONESHOT to make sure the socket may only be triggered
        * in the main loop of the MIP daemon */
        ep_ev.events = EPOLLIN | EPOLLONESHOT;
        ep_ev.data.fd = un_sock_conn;

        if(epoll_ctl(epfd, EPOLL_CTL_ADD, un_sock_conn, &ep_ev) == -1){
          //ERROR_HANDLING
          perror("main: epoll_ctl(): add un_sock_conn");
          close_sockets(un_sock, un_sock_name, un_sock_conn, signal_fd,
              local_mip_mac_table, num_eth_sds);
          exit(EXIT_FAILURE);
        }
      } /* Incoming application connection END */

      /* Incoming data on the over IPC from connected application */
      else if(events[i].data.fd == un_sock_conn){

        /* Unix communication based on code from group session
        * https://github.uio.no/persun/inf3190/tree/master/plenum3 */

        /* Receive data from the connected application over IPC */
        char msg_buf[MAX_MSG_SIZE] = { 0 };
        uint8_t dest_mip_addr;

        struct msghdr msg = { 0 };
        struct iovec iov[2];

        iov[0].iov_base = &dest_mip_addr;
        iov[0].iov_len = sizeof(dest_mip_addr);

        iov[1].iov_base = msg_buf;
        iov[1].iov_len = sizeof(msg_buf);

        msg.msg_iov = iov;
        msg.msg_iovlen = 2;

        ret = recvmsg(events[i].data.fd,&msg,0);

        if(ret == -1){
          perror("main: recvmsg: un_sock_conn");
          close_sockets(un_sock, un_sock_name, un_sock_conn, signal_fd,
              local_mip_mac_table, num_eth_sds);
          exit(EXIT_FAILURE);
        }
        /* Application has terminated the connection to the MIP daemon */
        else if (ret == 0){

          if(debug){
            fprintf(stdout,"Connection to application terminated.\n\n\n");
          }

          /* Remove the connected unix socket from the epoll instance */
          if(epoll_ctl(epfd,EPOLL_CTL_DEL,events[i].data.fd,&events[i]) == -1){
            perror("main: epoll_ctl: del un_sock_conn");
            close_sockets(un_sock, un_sock_name, un_sock_conn, signal_fd,
                local_mip_mac_table,num_eth_sds);
            exit(EXIT_FAILURE);
          }

          close(events[i].data.fd);
          un_sock_conn = -1; /* Indicates no application is connected */

          /* Rearm the unix socket listening for incoming connections from
          * applications */
          struct epoll_event ep_un_ev = { 0 };
          ep_un_ev.events = EPOLLIN | EPOLLONESHOT;
          ep_un_ev.data.fd = un_sock;

          epoll_ctl(epfd, EPOLL_CTL_MOD, un_sock, &ep_un_ev);

          continue;
        }

        /* The received data was an outgoing ping */
        if(debug){
          fprintf(stdout,"Received %ld bytes from client:\n",ret);
          fprintf(stdout,"Destination MIP address: %d\n",dest_mip_addr);
          fprintf(stdout,"Message: \"%s\"\n\n",msg_buf);
          fprintf(stdout,"Sending ping.\n");
        }

        if(debug) print_arp_table(mip_arp_table);

        /* Attempt to ping the host indicated by the client */
        ret = send_mip_packet(mip_arp_table, local_mip_mac_table,
            dest_mip_addr, msg_buf, 0b100, 0, debug);

        if(ret == -1){
          perror("main: send_mip_packet: un_sock_conn: send ping");
          close_sockets(un_sock, un_sock_name, un_sock_conn, signal_fd,
              local_mip_mac_table, num_eth_sds);
          exit(EXIT_FAILURE);
        }
        /* The ping message was too large */
        else if(ret == -2){
          if(debug){
            fprintf(stdout,"Ping message exceeds max length. Aborted send.\n");
          }
          continue;
        }
        /* The MIP address indicated by the client was not cached in the
        * MIP-ARP table */
        else if(ret == -3){
          if(debug){
            fprintf(stdout,"MIP address %d not in MIP-ARP table.\n",
              dest_mip_addr);
          }

          /* Send out a MIP-ARP broadcast to attempt to find the host indicated
          * by the client */
          ret = send_mip_broadcast(epfd, mip_arp_table, num_eth_sds,
              local_mip_mac_table, dest_mip_addr,debug);

          if(ret == -1){
            perror("main: send_mip_broadcast: un_sock_conn: "
                "send ping broadcast");
            close_sockets(un_sock, un_sock_name, un_sock_conn, signal_fd,
                local_mip_mac_table, num_eth_sds);
            exit(EXIT_FAILURE);
          }
          /* The broadcast timed out */
          else if(ret == -2){
            /* Rearm the socket for communicating over IPC */
            epoll_ctl(epfd,EPOLL_CTL_MOD,un_sock_conn,&ep_ev);
            continue;
          }

          if(debug){
            fprintf(stdout,"Re-sending ping.\n");
          }

          /* If the destination host was found through the broadast, attempt to
          * re-send the ping */
          ret = send_mip_packet(mip_arp_table, local_mip_mac_table,
              dest_mip_addr, msg_buf, 0b100, 0, debug);
        }


        int pong = 0; /* Indicates if a PONG response has been received */

        /* Wait until a PONG response is received, or timeout */
        for(;;){
          struct epoll_event ping_events[MAX_EVENTS];
          int ping_nfds;

          if(pong == 1){
            /* Rearm the socket for communicating over IPC */
            epoll_ctl(epfd, EPOLL_CTL_MOD, un_sock_conn, &ep_ev);
            break;
          }

          ping_nfds = epoll_wait(epfd, ping_events, MAX_EVENTS, PING_TIMEOUT);

          if(ping_nfds == -1){
            perror("main: epoll_wait: un_sock_conn: PONG response");
            close_sockets(un_sock, un_sock_name, un_sock_conn, signal_fd,
                local_mip_mac_table, num_eth_sds);
            exit(EXIT_FAILURE);
          }
          /* Waiting timed out */
          else if(ping_nfds == 0){
            if(debug){
              fprintf(stdout,"Timeout.\n");
            }
            /* Rearm the socket for communicating over IPC */
            epoll_ctl(epfd, EPOLL_CTL_MOD, un_sock_conn, &ep_ev);
            break;
          }

          /* Iterate through events triggered while waiting */
          for(j = 0; j < ping_nfds; j++){
            char buf[MAX_MSG_SIZE] = { 0 };
            uint8_t src_mip;
            int tra;

            /* Will store the source MIP address in src_mip, and the message
            * in buf */
            tra = recv_mip_packet(mip_arp_table, local_mip_mac_table,
                ping_events[j].data.fd, &src_mip, buf,debug);

            if(tra == -1){
              perror("main: recv: un_sock_conn: PONG response");
              close_sockets(un_sock, un_sock_name, un_sock_conn, signal_fd,
                  local_mip_mac_table, num_eth_sds);
              exit(EXIT_FAILURE);
            }else if(tra == -2){
              /* MIP packet was not for this host, discard it */
              continue;
            }

            /* Received packet was a transport packet */
            if(tra == 0b100){
              if(strcmp(buf,"PONG") != 0 || src_mip != dest_mip_addr){
                /* Discard it if it was not the expected PONG response */
                continue;
              }

              if(debug){
                fprintf(stdout,"Packet was a PONG response.\n");
              }

              /* Unix communication based on code from group session
              * https://github.uio.no/persun/inf3190/tree/master/plenum3 */

              /* Send the PONG response to the connected client */
              struct msghdr msg = { 0 };
              struct iovec iov[1];

              iov[0].iov_base = buf;
              iov[0].iov_len = strlen(buf)+1;

              msg.msg_iov = iov;
              msg.msg_iovlen = 1;

              ret = sendmsg(un_sock_conn,&msg,0);

              if(ret == -1){
                if(errno == EPIPE){
                  /* If the client disconnected from the MIP daemon while
                  * waiting for a PONG response, for example if it sent the
                  * ping while a server was connected to the MIP daemon */
                  if(debug){
                    fprintf(stdout,"Can't foward to client because it has "
                        "disconencted.");
                    pong = 1;
                    continue;
                  }
                }else{
                  perror("main: sendmsg: un_sock_conn: PONG response");
                  close_sockets(un_sock, un_sock_name, un_sock_conn, signal_fd,
                      local_mip_mac_table, num_eth_sds);
                  exit(EXIT_FAILURE);
                }
              }

              if(debug){
                fprintf(stdout,"Sent %ld bytes to client.\n",ret);
              }

              pong = 1;
            } /* Received a transport packet END */

          } /* Iterating through events triggered while waiting for PONG END */

        } /* Waiting for PONG response END */

        if(debug) print_arp_table(mip_arp_table);

      } /* Communication over IPC with connected application END */

      /* Incoming data over ethernet */
      else{
        int tra; /* Indicates the type of packet that was received */
        char buf[MAX_MSG_SIZE];
        uint8_t src_mip;

        /* The source MIP address of the received packet will be stored in
        * src_mip, and the message will be stored in buf */
        tra = recv_mip_packet(mip_arp_table, local_mip_mac_table,
            events[i].data.fd, &src_mip,buf,debug);

        if(tra == -1){
          perror("main: recv: eth socket");
          close_sockets(un_sock, un_sock_name, un_sock_conn, signal_fd,
              local_mip_mac_table, num_eth_sds);
          exit(EXIT_FAILURE);
        }
        /* The received packet was not for this host */
        else if(tra == -2){
          continue;
        }

        if(debug) print_arp_table(mip_arp_table);

        /* The received packet was a transport packet */
        if(tra == 0b100){
          /* Discard the packet if no server application is conencted to the
          * MIP daemon */
          if(un_sock_conn == -1){
            if(debug){
              fprintf(stdout,"No server connected. Discarding packet.\n");
            }
            continue;
          }

          if(debug){
            fprintf(stdout,"Packet was a ping.\n");
          }

          /* The received packet was a ping */

          /* Unix communication based on code from group session
          * https://github.uio.no/persun/inf3190/tree/master/plenum3 */

          /* Forward the ping message to the connected server application */
          struct msghdr ping_msg = { 0 };
          struct iovec ping_iov[1];

          ping_iov[0].iov_base = buf;
          ping_iov[0].iov_len = strlen(buf)+1;

          ping_msg.msg_iov = ping_iov;
          ping_msg.msg_iovlen = 1;

          ret = sendmsg(un_sock_conn, &ping_msg, 0);

          if(ret == -1){
            perror("main: sendmsg: un_sock_conn receive ping");
            close_sockets(un_sock, un_sock_name, un_sock_conn, signal_fd,
                local_mip_mac_table, num_eth_sds);
            exit(EXIT_FAILURE);
          }

          if(debug){
            fprintf(stdout,"Sent %ld bytes to server.\n",ret);
          }

          uint8_t pong_tra = 0b100;

          /* Wait for PONG response from the connected server application */

          /* A pong response message always has a fixed size */
          char pong_buf[IPC_PONG_RSP_SIZE];

          struct msghdr pong_msg = { 0 };
          struct iovec pong_iov[1];

          pong_iov[0].iov_base = pong_buf;
          pong_iov[0].iov_len = IPC_PONG_RSP_SIZE;

          pong_msg.msg_iov = pong_iov;
          pong_msg.msg_iovlen = 1;

          ret = recvmsg(un_sock_conn, &pong_msg, 0);

          if(ret == -1){
            perror("main: recvmsg: un_sock_conn send pong");
            close_sockets(un_sock, un_sock_name, un_sock_conn, signal_fd,
                local_mip_mac_table, num_eth_sds);
            exit(EXIT_FAILURE);
          }

          if(debug){
            fprintf(stdout,"Received %ld bytes from server:\n",ret);
            fprintf(stdout,"Message: \"%s\"\n\n",pong_buf);
            fprintf(stdout,"Sending pong response.\n");
          }

          /* Forward the PONG response to the host that the ping was received
          * from */
          ret = send_mip_packet(mip_arp_table, local_mip_mac_table, src_mip,
              pong_buf, pong_tra, 0, debug);

          if(ret == -1){
            perror("main: send_mip_packet: un_sock_conn send pong");
            close_sockets(un_sock, un_sock_name, un_sock_conn, signal_fd,
                local_mip_mac_table, num_eth_sds);
            exit(EXIT_FAILURE);
          }

        } /* Received transport packet END */

      } /* Received data over ethernet END */

    } /* Iterating through events triggered in the main loop END */

  } /* Polling sockets for event until keyboard interrupt END */

} /* int main() END */
