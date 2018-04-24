#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <time.h>
#include "transport_daemon.h"


int send_complete_packet(int mip_sock, uint8_t dest_mip, struct transport_packet *packet, int packet_size){
  ssize_t ret;

  struct msghdr packet_msg = { 0 };
  struct iovec packet_iov[2];

  packet_iov[0].iov_base = &dest_mip;
  packet_iov[0].iov_len = sizeof(dest_mip);

  packet_iov[1].iov_base = packet;
  packet_iov[1].iov_len = packet_size;

  packet_msg.msg_iov = packet_iov;
  packet_msg.msg_iovlen = 2;

  ret = sendmsg(mip_sock, &packet_msg, 0);

  if(ret == -1) return -1;

  return ret;
}











int resend_packets(struct conn_app *app_conn, struct socket_container *socks){
  int i;
  time_t now = time(NULL);
  for(i = 0; i < app_conn->num_ack_queue; i++){
    if(send_complete_packet(socks->mip, app_conn->mip, app_conn->sent_packets[i],
        app_conn->packet_size[i]) == -1) return -1;
    app_conn->packet_timestamp[i] = now;
  }
  return i;
}












struct transport_packet *create_packet(uint8_t pad_len, uint16_t port,
    uint16_t seq_num, uint8_t *payload, int payload_len){

  struct transport_packet *packet = (struct transport_packet *)
      calloc(sizeof(struct transport_packet) + payload_len, 1);

  packet->pad_and_port[0] = 0 | (pad_len<<6);
  packet->pad_and_port[0] |= port >> 8;
  packet->pad_and_port[1] = 0 | port;
  packet->seq_num = htons(seq_num);

  if(payload_len > 0){
    if(!payload){
      free(packet);
      return NULL;
    }
    memcpy(packet->payload, payload, payload_len);
  }

  return packet;
}










int remove_app_conn(int app_sock, struct socket_container *socks){
  int i,j;

  /* Find the entry to remove */
  for(i = 0; i < socks->num_apps; i++){
    if(socks->app_conns[i].sock == app_sock){

      /* Free the packets sent from the application, if any */
      for(j = 0; j < socks->app_conns[i].num_ack_queue; j++){
        free(socks->app_conns[i].sent_packets[j]);
      }

      /* Reorder the applications */
      for(j = i; j < socks->num_apps - 1; j++){
        socks->app_conns[j] = socks->app_conns[j+1];
        memset(&socks->app_conns[j+1], 0, sizeof(struct conn_app));
      }

      socks->num_apps--;
      break;
    }
  }

  /* Remove the socket from the epoll instance */
  epoll_ctl(socks->epfd, EPOLL_CTL_DEL, app_sock, NULL);
  close(app_sock);

  return socks->num_apps;
}










int send_packet_to_mip(int mip_sock, struct conn_app *app_conn,
    uint8_t *payload, int payload_len){

  ssize_t ret;
  uint8_t pad_len = 0;
  struct transport_packet *packet;

  /* Calculate padding and payload length */
  if(payload_len % 4 > 0) pad_len = 4 - (payload_len % 4);
  payload_len += pad_len;
  app_conn->seq_num++;

  packet = create_packet(pad_len, app_conn->port,
      app_conn->seq_num, payload, payload_len);

  if(!packet){
    return -1;
  }

  struct msghdr packet_msg = { 0 };
  struct iovec packet_iov[2];

  packet_iov[0].iov_base = &app_conn->mip;
  packet_iov[0].iov_len = sizeof(app_conn->mip);

  packet_iov[1].iov_base = packet;
  packet_iov[1].iov_len = sizeof(struct transport_packet) + payload_len;

  packet_msg.msg_iov = packet_iov;
  packet_msg.msg_iovlen = 2;

  ret = sendmsg(mip_sock, &packet_msg, 0);

  if(ret == -1){
    free(packet);
    return -1;
  }

  /* Add the packet to the window of sent packets, add a timestamp for it,
   * update the number of packets in the window, and the sequence number for
   * the session */
  app_conn->sent_packets[app_conn->num_ack_queue] = packet;
  app_conn->packet_timestamp[app_conn->num_ack_queue] = time(NULL);
  app_conn->packet_size[app_conn->num_ack_queue] =
      sizeof(struct transport_packet) + payload_len;
  app_conn->num_ack_queue++;

  return ret;

}












int recv_from_app(int app_sock, struct socket_container *socks,
    struct connection_data *conn_data, int debug){

  /* Receive a file segment from the client application */
  ssize_t ret;
  int i;
  struct conn_app *app_conn;

  for(i = 0; i < socks->num_apps; i++){
    if(socks->app_conns[i].sock == app_sock){
      app_conn = &socks->app_conns[i];
      break;
    }
  }

  uint8_t file_segment[1492] = { 0 };
  struct msghdr app_msg = { 0 };
  struct iovec app_iov[1];

  app_iov[0].iov_base = file_segment;
  app_iov[0].iov_len = MAX_PAYLOAD_SIZE;

  app_msg.msg_iov = app_iov;
  app_msg.msg_iovlen = 1;

  ret = recvmsg(app_sock, &app_msg, 0);

  if(ret == -1){
    return -1;
  }else if(ret == 0){
    /* Application has performed an orderly shutdown, remove it */

    if(debug){
      if(app_conn->mip == 255){
        fprintf(stdout, "File server listning on port %d has disconnected.\n",
            app_conn->port);
      }else{
        fprintf(stdout, "Client application sending file to MIP address %d on "
            "port %d has disconnected.\n", app_conn->mip, app_conn->port);
      }
    }

    remove_app_conn(app_sock, socks);

    return -2;
  }

  ret = send_packet_to_mip(socks->mip, app_conn, file_segment, ret);

  if(ret == -1){
    return -1;
  }

  if(app_conn->num_ack_queue == WINDOW_SIZE){
    struct epoll_event ep_app_ev = { 0 };
    ep_app_ev.data.fd = app_sock;
    epoll_ctl(socks->epfd, EPOLL_CTL_MOD, app_sock, &ep_app_ev);
  }

  return app_conn->num_ack_queue;

}












int port_listening(int port, struct socket_container *socks){
  int i;
  for(i = 0; i < socks->num_apps; i++){
    if(port == socks->app_conns[i].sock && socks->app_conns[i].mip == 255){
      return socks->app_conns[i].sock;
    }
  }
  return -1;
}












int is_conn(int sock, struct conn_app *app_conns, int sock_len){
  int i;
  for(i = 0; i < sock_len; i++){
    if(app_conns[i].sock == sock) return i;
  }

  return -1;
}










uint8_t get_padding_length(struct transport_packet *packet){
  return packet->pad_and_port[0] >> 6;
}










uint16_t get_port_number(struct transport_packet *packet){
  uint16_t port = 0 | ((packet->pad_and_port[0] & 0b00111111) << 8);
  port &= packet->pad_and_port[1];
  return port;
}










int check_seq_num(uint16_t to_check, uint16_t check_against, int w_size){
  if(to_check == check_against){
    return 1;
  }

  /* Check if the sequence number indicates a previously acked packet that
   * has been retransmitted, taking into account possible wrap-around of
   * the sequence number */
  else if(to_check < check_against){
    if(check_against < w_size){
      return 2;
    }else{
      if(to_check > (check_against - w_size)){
        return 2;
      }
    }
  }else if(to_check > (uint16_t)(check_against - w_size)){
    if(check_against < w_size){
      return 2;
    }
  }

  else if(to_check == 0){
    return 3;
  }

  return 0;
}











int check_session(struct connection_data *conn_data, uint8_t src_mip,
    uint8_t pad_len, uint16_t port, uint16_t seq_num){
  int i,ret;

  for(i = 0; i < conn_data->num_sessions; i++){
    if(src_mip == conn_data->mip_conns[i] && port == conn_data->port_conns[i]){

      ret = check_seq_num(seq_num, conn_data->seq_nums[i], WINDOW_SIZE);
      if(ret == 1){
        conn_data->seq_nums[i]++;
        break;
      }else if(ret == 2){
        return -1;
      }else if(ret == 3){
        /* Treating any packet with sequence number 0 as the start of a new
         * session */
        conn_data->seq_nums[i] = seq_num + 1;
        break;
      }else{
        return -2;
      }
    }
  }

  /* If no data was stored for this source port / MIP combination, make a new
   * entry for it */
  if(i == conn_data->num_sessions){
    if(seq_num != 0){
      /* Not the start of a new sequence */
      return -3;
    }

    conn_data->num_sessions++;

    conn_data->mip_conns = (uint8_t *) realloc(conn_data->mip_conns,
        conn_data->num_sessions);

    conn_data->port_conns = (uint16_t *) realloc(conn_data->port_conns,
        conn_data->num_sessions * sizeof(uint16_t));

    conn_data->seq_nums = (uint16_t *) realloc(conn_data->seq_nums,
        conn_data->num_sessions * sizeof(uint16_t));

    conn_data->mip_conns[conn_data->num_sessions] = src_mip;
    conn_data->port_conns[conn_data->num_sessions] = port;
    conn_data->seq_nums[conn_data->num_sessions] = seq_num + 1;
  }

  return conn_data->num_sessions;

}












int send_packet_to_app(int sock, uint8_t *payload, uint8_t src_mip,
    uint16_t seq_num, int payload_length){
  ssize_t ret;
  struct msghdr file_seg_msg = { 0 };
  struct iovec file_seg_iov[3];

  file_seg_iov[0].iov_base = &src_mip;
  file_seg_iov[0].iov_len = sizeof(src_mip);

  file_seg_iov[1].iov_base = &seq_num;
  file_seg_iov[1].iov_len = sizeof(seq_num);

  file_seg_iov[2].iov_base = payload;
  file_seg_iov[2].iov_len = payload_length;

  file_seg_msg.msg_iov = file_seg_iov;
  file_seg_msg.msg_iovlen = 3;

  ret = sendmsg(sock, &file_seg_msg, 0);

  return ret;
}














int send_ack(int sock, uint16_t seq_num, uint16_t port, uint8_t mip){
  struct transport_packet *packet = create_packet(0, port, seq_num, NULL, 0);

  if(!packet){
    return -1;
  }

  ssize_t ret;

  struct msghdr ack_msg = { 0 };
  struct iovec ack_iov[2];

  ack_iov[0].iov_base = &mip;
  ack_iov[0].iov_len = sizeof(mip);

  ack_iov[1].iov_base = packet;
  ack_iov[1].iov_len = PACKET_HDR_SIZE;

  ack_msg.msg_iov = ack_iov;
  ack_msg.msg_iovlen = 2;

  ret = sendmsg(sock, &ack_msg, 0);

  free(packet);

  return ret;
}












int update_client(struct conn_app *app_conn){

  struct msghdr update_msg = { 0 };
  struct iovec update_iov[1];

  update_iov[0].iov_base = &app_conn->payload_bytes_sent;
  update_iov[0].iov_len = sizeof(app_conn->payload_bytes_sent);

  update_msg.msg_iov = update_iov;
  update_msg.msg_iovlen = 1;

  if(sendmsg(app_conn->sock, &update_msg, 0) == -1) return -1;

  return app_conn->payload_bytes_sent;
}












int received_ack(struct socket_container *socks, uint16_t seq_num,
    uint16_t port, uint8_t mip){

  int i,j;
  int ret = -1;

  for(i = 0; i < socks->num_apps; i++){
    if(socks->app_conns[i].port == port && socks->app_conns[i].mip == mip){
      struct conn_app *app_conn = &socks->app_conns[i];
      int packet_num;

      if(app_conn->num_ack_queue == 0){
        break;
      }

      ret = check_seq_num(seq_num, app_conn->seq_num,
          app_conn->num_ack_queue);

      /* Check that the ack concerns one of the packets in the window */
      if(ret == 0 || ret == 3){
        ret = -2;
        break;
      }

      /* Check which packet the ack was for, taking into account possible
       * wrap-around of the sequence number */
      if(seq_num > app_conn->seq_num){
        packet_num = app_conn->num_ack_queue -
            ((app_conn->seq_num + (SEQ_NUM_MAX + 1)) - seq_num);
      }
      else{
        packet_num = app_conn->num_ack_queue -
            (app_conn->seq_num - seq_num);
      }

      /* All packets up to and including the on that was acked have been
       * received, because of the cumulative ack in Go-Back-N, remove them from
       * the window */
      for(j = 0; j < packet_num; j++){
        free(app_conn->sent_packets[j]);
        app_conn->payload_bytes_sent +=
            app_conn->packet_size[j] - PACKET_HDR_SIZE;
      }
      for(j = 0; j < app_conn->num_ack_queue - packet_num; j++){
        app_conn->sent_packets[j] = app_conn->sent_packets[j + packet_num];
        app_conn->packet_size[j] = app_conn->packet_size[j + packet_num];
        app_conn->packet_timestamp[j] =
            app_conn->packet_timestamp[j + packet_num];
      }
      for(; j < app_conn->num_ack_queue; j++){
        app_conn->sent_packets[j] = NULL;
        app_conn->packet_size[j] = 0;
        app_conn->packet_timestamp[j] = 0;
      }

      /* Make sure the socket is armed in the epoll instance if there is room
       * in the packet window */
      if(app_conn->num_ack_queue < WINDOW_SIZE){
        struct epoll_event ep_app_ev = { 0 };
        ep_app_ev.events = EPOLLIN;
        ep_app_ev.data.fd = app_conn->sock;
        epoll_ctl(socks->epfd, EPOLL_CTL_MOD, app_conn->sock,
            &ep_app_ev);
      }

      /* Update the amount of packets waiting for acks */
      app_conn->num_ack_queue =- packet_num;

      ret = app_conn->num_ack_queue;

      /* Update the client on the sending progress */
      if(update_client(app_conn) == -1) ret = -1;

      break;
    }
  }
  return ret;
}













int recv_transport_packet(struct socket_container *socks,
    struct connection_data *conn_data){

  ssize_t ret;

  struct msghdr mip_msg = { 0 };
  struct iovec mip_iov[2];

  uint8_t src_mip;
  struct transport_packet *packet =
      (struct transport_packet *) malloc(MAX_PACKET_SIZE);

  mip_iov[0].iov_base = &src_mip;
  mip_iov[0].iov_len = sizeof(src_mip);

  mip_iov[1].iov_base = packet;
  mip_iov[1].iov_len = MAX_PACKET_SIZE;

  mip_msg.msg_iov = mip_iov;
  mip_msg.msg_iovlen = 2;

  ret = recvmsg(socks->mip, &mip_msg, 0);

  if(ret == -1){
    free(packet);
    return -1;
  }
  else if(ret == 0){
    /* MIP daemon has performed an orderly shutdown */
    free(packet);
    return -2;
  }

  uint8_t pad_len = get_padding_length(packet);
  uint16_t port = get_port_number(packet);
  uint16_t seq_num = ntohs(packet->seq_num);
  int payload_length = ret - sizeof(src_mip) - PACKET_HDR_SIZE - pad_len;

  if(payload_length == 0){
    free(packet);
    /* Packet was an ACK */
    if(received_ack(socks, seq_num, port, src_mip) == -1){
      return -1;
    }
    return -3;
  }

  ret = check_session(conn_data, src_mip, pad_len, port, seq_num);

  if(ret == -1){
    free(packet);
    /* Previously acked packet, resend ack */

    ret = send_ack(socks->mip, seq_num, port, src_mip);

    if(ret == -1){
      return -1;
    }

    return 0;

  }

  if(ret < -1){
    /* Bad sequence number */
    free(packet);
    return -4;
  }

  int server_sock = port_listening(port, socks);

  if(server_sock == -1){
    free(packet);
    return -5;
  }

  ret = send_packet_to_app(server_sock, packet->payload, src_mip, seq_num,
      payload_length);

  free(packet);

  if(ret == -1){
    return -1;
  }

  ret = send_ack(socks->mip, seq_num, port, src_mip);

  if(ret == -1){
    return -1;
  }

  return 1;
}










/**
 * Handler for receiving a signal on the provided signal_fd
 *
 * @param signal_fd       The descriptor which received the signal.
 * @return                Returns 0 if the signal was a keyboard interrupt, 0
 *                        otherwise.
 */
int keyboard_signal(int signal_fd){
  struct signalfd_siginfo sig_info;
  ssize_t sig_size;

  sig_size = read(signal_fd, &sig_info, sizeof(struct signalfd_siginfo));

  /* Close all sockets and close stop the daemon */
  if(sig_size == 0){
    perror("\nCtrl-d: Received EOF signal from keyboard, stopping\n");
    return 0;
  }
  if(sig_info.ssi_signo == SIGINT){
    fprintf(stderr,"\nCtrl-c: Received interrupt from keyboard, "
        "stopping daemon\n");
    return 0;
  }
  else if(sig_info.ssi_signo == SIGQUIT){
    fprintf(stderr,"\nCtrl-\\: Received interrupt from keyboard, "
        "stopping daemon\n");
    return 0;
  }

  return 1;
}










void free_conn_data(struct connection_data *conn_data){
  free(conn_data->seq_nums);
  free(conn_data->port_conns);
  free(conn_data->mip_conns);
  free(conn_data);
}










int create_epoll_instance(struct socket_container *socks){

  /* Code concerning epoll is based on code from 'man 7 epoll' and group
  * session https://github.uio.no/persun/inf3190/blob/master/plenum3/epoll.c */

  int epfd = epoll_create(1);

  if (epfd == -1){
    return -1;
  }

  /* Add the unix socket used to listen for connections from applications to
  * the MIP daemon.
  * Using EPOLLONESHOT to make sure events for connections to the MIP daemon
  * from an application is only triggered in the main loop of the MIP daemon */
  struct epoll_event ep_app_ev = { 0 };
  ep_app_ev.events = EPOLLIN;
  ep_app_ev.data.fd = socks->app;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, socks->app, &ep_app_ev) == -1){
    return -2;
  }

  struct epoll_event ep_mip_ev = { 0 };
  ep_mip_ev.events = EPOLLIN;
  ep_mip_ev.data.fd = socks->mip;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, socks->mip,
      &ep_mip_ev) == -1){
    return -3;
  }

  struct epoll_event ep_sig_ev = { 0 };
  ep_sig_ev.events = EPOLLIN | EPOLLERR;
  ep_sig_ev.data.fd = socks->signal;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, socks->signal, &ep_sig_ev)
      == -1){
    return -4;
  }

  return epfd;
} /* create_epoll_instance() END */









int init_app(struct conn_app *app_conn, struct socket_container *socks, int epfd){

  ssize_t ret;
  uint8_t mip;
  uint16_t port;

  struct msghdr init_msg = { 0 };
  struct iovec init_iov[2];

  init_iov[0].iov_base = &mip;
  init_iov[0].iov_len = sizeof(mip);

  init_iov[1].iov_base = &port;
  init_iov[1].iov_len = sizeof(port);

  init_msg.msg_iov = init_iov;
  init_msg.msg_iovlen = 2;

  ret = recvmsg(app_conn->sock,&init_msg,0);

  if(ret != 3){
    close(app_conn->sock);
    return 0;
  }else if(ret == 0){
    if(epoll_ctl(epfd, EPOLL_CTL_DEL, app_conn->sock, NULL) == -1){
      close(app_conn->sock);
      return -1;
    }
    close(app_conn->sock);
    return 0;
  }

  app_conn->mip = mip;
  app_conn->port = port;
  app_conn->seq_num = SEQ_NUM_MAX;
  app_conn->num_ack_queue = 0;
  app_conn->payload_bytes_sent = 0;


  /* Add the socket to the epoll instance */
  struct epoll_event ep_conn_ev = { 0 };
  ep_conn_ev.events = EPOLLIN;
  ep_conn_ev.data.fd = app_conn->sock;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, app_conn->sock, &ep_conn_ev) == -1){
    close(app_conn->sock);
    return -1;
  }

  return 1;

}










int connect_socket(char* socket_name){
  /* Create unix IPC routing and forwarding sockets */
  struct sockaddr_un un_addr = { 0 };

  int conn_sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if(conn_sock == -1){
    return -1;
  }

  /* Bind the path and connect */
  un_addr.sun_family = AF_UNIX;
  strncpy(un_addr.sun_path, socket_name, sizeof(un_addr.sun_path));

  if(connect(conn_sock, (struct sockaddr *) &un_addr,
      sizeof(struct sockaddr_un)) == -1){
    return -2;
  }

  return conn_sock;
}









/**
 * Creates a signal handler which can be used to handle keyboard interrupts
 * when waiting for events in the epoll instance
 *
 * @returns       Returns a descriptor for a signal handler on success and -1
 *                on error.
 */
int setup_signal_fd(){
  /* Create a signal handler to be used when waiting for the epoll instance */
  int signal_fd;

  sigset_t mask;

  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGQUIT);

  sigprocmask(SIG_BLOCK, &mask, NULL);

  signal_fd = signalfd(-1, &mask, 0);
  if(signal_fd == -1){
    return -1;
  }

  return signal_fd;
}












void close_sockets(struct socket_container *socks, int unlink_mip_path){
  int i;
  for (i = 0; i < socks->num_apps; i++){
    close(socks->app_conns[i].sock);
  }
  struct sockaddr_un app_addr = { 0 };
  socklen_t app_addrlen = sizeof(app_addr);
  getsockname(socks->app, (struct sockaddr*) &app_addr, &app_addrlen);
  close(socks->app);
  if(unlink_mip_path) unlink(app_addr.sun_path);

  struct sockaddr_un mip_addr = { 0 };
  socklen_t mip_addrlen = sizeof(mip_addr);
  getsockname(socks->mip, (struct sockaddr*) &mip_addr,
    &mip_addrlen);
  close(socks->mip);
  unlink(mip_addr.sun_path);
  close(socks->signal);

  free(socks);
}








/**
 * Prints usage information to stderr for the user
 *
 * @param file_name Filename of the user executed, argv[0]
 * @return          none
 */
void print_help(char *file_name){
  fprintf(stderr,"USAGE: %s <timeout> <Socket_application> "
      "<Socket_transport> <timeout>\n", file_name);
  fprintf(stderr,"[-h]: optional help argument\n");
  fprintf(stderr,"[-d]: optional debug argument, prints communication "
    "information\n");
  fprintf(stderr,"<timeout>: timeout in seconds to be applied by the "
    "transport daemon\n");
  fprintf(stderr,"<Socket_application>: name of socket for IPC with "
    "MIP daemon\n");
  fprintf(stderr,"<Socket_transport>: name of socket for IPC with "
    "connected transport applications\n");
  exit(EXIT_FAILURE);
}









/**
 * Sets up a unix socket and binds it to the provided name, and listens to it
 *
 * @param un_sock_name Name to bind the unix socket to
 * @return             Returns the socket descriptor of the new unix socket on
 *                     success, -1 if socket() fails, -2 if bind() fails, -3 if
 *                     listen() fails
 *
 */
int setup_listen_socket(char* un_sock_name){
  /* Using SOCK_SEQPACKET for a connection-oriented, sequence-preserving socket
   * that preserves message boundaries */
  int un_sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);

  if (un_sock == -1){
    return -1;
  }

  /* Based on code from 'man 2 bind' */

  struct sockaddr_un un_sock_addr;
  memset(&un_sock_addr, 0, sizeof(struct sockaddr_un));

  un_sock_addr.sun_family = AF_UNIX;

  strncpy(un_sock_addr.sun_path,un_sock_name,sizeof(un_sock_addr.sun_path));


  if(bind (un_sock, (struct sockaddr*)&un_sock_addr,
  sizeof(struct sockaddr_un)) == -1)
  {
    return -2;
  }

  if(listen(un_sock, LISTEN_BACKLOG_UNIX) == -1){
    return -3;
  }

  return un_sock;
} /* setup_unix_socket() END */
