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
#include <errno.h>
#include "transport_daemon.h"




/**
 * Sends a pre-contructed transport packet to the MIP daemon
 *
 * @param mip_sock      The socket connected to the MIP daemon, to send the
 *                      packet through.
 * @param dest_mip      MIP address to send the packet to.
 * @param packet        Packet to send.
 * @param packet_size   Size of the packet.
 * @return              Returns amount of bytes sent to the MIP daemon on
 *                      success, -1 on error.
 */
int send_complete_packet(int mip_sock, uint8_t dest_mip,
    struct transport_packet *packet, int packet_size){

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




/**
 * Resends all un-acked packets associated with the local application
 * connection stored in the struct pointer to by app_conn
 *
 * @param app_conn  Pointer to structure containing data concerning local
 *                  connection with an application. Un-acked packets in this
 *                  struct will be resent, according to the data stored about
 *                  the connection.
 * @param socks     Pointer to structure containing data about local
 *                  connections. Used for sending data to the MIP daemon.
 * @return          Returns amount of packets resent on success, and -1 on
 *                  error.
 */
int resend_packets(struct conn_app *app_conn, struct socket_container *socks){
  int i;
  time_t now = time(NULL);

  /* Loop through all un-acked packets and re-send them */
  for(i = 0; i < app_conn->num_ack_queue; i++){
    if(send_complete_packet(socks->mip, app_conn->mip,
        app_conn->sent_packets[i], app_conn->packet_size[i]) == -1) return -1;
    app_conn->packet_timestamp[i] = now;
  }
  return i;
}




/**
 * Creates a transport packet and returns a pointer to it, using the supplied
 * arguments.
 *
 * @param pad_len     Length of the padding used in the packet.
 * @param port        The port to send the packet on.
 * @param seq_num     The sequence number of the packet.
 * @param payload     The payload of the packet.
 * @param payload_len The size of the payload in bytes.
 * @return            Returns the created packet on success, and NULL on error.
 */
struct transport_packet *create_packet(uint8_t pad_len, uint16_t port,
    uint16_t seq_num, uint8_t *payload, int payload_len){

  /* Allocate space based on payload length */
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
    /* The call to calloc when allocating memory makes the packet padded with
     * 0 bytes if necessary */
    memcpy(packet->payload, payload, payload_len);
  }

  return packet;
}




/**
 * Removes the local application connection associated with the supplied socket
 * from the data concerning local connections.
 *
 * @param app_sock  The socket associated with the connection to be removed.
 * @param socks     Pointer to structure containing data concerning local
 *                  connections.
 * @return          Returns number of connected applications after removal.
 */
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



/**
 * Constructs a transport packet using the suppplied arguments, and sends it to
 * a MIP address on a port specified in the application connection supplied,
 * via the MIP daemon.
 *
 * @param mip_sock    The socket for MIP daemon communication, to send the
 *                    packet through.
 * @param app_conn    Pointer to structure containing data about a local
 *                    application connection. Packet metadata will be filled in
 *                    based on the data in this structure.
 * @param payload     The payload of the packet to send.
 * @param payload_len The size of the payload.
 * @param debug       Indicates if debug information should be logged to
 *                    console.
 * @return            Returns amount of bytes sent to the MIP daemon on
 *                    success and -1 on error.
 */
int send_packet_to_mip(int mip_sock, struct conn_app *app_conn,
    uint8_t *payload, int payload_len, int debug){

  ssize_t ret;
  uint8_t pad_len = 0;
  struct transport_packet *packet;

  /* Calculate padding and payload length */
  if(payload_len % 4 > 0) pad_len = 4 - (payload_len % 4);
  payload_len += pad_len;

  /* Increment the sequence number (initialized to SEQ_NUM_MAX) */
  app_conn->seq_num++;

  /* Create the packet */
  packet = create_packet(pad_len, app_conn->port,
      app_conn->seq_num, payload, payload_len);

  if(!packet){
    return -1;
  }

  /* Send the packet to the MIP daemon */
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
  app_conn->packet_pad[app_conn->num_ack_queue] = pad_len;
  app_conn->num_ack_queue++;

  if(debug){
    fprintf(stdout, "Sent packet of %ld bytes to MIP daemon.\n", ret);
    fprintf(stdout, "Sequence number: %d\tNumber of packets waiting for ack: %d\n", app_conn->seq_num, app_conn->num_ack_queue);
  }

  return ret;

}



/**
 * Handles incoming data from a connected application. If the data is a
 * file segment from a connected client application, the file segment is sent
 * a transport packet is constructed and is sent via the MIP daemon to the
 * recipient specified in the data concerning the local application connection
 * found in the supplied local connection information.
 * If instead the application has disconnected, the information
 * regarding the local application connection is deleted.
 *
 * @param app_sock      The socket the data is to be received from.
 * @param epoll_events  The type of event epoll event which triggered this
 *                      functions. Indicates if the application has
 *                      disconnected.
 * @param socks         Pointer to structure containing data concerning local
 *                      connections. Used for constructing the header of the
 *                      transport packet, and determining the recipient.
 * @param debug         Indicates if debug information should be logged to the
 *                      console.
 * @return              Returns the number of packets awaiting acks that were
 *                      sent with data from the client application that the
 *                      data was received from, -1 on error, and -2 if the
 *                      application has disconnected.
 */
int recv_from_app(int app_sock, uint32_t epoll_events,
    struct socket_container *socks, int debug){

  ssize_t ret;
  int i;
  struct conn_app *app_conn;

  /* Find the data concerning the connected application that data is being
   * received from */
  for(i = 0; i < socks->num_apps; i++){
    if(socks->app_conns[i].sock == app_sock){
      app_conn = &socks->app_conns[i];
      break;
    }
  }

  /* Receive a file segment from the client application */
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
  }else if(ret == 0 || (epoll_events & EPOLLHUP) == EPOLLHUP){
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

  if(debug){
    fprintf(stdout, "Received file segment of %ld bytes from transport client.\n", ret);
    fprintf(stdout, "Destination MIP: %3d\tPort: %5d\n", app_conn->mip, app_conn->port);
  }

  /* Send the packet */
  ret = send_packet_to_mip(socks->mip, app_conn, file_segment, ret, debug);

  if(ret == -1){
    return -1;
  }

  /* Stop listening for events from the connected application if the packet
   * window is full */
  if(app_conn->num_ack_queue == WINDOW_SIZE){
    struct epoll_event ep_app_ev = { 0 };
    ep_app_ev.data.fd = app_sock;
    epoll_ctl(socks->epfd, EPOLL_CTL_MOD, app_sock, &ep_app_ev);
  }

  return app_conn->num_ack_queue;

}



/**
 * Checks if any server application is listening on the supplied port.
 *
 * @param port  The port to check if any server application is listening on.
 * @param socks Pointer to structure containing data concerning local
 *              connections. To check for listening server applications in.
 * @return      Returns the socket of the server application listening to the
 *              port if there is one, and -1 if there are none listening.
 */
int port_listening(int port, struct socket_container *socks){
  int i;

  /* Go through all connected applications and check if they are a server and
   * are listning to the provided port */
  for(i = 0; i < socks->num_apps; i++){
    if(port == socks->app_conns[i].port && socks->app_conns[i].mip == 255){
      return socks->app_conns[i].sock;
    }
  }
  return -1;
}




/**
 * Checks if the socket supplied to the function is a socket associated with
 * a connected application.
 *
 * @param sock      The socket to check.
 * @param app_conns Array of structures containing information concerning
 *                  connected applications.
 * @param num_conns The number of connected applications stored in the
 *                  app_conns array.
 * @return          Returns the index of the connection in the app_conns array
 *                  if it is there, and -1 if not.
 */
int is_conn(int sock, struct conn_app *app_conns, int num_conns){
  int i;

  /* Go through all connected applications and check if any of them is
   * associated with the provided socket */
  for(i = 0; i < num_conns; i++){
    if(app_conns[i].sock == sock) return i;
  }

  return -1;
}



/**
 * Extracts the padding length stored in the header of the supplied packet.
 *
 * @param packet  Pointer to the packet to extract the padding length from.
 * @return        Returns the padding length stored in the packet header.
 */
uint8_t get_padding_length(struct transport_packet *packet){
  return packet->pad_and_port[0] >> 6;
}




/**
 * Extracts the port number stored in the header of the supplied packet.
 *
 * @param packet  Pointer to the packet to extract the port number from.
 * @return        Returns the port number stored in the packet header.
 */
uint16_t get_port_number(struct transport_packet *packet){
  uint16_t port = 0 | ((packet->pad_and_port[0] & 0b00111111) << 8);
  port |= packet->pad_and_port[1];
  return port;
}



/**
 * Checks the first supplied sequence number agains the second, using the
 * supplied window size, to see if they match, if the sequence number is within
 * the window, and if it is zero.
 *
 * @param to_check      Sequence number to check.
 * @param check_against Sequence number to check against.
 * @param w_size        Size of the window the check number could be within.
 * @return              Returns 1 if the sequence numbers are equal.
 * @return              Returns 2 if the sequence number is within the window
 *                      specified by w_size, and the sequence number is not 0.
 *                      Returns 3 if the sequence number is outside the window
 *                      specified by w_size, and the sequence number is 0.
 *                      Returns 4 if the sequence number is within the window
 *                      specified by w_size, and the sequence number is 0.
 *                      Returns 0 if the sequence number is otherwise outside
 *                      the window specified by w_size.
 */
int check_seq_num(uint16_t to_check, uint16_t check_against, int w_size){
  if(to_check == check_against){
    return 1;
  }

  /* Check if the sequence number indicates a previously acked packet that
   * has been retransmitted, taking into account possible wrap-around of
   * the sequence number */
  else if(to_check < check_against){
    if(check_against < w_size){
      if(to_check == 0){
        return 4;
      }
      return 2;
    }else{
      if(to_check > (check_against - w_size)){
        if(to_check == 0){
          return 4;
        }
        return 2;
      }
    }
  }else if(to_check > (uint16_t)(check_against - w_size)){
    if(check_against < w_size){
      if(to_check == 0){
        return 4;
      }
      return 2;
    }
  }

  if(to_check == 0){
    return 3;
  }

  return 0;
}




/**
 * Checks if there exists a session for the provided MIP address and port, and
 * if the sequence number either matches the expected one, or is within the
 * packet window. If there is none, one is created if the sequence number
 * provided is zero. If there is, and the sequence number indicates that it is
 * the start of a new session, in which case a new session is created and the
 * previous session is discarded.
 *
 * @param conn_data Pointer to structure containing data concerning remote
 *                  connection sessions. Used to check for previous existing
 *                  sessions and storing new sessions, as well as checking the
 *                  provided sequence number.
 * @param src_mip   The MIP address for the session to look up and possibly
 *                  create.
 * @param port      The port for the session to look up and possibly create.
 * @param seq_num   The sequence number to check for match against the session.
 * @param debug     Indicates if debug information should be logged to the
 *                  console.
 * @return          Returns 0 if the sequence number matched the expected
 *                  sequence number of the existing session, -1 if the it is
 *                  within the packet window, and no new session is created, -2
 *                  if it was outside the packet window, and no new session is
 *                  created, -3 if there was no existing session, but the
 *                  sequence number did not indicate the start of a new
 *                  session, 1 if the sequence number was within the window,
 *                  but indicated the start of a new session, and 2 if there
 *                  was no existing session and the sequence number indicated
 *                  the start of a new session.
 */
int check_session(struct connection_data *conn_data, uint8_t src_mip,
    uint16_t port, uint16_t seq_num, int debug){
  int i,ret = 0;

  /* Iterate through all sessions */
  for(i = 0; i < conn_data->num_sessions; i++){

    /* If it is the relevant session */
    if(src_mip == conn_data->mip_conns[i] && port == conn_data->port_conns[i]){

      /* Verify the sequence number provided */
      ret = check_seq_num(seq_num, conn_data->seq_nums[i], WINDOW_SIZE);

      /* If it was the expected sequence number */
      if(ret == 1){

        if(debug){
          fprintf(stdout, "Expected sequence number: %d\n",
              conn_data->seq_nums[i]);
        }

        conn_data->seq_nums[i]++;
        ret = 0;
        break;
      }
      /* If it was within the packet window, and not 0 */
      else if(ret == 2){
        return -1;
      }
      /* If it was zero */
      else if(ret == 3 || ret == 4){
        /* Treating any packet with sequence number 0 as the start of a new
         * session */
        if(debug){
          fprintf(stdout, "Expected sequnce number: %d\n",
              conn_data->seq_nums[i]);
          fprintf(stdout, "Sequence number of packet was %d, indicating the "
              "start of a new session.\n", seq_num);
          fprintf(stdout, "Treating old session as done and establishing new "
              "session.\n");
        }
        ret = 1;
        conn_data->seq_nums[i] = seq_num + 1;
        break;
      }
      /* If it was not within the packet window, and not 0 */
      else{
        if(debug){
          fprintf(stdout, "Expected sequence number: %d\n",
              conn_data->seq_nums[i]);
          fprintf(stdout, "Sequence number of packet was %d, and outside the "
              "expected window of %d packets, discarding packet.\n", seq_num,
              WINDOW_SIZE);
        }
        return -2;
      }
    }
  }

  /* If no data was stored for this source port / MIP combination, make a new
   * session for it */
  if(i == conn_data->num_sessions){
    if(debug){
      fprintf(stdout, "Establishing new session for MIP address %d and port "
          "%d.\n", src_mip, port);
    }

    ret = 2;

    if(seq_num != 0){
      /* Not the start of a new sequence */
      return -3;
    }

    conn_data->num_sessions++;

    /* Initialize the session */
    conn_data->mip_conns = (uint8_t *) realloc(conn_data->mip_conns,
        conn_data->num_sessions);

    conn_data->port_conns = (uint16_t *) realloc(conn_data->port_conns,
        conn_data->num_sessions * sizeof(uint16_t));

    conn_data->seq_nums = (uint16_t *) realloc(conn_data->seq_nums,
        conn_data->num_sessions * sizeof(uint16_t));

    conn_data->mip_conns[conn_data->num_sessions - 1] = src_mip;
    conn_data->port_conns[conn_data->num_sessions - 1] = port;
    conn_data->seq_nums[conn_data->num_sessions - 1] = seq_num + 1;
  }

  return ret;

}




/**
 * Sends the payload of a transport packet, prepended with the source MIP
 * address and an int indicating whether or not this is the start of a new
 * session, to the server application connected to the provided socket.
 *
 * @param sock            The socket of the connected application to send the
 *                        payload to.
 * @param payload         The payload to send to the connected application.
 * @param src_mip         The origin MIP address of the transport packet.
 * @param new_session     Indicates whether this is the start of a new
 *                        session.
 * @param payload_length  Size of the payload in bytes.
 * @return                Returns amount of bytes sent to the connected
 *                        application on success, and -1 on error.
 */
int send_packet_to_app(int sock, uint8_t *payload, uint8_t src_mip,
    int new_session, int payload_length){

  ssize_t ret;
  struct msghdr file_seg_msg = { 0 };
  struct iovec file_seg_iov[3];

  file_seg_iov[0].iov_base = &src_mip;
  file_seg_iov[0].iov_len = sizeof(src_mip);

  file_seg_iov[1].iov_base = &new_session;
  file_seg_iov[1].iov_len = sizeof(new_session);

  file_seg_iov[2].iov_base = payload;
  file_seg_iov[2].iov_len = payload_length;

  file_seg_msg.msg_iov = file_seg_iov;
  file_seg_msg.msg_iovlen = 3;

  ret = sendmsg(sock, &file_seg_msg, 0);

  return ret;
}



/**
 * Sends an ack with the provided sequence number to the provided MIP address,
 * on the provided port.
 *
 * @param sock    Socket for MIP daemon communication, which the ack will go
 *                sent through.
 * @param seq_num The sequence number of the ack.
 * @param port    The port to send the ack on.
 * @param mip     The MIP address to send the ack to.
 * @param debug   Indicats if debug information should be logged to console.
 * @return        Returns amount of bytes sent to the MIP daemon on success and
 *                -1 on error.
 */
int send_ack(int sock, uint16_t seq_num, uint16_t port, uint8_t mip,
    int debug){

  if(debug){
    fprintf(stdout, "Sending ack for packet with sequence number %d for port "
        "%d, from MIP address %d.\n", seq_num, port, mip);
  }

  /* Create the ack */
  struct transport_packet *packet = create_packet(0, port, seq_num, NULL, 0);

  if(!packet){
    return -1;
  }

  /* Send it */
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



/**
 * Sends an update to a connected client application with how many bytes of
 * payload in total has been acked by the client's intended recipient.
 *
 * @param app_conn  Pointer to a structure containing data concerning the
 *                  connected application which will receive the update.
 * @param debug     Indicates if debug information should be logged to console.
 * @return          Returns the total amount of payload bytes acked by the
 *                  client's intended recipient on success, and -1 on error.
 */
int update_client(struct conn_app *app_conn, int debug){

  struct msghdr update_msg = { 0 };
  struct iovec update_iov[1];

  update_iov[0].iov_base = &app_conn->payload_bytes_sent;
  update_iov[0].iov_len = sizeof(app_conn->payload_bytes_sent);

  update_msg.msg_iov = update_iov;
  update_msg.msg_iovlen = 1;

  if(sendmsg(app_conn->sock, &update_msg, 0) == -1) return -1;

  if(debug){
    fprintf(stdout, "Sent confirmation to client that %ld bytes of file has "
        "reached recipient.\n", app_conn->payload_bytes_sent);
  }

  return app_conn->payload_bytes_sent;
}



/**
 * After an ack has been received, checks if the session specified by the
 * souce MIP address of the ack and the port it was sent on is waiting for an
 * ack for a packet with the sequence number of the ack. If it is, the packet
 * or all un-acked packets up to and including the sequence number of the acked
 * packet are removed from the packet window, and an update is sent to the
 * client the packets originated from with the total amount of payload bytes
 * that the sender of the ack has received from that client.
 *
 * @param socks   Pointer to a structure containing data concerning local
 *                connections. Used to check for un-acked packets, and to
 *                update the client.
 * @param seq_num The sequence number of the ack.
 * @param port    The port the ack was sent on.
 * @param mip     The source MIP address of the ack.
 * @param debug   Indicates if debug information should be logged to the
 *                console.
 * @return        Returns number of un-acked packets from the client whose
 *                packet was acked if a packet was indeed acked, -1 on error,
 *                -2 if there was a session with the source MIP address and
 *                port of the ack, but no packet was waiting for it, -3 if
 *                there was no session for the source MIP address and port,
 *                and -4 if the client application that had sent the packet
 *                that was acked has disconnected.
 */
int received_ack(struct socket_container *socks, uint16_t seq_num,
    uint16_t port, uint8_t mip, int debug){

  int i,j;
  int ret = -3;

  /* Iterate through all connected applications */
  for(i = 0; i < socks->num_apps; i++){

    /* If it is sending to the provided mip on the provided port */
    if(socks->app_conns[i].port == port && socks->app_conns[i].mip == mip){
      struct conn_app *app_conn = &socks->app_conns[i];
      int packet_num;

      /* If no packets are currently awaiting acks from the client */
      if(app_conn->num_ack_queue == 0){
        if(debug){
          fprintf(stdout, "No packets currently awaiting ack, discarding "
              "ack.\n");
        }
        break;
      }

      if(debug){
        if(app_conn->num_ack_queue == 1){
          fprintf(stdout, "Sequence numbers of packets awaiting acks: %d\n",
              app_conn->seq_num);
        }
        fprintf(stdout, "Sequence numbers of packets awaiting acks: %d - %d\n",
            app_conn->seq_num - (app_conn->num_ack_queue - 1),
            app_conn->seq_num);
      }

      /* Verify the sequence number of the ack */
      ret = check_seq_num(seq_num, app_conn->seq_num,
          app_conn->num_ack_queue);

      /* Check that the ack concerns one of the packets in the window */
      if(ret == 0 || ret == 3){
        if(debug){
          fprintf(stdout, "Sequence number of ack didn't match any of the "
              "packets awaiting ack, discarding ack.\n");
        }
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

      /* All packets up to and including the packet that was acked have been
       * received, because of the cumulative ack in Go-Back-N, remove them from
       * the window */
      for(j = 0; j < packet_num; j++){
        free(app_conn->sent_packets[j]);
        app_conn->payload_bytes_sent +=
            app_conn->packet_size[j] - PACKET_HDR_SIZE - app_conn->packet_pad[i];
      }
      for(j = 0; j < app_conn->num_ack_queue - packet_num; j++){
        app_conn->sent_packets[j] = app_conn->sent_packets[j + packet_num];
        app_conn->packet_size[j] = app_conn->packet_size[j + packet_num];
        app_conn->packet_pad[j] = app_conn->packet_pad[j + packet_num];
        app_conn->packet_timestamp[j] =
            app_conn->packet_timestamp[j + packet_num];
      }
      for(; j < app_conn->num_ack_queue; j++){
        app_conn->sent_packets[j] = NULL;
        app_conn->packet_size[j] = 0;
        app_conn->packet_pad[j] = 0;
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

      if(debug){
        fprintf(stdout, "Packet %d of %d was acked.\n",
            packet_num, app_conn->num_ack_queue);
        if(packet_num > 1){
          fprintf(stdout, "%d additional un-acked packets sent prior to the "
              "acked packet acked by cumulative ack.\n", packet_num - 1);
        }
      }

      /* Update the amount of packets waiting for acks */
      app_conn->num_ack_queue -= packet_num;

      if(debug){
        fprintf(stdout, "Current number of packets awaiting ack from mip %d "
            "on port %d: %d\n", mip, port, app_conn->num_ack_queue);
      }

      ret = app_conn->num_ack_queue;

      /* Update the client on the sending progress */
      if(update_client(app_conn, debug) == -1){

        if(errno == EPIPE){
          if(debug){
            fprintf(stdout, "File client sending to MIP %d on  port %d has "
                "disconnected during a transfer.\n", mip, port);
          }
          remove_app_conn(app_conn->sock, socks);
          return -4;
        }

        errno = EPIPE;

        ret = -1;
      }

      break;
    }
  }
  return ret;
}




/**
 * Handles reception of a transport packet from the MIP daemon. Receives the
 * packet, then checks if the packet is an ack, if it is, it passes it to a
 * function for handling acks, if not, checks if any connected server
 * application is listening on the port specified in the header of the packet.
 * If there is not, the packet is discarded, and if there is, the function
 * checks if the packet was expected by calling a function which verifies the
 * session and sequence number. If it was not expected, the packet is
 * discarded, if it was the next expected packet, an ack is sent and the
 * payload of the packet is sent to the connected server application listening
 * on the port in the packet header if it is still connected, and if the packet
 * was not the next expected packet, but was within the packet sending window,
 * an ack is resent for the packet.
 *
 * @param socks     Pointer to structure containing data about local
 *                  connections. Used to verify sequence numbers of acks and
 *                  sending data to connected servers.
 * @param conn_data Pointer to structure containing data concerning remote
 *                  connection sessions. Used to verify session and sequence
 *                  number of received packets.
 * @param debug     Indicates if debug information should be logged to the
 *                  console.
 */
int recv_transport_packet(struct socket_container *socks,
    struct connection_data *conn_data, int debug){

  /* Receive the packet */
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

  /* Extract metadata */
  uint8_t pad_len = get_padding_length(packet);
  uint16_t port = get_port_number(packet);
  uint16_t seq_num = ntohs(packet->seq_num);
  int payload_length = ret - sizeof(src_mip) - PACKET_HDR_SIZE - pad_len;

  if(debug){
    fprintf(stdout, "Received transport packet of %ld bytes from MIP address %d.\n", ret, src_mip);
    fprintf(stdout, "Packet payload size: %d\tPort: %d\tSequence number: %d\n", payload_length, port, seq_num);
  }

  /* Check if the packet is an ack */
  if(payload_length == 0){
    if(debug){
      fprintf(stdout, "Received packet was an ack.\n");
    }
    free(packet);
    /* Packet was an ACK */
    ret = received_ack(socks, seq_num, port, src_mip, debug);
    if(ret == -1){
      if(errno == EPIPE){
        return -3;
      }
      return -1;
    }else if(ret == -3){
      if(debug){
        fprintf(stdout, "No packets waiting for ack from MIP %d on port %d.\n",
            src_mip, port);
      }
    }
    return -3;
  }

  /* Check if any server is listening on the port the packet was sent on */
  int server_sock = port_listening(port, socks);

  if(server_sock == -1){
    if(debug){
      fprintf(stdout, "No server listening on port %d, discarding packet.\n", port);
    }
    free(packet);
    return -5;
  }

  /* Verify sequence number and session */
  ret = check_session(conn_data, src_mip, port, seq_num, debug);

  if(ret == -1){
    if(debug){
      fprintf(stdout, "Packet has already been received, resending ack.\n");
    }
    free(packet);

    /* Previously acked packet, resend ack */
    ret = send_ack(socks->mip, seq_num, port, src_mip, debug);

    if(ret == -1){
      return -1;
    }

    if(debug){
      fprintf(stdout, "Sent %ld bytes to MIP daemon.\n", ret);
    }

    return 0;
  }

  if(ret < -1){
    /* Bad sequence number */
    if(debug){
      if(ret == -3){
        fprintf(stdout, "No previous session for source MIP %d on port %d, "
            "but sequence number %d of packet did not indicate start of a new "
            "session, discarding packet.\n", src_mip, port, seq_num);
      }
    }
    free(packet);
    return -4;
  }

  if(debug){
    fprintf(stdout, "Sending payload to server listening on port %d.\n", port);
  }

  /* Send the payload of the packet to the listening server application */
  ret = send_packet_to_app(server_sock, packet->payload, src_mip,
      (int) ret, payload_length);

  free(packet);

  if(ret == -1){

    if(errno == EPIPE){
      if(debug){
        fprintf(stdout, "File server listning on port %d has disconnected "
            "during a transfer.\n",port);
      }
      remove_app_conn(server_sock, socks);
      return 1;
    }

    return -1;
  }

  if(debug){
    fprintf(stdout, "Sent %ld bytes to server.\n", ret);
  }

  /* Send an ack for the received packet */
  ret = send_ack(socks->mip, seq_num, port, src_mip, debug);

  if(ret == -1){
    return -1;
  }

  if(debug){
    fprintf(stdout, "Sent %ld bytes to MIP daemon.\n", ret);
  }

  return 1;
}



/**
 * Handler for receiving a signal on the provided signal_fd
 *
 * @param signal_fd       The descriptor which received the signal.
 * @return                Returns 0 if the signal was a keyboard interrupt, 1
 *                        otherwise.
 */
int keyboard_signal(int signal_fd){
  struct signalfd_siginfo sig_info;
  ssize_t sig_size;

  sig_size = read(signal_fd, &sig_info, sizeof(struct signalfd_siginfo));

  /* Check what signal was raised */
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



/**
 * Frees the remote connection data stored in the structure pointed to by the
 * provided argument.
 *
 * @param conn_data Pointer to the data that is to be freed.
 * @return          None
 */
void free_conn_data(struct connection_data *conn_data){
  free(conn_data->seq_nums);
  free(conn_data->port_conns);
  free(conn_data->mip_conns);
  free(conn_data);
}



/**
 * Creates an epoll instance and listens for events on the sockets provided in
 * the supplied structure.
 *
 * @param socks Pointer to structure containing local connetion data. Its
 *              content will be added to the epoll instance.
 * @return      Returns the created epoll instance on success and a negative
 *              number on error.
 */
int create_epoll_instance(struct socket_container *socks){

  /* Code concerning epoll is based on code from 'man 7 epoll' and group
  * session https://github.uio.no/persun/inf3190/blob/master/plenum3/epoll.c */

  int epfd = epoll_create(1);

  if (epfd == -1){
    return -1;
  }

  /* Add the unix sockets for the MIP daemon and application listener as well
   * as the signal handler to the epoll instance*/
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


/**
 * Intializes the connection data for a connected application. Receives a MIP
 * address and port from the connected application. The connected application
 * is a server if the provided MIP address is invalid, i.e. 255, and a client
 * if not.
 *
 * @param app_conn  Pointer to structure for containing data concerning the
 *                  connection to the application.
 * @param epfd      The epoll instance the socket of the connection to the
 *                  application will be added to for event handling.
 * @return          Returns 1 on success, 0 if there was an issue receiving
 *                  initialization data from the application, and -1 on error.
 */
int init_app(struct conn_app *app_conn, int epfd){

  /* Receive initialization data from the connected application */
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

  ret = recvmsg(app_conn->sock, &init_msg, 0);

  /* Communication error */
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

  /* Initialize data */
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



/**
 * Create a socket and connect it to the path provided as an argument.
 *
 * @param socket_name Path to connect the socket to.
 * @return            Returns the connected socket on success, and -1 on error,
 *                    and -2 if the function was unable to connect to the MIP
 *                    daemon.
 */
int connect_socket(char* socket_name){

  struct sockaddr_un un_addr = { 0 };

  /* Create the socket */
  int conn_sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if(conn_sock == -1){
    return -1;
  }

  /* Connect it to the path */
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


/**
 * Closes all local connection sockets, and unlinks the path of the socket used
 * for communication with connected applications. If the second argument is 1,
 * the path of the socket used for communication with the MIP daemon will also
 * be unlinked.
 *
 * @param socks           Pointer to structure containing data concerning local
 *                        connections, which are to be closed.
 * @param unlink_mip_path Indicates if the path of the MIP communication socket
 *                        should be unlinked.
 * @return                None
 */
void close_sockets(struct socket_container *socks, int unlink_mip_path){
  int i;

  /* Close connected application sockets */
  for (i = 0; i < socks->num_apps; i++){
    close(socks->app_conns[i].sock);
  }

  /* Close the socket listening for application connections */
  struct sockaddr_un app_addr = { 0 };
  socklen_t app_addrlen = sizeof(app_addr);
  getsockname(socks->app, (struct sockaddr*) &app_addr, &app_addrlen);
  close(socks->app);
  unlink(app_addr.sun_path);

  /* Close the connected to the MIP daemon */
  struct sockaddr_un mip_addr = { 0 };
  socklen_t mip_addrlen = sizeof(mip_addr);
  getsockname(socks->mip, (struct sockaddr*) &mip_addr,
    &mip_addrlen);
  close(socks->mip);
  /* Unlink the path of the MIP daemon socket if specified */
  if(unlink_mip_path) unlink(mip_addr.sun_path);

  /* Close the signal handler */
  close(socks->signal);

  /* Free the data */
  free(socks);
}



/**
 * Prints usage information to stderr for the user
 *
 * @param file_name Filename of the user executed file, argv[0]
 * @return          None
 */
void print_help(char *file_name){
  fprintf(stderr,"USAGE: %s [-h] [-d] <timeout> <Socket_application> "
      "<Socket_transport>\n", file_name);
  fprintf(stderr,"[-h]: optional help argument\n");
  fprintf(stderr,"[-d]: optional debug argument, prints communication "
    "information\n");
  fprintf(stderr,"<timeout>: timeout in seconds to be applied by the "
    "transport daemon\n");
  fprintf(stderr,"<Socket_application>: name of socket for IPC with "
    "MIP daemon\n");
  fprintf(stderr,"<Socket_transport>: name of socket for IPC with "
    "connected transport applications\n");
}



/**
 * Sets up a unix socket and binds it to the provided name, and listens to it
 *
 * @param un_sock_name Name to bind the unix socket to
 * @return             Returns the socket descriptor of the new unix socket on
 *                     success, and a negative number on error.
 */
int setup_listen_socket(char* un_sock_name){
  /* Using SOCK_SEQPACKET for a connection-oriented, sequence-preserving socket
   * that preserves message boundaries */

  /* Create the socket */
  int un_sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);

  if (un_sock == -1){
    return -1;
  }

  /* Based on code from 'man 2 bind' */
  struct sockaddr_un un_sock_addr;
  memset(&un_sock_addr, 0, sizeof(struct sockaddr_un));

  un_sock_addr.sun_family = AF_UNIX;

  strncpy(un_sock_addr.sun_path,un_sock_name,sizeof(un_sock_addr.sun_path));

  /* Bind it to the path */
  if(bind(un_sock, (struct sockaddr*) &un_sock_addr,
      sizeof(struct sockaddr_un)) == -1) {
    return -2;
  }

  /* Listen for incoming connections */
  if(listen(un_sock, LISTEN_BACKLOG_UNIX) == -1){
    return -3;
  }

  return un_sock;
}
