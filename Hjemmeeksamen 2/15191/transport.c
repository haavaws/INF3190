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
 * Resends any un-acked packets associated with the local application
 * connection stored in the struct pointer to by app_conn, in accordance with
 * Selective Repeat. However, if one of the packets being resent is the first
 * packet of the transfer session, all packets are resent instead, because of
 * how a new session is started.
 *
 * @param app_conn  Pointer to structure containing data concerning local
 *                  connection with an application. Un-acked packets in this
 *                  struct will be resent, according to the data stored about
 *                  the connection.
 * @param data     Pointer to structure containing data connection data. Used
 *                  for sending data to the MIP daemon.
 * @return          Returns amount of packets resent on success, and -1 on
 *                  error.
 */
int resend_packets(struct app_data *app_conn, struct data_container *data,
    int debug){
  int i,j;
  time_t now = time(NULL);

  /* Loop through all un-acked packets and re-send them */
  for(i = 0; i < app_conn->num_ack_queue; i++){
    if(app_conn->packet_acked[i] != 1){
      if(send_complete_packet(data->mip, app_conn->mip,
          app_conn->packet_window[i], app_conn->packet_size[i]) == -1){
        return -1;
      }
      app_conn->packet_timestamp[i] = now;
      if(debug){
        fprintf(stdout, "Resent packet to MIP address %d on port %d with sequence number %d.\n", app_conn->mip, app_conn->port, app_conn->seq_num - (app_conn->num_ack_queue - 1) + i);
      }

      /* If the packet is the start of a transfer session, set all packets to
       * unacked so that they will be resent */
      if((app_conn->seq_num - (app_conn->num_ack_queue -1) + i) == 0){
        for(j = i; j < app_conn->num_ack_queue; j++){
          app_conn->packet_acked[j] = 0;
        }
      }

    }
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
 * Deletes a remote connection session from the provided MIP address on the
 * provided port from the data structure provided.
 *
 * @param data  Data structure containing the session to be removed.
 * @param mip   Source MIP address of the session to be removed.
 * @param port  Port of the session to be removed.
 * @return      Returns the number of sessions remaining after removal.
 */
int remove_session(struct data_container *data, uint8_t mip, uint16_t port){
  int i,j;

  for(i = 0; i < data->num_sessions; i++){
    if(data->sessions[i]->mip_conn == mip && data->sessions[i]->port_conn == port){
      for(j = 0; j < 10; j++){
        free(data->sessions[i]->packet_window[j]);
      }

      free(data->sessions[i]);

      for(j = i; j < data->num_sessions - 1; j++){
        data->sessions[j] = data->sessions[j + 1];
      }

      data->num_sessions--;

      data->sessions = (struct session_data **) realloc(data->sessions, sizeof(struct session_data *) * data->num_sessions);

      break;
    }
  }

  return data->num_sessions;
}




/**
 * Removes the local application connection associated with the supplied socket
 * from the provided data structure, and any data associated with it is
 * discarded. If the application for was a server, any sessions connected to to
 * the server is deleted.
 *
 * @param app_sock  The socket associated with the connection to be removed.
 * @param data      Pointer to data structure containing information concerning
 *                  the local application.
 * @return          Returns number of connected applications after removal.
 */
int remove_app_conn(int app_sock, struct data_container *data){
  int i,j;

  /* Find the entry to remove */
  for(i = 0; i < data->num_apps; i++){
    if(data->app_conns[i]->sock == app_sock){

      /* If the application is a server, delete any associated remote connected
       * sessions. */
      if(data->app_conns[i]->mip == 255){
        for(j = 0; j < data->num_sessions; j++){
          if(data->sessions[j]->port_conn == data->app_conns[i]->port){
            remove_session(data, data->sessions[j]->port_conn, data->sessions[j]->mip_conn);
          }
        }
      }

      /* Free the packets sent from the application, if any */
      for(j = 0; j < data->app_conns[i]->num_ack_queue; j++){
        free(data->app_conns[i]->packet_window[j]);
      }

      free(data->app_conns[i]);

      /* Reorder the applications */
      for(j = i; j < data->num_apps - 1; j++){
        data->app_conns[j] = data->app_conns[j + 1];
      }

      data->num_apps--;

      data->app_conns = (struct app_data **) realloc(data->app_conns, sizeof(struct app_data *) * data->num_apps);

      break;
    }
  }

  /* Remove the socket from the epoll instance */
  epoll_ctl(data->epfd, EPOLL_CTL_DEL, app_sock, NULL);
  close(app_sock);

  return data->num_apps;
}



/**
 * Constructs a transport packet using the suppplied arguments, and sends it to
 * a MIP address on a port specified in the application connection supplied,
 * via the MIP daemon.
 *
 * @param mip_sock    The socket for MIP daemon communication, to send the
 *                    packet through.
 * @param app_conn    Pointer to structure containing data about a local
 *                    application connection. Packet metadata will be gathered
 *                    from this structure.
 * @param payload     The payload of the packet to send.
 * @param payload_len The size of the payload.
 * @param debug       Indicates if debug information should be logged to
 *                    console.
 * @return            Returns amount of bytes sent to the MIP daemon on
 *                    success and -1 on error.
 */
int send_packet_to_mip(int mip_sock, struct app_data *app_conn,
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

  /* Add the packet to the packet window, add a timestamp for it, update the
   * number of packets in the window, and the sequence number for the
   * session */
  app_conn->packet_window[app_conn->num_ack_queue] = packet;
  app_conn->packet_timestamp[app_conn->num_ack_queue] = time(NULL);
  app_conn->packet_size[app_conn->num_ack_queue] =
      sizeof(struct transport_packet) + payload_len;
  app_conn->packet_pad[app_conn->num_ack_queue] = pad_len;
  app_conn->packet_seq_num[app_conn->num_ack_queue] = app_conn->seq_num;
  app_conn->packet_acked[app_conn->num_ack_queue] = 0;

  app_conn->num_ack_queue++;

  if(debug){
    fprintf(stdout, "Sent packet of %ld bytes to MIP daemon.\n", ret);
    fprintf(stdout, "Sequence number: %d\tNumber of packets waiting for ack: %d\n", app_conn->seq_num, app_conn->num_ack_queue);
  }

  return ret;

}



/**
 * Handles incoming data from a connected application. If the data is a
 * file segment from a connected client application, the file segment is used
 * to construct a transport packet and it is sent via the MIP daemon to the
 * recipient specified in the data concerning the local application connection
 * found in the supplied data structure.
 * If instead the application has disconnected, the information
 * regarding the local application connection is deleted.
 *
 * @param app_sock      The socket the data is to be received from.
 * @param epoll_events  The type of event epoll event which triggered this
 *                      functions. Indicates if the application has
 *                      disconnected.
 * @param data          Pointer to structure containing connection data. Used
 *                      for constructing the header of the transport packet,
 *                      and determining the recipient.
 * @param debug         Indicates if debug information should be logged to the
 *                      console.
 * @return              Returns the number of packets awaiting acks that were
 *                      sent with data from the client application that the
 *                      data was received from, -1 on error, and -2 if the
 *                      application has disconnected.
 */
int recv_from_app(int app_sock, uint32_t epoll_events,
    struct data_container *data, int debug){

  ssize_t ret;
  int i;
  struct app_data *app_conn;

  /* Find the data concerning the connected application that data is being
   * received from */
  for(i = 0; i < data->num_apps; i++){
    if(data->app_conns[i]->sock == app_sock){
      app_conn = data->app_conns[i];
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

    remove_app_conn(app_sock, data);

    return -2;
  }

  if(debug){
    fprintf(stdout, "Received file segment of %ld bytes from transport client.\n", ret);
    fprintf(stdout, "Destination MIP: %3d\tPort: %5d\n", app_conn->mip, app_conn->port);
  }

  /* Send the packet */
  ret = send_packet_to_mip(data->mip, app_conn, file_segment, ret, debug);

  if(ret == -1){
    return -1;
  }

  /* Stop listening for events from the connected application if the packet
   * window is full */
  if(app_conn->num_ack_queue == WINDOW_SIZE){
    struct epoll_event ep_app_ev = { 0 };
    ep_app_ev.data.fd = app_sock;
    epoll_ctl(data->epfd, EPOLL_CTL_MOD, app_sock, &ep_app_ev);
  }

  return app_conn->num_ack_queue;

}



/**
 * Checks if any server application is listening on the supplied port.
 *
 * @param port  The port to check if any server application is listening on.
 * @param data  Pointer to structure containing data concerning  connections.
 *              To check for listening server applications in.
 * @return      Returns the socket of the server application listening to the
 *              port if there is one, and -1 if there are none listening.
 */
int port_listening(int port, struct data_container *data){
  int i;

  /* Go through all connected applications and check if they are a server and
   * are listning to the provided port */
  for(i = 0; i < data->num_apps; i++){
    if(port == data->app_conns[i]->port && data->app_conns[i]->mip == 255){
      return data->app_conns[i]->sock;
    }
  }
  return -1;
}




/**
 * Checks if the socket supplied to the function is a socket associated with
 * a connected application.
 *
 * @param sock      The socket to check.
 * @param app_conns Array of pointers to structures containing information
 *                  concerning connected applications.
 * @param num_conns The number of connected applications stored in the
 *                  app_conns array.
 * @return          Returns the index of the connection in the app_conns array
 *                  if it is there, and -1 if not.
 */
int is_conn(int sock, struct data_container *data){
  int i;

  /* Go through all connected applications and check if any of them is
   * associated with the provided socket */
  for(i = 0; i < data->num_apps; i++){
    if(data->app_conns[i]->sock == sock) return i;
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
 * Checks the first supplied sequence number against the second, using the
 * supplied window size, to see if they match, if the sequence number is within
 * the window, and if it is zero.
 *
 * @param to_check      Sequence number to check.
 * @param check_against Sequence number to check against.
 * @param w_size        Size of the window the check number could be within.
 * @return              Returns 1 if the sequence numbers are equal.
 * @return              Returns 2 if the sequence number is within the window
 *                      specified by w_size, before the second sequence number,
 *                      and the sequence number is not 0.
 *                      Returns 3 if the sequence number is outside the window
 *                      specified by w_size, and the sequence number is 0.
 *                      Returns 4 if the sequence number is within the window
 *                      specified by w_size, and the sequence number is 0.
 *                      Returns 5 if the sequence numbe ris within the window
 *                      specified by w_size, after the second sequence number,
 *                      and the sequence number is not 0.
 *                      Returns 6 if the sequence number is within the window
 *                      specified by w_size and the sequence number is 0.
 *                      Returns 0 if the sequence number is otherwise outside
 *                      the window specified by w_size.
 */
int check_seq_num(uint16_t to_check, uint16_t check_against, int w_size){
  if(to_check == check_against){
    return 1;
  }

  /* Check if the sequence number is within the packet window before the
   * sequnce number to check against, taking into account possible
   * wrap-around */
  if(to_check < check_against){
    if(check_against <= w_size){
      if(to_check == 0){
        return 4;
      }
      return 2;
    }else{
      if(to_check >= (check_against - w_size)){
        if(to_check == 0){
          return 4;
        }
        return 2;
      }
    }
  }else if(to_check >= (uint16_t)(check_against - w_size)){
    if(check_against > (uint16_t)(check_against + w_size)){
      if(to_check == 0){
        return 4;
      }
      return 2;
    }
  }

  /* Check if the sequence number is within the packet window after the sequnce
   * number to check against, taking into account possible wrap-around */
  if(to_check >= check_against){
    if(check_against > (uint16_t) (check_against + w_size)){
      if(to_check == 0){
        return 6;
      }
      return 5;
    }else if(to_check < (check_against + w_size)){
      if(to_check == 0){
        return 6;
      }
      return 5;
    }
  }else if(to_check < (check_against + w_size)){
    if(check_against > (uint16_t) (check_against + w_size)){
      if(to_check == 0){
        return 6;
      }
      return 5;
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
 * the start of a new session, a new session is created and the previous
 * session is discarded.
 *
 * @param data      Pointer to structure containing data concerning
 *                  connections. Used to check for previous existing sessions
 *                  and storing new sessions, as well as checking the provided
 *                  sequence number.
 * @param src_mip   The MIP address of the session to look up and possibly
 *                  create.
 * @param port      The port of the session to look up and possibly create.
 * @param seq_num   The sequence number to check for match against the session.
 * @param debug     Indicates if debug information should be logged to the
 *                  console.
 * @return          Returns 0 if the sequence number matched the expected
 *                  sequence number of the existing session, -1 if it is within
 *                  the packet window, and no new session is created, -2 if it
 *                  was outside the packet window, and no new session is
 *                  created, -3 if there was no existing session, but the
 *                  sequence number did not indicate the start of a new
 *                  session, -4 if it was within the packet window following
 *                  the sequence number of the session, 1 if the sequence
 *                  number was within the window, but indicated the start of a
 *                  new session, and 2 if there was no existing session and the
 *                  sequence number indicated the start of a new session.
 */
int check_session(struct data_container *data, uint8_t src_mip,
    uint16_t port, uint16_t seq_num, int debug){
  int i,ret = -2;

  /* Iterate through all sessions */
  for(i = 0; i < data->num_sessions; i++){

    /* If it is the relevant session */
    if(src_mip == data->sessions[i]->mip_conn && port == data->sessions[i]->port_conn){
      struct session_data *session = data->sessions[i];

      /* Verify the sequence number provided */
      ret = check_seq_num(seq_num, session->seq_num, WINDOW_SIZE);

      /* If it was the expected sequence number */
      if(ret == 1){

        if(debug){
          fprintf(stdout, "Expected sequence number: %d\n",
              session->seq_num);
        }

        ret = 0;
        break;
      }
      /* If it was within the sending packet window, and not 0 */
      else if(ret == 2){
        return -1;
      }
      /* If it was zero, and not the expected sequence number */
      else if(ret == 3 || ret == 4 || ret == 6){
        /* Treating any packet with sequence number 0 as the start of a new
         * session */
        if(debug){
          fprintf(stdout, "Expected sequnce number: %d\n",
              session->seq_num);
          fprintf(stdout, "Sequence number of packet was %d, indicating the "
              "start of a new session.\n", seq_num);
          fprintf(stdout, "Treating old session as done and establishing new "
              "session.\n");
        }
        /* Remove previous session */
        remove_session(data, src_mip, port);
        /* Ensure creation of new session later */
        i = data->num_sessions;
        ret = 1;
        break;
      }
      /* If it was within receiving packet window, and not 0 */
      else if(ret == 5){
        if(debug){
          fprintf(stdout, "Expected sequence number: %d\n",
              session->seq_num);
          fprintf(stdout, "Sequence number of packet was %d, and inside the "
              "receiving window of %d packets, buffering packet.\n", seq_num,
              WINDOW_SIZE);
        }
        return -4;

      }
      /* If it was not within the packet window, and not 0 */
      else{
        if(debug){
          fprintf(stdout, "Expected sequence number: %d\n",
              session->seq_num);
          fprintf(stdout, "Sequence number of packet was %d, and outside the "
              "sending window of %d packets, discarding packet.\n", seq_num,
              WINDOW_SIZE);
        }
        return -2;
      }
    }
  }

  /* If no data was stored for this source port / MIP combination, or a new
   * new session was indicated, create a new session */
  if(i == data->num_sessions){
    if(debug){
      fprintf(stdout, "Establishing new session for MIP address %d and port "
          "%d.\n", src_mip, port);
    }

    if(ret != 1) ret = 2;

    if(seq_num != 0){
      /* Not the start of a new sequence */
      return -3;
    }

    data->num_sessions++;

    /* Initialize the session */
    data->sessions = (struct session_data **) realloc(data->sessions,
        sizeof(struct session_data *) * data->num_sessions);

    struct session_data *session = (struct session_data *) calloc(1, sizeof(struct session_data));

    session->mip_conn = src_mip;
    session->port_conn = port;
    session->seq_num = seq_num;
    session->num_buffered = 0;
    for(i = 0; i < WINDOW_SIZE; i++){
      session->packet_window[i] = NULL;
    }

    /* Store the newly created session */
    data->sessions[data->num_sessions - 1] = session;
  }

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

  if(ret != -1){
    if(debug){
      fprintf(stdout, "Sent %ld bytes to MIP daemon.\n", ret);
    }
  }

  free(packet);

  return ret;
}




/**
 * Sends only the payloads of packets consecutively buffered in the packet
 * window for the transfer session, starting from the next expected packet if
 * it is buffered, to the connected server application and consequently removes
 * them from the packet window. The deliveries are prepended with the source
 * MIP address and an int indicating whether or not it is the start of a new
 * transfer.
 *
 * @param data            Pointer to structure containing connection data.
 *                        Buffered packets are extracted from this structure.
 * @param sock            The socket of the connected application to send the
 *                        payload to.
 * @param src_mip         The origin MIP address of the transport packets.
 * @param new_session     Indicates whether this is the start of a new
 *                        session.
 * @param payload_length  Size of the payload in bytes.
 * @return                Returns number of packets sent to the connected
 *                        application on success, and -1 on error.
 */
int send_packet_to_app(struct data_container *data, int sock, uint8_t src_mip,
    uint16_t port, int new_session, int debug){
  int i,j,ret = 0;

  /* Find the session associated with the source MIP address and port. */
  for(i = 0; i < data->num_sessions; i++){
    if(data->sessions[i]->mip_conn == src_mip && data->sessions[i]->port_conn == port){
      struct session_data *session = data->sessions[i];

      /* Go through the packet window */
      for(j = 0; j < WINDOW_SIZE; j++){
        /* Only send consecutively buffered packets */
        if(!session->packet_window[j]){
          break;
        }

        /* Send the buffered packet */
        struct msghdr file_seg_msg = { 0 };
        struct iovec file_seg_iov[3];

        file_seg_iov[0].iov_base = &src_mip;
        file_seg_iov[0].iov_len = sizeof(src_mip);

        file_seg_iov[1].iov_base = &new_session;
        file_seg_iov[1].iov_len = sizeof(new_session);

        file_seg_iov[2].iov_base = session->packet_window[j]->payload;
        file_seg_iov[2].iov_len = session->packet_payload_len[j];

        file_seg_msg.msg_iov = file_seg_iov;
        file_seg_msg.msg_iovlen = 3;

        ret = sendmsg(sock, &file_seg_msg, 0);

        if(ret == -1){
          return -1;
        }

        if(debug){
          fprintf(stdout, "Sent %d bytes to server, for packet with sequence number: %d.\n", ret, session->seq_num);
        }

        free(session->packet_window[j]);

        session->seq_num++;
      }

      /* Remove the sent packets from the packet window */
      for(i = 0; i < WINDOW_SIZE - j; i++){
        session->packet_window[i] = session->packet_window[i + j];
        session->packet_payload_len[i] = session->packet_payload_len[i + j];
      }
      for(; i < WINDOW_SIZE; i++){
        session->packet_window[i] = NULL;
        session->packet_payload_len[i] = 0;
      }


      break;
    }
  }

  return j;
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
int update_client(struct app_data *app_conn, int debug){

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
 * source MIP address and port of the ack is waiting for an ack for a packet
 * with the sequence number of the ack. If it is, the packet is set as acked in
 * the packet window, and if it is the first packet of the window, the amount
 * of bytes received by the intnded recipient is updated to include the size of
 * the acked packet and any consecutively acked packets after the first one in
 * the packet window, after which they are removed from the packet window, and
 * an update is sent to the client the packet originated from with the total
 * amount of payload bytes that the sender of the ack has received from that
 * client. If the packet was not the first in the packet window, the packet is
 * simply set to acked in the packet window. If the packet window was
 * was previously full, but that is no longer the case, the transport daemon
 * will start receiving data from the client application again.
 *
 * @param data    Pointer to a structure containing data concerning
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
int received_ack(struct data_container *data, uint16_t seq_num,
    uint16_t port, uint8_t mip, int debug){

  int i,j,k;
  int ret = -3;

  /* Iterate through all connected applications */
  for(i = 0; i < data->num_apps; i++){

    /* If it is sending to the provided mip on the provided port */
    if(data->app_conns[i]->port == port && data->app_conns[i]->mip == mip){
      struct app_data *app_conn = data->app_conns[i];
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
      if(ret == 0 || ret == 3 || ret == 5 || ret == 6){
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

      /* Set the packet to be acked */
      app_conn->packet_acked[packet_num - 1] = 1;

      /* Go through all packets in the packet window, and the size of the
       * payload of all packets consequtively acked from the start of the
       * window is added to the total amount of acked bytes, and the packets
       * are freed */
      for(j = 0; j < app_conn->num_ack_queue; j++){
        if(app_conn->packet_acked[j] == 1){
          free(app_conn->packet_window[j]);
          app_conn->payload_bytes_sent +=
              app_conn->packet_size[j] - PACKET_HDR_SIZE - app_conn->packet_pad[j];
        }else{
          break;
        }
      }
      /* The packet window is reordered */
      for(k = 0; k < app_conn->num_ack_queue - j; k++){
        app_conn->packet_window[k] = app_conn->packet_window[k + j];
        app_conn->packet_size[k] = app_conn->packet_size[k + j];
        app_conn->packet_pad[k] = app_conn->packet_pad[k + j];
        app_conn->packet_timestamp[k] =
            app_conn->packet_timestamp[k + j];
        app_conn->packet_seq_num[k] = app_conn->packet_seq_num[k + j];
        app_conn->packet_acked[k] = app_conn->packet_acked[k + j];
      }
      /* The entries after the new packet window are reset */
      for(; k < app_conn->num_ack_queue; k++){
        app_conn->packet_window[k] = NULL;
        app_conn->packet_size[k] = 0;
        app_conn->packet_pad[k] = 0;
        app_conn->packet_timestamp[k] = 0;
        app_conn->packet_seq_num[k] = 0;
        app_conn->packet_acked[k] = 0;
      }

      if(debug){
        fprintf(stdout, "Packet %d of %d was acked.\n",
            packet_num, app_conn->num_ack_queue);
        if(j > 1){
          fprintf(stdout, "The first %d packets in the packet window are now "
              "acked, and were removed from the window.\n",j);
        }
        else if(j == 0){
          fprintf(stdout, "Still waiting for ack on first packet in packet "
              "window, with sequence number %d.\n",
              app_conn->seq_num - (app_conn->num_ack_queue - 1));
        }
      }

      /* Update the amount of packets waiting for acks */
      app_conn->num_ack_queue -= j;

      if(debug){
        fprintf(stdout, "Current number of packets awaiting ack from mip %d "
            "on port %d: %d\n", mip, port, app_conn->num_ack_queue);
      }

      /* Make sure the socket is armed in the epoll instance if there is room
       * in the packet window */
      if(app_conn->num_ack_queue < WINDOW_SIZE){
        struct epoll_event ep_app_ev = { 0 };
        ep_app_ev.events = EPOLLIN;
        ep_app_ev.data.fd = app_conn->sock;
        epoll_ctl(data->epfd, EPOLL_CTL_MOD, app_conn->sock,
            &ep_app_ev);
      }

      ret = app_conn->num_ack_queue;

      /* Update the client on the sending progress */
      if(update_client(app_conn, debug) == -1){
        /* Handle disconnect during transfer */
        if(errno == EPIPE){
          if(debug){
            fprintf(stdout, "File client sending to MIP %d on  port %d has "
                "disconnected during a transfer.\n", mip, port);
          }
          remove_app_conn(app_conn->sock, data);
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
 * Buffer the provided packet in the packet window of the session specified by
 * the provided MIP address and port, using the provided sequence number.
 *
 * @param data        Pointer to structure containin data concerning
 *                    connections. Used to find the session to buffer in.
 * @param packet      Packet to be buffered.
 * @param mip         Source MIP address of the packet to be buffered.
 * @param port        Port of the packet to be buffered.
 * @param seq_num     Sequence number of the packet.
 * @param payload_len Size of the payload of the packet.
 */
int buffer_packet(struct data_container *data, struct transport_packet *packet, uint8_t mip, uint16_t port, uint16_t seq_num, int payload_len){
  int i;

  /* Find the correct session */
  for(i = 0; i < data->num_sessions; i++){
    if(data->sessions[i]->mip_conn == mip && data->sessions[i]->port_conn == port){
      /* Buffer the packet in the packet window */
      struct session_data *session = data->sessions[i];
      int packet_num = seq_num - session->seq_num;
      session->packet_window[packet_num] = packet;
      session->packet_payload_len[packet_num] = payload_len;
      session->num_buffered++;
    }
  }

  return 1;
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
 * on the port in the packet header if it is still connected, along with any
 * packet buffered consecutively after that packet in the packet window of the
 * session, if the packet was not the next expected packet, but was within the
 * receipt packet window, the packet is buffered in the packet window, and an
 * ack is sent for the packet. If the packet was not the next expected packet,
 * but was a previously received packet within the packet sending window, an
 * ack is resent for the packet to the source.
 *
 * @param data      Pointer to structure containing data concerning
 *                  connections. Used to verify sessions and sequence numbers
 *                  of received packets and sending data to connected servers.
 * @param debug     Indicates if debug information should be logged to the
 *                  console.
 * @return          Returns the number of packets sent to the listening server
 *                  if it exists and the sequence number of the packet was
 *                  appropriate. -1 on error, -2 if the MIP daemon has shut
 *                  down, -3 if the packet was an ack, -4 if it was a transport
 *                  packet, but its sequence number was inappropriate, -5 if
 *                  the packet wasn't an ack, but no server application was
 *                  listening on the port it was sent on.
 */
int recv_transport_packet(struct data_container *data, int debug){

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

  ret = recvmsg(data->mip, &mip_msg, 0);

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
    ret = received_ack(data, seq_num, port, src_mip, debug);
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
  int server_sock = port_listening(port, data);

  if(server_sock == -1){
    if(debug){
      fprintf(stdout, "No server listening on port %d, discarding packet.\n", port);
    }
    free(packet);
    return -5;
  }

  /* Verify sequence number and session */
  ret = check_session(data, src_mip, port, seq_num, debug);

  int new_session = ret;

  if(ret == -1){
    if(debug){
      fprintf(stdout, "Packet has already been received, resending ack.\n");
    }
    free(packet);

    /* Previously acked packet, resend ack */
    ret = send_ack(data->mip, seq_num, port, src_mip, debug);

    if(ret == -1){
      return -1;
    }

    return 0;
  }else if(ret == -2 || ret == -3){
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

  /* Buffer the packet */
  ret = buffer_packet(data, packet, src_mip, port, seq_num, payload_length);


  if(debug){
    fprintf(stdout, "Sending payload to server listening on port %d.\n", port);
  }

  /* Send any consequtively buffered packets to the listening server */
  ret = send_packet_to_app(data, server_sock, src_mip, port, new_session, debug);

  if(ret == -1){

    if(errno == EPIPE){
      if(debug){
        fprintf(stdout, "File server listning on port %d has disconnected "
            "during a transfer.\n",port);
      }
      remove_app_conn(server_sock, data);
      return 1;
    }

    return -1;
  }

  if(debug){
    fprintf(stdout, "Sent %ld packets to server listneing on port %d, with sequence numbers %d-%d\n", ret, port, seq_num, (int) (seq_num + ret));
  }

  /* Send an ack for the received packet */
  if(send_ack(data->mip, seq_num, port, src_mip, debug) == -1){
    return -1;
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
 * Creates an epoll instance and listens for events on the sockets provided in
 * the supplied structure.
 *
 * @param data Pointer to structure containing local connetion data. Its
 *              content will be added to the epoll instance.
 * @return      Returns the created epoll instance on success and a negative
 *              number on error.
 */
int create_epoll_instance(struct data_container *data){

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
  ep_app_ev.data.fd = data->app;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, data->app, &ep_app_ev) == -1){
    return -2;
  }

  struct epoll_event ep_mip_ev = { 0 };
  ep_mip_ev.events = EPOLLIN;
  ep_mip_ev.data.fd = data->mip;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, data->mip,
      &ep_mip_ev) == -1){
    return -3;
  }

  struct epoll_event ep_sig_ev = { 0 };
  ep_sig_ev.events = EPOLLIN | EPOLLERR;
  ep_sig_ev.data.fd = data->signal;

  if(epoll_ctl(epfd, EPOLL_CTL_ADD, data->signal, &ep_sig_ev)
      == -1){
    return -4;
  }

  return epfd;
} /* create_epoll_instance() END */



/**
 * Intializes the connection data for a connected application. Receives a MIP
 * address and port from the connected application. The connected application
 * is a server if the provided MIP address is invalid, i.e. 255, and a client
 * if not. If there already exists a connected application with the same MIP
 * address and port, the connection is instead closed.
 *
 * @param data      Pointer to structure containing data concerning
 *                  connections. Used to look up previously existing
 *                  application connections.
 * @param app_conn  Pointer to structure for containing data concerning the
 *                  connection to the application.
 * @param epfd      The epoll instance the socket of the connection to the
 *                  application will be added to for event handling.
 * @return          Returns 1 on success, 0 if there was an issue receiving
 *                  initialization data from the application, and -1 on error.
 */
int init_app(struct data_container *data, struct app_data *app_conn, int epfd){

  /* Receive initialization data from the connected application */
  ssize_t ret;
  int i;
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

  for(i = 0; i < data->num_apps; i++){
    if(mip == data->app_conns[i]->mip && port == data->app_conns[i]->port){
      close(app_conn->sock);
      return -2;
    }
  }


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
 * @return        Returns a descriptor for a signal handler on success and -1
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
 * Closes all local connections, frees any connection data, and unlinks the
 * path of the socket used for communication with connected applications. If
 * the second argument is 1, the path of the socket used for communication with
 * the MIP daemon will also be unlinked.
 *
 * @param data            Pointer to structure containing data concerning
 *                        connections, which are to be closed and associated
 *                        data freed.
 * @param unlink_mip_path Indicates if the path of the MIP communication socket
 *                        should be unlinked.
 * @return                None
 */
void close_sockets(struct data_container *data, int unlink_mip_path){
  int i,j;

  /* Close connected application sockets, and free their associated packet
   * windows */
  for (i = 0; i < data->num_apps; i++){
    for(j = 0; j < WINDOW_SIZE; j++){
      free(data->app_conns[i]->packet_window[j]);
    }
    close(data->app_conns[i]->sock);
  }
  /* Free all sessions and their associated packet windows */
  for(i = 0; i < data->num_sessions; i++){
    for(j = 0; j < WINDOW_SIZE; j++){
      free(data->sessions[i]->packet_window[j]);
    }
    free(data->sessions[i]);
  }

  /* Close the socket listening for application connections */
  struct sockaddr_un app_addr = { 0 };
  socklen_t app_addrlen = sizeof(app_addr);
  getsockname(data->app, (struct sockaddr*) &app_addr, &app_addrlen);
  close(data->app);
  unlink(app_addr.sun_path);

  /* Close the connected to the MIP daemon */
  struct sockaddr_un mip_addr = { 0 };
  socklen_t mip_addrlen = sizeof(mip_addr);
  getsockname(data->mip, (struct sockaddr*) &mip_addr,
    &mip_addrlen);
  close(data->mip);
  /* Unlink the path of the MIP daemon socket if specified */
  if(unlink_mip_path) unlink(mip_addr.sun_path);

  /* Close the signal handler */
  close(data->signal);

  /* Free the data */
  free(data->app_conns);
  free(data->sessions);
  free(data);
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
