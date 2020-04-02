/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "server_setup.h"
#include <stdlib.h>
#include "util.h"

/* Function
 *
 * Accepts a TCP connection on a custom port (IPv4 or IPv6).  Speaks MQTT.
 *
 * Read commands from FILE (set with --config). The commands control how to
 * act and is reset to defaults each client TCP connect.
 *
 * Config file keywords:
 *
 * TODO
 */

/* based on sockfilt.c */

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#define ENABLE_CURLX_PRINTF
/* make the curlx header define all printf() functions to use the curlx_*
   versions instead */
#include "curlx.h" /* from the private lib dir */
#include "getpart.h"
#include "inet_pton.h"
#include "util.h"
#include "server_sockaddr.h"
#include "warnless.h"

/* include memdebug.h last */
#include "memdebug.h"

#ifdef USE_WINSOCK
#undef  EINTR
#define EINTR    4 /* errno.h value */
#undef  EAGAIN
#define EAGAIN  11 /* errno.h value */
#undef  ENOMEM
#define ENOMEM  12 /* errno.h value */
#undef  EINVAL
#define EINVAL  22 /* errno.h value */
#endif

#define DEFAULT_PORT 1883 /* MQTT default port */

#ifndef DEFAULT_LOGFILE
#define DEFAULT_LOGFILE "log/mqttd.log"
#endif

#ifndef DEFAULT_CONFIG
#define DEFAULT_CONFIG "mqttd.config"
#endif

#define MQTT_MSG_CONNECT    0x10
#define MQTT_MSG_CONNACK    0x20
#define MQTT_MSG_PUBLISH    0x30
#define MQTT_MSG_SUBSCRIBE  0x82
#define MQTT_MSG_SUBACK     0x90
#define MQTT_MSG_DISCONNECT 0xe0

#define MQTT_CONNACK_LEN 4
#define MQTT_SUBACK_LEN 5
#define MQTT_CLIENTID_LEN 12 /* "curl0123abcd" */
#define MQTT_HEADER_LEN 5    /* max 5 bytes */

struct configurable {
  unsigned char version; /* initial version byte in the request must match
                            this */
};

#define CONFIG_VERSION 5

static struct configurable config;

const char *serverlogfile = DEFAULT_LOGFILE;
static const char *configfile = DEFAULT_CONFIG;

#ifdef ENABLE_IPV6
static bool use_ipv6 = FALSE;
#endif
static const char *ipv_inuse = "IPv4";
static unsigned short port = DEFAULT_PORT;

static void resetdefaults(void)
{
  logmsg("Reset to defaults");
  config.version = CONFIG_VERSION;
}

static unsigned char byteval(char *value)
{
  unsigned long num = strtoul(value, NULL, 10);
  return num & 0xff;
}

static void getconfig(void)
{
  FILE *fp = fopen(configfile, FOPEN_READTEXT);
  resetdefaults();
  if(fp) {
    char buffer[512];
    logmsg("parse config file");
    while(fgets(buffer, sizeof(buffer), fp)) {
      char key[32];
      char value[32];
      if(2 == sscanf(buffer, "%31s %31s", key, value)) {
        if(!strcmp(key, "version")) {
          config.version = byteval(value);
          logmsg("version [%d] set", config.version);
        }
      }
    }
    fclose(fp);
  }
}


/* do-nothing macro replacement for systems which lack siginterrupt() */

#ifndef HAVE_SIGINTERRUPT
#define siginterrupt(x,y) do {} while(0)
#endif

/* vars used to keep around previous signal handlers */

typedef RETSIGTYPE (*SIGHANDLER_T)(int);

#ifdef SIGHUP
static SIGHANDLER_T old_sighup_handler  = SIG_ERR;
#endif

#ifdef SIGPIPE
static SIGHANDLER_T old_sigpipe_handler = SIG_ERR;
#endif

#ifdef SIGALRM
static SIGHANDLER_T old_sigalrm_handler = SIG_ERR;
#endif

#ifdef SIGINT
static SIGHANDLER_T old_sigint_handler  = SIG_ERR;
#endif

#if defined(SIGBREAK) && defined(WIN32)
static SIGHANDLER_T old_sigbreak_handler = SIG_ERR;
#endif

/* var which if set indicates that the program should finish execution */

SIG_ATOMIC_T got_exit_signal = 0;

/* if next is set indicates the first signal handled in exit_signal_handler */

static volatile int exit_signal = 0;

/* signal handler that will be triggered to indicate that the program
  should finish its execution in a controlled manner as soon as possible.
  The first time this is called it will set got_exit_signal to one and
  store in exit_signal the signal that triggered its execution. */

static RETSIGTYPE exit_signal_handler(int signum)
{
  int old_errno = errno;
  if(got_exit_signal == 0) {
    got_exit_signal = 1;
    exit_signal = signum;
  }
  (void)signal(signum, exit_signal_handler);
  errno = old_errno;
}

static void install_signal_handlers(void)
{
#ifdef SIGHUP
  /* ignore SIGHUP signal */
  old_sighup_handler = signal(SIGHUP, SIG_IGN);
  if(old_sighup_handler == SIG_ERR)
    logmsg("cannot install SIGHUP handler: %s", strerror(errno));
#endif
#ifdef SIGPIPE
  /* ignore SIGPIPE signal */
  old_sigpipe_handler = signal(SIGPIPE, SIG_IGN);
  if(old_sigpipe_handler == SIG_ERR)
    logmsg("cannot install SIGPIPE handler: %s", strerror(errno));
#endif
#ifdef SIGALRM
  /* ignore SIGALRM signal */
  old_sigalrm_handler = signal(SIGALRM, SIG_IGN);
  if(old_sigalrm_handler == SIG_ERR)
    logmsg("cannot install SIGALRM handler: %s", strerror(errno));
#endif
#ifdef SIGINT
  /* handle SIGINT signal with our exit_signal_handler */
  old_sigint_handler = signal(SIGINT, exit_signal_handler);
  if(old_sigint_handler == SIG_ERR)
    logmsg("cannot install SIGINT handler: %s", strerror(errno));
  else
    siginterrupt(SIGINT, 1);
#endif
#if defined(SIGBREAK) && defined(WIN32)
  /* handle SIGBREAK signal with our exit_signal_handler */
  old_sigbreak_handler = signal(SIGBREAK, exit_signal_handler);
  if(old_sigbreak_handler == SIG_ERR)
    logmsg("cannot install SIGBREAK handler: %s", strerror(errno));
  else
    siginterrupt(SIGBREAK, 1);
#endif
}

static void restore_signal_handlers(void)
{
#ifdef SIGHUP
  if(SIG_ERR != old_sighup_handler)
    (void)signal(SIGHUP, old_sighup_handler);
#endif
#ifdef SIGPIPE
  if(SIG_ERR != old_sigpipe_handler)
    (void)signal(SIGPIPE, old_sigpipe_handler);
#endif
#ifdef SIGALRM
  if(SIG_ERR != old_sigalrm_handler)
    (void)signal(SIGALRM, old_sigalrm_handler);
#endif
#ifdef SIGINT
  if(SIG_ERR != old_sigint_handler)
    (void)signal(SIGINT, old_sigint_handler);
#endif
#if defined(SIGBREAK) && defined(WIN32)
  if(SIG_ERR != old_sigbreak_handler)
    (void)signal(SIGBREAK, old_sigbreak_handler);
#endif
}

static void loghex(unsigned char *buffer, ssize_t len)
{
  char data[1200];
  ssize_t i;
  unsigned char *ptr = buffer;
  char *optr = data;
  ssize_t width = 0;
  int left = sizeof(data);

  for(i = 0; i<len && (left >= 0); i++) {
    msnprintf(optr, left, "%02x", ptr[i]);
    width += 2;
    optr += 2;
    left -= 2;
  }
  if(width)
    logmsg("'%s'", data);
}

/* return 0 on success */
static int connack(curl_socket_t fd)
{
  unsigned char packet[]={
    MQTT_MSG_CONNACK, 0x02,
    0x00, 0x00
  };
  ssize_t rc = send(fd, (char *)packet,
                    (SEND_TYPE_ARG3)sizeof(packet), 0);
  if(rc == sizeof(packet)) {
    logmsg("WROTE %d bytes [CONACK]", rc);
    loghex(packet, rc);
    return 0;
  }
  return 1;
}

/* return 0 on success */
static int suback(curl_socket_t fd, unsigned short packetid)
{
  unsigned char packet[]={
    MQTT_MSG_SUBACK, 0x03,
    (unsigned char)(packetid >> 8), (unsigned char)(packetid & 0xff),
    0x00
  };
  ssize_t rc = send(fd, (char *)packet,
                    (SEND_TYPE_ARG3)sizeof(packet), 0);
  if(rc == sizeof(packet)) {
    logmsg("WROTE %d bytes [SUBACK]", rc);
    loghex(packet, rc);
    return 0;
  }
  return 1;
}

/* return 0 on success */
static int disconnect(curl_socket_t fd)
{
  unsigned char packet[]={
    MQTT_MSG_DISCONNECT, 0x00,
  };
  ssize_t rc = send(fd, (char *)packet,
                    (SEND_TYPE_ARG3)sizeof(packet), 0);
  if(rc == sizeof(packet)) {
    logmsg("WROTE %d bytes [DISCONNECT]", rc);
    loghex(packet, rc);
    return 0;
  }
  return 1;
}



/*
  do

     encodedByte = X MOD 128

     X = X DIV 128

     // if there are more data to encode, set the top bit of this byte

     if ( X > 0 )

        encodedByte = encodedByte OR 128

      endif

    'output' encodedByte

  while ( X > 0 )

*/

/* return number of bytes used */
static int encode_length(size_t packetlen, char *remlength) /* 4 bytes */
{
  int bytes = 0;
  unsigned char encode;

  do {
    encode = packetlen % 0x80;
    packetlen /= 0x80;
    if(packetlen)
      encode |= 0x80;

    remlength[bytes++] = encode;

    if(bytes > 3) {
      logmsg("too large packet!");
      return 0;
    }
  } while(packetlen);

  return bytes;
}

/* return 0 on success */
static int publish(curl_socket_t fd, unsigned short packetid,
                   char *topic, char *payload, size_t payloadlen)
{
  size_t topiclen = strlen(topic);
  unsigned char *packet;
  size_t payloadindex;
  ssize_t remaininglength = topiclen + 2 + payloadlen;
  ssize_t packetlen;
  ssize_t rc;
  char rembuffer[4];
  int encodedlen;

  encodedlen = encode_length(remaininglength, rembuffer);

  /* one packet type byte (possibly two more for packetid) */
  packetlen = remaininglength + encodedlen + 1;
  packet = malloc(packetlen);
  if(!packet)
    return 1;

  packet[0] = MQTT_MSG_PUBLISH; /* TODO: set QoS? */
  memcpy(&packet[1], rembuffer, encodedlen);

  (void)packetid;
  /* packet_id if QoS is set */

  packet[1 + encodedlen] = (unsigned char)(topiclen >> 8);
  packet[2 + encodedlen] = (unsigned char)(topiclen & 0xff);
  memcpy(&packet[3 + encodedlen], topic, topiclen);

  payloadindex = 3 + topiclen + encodedlen;
  memcpy(&packet[payloadindex], payload, payloadlen);

  rc = send(fd, (char *)packet, (SEND_TYPE_ARG3)packetlen, 0);
  if(rc == packetlen) {
    logmsg("WROTE %d bytes [PUBLISH]", rc);
    loghex(packet, rc);
    return 0;
  }
  return 1;
}

#define MAX_TOPIC_LENGTH 65535
#define MAX_CLIENT_ID_LENGTH 32

static char topic[MAX_TOPIC_LENGTH + 1];

static curl_socket_t mqttit(curl_socket_t fd)
{
  unsigned char buffer[256 + 16];
  ssize_t rc;
  unsigned char byte;
  unsigned short packet_id;
  unsigned int payload_len;
  unsigned int topic_len;
  char client_id[MAX_CLIENT_ID_LENGTH];
  char *filename;
  long testno;

  static const char protocol[7] = {
    0x00, 0x04,       /* protocol length */
    'M','Q','T','T',  /* protocol name */
    0x04              /* protocol level */
  };

  getconfig();

  rc = recv(fd, (char *)buffer, sizeof(buffer), 0);

  logmsg("READ %d bytes", rc);
  loghex(buffer, rc);

  if(rc > 14) {
    if(buffer[0] != MQTT_MSG_CONNECT) {
      logmsg("CONNECT was not the first byte!");
      goto end;
    }
    byte = buffer[1]; /* variable length really */
    if(byte != (rc - 2)) {
      logmsg("Remaining Length field was %x, expected to be %x!",
             byte, rc - 2);
      goto end;
    }
    if(memcmp(protocol, &buffer[2], sizeof(protocol))) {
      logmsg("Protocol preamble mismatch");
      goto end;
    }
    /* ignore the connect flag and keepalive bytes */

    payload_len = (buffer[12] << 8) | buffer[13];
    if(payload_len != (rc - 14)) {
      logmsg("Payload length mismatch, expected %x got %x",
             rc - 14, payload_len);
      goto end;
    }
    else if((payload_len + 1) > MAX_CLIENT_ID_LENGTH) {
      logmsg("Too large client id");
      goto end;
    }
    memcpy(client_id, &buffer[14], payload_len);
    client_id[payload_len] = 0;
  }
  else {
    logmsg("Too small CONNECT packet!");
    goto end;
  }
  logmsg("MQTT client connect accepted: %s", client_id);

  /* The first packet sent from the Server to the Client MUST be a CONNACK
     Packet */

  if(connack(fd)) {
    logmsg("failed sending CONNACK");
    goto end;
  }

  /* get the request */
  rc = recv(fd, (char *)buffer, sizeof(buffer), 0);

  logmsg("READ %d bytes", rc);
  loghex(buffer, rc);

  if(rc > 6) {
    if(buffer[0] == MQTT_MSG_SUBSCRIBE) {
      logmsg("Incoming SUBSCRIBE");
      payload_len = buffer[1] + 2;
      if(payload_len != rc) {
        logmsg("Wrong packetlen, got %d expected %d",
               payload_len - 2, rc - 2);
        goto end;
      }
      /* two bytes packet id */
      packet_id = (unsigned short)((buffer[2] << 8) | buffer[3]);

      /* two bytes topic length */
      topic_len = (buffer[4] << 8) | buffer[5];
      if(topic_len > (payload_len - 7)) {
        logmsg("Wrong topic length, got %d",
               topic_len);
        goto end;
      }
      memcpy(topic, &buffer[6], topic_len);
      topic[topic_len] = 0;
      logmsg("SUBSCRIBE to '%s' [%d]", topic, packet_id);
      if(suback(fd, packet_id)) {
        logmsg("failed sending SUBACK");
        goto end;
      }
      testno = strtol(topic, NULL, 10);
      if(testno) {
        FILE *stream;
        int error;
        char *data;
        size_t datalen;
        filename = test2file(testno);
        stream = fopen(filename, "rb");
        error = getpart(&data, &datalen, "reply", "data", stream);
        if(!error)
          publish(fd, packet_id, topic, data, datalen);
      }
      else {
        char *def = (char *)"this is random payload yes yes it is";
        publish(fd, packet_id, topic, def, strlen(def));
      }
      disconnect(fd);
    }
    else {
      /* not supported (yet) */
      goto end;
    }
  }
  end:
  return CURL_SOCKET_BAD;
}

/*
  sockfdp is a pointer to an established stream or CURL_SOCKET_BAD

  if sockfd is CURL_SOCKET_BAD, listendfd is a listening socket we must
  accept()
*/
static bool incoming(curl_socket_t listenfd)
{
  fd_set fds_read;
  fd_set fds_write;
  fd_set fds_err;
  int clients = 0; /* connected clients */

  if(got_exit_signal) {
    logmsg("signalled to die, exiting...");
    return FALSE;
  }

#ifdef HAVE_GETPPID
  /* As a last resort, quit if socks5 process becomes orphan. */
  if(getppid() <= 1) {
    logmsg("process becomes orphan, exiting");
    return FALSE;
  }
#endif

  do {
    ssize_t rc;
    int error = 0;
    curl_socket_t sockfd = listenfd;
    int maxfd = (int)sockfd;

    FD_ZERO(&fds_read);
    FD_ZERO(&fds_write);
    FD_ZERO(&fds_err);

    /* there's always a socket to wait for */
    FD_SET(sockfd, &fds_read);

    do {
      /* select() blocking behavior call on blocking descriptors please */
      rc = select(maxfd + 1, &fds_read, &fds_write, &fds_err, NULL);
      if(got_exit_signal) {
        logmsg("signalled to die, exiting...");
        return FALSE;
      }
    } while((rc == -1) && ((error = errno) == EINTR));

    if(rc < 0) {
      logmsg("select() failed with error: (%d) %s",
             error, strerror(error));
      return FALSE;
    }

    if(FD_ISSET(sockfd, &fds_read)) {
      curl_socket_t newfd = accept(sockfd, NULL, NULL);
      if(CURL_SOCKET_BAD == newfd) {
        error = SOCKERRNO;
        logmsg("accept(%d, NULL, NULL) failed with error: (%d) %s",
               sockfd, error, strerror(error));
      }
      else {
        logmsg("====> Client connect, fd %d. Read config from %s",
               newfd, configfile);
        (void)mqttit(newfd); /* until done */

        logmsg("====> Client disconnect");
        sclose(newfd);
      }
    }
  } while(clients);

  return TRUE;
}

static curl_socket_t sockdaemon(curl_socket_t sock,
                                unsigned short *listenport)
{
  /* passive daemon style */
  srvr_sockaddr_union_t listener;
  int flag;
  int rc;
  int totdelay = 0;
  int maxretr = 10;
  int delay = 20;
  int attempt = 0;
  int error = 0;

  do {
    attempt++;
    flag = 1;
    rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
         (void *)&flag, sizeof(flag));
    if(rc) {
      error = SOCKERRNO;
      logmsg("setsockopt(SO_REUSEADDR) failed with error: (%d) %s",
             error, strerror(error));
      if(maxretr) {
        rc = wait_ms(delay);
        if(rc) {
          /* should not happen */
          error = errno;
          logmsg("wait_ms() failed with error: (%d) %s",
                 error, strerror(error));
          sclose(sock);
          return CURL_SOCKET_BAD;
        }
        if(got_exit_signal) {
          logmsg("signalled to die, exiting...");
          sclose(sock);
          return CURL_SOCKET_BAD;
        }
        totdelay += delay;
        delay *= 2; /* double the sleep for next attempt */
      }
    }
  } while(rc && maxretr--);

  if(rc) {
    logmsg("setsockopt(SO_REUSEADDR) failed %d times in %d ms. Error: (%d) %s",
           attempt, totdelay, error, strerror(error));
    logmsg("Continuing anyway...");
  }

  /* When the specified listener port is zero, it is actually a
     request to let the system choose a non-zero available port. */

#ifdef ENABLE_IPV6
  if(!use_ipv6) {
#endif
    memset(&listener.sa4, 0, sizeof(listener.sa4));
    listener.sa4.sin_family = AF_INET;
    listener.sa4.sin_addr.s_addr = INADDR_ANY;
    listener.sa4.sin_port = htons(*listenport);
    rc = bind(sock, &listener.sa, sizeof(listener.sa4));
#ifdef ENABLE_IPV6
  }
  else {
    memset(&listener.sa6, 0, sizeof(listener.sa6));
    listener.sa6.sin6_family = AF_INET6;
    listener.sa6.sin6_addr = in6addr_any;
    listener.sa6.sin6_port = htons(*listenport);
    rc = bind(sock, &listener.sa, sizeof(listener.sa6));
  }
#endif /* ENABLE_IPV6 */
  if(rc) {
    error = SOCKERRNO;
    logmsg("Error binding socket on port %hu: (%d) %s",
           *listenport, error, strerror(error));
    sclose(sock);
    return CURL_SOCKET_BAD;
  }

  if(!*listenport) {
    /* The system was supposed to choose a port number, figure out which
       port we actually got and update the listener port value with it. */
    curl_socklen_t la_size;
    srvr_sockaddr_union_t localaddr;
#ifdef ENABLE_IPV6
    if(!use_ipv6)
#endif
      la_size = sizeof(localaddr.sa4);
#ifdef ENABLE_IPV6
    else
      la_size = sizeof(localaddr.sa6);
#endif
    memset(&localaddr.sa, 0, (size_t)la_size);
    if(getsockname(sock, &localaddr.sa, &la_size) < 0) {
      error = SOCKERRNO;
      logmsg("getsockname() failed with error: (%d) %s",
             error, strerror(error));
      sclose(sock);
      return CURL_SOCKET_BAD;
    }
    switch(localaddr.sa.sa_family) {
    case AF_INET:
      *listenport = ntohs(localaddr.sa4.sin_port);
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      *listenport = ntohs(localaddr.sa6.sin6_port);
      break;
#endif
    default:
      break;
    }
    if(!*listenport) {
      /* Real failure, listener port shall not be zero beyond this point. */
      logmsg("Apparently getsockname() succeeded, with listener port zero.");
      logmsg("A valid reason for this failure is a binary built without");
      logmsg("proper network library linkage. This might not be the only");
      logmsg("reason, but double check it before anything else.");
      sclose(sock);
      return CURL_SOCKET_BAD;
    }
  }

  /* start accepting connections */
  rc = listen(sock, 5);
  if(0 != rc) {
    error = SOCKERRNO;
    logmsg("listen(%d, 5) failed with error: (%d) %s",
           sock, error, strerror(error));
    sclose(sock);
    return CURL_SOCKET_BAD;
  }

  return sock;
}


int main(int argc, char *argv[])
{
  curl_socket_t sock = CURL_SOCKET_BAD;
  curl_socket_t msgsock = CURL_SOCKET_BAD;
  int wrotepidfile = 0;
  const char *pidname = ".mqttd.pid";
  bool juggle_again;
  int error;
  int arg = 1;

  while(argc>arg) {
    if(!strcmp("--version", argv[arg])) {
      printf("mqttd IPv4%s\n",
#ifdef ENABLE_IPV6
             "/IPv6"
#else
             ""
#endif
             );
      return 0;
    }
    else if(!strcmp("--pidfile", argv[arg])) {
      arg++;
      if(argc>arg)
        pidname = argv[arg++];
    }
    else if(!strcmp("--config", argv[arg])) {
      arg++;
      if(argc>arg)
        configfile = argv[arg++];
    }
    else if(!strcmp("--logfile", argv[arg])) {
      arg++;
      if(argc>arg)
        serverlogfile = argv[arg++];
    }
    else if(!strcmp("--ipv6", argv[arg])) {
#ifdef ENABLE_IPV6
      ipv_inuse = "IPv6";
      use_ipv6 = TRUE;
#endif
      arg++;
    }
    else if(!strcmp("--ipv4", argv[arg])) {
      /* for completeness, we support this option as well */
#ifdef ENABLE_IPV6
      ipv_inuse = "IPv4";
      use_ipv6 = FALSE;
#endif
      arg++;
    }
    else if(!strcmp("--port", argv[arg])) {
      arg++;
      if(argc>arg) {
        char *endptr;
        unsigned long ulnum = strtoul(argv[arg], &endptr, 10);
        if((endptr != argv[arg] + strlen(argv[arg])) ||
           ((ulnum != 0UL) && ((ulnum < 1025UL) || (ulnum > 65535UL)))) {
          fprintf(stderr, "mqttd: invalid --port argument (%s)\n",
                  argv[arg]);
          return 0;
        }
        port = curlx_ultous(ulnum);
        arg++;
      }
    }
    else {
      puts("Usage: mqttd [option]\n"
           " --config [file]\n"
           " --version\n"
           " --logfile [file]\n"
           " --pidfile [file]\n"
           " --ipv4\n"
           " --ipv6\n"
           " --port [port]\n");
      return 0;
    }
  }

#ifdef WIN32
  win32_init();
  atexit(win32_cleanup);

  setmode(fileno(stdin), O_BINARY);
  setmode(fileno(stdout), O_BINARY);
  setmode(fileno(stderr), O_BINARY);
#endif

  install_signal_handlers();

#ifdef ENABLE_IPV6
  if(!use_ipv6)
#endif
    sock = socket(AF_INET, SOCK_STREAM, 0);
#ifdef ENABLE_IPV6
  else
    sock = socket(AF_INET6, SOCK_STREAM, 0);
#endif

  if(CURL_SOCKET_BAD == sock) {
    error = SOCKERRNO;
    logmsg("Error creating socket: (%d) %s",
           error, strerror(error));
    goto socks5_cleanup;
  }

  {
    /* passive daemon style */
    sock = sockdaemon(sock, &port);
    if(CURL_SOCKET_BAD == sock) {
      goto socks5_cleanup;
    }
    msgsock = CURL_SOCKET_BAD; /* no stream socket yet */
  }

  logmsg("Running %s version", ipv_inuse);
  logmsg("Listening on port %hu", port);

  wrotepidfile = write_pidfile(pidname);
  if(!wrotepidfile) {
    goto socks5_cleanup;
  }

  do {
    juggle_again = incoming(sock);
  } while(juggle_again);

socks5_cleanup:

  if((msgsock != sock) && (msgsock != CURL_SOCKET_BAD))
    sclose(msgsock);

  if(sock != CURL_SOCKET_BAD)
    sclose(sock);

  if(wrotepidfile)
    unlink(pidname);

  restore_signal_handlers();

  if(got_exit_signal) {
    logmsg("============> mqttd exits with signal (%d)", exit_signal);
    /*
     * To properly set the return status of the process we
     * must raise the same signal SIGINT or SIGTERM that we
     * caught and let the old handler take care of it.
     */
    raise(exit_signal);
  }

  logmsg("============> mqttd quits");
  return 0;
}
