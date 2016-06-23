#include "rtmp_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/times.h>
#include <unistd.h>

#ifndef offsetof
#define offsetof(type, member) ((size_t)((char *)&(((type *)0)->member)))
#endif

#ifndef container_of
#define container_of(ptr, type, member)                                        \
  ((type *)((char *)ptr - offsetof(type, member)))
#endif

uv_tcp_t tcp_srv_handle;
#define BUF_LEN 2048

#define HANDSHAKE_C0_C1 0
#define HANDSHAKE_C2 1
#define HANDSHAKE_FINISHED 1

#define TEF_BIG 0
#define TEF_LITTLE 1

const static size_t c0_size = 1;
const static size_t s0_size = 1;
const static size_t c1_size = 1536;
const static size_t s1_size = 1536;
const static size_t c2_size = 1536;
const static size_t s2_size = 1536;
static uint32_t clk_tck;

struct rtmp_session_s {
  uv_tcp_t tcp_cli_handle;
  uv_write_t w_req;
  char *recv_buf;
  int status;
  int fp9;
};

typedef struct rtmp_session_s rtmp_session_t;

#define CHECK_STATUS_WHIT_RETURN(ret, name)                                    \
  do {                                                                         \
    if (ret) {                                                                 \
      fprintf(stderr, "%s:%s", name, uv_strerror(ret));                        \
      return ret;                                                              \
    }                                                                          \
  } while (0);

#define CHECK_STATUS_WHITOUT_RETURN(ret, name)                                 \
  do {                                                                         \
    if (ret) {                                                                 \
      fprintf(stderr, "%s:%s", name, uv_strerror(ret));                        \
      return;                                                                  \
    }                                                                          \
  } while (0);

static void on_connection(uv_stream_t *server, int status);
static void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void on_close(uv_handle_t *handle);
static void on_write(uv_write_t *req, int status);
static rtmp_session_t *rtmp_session_init(uv_loop_t *loop);
static void rtmp_handshark(rtmp_session_t *c);
static int raw_write_uint32_v(uint8_t *buf, int flag, uint32_t v, int start,
                              int count);
static uint32_t read_uint32_v(uint8_t *buf, int flag, int start, int count);

static uint32_t get_time() {
  struct tms t;
  if (!clk_tck)
    clk_tck = sysconf(_SC_CLK_TCK);
  return times(&t) * 1000 / clk_tck;
}
int rtmp_server_init(uv_loop_t *loop, char *ip, int port) {
  struct sockaddr_in srv_addr;
  int r = uv_ip4_addr(ip, port, &srv_addr);
  CHECK_STATUS_WHIT_RETURN(r, "uv_ip4_addr")

  r = uv_tcp_init(loop, &tcp_srv_handle);
  CHECK_STATUS_WHIT_RETURN(r, "uv_tcp_init")

  r = uv_tcp_bind(&tcp_srv_handle, (struct sockaddr *)&srv_addr, 0);
  CHECK_STATUS_WHIT_RETURN(r, "uv_tcp_bind")

  r = uv_listen((uv_stream_t *)&tcp_srv_handle, 128, on_connection);
  CHECK_STATUS_WHIT_RETURN(r, "uv_listen");
  return 0;
}

static void on_connection(uv_stream_t *server, int status) {
  CHECK_STATUS_WHITOUT_RETURN(status, "on_connection")

  rtmp_session_t *c = rtmp_session_init(server->loop);
  if (!c)
    return;

  int r = uv_accept(server, (uv_stream_t *)&c->tcp_cli_handle);
  CHECK_STATUS_WHITOUT_RETURN(r, "uv_accept");

  r = uv_read_start((uv_stream_t *)&c->tcp_cli_handle, on_alloc, on_read);
  CHECK_STATUS_WHITOUT_RETURN(r, "uv_read_start")
}

static void on_alloc(uv_handle_t *handle, size_t suggested_size,
                     uv_buf_t *buf) {
  rtmp_session_t *c = container_of(handle, rtmp_session_t, tcp_cli_handle);
  buf->base = c->recv_buf;
  buf->len = BUF_LEN;
}

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
  if (nread < 0) {
    uv_close((uv_handle_t *)stream, on_close);
    return;
  } else if (nread == 0) {
    return;
  }
  rtmp_session_t *c = container_of(stream, rtmp_session_t, tcp_cli_handle);
  rtmp_handshark(c);
  fprintf(stderr, "len: %zd, on_read: %s\n", nread, c->recv_buf);
}

static void on_close(uv_handle_t *handle) {
  fprintf(stderr, "on_close\n");
  rtmp_session_t *c = container_of(handle, rtmp_session_t, tcp_cli_handle);
  free(c->recv_buf);
  free(c);
}

static void on_write(uv_write_t *req, int status) {
  if (status)
    fprintf(stderr, "send to rtmp client error!\n");
  fprintf(stderr, "send to rtmp client ok\n");
}

static rtmp_session_t *rtmp_session_init(uv_loop_t *loop) {
  rtmp_session_t *c = (rtmp_session_t *)malloc(sizeof(rtmp_session_t));
  memset(c, 0x0, sizeof(rtmp_session_t));
  int r = uv_tcp_init(loop, &c->tcp_cli_handle);
  if (r) {
    fprintf(stderr, "uv_tcp_init:%s\n", uv_strerror(r));
    free(c);
    return NULL;
  }
  c->recv_buf = (char *)malloc(BUF_LEN);
  c->status = HANDSHAKE_C0_C1;
  return c;
}

static void rtmp_handshark(rtmp_session_t *c) {
  memset(c->recv_buf + 1, 0x0, BUF_LEN - 1);
  if (c->status == HANDSHAKE_C0_C1) {
    if (c->recv_buf[0] != 0x3 && c->recv_buf[0] != 0x6) { // 0x6 ssl
      fprintf(stderr, "type reques is not 0x3 or 0x6");
      return;
    }
    uint32_t uptime = get_time();
    raw_write_uint32_v(c->recv_buf, TEF_BIG, uptime, 1, 4);
    raw_write_uint32_v(c->recv_buf, TEF_BIG, 0x03050101, 5, 4);
    c->fp9 = 0;
    uv_buf_t buf[] = {{.base = c->recv_buf, .len = 1537}};

    uint8_t *serversig = c->recv_buf + 1;
    if (serversig[4])
      c->fp9 = 1;
    int i;
    for (i = 8; i < 1536; i++) {
      serversig[i] = rand();
    }

    uv_write(&c->w_req, (uv_stream_t *)&c->tcp_cli_handle, buf, 1, on_write);
    c->status = HANDSHAKE_C2;
  } else if (c->status == HANDSHAKE_C2) {
    uint8_t *clientsig = c->recv_buf + 1;
    fprintf(stderr, "Flash player version: %d.%d.%d.%d\n", clientsig[4],
            clientsig[5], clientsig[6], clientsig[7]);

    memset(c->recv_buf + 1, 0x0, BUF_LEN - 1);
    uv_buf_t buf[] = {{.base = clientsig, .len = 1536}};
    uv_write(&c->w_req, (uv_stream_t *)&c->tcp_cli_handle, buf, 1, on_write);
    c->status = HANDSHAKE_FINISHED;
  }
}

static int raw_write_uint32_v(uint8_t *buf, int flag, uint32_t v, int start,
                              int count) {
  int idx = 0;

  while (idx < count) {
    if (flag == TEF_BIG) {
      buf[start + idx] = (v >> (8 * (count - 1 - idx))) & 0xff;
    } else {
      buf[start + idx] = (v >> (8 * idx)) & 0xff;
    }

    idx++;
  }
  return 0;
}

static uint32_t read_uint32_v(uint8_t *buf, int flag, int start, int count) {
  int processed = 0;
  char *ptr = buf + start;
  uint32_t facts[] = {1, 256, 65536, 16777216};
  uint32_t ret = 0;
  while (ptr && processed < count) {
    if (flag == TEF_BIG) {
      ret = ret * 256 + ptr[processed];
    } else {
      ret = ret + facts[processed] * ptr[processed];
    }
    ++processed;
  }
  return ret;
}
