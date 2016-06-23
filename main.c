#include "rtmp_server.h"

uv_loop_t *g_loop;

int main(int argc, char **argv) {
  g_loop = uv_default_loop();
  if (rtmp_server_init(g_loop, "0.0.0.0", 1935))
    return 1;
  fprintf(stderr, "rtmp server listen on 1935\n");
  return uv_run(g_loop, UV_RUN_DEFAULT);
}
