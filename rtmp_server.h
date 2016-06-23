#ifndef _RTMP_SERVER_H_
#define _RTMP_SERVER_H_

#include "uv.h"

int rtmp_server_init(uv_loop_t* loop, char* ip, int port);

#endif
