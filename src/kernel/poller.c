//
// Created by ldk on 9/29/25.
//

#include <sys/types.h>
#include <sys/socket.h>

#ifdef __linux__
#include <sys/epoll.h>
#include <sys/timerfd.h>
#else
#include <sys/event.h>
#undef LIST_HEAD
#undef SLIST_HEAD
#endif
#include <error.h>
#include <unistd.h>

#include "poller.h"
#include "list.h"

#define POLLER_BUFSIZE      (256 * 1024)
#define POLLER_EVENTS_MAX   256

struct poller_node {
    int state;
    int error;
    struct poller_data data;
#pragma pack(1)
    union {
        struct list_head list;
        // struct rb_node rb;
    };
};