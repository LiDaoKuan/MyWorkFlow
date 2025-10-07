//
// Created by ldk on 10/6/25.
//

#ifndef MYWORKFLOW_MSGQUEUE_H
#define MYWORKFLOW_MSGQUEUE_H

#include <stddef.h>

typedef struct __msgqueue msgqueue_t;

#ifdef __cplusplus
extern "C" {
#endif

msgqueue_t *msgqueue_create(size_t max_len, int linkoff);
void *msgqueue_get(msgqueue_t *queue);
void msgqueue_put(void *msg, msgqueue_t *queue);
void msgqueue_put_head(void *msg, msgqueue_t *queue);
void msgqueue_set_nonblock(msgqueue_t *queue);
void msgqueue_set_block(msgqueue_t *queue);
void msgqueue_destroy(msgqueue_t *queue);

#ifdef __cplusplus
}
#endif

#endif //MYWORKFLOW_MSGQUEUE_H