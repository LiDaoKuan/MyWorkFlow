//
// Created by ldk on 10/2/25.
//

#ifndef MYWORKFLOW_IOSERVICE_LINUX_H
#define MYWORKFLOW_IOSERVICE_LINUX_H

#include <sys/uio.h>
#include <sys/eventfd.h>
#include <cstddef>
#include <pthread.h>
#include "list.h"

#define IOS_STATE_SUCCESS   0
#define IOS_STATE_ERROR     1

class IOSession {
private:
    virtual int prepare() = 0;
    virtual void handle(int state, int error) = 0;

protected:
    void prep_pread(int fd, void *buf, size_t count, long long offset);
    void prep_pwrite(int fd, void *buf, size_t count, long long offset);
    void prep_preadv(int fd, struct iovec *iov, int iovcnt, long long offset);
    void prep_pwritev(int fd, struct iovec *iov, int iovcnt, long long offset);
    void prep_fsync(int fd);
    void prep_fdsync(int fd);

    [[nodiscard]] long get_res() const { return this->res; }

private:
    char iocb_buf[64];
    long res;

    struct list_head list;

public:
    virtual ~IOSession() = default;
    friend class IOService;
    friend class Communicator;
};

class IOService {
public:
    int init(int maxevents);
    void deinit();

    int request(IOSession *session);

private:
    virtual void handle_stop(int error) {};
    virtual void handle_unbound() = 0;

private:
    virtual int create_event_fd() { return eventfd(0, 0); }

    void incref();
    void decref();

private:
    struct io_context *io_ctx;
    int event_fd;
    int ref;
    struct list_head session_list;
    pthread_mutex_t mutex;

private:
    static void *aio_finish(void *context);

public:
    virtual ~IOService();
    friend class Communicator;
};

#endif //MYWORKFLOW_IOSERVICE_LINUX_H