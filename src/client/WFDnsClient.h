//
// Created by ldk on 11/27/25.
//

#ifndef MYWORKFLOW_WFDNSCLIENT_H
#define MYWORKFLOW_WFDNSCLIENT_H

#include <string>
#include <atomic>
#include "WFTaskFactory.h"
#include "dns_types.h"
#include "DnsMessage.h"

class WFDnsClient {
public:
    int init(const std::string &url);
    int init(const std::string &url, const std::string &search_list,
             int ndots, int attempts, bool rotate);
    void deinit();

    WFDnsTask *create_dns_task(const std::string &name, dns_callback_t callback);

private:
    void *params{nullptr};
    std::atomic<size_t> id;

public:
    virtual ~WFDnsClient() = default;
};

#endif // MYWORKFLOW_WFDNSCLIENT_H