//
// Created by ldk on 9/28/25.
//

/*
Copyright (c) 2019 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Xie Han (xiehan@sogou-inc.com)
*/

template<class REQ, class RESP>
int WFNetworkTask<REQ, RESP>::get_peer_addr(struct sockaddr *addr,
                                            socklen_t *addrlen) const
{
    const struct sockaddr *p;
    socklen_t len;

    if (this->target)
    {
        this->target->get_addr(&p, &len);
        if (*addrlen >= len)
        {
            memcpy(addr, p, len);
            *addrlen = len;
            return 0;
        }

        errno = ENOBUFS;
    }
    else
        errno = ENOTCONN;

    return -1;
}
