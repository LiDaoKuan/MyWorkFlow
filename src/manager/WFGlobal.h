//
// Created by ldk on 10/25/25.
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

  Authors: Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#ifndef MYWORKFLOW_WFGLOBAL_H
#define MYWORKFLOW_WFGLOBAL_H

#if __cplusplus < 201100
#error CPLUSPLUS VERSION required at least C++11. Please use "-std=c++11".
#include <C++11_REQUIRED>
#endif

#include <openssl/ssl.h>
#include <string>
#include "CommScheduler.h"
#include "DnsCache.h"
#include "RouteManager.h"
#include "Executor.h"
#include "EndpointParams.h"
//#include "WFResourcePool.h"
//#include "WFNameService.h"
//#include "WFDnsResolver.h"

class WFGlobal {};


#endif //MYWORKFLOW_WFGLOBAL_H