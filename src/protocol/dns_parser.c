//
// Created by ldk on 10/25/25.
//

/*
  Copyright (c) 2021 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Liu Kai (liukaidx@sogou-inc.com)
*/

#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "dns_types.h"
#include "dns_parser.h"

#define DNS_LABELS_MAX			63
#define DNS_NAMES_MAX			256
#define DNS_MSGBASE_INIT_SIZE	514 // 512 + 2(leading length)
#define MAX(x, y) ((x) <= (y) ? (y) : (x))


