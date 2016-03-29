/*
 * Copyright (c) 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#ifndef _PRIVACY_GUARD_DAEMON_H_
#define _PRIVACY_GUARD_DAEMON_H_

#include "privacy_guard_client_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int EXTERN_API privacy_guard_daemon_initialize(void);
int EXTERN_API privacy_guard_daemon_start(void);
int EXTERN_API privacy_guard_daemon_stop(void);
int EXTERN_API privacy_guard_daemon_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif //_PRIVACY_GUARD_DAEMON_H_

