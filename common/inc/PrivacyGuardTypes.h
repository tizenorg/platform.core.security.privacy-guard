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

#ifndef _PRIVACYGUARDTYPES_H_
#define _PRIVACYGUARDTYPES_H_

#include <string>
#include <tzplatform_config.h>
#include "privacy_guard_client_types.h"

#define PRIVACY_DB_PATH         tzplatform_mkpath(TZ_SYS_DB,".privacy_guard.db")

//#define CYNARA_BUFFER_SIZE 1024
#define CYNARA_BUFFER_SIZE 100
#define USER_APP_PREFIX "User::App::"
#define USER_APP_PREFIX_LEN 11

typedef struct _privacy_data_s {
	char *privacy_id;
	int monitor_policy;
} privacy_data_s;

typedef struct _package_data_s {
	char *package_id;
	int count;
	int monitor_policy;
} package_data_s;

static const std::string SERVER_ADDRESS ("/tmp/privacy_guard_server");
static const std::string DBUS_PATH("/privacy_guard/dbus_notification");
static const std::string DBUS_SIGNAL_INTERFACE("org.tizen.privacy_guard.signal");
static const std::string DBUS_SIGNAL_SETTING_CHANGED("privacy_setting_changed");
static const std::string DBUS_SIGNAL_PKG_REMOVED("privacy_pkg_removed");

#endif // _PRIVACYGUARDTYPES_H_
