/*
 * Copyright (c) 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file	privacy_guard_client_internal.h
 * @brief	APIs for privacy-guard-client
 */

#ifndef _PRIVACY_GUARD_CLIENT_INTERNAL_H_
#define _PRIVACY_GUARD_CLIENT_INTERNAL_H_

#include <time.h>
#include "privacy_guard_client_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @fn int privacy_guard_client_add_privacy_access_log(const int user_id, const char *package_id, const char *privacy_id)
 * @brief add log for usage of privacy api to StatisticsMonitor DB
 * @param[in] user_id user ID
 * @param[in] package_id package ID
 * @param[in] privacy_id privacy ID [e.g. http://tizen.org/privacy/contact]
 * @return the result of operation (ERRORCODE : success, ....)
 */
EXTERN_API int privacy_guard_client_add_privacy_access_log(const int user_id, const char *package_id, const char *privacy_id);

/**
 * @fn int privacy_guard_client_delete_all_logs_and_monitor_policy(void)
 * @brief clear all data from StatisticsMonitor and MonitorPolicy DB
 */
EXTERN_API int privacy_guard_client_delete_all_logs_and_monitor_policy(void);

/**
 * @fn int privacy_guard_client_add_monitor_policy(const int user_id, const char *package_id, const char **privilege_list, const int monitor_policy)
 * @brief add monitor policy by user id and specified package to MonitorPolicy DB
 * @param[in] user_id The user ID
 * @param[in] package_id The package ID
 * @param[in] privilege_list The privilege list
 * @param[in] monitor_policy The monitor policy (0 or 1)
 */
EXTERN_API int privacy_guard_client_add_monitor_policy(const int user_id, const char *package_id, const char **privilege_list, const int monitor_policy);

/**
 * @fn int privacy_guard_client_delete_logs_by_package_id(const char *package_id)
 * @brief remove statistics info by specified package from StatisticsMonitor DB
 * @param[in] package_id package ID
 */
EXTERN_API int privacy_guard_client_delete_logs_by_package_id(const char *package_id);

/**
 * @fn int privacy_guard_client_delete_monitor_policy_by_package_id(const char *package_id)
 * @brief remove statistics info by specified package from MonitorPolicy DB
 * @param[in] package_id The package ID
 */
EXTERN_API int privacy_guard_client_delete_monitor_policy_by_package_id(const char *package_id);

#ifdef __cplusplus
}
#endif


#endif //_PRIVACY_GUARD_CLIENT_INTERNAL_H_

