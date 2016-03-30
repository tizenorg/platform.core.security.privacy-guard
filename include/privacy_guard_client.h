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
 * @file	privacy_guard_client.h
 * @brief	APIs for privacy-guard-client
 */

#ifndef _PRIVACY_GUARD_CLIENT_H_
#define _PRIVACY_GUARD_CLIENT_H_

#include <time.h>
#include "privacy_guard_client_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief	Called when the reply of the monitor policy request is delivered.
 * @since	tizen 3.0
 *
 * @param[in] privacy_id		The privacy ID
 * @param[in] monitor_policy	The monitor policy (0 or 1)
 * @param[in] user_data		The user data passed from the callback registration function
 *
 * @returns: true to continue with the next iteration of the loop, otherwise return false to break out of the loop
 *
 * @see	privacy_guard_client_foreach_monitor_policy_by_package_id()
 */
typedef bool (*privacy_guard_client_monitor_policy_cb) (const char *privacy_id, const int monitor_policy, void *user_data);

/**
 * @brief	Called when the reply of the package id request is delivered.
 * @since	tizen 3.0
 *
 * @param[in] package_id	The package ID
 * @param[in] user_data	The user data passed from the callback registration function
 *
 * @returns: true to continue with the next iteration of the loop, otherwise return false to break out of the loop
 *
 * @see	privacy_guard_client_foreach_privacy_package_id()
 */
typedef bool (*privacy_guard_client_package_id_cb) (const char *package_id, void *user_data);

/**
 * @brief	Called when the reply of the privacy count request is delivered.
 * @since	tizen 3.0
 *
 * @param[in] privacy_id	The privacy ID
 * @param[in] count		The privacy count
 * @param[in] user_data	The user data passed from the callback registration function
 *
 * @returns: true to continue with the next iteration of the loop, otherwise return false to break out of the loop
 *
 * @see	privacy_guard_client_foreach_log_count_by_privacy_id()
 */
typedef bool (*privacy_guard_client_privacy_count_cb) (const char *privacy_id, const int count, void *user_data);

/**
 * @brief	Called when the reply of the privacy count request of package is delivered.
 * @since	tizen 3.0
 *
 * @param[in] privacy_id	The privacy ID
 * @param[in] count		The privacy count of a package
 * @param[in] user_data	The user data passed from the callback registration function
 *
 * @returns: true to continue with the next iteration of the loop, otherwise return false to break out of the loop
 *
 * @see	privacy_guard_client_foreach_log_count_by_package_id()
 */
typedef bool (*privacy_guard_client_privacy_count_of_package_cb) (const char *package_id, const int count, void *user_data);

/**
 * @fn int privacy_guard_client_foreach_total_privacy_count_of_package(const int user_id, const int start_date, const int end_date, privacy_guard_client_privacy_count_of_package_cb callback, void *user_data)
 * @brief get total privacy access count for each packcage
 * @param[in] user_id		user ID
 * @param[in] start_date 	start date to be monitored (Unix time)
 * @param[in] end_date 	end date to be monitored (Unix time)
 * @param[in] callback 		The callback function to invoke
 * @param[in] user_data	The user data to be passed to the callback function
 */
EXTERN_API int privacy_guard_client_foreach_total_privacy_count_of_package(const int user_id, const time_t start_date, const time_t end_date, privacy_guard_client_privacy_count_of_package_cb callback, void *user_data);

/**
 * @fn int privacy_guard_client_foreach_total_privacy_count_of_privacy(const int user_id, const int start_date, const int end_date, privacy_guard_client_privacy_count_cb callback, void *user_data)
 * @brief get total privacy access count for each privacy
 * @param[in] user_id 		user ID
 * @param[in] start_date 	start date to be monitored (Unix time)
 * @param[in] end_date 	end date to be monitored (Unix time)
 * @param[in] callback 		The callback function to invoke
 * @param[in] user_data 	The user data to be passed to the callback function
 */
EXTERN_API int privacy_guard_client_foreach_total_privacy_count_of_privacy(const int user_id, const time_t start_date, const time_t end_date, privacy_guard_client_privacy_count_cb callback, void *user_data);

/**
 * @fn int privacy_guard_client_foreach_privacy_count_by_privacy_id(const int user_id, const int start_date, const int end_date, const char* privacy_id, privacy_guard_client_privacy_count_of_package_cb callback, void *user_data)
 * @brief get privacy access count by specified privacy
 * @param[in] user_id 		user ID
 * @param[in] start_date 	start date to be monitored (Unix time)
 * @param[in] end_date 	end date to be monitored (Unix time)
 * @param[in] privacy_id 	privacy ID
 * @param[in] callback 		The callback function to invoke
 * @param[in] user_data 	The user data to be passed to the callback function
 */
EXTERN_API int privacy_guard_client_foreach_privacy_count_by_privacy_id(const int user_id, const time_t start_date, const time_t end_date, const char *privacy_id, privacy_guard_client_privacy_count_of_package_cb callback, void *user_data);

/**
 * @fn int privacy_guard_client_foreach_privacy_count_by_package_id(const int user_id, const int start_date, const int end_date, const char *package_id, privacy_guard_client_privacy_count_cb callback, void *user_data)
 * @brief get privacy access count by specified package
 * @param[in] user_id 		user ID
 * @param[in] start_date 	start date to be monitored (Unix time)
 * @param[in] end_date	end date to be monitored (Unix time)
 * @param[in] package_id 	package ID
 * @param[in] callback 		The callback function to invoke
 * @param[in] user_data 	The user data to be passed to the callback function
 */
EXTERN_API int privacy_guard_client_foreach_privacy_count_by_package_id(const int user_id, const time_t start_date, const time_t end_date, const char *package_id, privacy_guard_client_privacy_count_cb callback, void *user_data);

/**
 * @fn int privacy_guard_client_update_monitor_policy(const int user_id, const char *package_id, const char *privacy_id, int monitor_policy)
 * @brief update monitor policy
 * @param[in] user_id 			The user ID
 * @param[in] package_id 		The package ID
 * @param[in] privacy_id 		The privacy ID
 * @param[in] monitor_policy 	monitor policy (0 or 1) to be set
 */
EXTERN_API int privacy_guard_client_update_monitor_policy(const int user_id, const char *package_id, const char *privacy_id, const int monitor_policy);

/**
 * @fn int privacy_guard_client_foreach_monitor_policy_by_package_id(const int user_id, const char *package_id,
		privacy_guard_client_monitor_policy_cb callback, void *user_data)
 * @brief get monitor policy by package
 * @param[in] user_id 		The user ID
 * @param[in] package_id 	The package ID
 * @param[in] callback The 	callback function to invoke
 */
EXTERN_API int privacy_guard_client_foreach_monitor_policy_by_package_id(const int user_id, const char *package_id,
		privacy_guard_client_monitor_policy_cb callback, void *user_data);

/**
 * @fn int privacy_guard_client_check_privacy_package(const int user_id, const char *package_id, bool *is_privacy_package)
 * @brief check whether the package use a privacy or not
 * @param[in] user_id 				The user ID
 * @param[in] package_id 			The package ID
 * @param[out] is_privacy_package 	The result of privacy package or not
 * @return the result of operation (ERRORCODE : success, ....)
 */
EXTERN_API int privacy_guard_client_check_privacy_package(const int user_id, const char *package_id, bool *is_privacy_package);

/**
 * @fn int privacy_guard_client_foreach_privacy_package_id(const int user_id, privacy_guard_client_package_id_cb callback, void *user_data)
 * @brief get package using one or more privacy
 * @param[in] user_id 		The user ID
 * @param[in] callback 		The callback function to invoke
 * @param[in] user_data 	The user data to be passed to the callback function
 */
EXTERN_API int privacy_guard_client_foreach_privacy_package_id(const int user_id, privacy_guard_client_package_id_cb callback, void *user_data);

/**
 * @fn int privacy_guard_client_foreach_package_by_privacy_id(const int user_id, const char *privacy_id, privacy_guard_client_package_id_cb callback, void *user_data)
 * @brief get package using specified privacy
 * @param[in] user_id 		The user ID
 * @param[in] privacy_id 	The privacy ID
 * @param[in] callback 		The callback function to invoke
 * @param[in] user_data The user data to be passed to the callback function
 */
EXTERN_API int privacy_guard_client_foreach_package_by_privacy_id(const int user_id, const char *privacy_id, privacy_guard_client_package_id_cb callback, void *user_data);

/**
 * @fn int privacy_guard_client_update_main_monitor_policy(const int user_id, const bool main_monitor_policy)
 * @brief update main monitor policy
 * @param[in] user_id 				The user ID
 * @param[in] main_monitor_policy  	The main monitor policy (false or true) to be set
 */
EXTERN_API int privacy_guard_client_update_main_monitor_policy(const int user_id, const bool main_monitor_policy);

/**
 * @fn int privacy_guard_client_update_main_monitor_policy(const int user_id, const bool main_monitor_policy)
 * @brief get main monitor policy
 * @param[in] user_id 				The user ID
 * @param[out] main_monitor_policy 	The value of main monitor policy
 */
EXTERN_API int privacy_guard_client_get_main_monitor_policy(const int user_id, bool *main_monitor_policy);

/**
 * @fn int privacy_guard_client_update_main_monitor_policy(const int user_id, const bool main_monitor_policy)
 * @brief Delete main monitor policy
 * @param[in] user_id 		The user ID to be deleted
 */
EXTERN_API int privacy_guard_client_delete_main_monitor_policy_by_user_id(const int user_id);
#ifdef __cplusplus
}
#endif


#endif //_PRIVACY_GUARD_CLIENT_H_
