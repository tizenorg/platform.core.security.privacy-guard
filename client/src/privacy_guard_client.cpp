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

#include <string.h>
#include <string>
#include <memory>
#include <dlog.h>
#include "PrivacyChecker.h"
#include "PrivacyGuardClient.h"
#include "privacy_guard_client.h"
#include "privacy_guard_client_internal.h"
#include "privacy_guard_client_internal_types.h"
#include "Utils.h"

#define MONITOR_POLICY_OFF 0
#define MONITOR_POLICY_ON 1

#ifndef TIZEN_PATH_MIN
#define TIZEN_PATH_MIN 5
#endif

#ifndef TIZEN_PATH_MAX
#define TIZEN_PATH_MAX 1024
#endif

int privacy_guard_client_add_privacy_access_log(const int user_id, const char *package_id, const char *privilege_id)
{
	if (user_id < 0 || package_id == NULL || privilege_id == NULL)
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;

	int monitor_policy = 0;
	std::string privacy_id;

	PF_LOGD("user_id : %d, package_id : %s, privilege_id : %s", user_id, package_id, privilege_id);

	int retval = PrivacyChecker::checkMonitorPolicyWithPrivilege(user_id, std::string(package_id), std::string(privilege_id), privacy_id, monitor_policy);

	PF_LOGD("monitor policy : %d", monitor_policy);

	if (retval == PRIV_FLTR_ERROR_SUCCESS && monitor_policy == MONITOR_POLICY_ON) {
		PrivacyGuardClient *pInst = PrivacyGuardClient::getInstance();
		retval = pInst->PgAddPrivacyAccessLog(user_id, std::string(package_id), std::string(privacy_id));
	}
	PF_LOGD("retval : %d", retval);
	return retval;
}

int privacy_guard_client_delete_all_logs_and_monitor_policy(void)
{
	PrivacyGuardClient *pInst = PrivacyGuardClient::getInstance();

	int retval = pInst->PgDeleteAllLogsAndMonitorPolicy();

	return retval;
}

int privacy_guard_client_delete_logs_by_package_id(const char *package_id)
{
	if (package_id == NULL)
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;

	PrivacyGuardClient *pInst = PrivacyGuardClient::getInstance();

	int retval = pInst->PgDeleteLogsByPackageId(std::string(package_id));

	return retval;
}

int privacy_guard_client_delete_monitor_policy_by_package_id(const char *package_id)
{
	if (package_id == NULL)
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;

	PrivacyGuardClient *pInst = PrivacyGuardClient::getInstance();

	int retval = pInst->PgDeleteMonitorPolicyByPackageId(std::string(package_id));

	return retval;
}

int privacy_guard_client_foreach_total_privacy_count_of_package(const int user_id, const time_t start_date,
		const time_t end_date, privacy_guard_client_privacy_count_of_package_cb callback, void *user_data)
{
	if (user_id < 0 || start_date > end_date || start_date <= 0)
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;
	PrivacyGuardClient *pInst = PrivacyGuardClient::getInstance();
	std::list <std::pair<std::string, int>> list;

	PF_LOGD("start_date : %d, end_date : %d", start_date, end_date);
	int retval = pInst->PgForeachTotalPrivacyCountOfPackage(user_id, start_date, end_date, list);

	if (retval != PRIV_FLTR_ERROR_SUCCESS)
		return retval;
	if (list.size() == 0)
		return PRIV_FLTR_ERROR_NO_DATA;

	for (std::list <std::pair <std::string, int>>::iterator iter = list.begin(); iter != list.end(); ++iter) {
		PF_LOGD("result > package_id : %s, count : %d", iter->first.c_str(), iter->second);
		bool ret = callback(iter->first.c_str(), iter->second, user_data);
		if (ret == false)
			break;
	}

	return retval;
}

int privacy_guard_client_foreach_total_privacy_count_of_privacy(const int user_id, const time_t start_date,
		const time_t end_date, privacy_guard_client_privacy_count_cb callback, void *user_data)
{
	if (user_id < 0 || start_date > end_date || start_date <= 0)
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;

	PrivacyGuardClient *pInst = PrivacyGuardClient::getInstance();
	std::list <std::pair<std::string, int>> list;

	PF_LOGD("start_date : %d, end_date : %d", start_date, end_date);
	int retval = pInst->PgForeachTotalPrivacyCountOfPrivacy(user_id, start_date, end_date, list);

	if (retval != PRIV_FLTR_ERROR_SUCCESS)
		return retval;
	if (list.size() == 0)
		return PRIV_FLTR_ERROR_NO_DATA;

	for (std::list <std::pair <std::string, int>>::iterator iter = list.begin(); iter != list.end(); ++iter) {
		PF_LOGD("result > privacy_id : %s, count : %d", iter->first.c_str(), iter->second);
		bool ret = callback(iter->first.c_str(), iter->second, user_data);
		if (ret == false)
			break;
	}

	return retval;
}

int privacy_guard_client_foreach_privacy_count_by_privacy_id(const int user_id, const time_t start_date,
		const time_t end_date, const char *privacy_id,
		privacy_guard_client_privacy_count_of_package_cb callback, void *user_data)
{
	if (user_id < 0 || start_date > end_date || start_date <= 0 || privacy_id == NULL)
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;

	PrivacyGuardClient *pInst = PrivacyGuardClient::getInstance();
	std::list <std::pair<std::string, int>> list;

	PF_LOGD("start_date : %d, end_date : %d", start_date, end_date);
	int retval = pInst->PgForeachPrivacyCountByPrivacyId(user_id, start_date, end_date, std::string(privacy_id), list);

	if (retval != PRIV_FLTR_ERROR_SUCCESS)
		return retval;
	if (list.size() == 0)
		return PRIV_FLTR_ERROR_NO_DATA;

	for (std::list <std::pair <std::string, int>>::iterator iter = list.begin(); iter != list.end(); ++iter) {
		PF_LOGD("result > package_id : %s, count : %d", iter->first.c_str(), iter->second);
		bool ret = callback(iter->first.c_str(), iter->second, user_data);
		if (ret == false)
			break;
	}

	return retval;
}


int privacy_guard_client_foreach_privacy_count_by_package_id(const int user_id, const time_t start_date,
		const time_t end_date, const char *package_id,
		privacy_guard_client_privacy_count_cb callback, void *user_data)
{
	if (user_id < 0 || start_date > end_date || start_date <= 0 || package_id == NULL)
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;

	PrivacyGuardClient *pInst = PrivacyGuardClient::getInstance();
	std::list <std::pair<std::string, int>> list;

	PF_LOGD("start_date : %d, end_date : %d", start_date, end_date);
	int retval = pInst->PgForeachPrivacyCountByPackageId(user_id, start_date, end_date, std::string(package_id), list);

	if (retval != PRIV_FLTR_ERROR_SUCCESS)
		return retval;
	if (list.size() == 0)
		return PRIV_FLTR_ERROR_NO_DATA;

	for (std::list <std::pair <std::string, int>>::iterator iter = list.begin(); iter != list.end(); ++iter) {
		PF_LOGD("result > privacy_id : %s, count : %d", iter->first.c_str(), iter->second);
		bool ret = callback(iter->first.c_str(), iter->second, user_data);
		if (ret == false)
			break;
	}

	return retval;
}

int privacy_guard_client_add_monitor_policy(const int user_id, const char *package_id, const char **privilege_list, const int monitor_policy)
{
	if (user_id < 0 || package_id == NULL)
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;

    PrivacyGuardClient *pInst = PrivacyGuardClient::getInstance();
    std::list < std::string > privilegeList;

    while (*privilege_list[0] != '\0')
    {
		PF_LOGD("privacyList : %s", *privilege_list);
		privilegeList.push_back(std::string(*privilege_list++));
    }

    int retval = pInst->PgAddMonitorPolicy(user_id, std::string(package_id), privilegeList, monitor_policy);

    return retval;
}

int privacy_guard_client_update_monitor_policy(const int user_id, const char *package_id, const char *privacy_id, const int monitor_policy)
{
	if (user_id < 0 || package_id == NULL || privacy_id == NULL)
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;

    PrivacyGuardClient *pInst = PrivacyGuardClient::getInstance();

    int retval = pInst->PgUpdateMonitorPolicy(user_id, std::string(package_id), std::string(privacy_id), monitor_policy);

    return retval;
}

int privacy_guard_client_foreach_monitor_policy_by_package_id(const int user_id, const char *package_id,
		privacy_guard_client_monitor_policy_cb callback, void *user_data)
{
	if (user_id < 0 || package_id == NULL)
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;

	PF_LOGD("package_id : %s", package_id);

	std::list <privacy_data_s> privacyInfoList;
	int retval = -1;

	retval = PrivacyGuardClient::getInstance()->PgForeachMonitorPolicyByPackageId(user_id, std::string(package_id), privacyInfoList);

	if (retval != PRIV_FLTR_ERROR_SUCCESS) {
		PF_LOGE("PgForeachMonitorPolicyByPackageId : fail");
		return retval;
	}

	if (privacyInfoList.size() == 0) {
		PF_LOGE("PgForeachMonitorPolicyByPackageId (privacyList.size = 0): fail");
		return PRIV_FLTR_ERROR_NO_DATA;
	}

	for (std::list <privacy_data_s>::iterator iter = privacyInfoList.begin(); iter != privacyInfoList.end(); ++iter) {
		PF_LOGD("result > privacy_id : %s, monitor_policy : %d",
						iter->privacy_id, iter->monitor_policy);
		bool ret = callback(iter->privacy_id, iter->monitor_policy, user_data);
		if (ret == false)
			break;
	}

	return retval;
}

int privacy_guard_client_check_privacy_package(const int user_id, const char *package_id, bool *is_privacy_package)
{
	if (user_id < 0 || package_id == NULL)
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;

	PrivacyGuardClient* pInst = PrivacyGuardClient::getInstance();

	PF_LOGD("user_id : %d, package_id : %s", user_id, package_id);
	int retval = pInst->PgCheckPrivacyPackage(user_id, std::string(package_id), *is_privacy_package);
	PF_LOGD("result > is_privacy_package : %d", *is_privacy_package);

	return retval;
}

int privacy_guard_client_foreach_privacy_package_id(const int user_id, privacy_guard_client_package_id_cb callback, void *user_data)
{
	if (user_id < 0)
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;

	PrivacyGuardClient* pInst = PrivacyGuardClient::getInstance();

	std::list < std::string > packageList;

	int retval = pInst->PgForeachPrivacyPackageId(user_id, packageList);
	if (retval != PRIV_FLTR_ERROR_SUCCESS) {
		PF_LOGE("PgForeachPrivacyPackageId : fail");
		return retval;
	}

	if (packageList.size() == 0) {
		PF_LOGE("PgForeachPrivacyPackageId (packageList.size = 0): fail");
		return PRIV_FLTR_ERROR_NO_DATA;
	}

	for (std::list < std::string >::iterator iter = packageList.begin(); iter != packageList.end(); ++iter) {
		PF_LOGD("package_id : %s", iter->c_str());
		bool ret = callback(iter->c_str(), user_data);
		if (ret == false)
			break;
	}

	return retval;
}

int privacy_guard_client_foreach_package_by_privacy_id(const int user_id, const char *privacy_id, privacy_guard_client_package_id_cb callback, void *user_data)
{
	if (user_id < 0 || privacy_id == NULL)
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;

	PrivacyGuardClient* pInst = PrivacyGuardClient::getInstance();

	std::list < std::string > packageList;

	int retval = pInst->PgForeachPackageByPrivacyId(user_id, std::string(privacy_id), packageList);
	if (retval != PRIV_FLTR_ERROR_SUCCESS) {
		PF_LOGE("PgForeachPackageByPrivacyId : fail");
		return retval;
	}

	if (packageList.size() == 0) {
		PF_LOGE("PgForeachPackageByPrivacyId (packageList.size = 0): fail");
		return PRIV_FLTR_ERROR_NO_DATA;
	}

	for (std::list < std::string >::iterator iter = packageList.begin(); iter != packageList.end(); ++iter) {
		PF_LOGD("package_id : %s", iter->c_str());
		bool ret = callback(iter->c_str(), user_data);
		if (ret == false)
			break;
	}

	return retval;
}

int privacy_guard_client_update_main_monitor_policy(const int user_id, const bool main_monitor_policy)
{
	if (user_id < 0)
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;

    PrivacyGuardClient *pInst = PrivacyGuardClient::getInstance();

    int retval = pInst->PgUpdateMainMonitorPolicy(user_id, main_monitor_policy);

    return retval;
}

int privacy_guard_client_get_main_monitor_policy(const int user_id, bool *main_monitor_policy)
{
	if (user_id < 0)
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;

	PrivacyGuardClient* pInst = PrivacyGuardClient::getInstance();

	PF_LOGD("user_id : %d", user_id);
	int retval = pInst->PgGetMainMonitorPolicy(user_id, *main_monitor_policy);
	PF_LOGD("result > main_monitor_policy : %d", *main_monitor_policy);

	return retval;
}

int privacy_guard_client_delete_main_monitor_policy_by_user_id(const int user_id)
{
	if (user_id < 0)
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;

	PrivacyGuardClient *pInst = PrivacyGuardClient::getInstance();

	int retval = pInst->PgDeleteMainMonitorPolicyByUserId(user_id);

	return retval;
}
