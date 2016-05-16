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

#include <set>
#include <libintl.h>
#include <system_info.h>
#include <privilege_info.h>
#include "PrivacyIdInfo.h"
#include "privacy_guard_client_types.h"
#include "PrivacyGuardTypes.h"
#include "Utils.h"

std::map< std::string, std::string > PrivacyIdInfo::m_privilegeToPrivacyMap;
bool PrivacyIdInfo:: m_isInitialized;

int
PrivacyIdInfo::initialize(void)
{
	GList *privacy_list = NULL, *privilege_list = NULL;
	GList *l = NULL, *k = NULL;

	int ret = privilege_info_get_privacy_list(&privacy_list);
	if (ret != PRVMGR_ERR_NONE) {
		PG_LOGE("Failed to get privacy list from security-privilege-manager [%d].", ret);
		return PRIV_GUARD_ERROR_INTERNAL_ERROR;
	}

	for (l = privacy_list; l != NULL; l = l->next) {
		char *privacy_id = (char*)l->data;
		ret = privilege_info_get_privilege_list_by_privacy(privacy_id, &privilege_list);
		if (ret != PRVMGR_ERR_NONE) {
			PG_LOGE("Failed to get privilege list from security-privilege-manager [%d] using privacy[%s].", ret, privacy_id);
			g_list_free(privacy_list);
			return PRIV_GUARD_ERROR_INTERNAL_ERROR;
		}

		for (k = privilege_list; k != NULL; k = k->next) {
			char *privilege_id = (char*)k->data;
			PG_LOGD("(privacy, privilege): (%s, %s)", privacy_id, privilege_id);
			m_privilegeToPrivacyMap.insert(std::map< std::string, std::string >::value_type(std::string(privilege_id), std::string(privacy_id)));
		}
	}

	g_list_free(privacy_list);
	g_list_free(privilege_list);

	m_isInitialized = true;

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyIdInfo::getPrivacyIdFromPrivilege(const std::string privilege, std::string& privacyId)
{
	if (!m_isInitialized) {
		initialize();
	}

	std::map< std::string, std::string >::iterator iter = m_privilegeToPrivacyMap.find(privilege);
	if (iter == m_privilegeToPrivacyMap.end()) {
		PG_LOGE("There is no matching privacy to privilege [%s]", privilege.c_str());
		return PRIV_GUARD_ERROR_NO_DATA;
	}

	privacyId = iter->second;

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyIdInfo::getPrivilegeListFromPrivacyId(const std::string privacyId, std::list< std::string >& privilegeList)
{
	if (!m_isInitialized) {
		initialize();
	}

	privilegeList.clear();

	for (std::map< std::string, std::string >::iterator iter = m_privilegeToPrivacyMap.begin(); iter != m_privilegeToPrivacyMap.end(); ++iter) {
		if (privacyId.compare((iter->second)) == 0) {
			privilegeList.push_back(iter->first);
		}
	}

	if (privilegeList.size() == 0) {
		PG_LOGE("There is no matching privilege to privacy [%s].", privacyId.c_str());
		return PRIV_GUARD_ERROR_NO_DATA;
	}

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyIdInfo::getPrivacyIdListFromPrivilegeList(const std::list< std::string > privilegeList, std::list< std::string >& privacyIdList)
{
	if (!m_isInitialized) {
		initialize();
	}

	privacyIdList.clear();

	std::set< std::string > privacyIdSet;

	for (std::list< std::string >::const_iterator iter = privilegeList.begin(); iter != privilegeList.end(); ++iter) {
		std::string privacyId;
		int res = getPrivacyIdFromPrivilege(*iter, privacyId);
		if (res == PRIV_GUARD_ERROR_SUCCESS) {
			PG_LOGD("Privacy ID [%s] from Privilege [%s]", privacyId.c_str(), iter->c_str());
			privacyIdSet.insert(privacyId);
		}
	}

	for (std::set< std::string >::iterator iter = privacyIdSet.begin(); iter != privacyIdSet.end(); ++iter) {
		privacyIdList.push_back(*iter);
	}

	return PRIV_GUARD_ERROR_SUCCESS;
}

bool
PrivacyIdInfo::isValidPrivacyId(const std::string privacyId)
{
	if (!m_isInitialized) {
		initialize();
	}

	for (std::map< std::string, std::string >::iterator iter = m_privilegeToPrivacyMap.begin(); iter != m_privilegeToPrivacyMap.end(); ++iter) {
		if (privacyId.compare((iter->second)) == 0) {
			return true;
		}
	}

	return false;
}

int
PrivacyIdInfo::getAllPrivacyId(std::list< std::string >& privacyIdList)
{
	if (!m_isInitialized)
	{
		initialize();
	}

	GList *privacy_list = NULL;
	GList *l = NULL;

	int ret = privilege_info_get_privacy_list(&privacy_list);
	if (ret != PRVMGR_ERR_NONE) {
		PG_LOGE("Failed to get privacy list from security-privilege-manager [%d].", ret);
		return PRIV_GUARD_ERROR_INTERNAL_ERROR;
	}

	for (l = privacy_list; l != NULL; l = l->next) {
		char *privacy_id = (char*)l->data;
		PG_LOGD("[kylee] privacy_id: %s", privacy_id);
		privacyIdList.push_back(std::string(privacy_id));
	}

	return PRIV_GUARD_ERROR_SUCCESS;
}

/*
int
PrivacyIdInfo::getPrivaycDisplayName(const std::string privacyId, std::string& displayName)
{
	if (!m_isInitialized)
	{
		initialize();
	}

	std::string sql = std::string("SELECT STR_MODULE_ID, STR_NAME_ID from PrivacyInfo where PRIVACY_ID=?");

	openDb(PRIVACY_INFO_DB_PATH, pDbHandler, SQLITE_OPEN_READONLY);
	prepareDb(pDbHandler, sql.c_str(), pStmt);

	int res = sqlite3_bind_text(pStmt.get(), 1, privacyId.c_str(), -1, SQLITE_TRANSIENT);
	TryReturn(res == SQLITE_OK, PRIV_GUARD_ERROR_DB_ERROR, , "sqlite3_bind_text : %d", res);

	if (sqlite3_step(pStmt.get()) == SQLITE_ROW)
	{
		const char* pModuleId = reinterpret_cast < const char* > (sqlite3_column_text(pStmt.get(), 0));
		const char* pNameId = reinterpret_cast < const char* > (sqlite3_column_text(pStmt.get(), 1));

		if (pNameId == NULL)
		{
			displayName = privacyId;
		}
		else
		{
			displayName = std::string(dgettext(pModuleId, pNameId));
		}
	}
	else
	{
		PG_LOGI("Cannot find privacy string %s ", privacyId.c_str());
		return PRIV_GUARD_ERROR_NO_DATA;
	}

	return PRIV_GUARD_ERROR_SUCCESS;
}
*/

/*
int
PrivacyIdInfo::getPrivaycDescription(const std::string privacyId, std::string& displayName)
{
	if (!m_isInitialized)
	{
		initialize();
	}

	std::string sql = std::string("SELECT STR_MODULE_ID, STR_NAME_ID from PrivacyInfo where PRIVACY_ID=?");

	openDb(PRIVACY_INFO_DB_PATH, pDbHandler, SQLITE_OPEN_READONLY);
	prepareDb(pDbHandler, sql.c_str(), pStmt);

	int res = sqlite3_bind_text(pStmt.get(), 1, privacyId.c_str(), -1, SQLITE_TRANSIENT);
	TryReturn(res == SQLITE_OK, PRIV_GUARD_ERROR_DB_ERROR, , "sqlite3_bind_text : %d", res);

	if (sqlite3_step(pStmt.get()) == SQLITE_ROW)
	{
		const char* pModuleId = reinterpret_cast < const char* > (sqlite3_column_text(pStmt.get(), 0));
		const char* pNameId = reinterpret_cast < const char* > (sqlite3_column_text(pStmt.get(), 1));

		displayName = std::string(dgettext(pModuleId, pNameId));
	}
	else
	{
		PG_LOGI("Cannot find privacy string %s ", privacyId.c_str());
		return PRIV_GUARD_ERROR_NO_DATA;
	}

	return PRIV_GUARD_ERROR_SUCCESS;
}
*/

/*int
PrivacyIdInfo::isFeatureEnabled(const char* feature, bool& enabled)
{
	int res = PRIV_GUARD_ERROR_SUCCESS;

	if (feature == NULL)
	{
		enabled = true;
		return res;
	}

	res = system_info_get_platform_bool(feature, &enabled);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, PRIV_GUARD_ERROR_SYSTEM_ERROR, , "system_info_get_platform_bool : %d", res);

	return PRIV_GUARD_ERROR_SUCCESS;
}
*/
