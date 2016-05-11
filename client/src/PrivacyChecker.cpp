/*
 * Copyright (c) 2012 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <algorithm>
#include <memory>
#include <sqlite3.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <sys/types.h>
#include <unistd.h>
#include "PrivacyChecker.h"
#include "PrivacyIdInfo.h"
#include "PrivacyGuardClient.h"
#include "SocketClient.h"
#include "Utils.h"

#define BUF_SIZE 256

bool PrivacyChecker::m_isInitialized = false;
bool PrivacyChecker::m_isMonitorEnable = false;
std::map < std::string, bool >PrivacyChecker::m_privacyCache;
std::map < std::string, std::map < std::string, bool > > PrivacyChecker::m_privacyInfoCache;
std::map < std::string, int > PrivacyChecker::m_monitorPolicyCache;
std::mutex PrivacyChecker::m_cacheMutex;
std::mutex PrivacyChecker::m_dbusMutex;
std::mutex PrivacyChecker::m_initializeMutex;
std::string PrivacyChecker::m_pkgId;
DBusConnection* PrivacyChecker::m_pDBusConnection;
GMainLoop* PrivacyChecker::m_pLoop = NULL;
GMainContext* PrivacyChecker::m_pHandlerGMainContext = NULL;
const int MAX_LOCAL_BUF_SIZE = 128;
pthread_t PrivacyChecker::m_signalThread;

int
PrivacyChecker::initialize(void)
{
	if (m_isInitialized) {
		return PRIV_GUARD_ERROR_SUCCESS;
	}

	std::lock_guard < std::mutex > guard(m_cacheMutex);

	int res = initMonitorPolicyCache();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, ,"Failed to update cache (%d)", res);

	res = initializeGMain();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, ,"Failed to initialize() (%d)", res);

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyChecker::initializeGMain(void)
{
	std::unique_lock<std::mutex> initlock(m_initializeMutex);

	TryReturn(!m_isInitialized, PRIV_GUARD_ERROR_SUCCESS, , "Already Initalized");

	m_pHandlerGMainContext = g_main_context_new();
	TryReturn(m_pHandlerGMainContext != NULL, PRIV_GUARD_ERROR_SYSTEM_ERROR, ,"cannot create m_pHandlerGMainContext");

	m_pLoop = g_main_loop_new(m_pHandlerGMainContext, FALSE);
	TryReturn(m_pLoop != NULL, PRIV_GUARD_ERROR_SYSTEM_ERROR, ,"cannot create m_pLoop");

	std::unique_lock<std::mutex> lock(m_dbusMutex);
	char buf[BUF_SIZE];
	int res = pthread_create(&m_signalThread, NULL, &runSignalListenerThread, NULL);
	TryReturn(res >= 0, PRIV_GUARD_ERROR_SYSTEM_ERROR, errno = res;, "Failed to create listener thread :%s", strerror_r(res, buf, sizeof(buf)));

	m_isInitialized = true;

	return PRIV_GUARD_ERROR_SUCCESS;
}

void
PrivacyChecker::printMonitorPolicyCache(void)
{
	for(std::map<std::string, int>::iterator itr = m_monitorPolicyCache.begin(); itr != m_monitorPolicyCache.end(); itr++) {
		PG_LOGD("PRIVACY string : %s", itr->first.c_str());
		PG_LOGD("PRIVACY monitor_policy : %d", itr->second);
	}
}

int
PrivacyChecker::initMonitorPolicyCache(void)
{
	PG_LOGD("PrivacyChecker::initCache");

	std::list < std::pair < std::string, int > > monitorPolicyList;
	int retval = PrivacyGuardClient::getInstance()->PgGetAllMonitorPolicy(monitorPolicyList);
	if(retval == PRIV_GUARD_ERROR_SUCCESS && !monitorPolicyList.empty()) {
		m_monitorPolicyCache.insert(monitorPolicyList.begin(), monitorPolicyList.end());
	}
	return retval;
}

int
PrivacyChecker::getMonitorPolicy(const int userId, const std::string packageId, const std::string privacyId, int &monitorPolicy)
{
	PG_LOGD("getMonitorPolicy m_isInitialized : %d", m_isInitialized);

	if (m_isInitialized == false) {
		initialize();
	}
//	printMonitorPolicyCache();

	std::string userPkgIdPrivacyId = std::to_string(userId) + std::string("|") + packageId + std::string("|") + privacyId;
	PG_LOGD("key : %s", userPkgIdPrivacyId.c_str());
	std::map<std::string, int>::iterator itr = m_monitorPolicyCache.find(userPkgIdPrivacyId);
	int res = PRIV_GUARD_ERROR_SUCCESS;
	if(itr != m_monitorPolicyCache.end()) {
		monitorPolicy = itr->second;
	}
	else {
		monitorPolicy = 0;
		res = PRIV_GUARD_ERROR_NO_DATA;
	}

	return res;
}

void
PrivacyChecker::checkMonitorByPrivilege(const std::string privilegeId)
{
	PG_LOGD("checkMonitorByPrivilege");

	if(privilegeId.compare("http://tizen.org/privilege/calendar.read") == 0 ||
			privilegeId.compare("http://tizen.org/privilege/calendar.write") == 0 ||
			privilegeId.compare("http://tizen.org/privilege/contact.read") == 0 ||
			privilegeId.compare("http://tizen.org/privilege/contact.write") == 0 ||
			privilegeId.compare("http://tizen.org/privilege/location") == 0 ||
			privilegeId.compare("http://tizen.org/privilege/messaging.write") == 0 ||
			privilegeId.compare("http://tizen.org/privilege/messaging.read") == 0 ||
			privilegeId.compare("http://tizen.org/privilege/messaging.send") == 0 ||
			privilegeId.compare("http://tizen.org/privilege/messaging.sms") == 0 ||
			privilegeId.compare("http://tizen.org/privilege/messaging.mms") == 0 ||
			privilegeId.compare("http://tizen.org/privilege/messaging.email") == 0) {
		m_isMonitorEnable = true;
	}
	else {
		m_isMonitorEnable = false;
	}
}

int
PrivacyChecker::checkMonitorPolicyWithPrivilege(const int userId, const std::string packageId, const std::string privilegeId, std::string &privacyId, int &monitorPolicy)
{
	checkMonitorByPrivilege(privilegeId);
	if (m_isMonitorEnable == true) {
		int res = PrivacyIdInfo::getPrivacyIdFromPrivilege(privilegeId, privacyId);
		TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "getPrivacyIdFromPrivilege : %d", res);
		return getMonitorPolicy(userId, packageId, privacyId, monitorPolicy);
	}
	else {
		return PRIV_GUARD_ERROR_NO_DATA;
	}
}

void*
PrivacyChecker::runSignalListenerThread(void* pData)
{
	pthread_detach(pthread_self());
	PG_LOGI("Running g main loop for signal");

	initializeDbus();

	g_main_loop_run(m_pLoop);

	finalizeDbus();

	pthread_exit(NULL);

	return (void*) 0;
}

int
PrivacyChecker::initializeDbus(void)
{
	DBusError error;
	dbus_error_init(&error);

	m_pDBusConnection = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
	TryReturn(m_pDBusConnection != NULL, PRIV_GUARD_ERROR_SYSTEM_ERROR, dbus_error_free(&error), "dbus_bus_get_private [%s] : %d", PRIV_GUARD_ERROR_SYSTEM_ERROR);

	dbus_connection_setup_with_g_main(m_pDBusConnection, m_pHandlerGMainContext);
	std::unique_ptr < char[] > pRule(new char[MAX_LOCAL_BUF_SIZE]);

	snprintf(pRule.get(), MAX_LOCAL_BUF_SIZE, "path='%s',type='signal',interface='%s'", DBUS_PATH.c_str(), DBUS_SIGNAL_INTERFACE.c_str());
	dbus_bus_add_match(m_pDBusConnection, pRule.get(), &error);
	TryReturn(!dbus_error_is_set(&error), PRIV_GUARD_ERROR_SYSTEM_ERROR, dbus_error_free(&error), "dbus_bus_add_match[%s] : %d", error.message, PRIV_GUARD_ERROR_SYSTEM_ERROR);

	dbus_bool_t r = dbus_connection_add_filter(m_pDBusConnection, handleNotification, NULL, NULL);
	TryReturn(r, PRIV_GUARD_ERROR_SYSTEM_ERROR, , "dbus_connection_add_filter: %d", PRIV_GUARD_ERROR_SYSTEM_ERROR);

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyChecker::finalizeDbus(void)
{
	dbus_connection_remove_filter(m_pDBusConnection, handleNotification, NULL);
	dbus_connection_close(m_pDBusConnection);
	m_pDBusConnection = NULL;

	return PRIV_GUARD_ERROR_SUCCESS;
}


DBusHandlerResult
PrivacyChecker::handleNotification(DBusConnection* connection, DBusMessage* message, void* user_data)
{
	DBusError error;
	dbus_bool_t r;
	dbus_error_init(&error);

	char* pPkgId;
	char* pPrivacyId;

	if (dbus_message_is_signal(message, DBUS_SIGNAL_INTERFACE.c_str(), DBUS_SIGNAL_SETTING_CHANGED.c_str()))
	{
		r = dbus_message_get_args(message, &error,
			DBUS_TYPE_STRING, &pPkgId,
			DBUS_TYPE_STRING, &pPrivacyId,
			DBUS_TYPE_INVALID);
		TryReturn(r, DBUS_HANDLER_RESULT_NOT_YET_HANDLED, , "Fail to get data : %s", error.message);

		std::lock_guard < std::mutex > guard(m_cacheMutex);

		if (std::string(pPkgId) == m_pkgId)
		{
			PG_LOGI("Current app pkg privacy information updated");
			updateCache(m_pkgId, pPrivacyId, m_privacyCache);
			//printCache();
		}

		std::map < std::string, std::map < std::string, bool > > :: iterator iter = m_privacyInfoCache.find(std::string(pPkgId));
		if (iter != m_privacyInfoCache.end())
		{
			PG_LOGI("Current pkg privacy is in cache");
			updateCache(std::string(pPkgId), pPrivacyId, iter->second);
		}

	}
	else if (dbus_message_is_signal(message, DBUS_SIGNAL_INTERFACE.c_str(), DBUS_SIGNAL_PKG_REMOVED.c_str()))
	{
		r = dbus_message_get_args(message, &error,
			DBUS_TYPE_STRING, &pPkgId,
			DBUS_TYPE_INVALID);
		TryReturn(r, DBUS_HANDLER_RESULT_NOT_YET_HANDLED, , "Fail to get data : %s", error.message);

		std::lock_guard < std::mutex > guard(m_cacheMutex);

		std::map < std::string, std::map < std::string, bool > > :: iterator iter = m_privacyInfoCache.find(std::string(pPkgId));
		if (iter != m_privacyInfoCache.end())
		{
			m_privacyInfoCache.erase(iter);
		}
	}

	// This event is not only for specific handler. All handlers of daemons should be check it and handle it.
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

int
PrivacyChecker::check(const std::string privacyId, std::map < std::string, bool >& privacyMap)
{
	TryReturn(m_isInitialized, PRIV_GUARD_ERROR_NOT_INITIALIZED, , "Not initialized");

	std::map < std::string, bool >::iterator iter;

	iter = privacyMap.find(privacyId);
	if (iter == privacyMap.end() )
	{
		PG_LOGD("The application cannot access the privacy inforamtion.");
		return PRIV_GUARD_ERROR_USER_NOT_CONSENTED;
	}
	else if (!iter->second)
	{
		PG_LOGD("User does not consented to access the privacy information");
		return PRIV_GUARD_ERROR_USER_NOT_CONSENTED;
	}

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyChecker::check(const std::string privacyId)
{
	if (!m_isInitialized)
		return PRIV_GUARD_ERROR_NOT_INITIALIZED;

	std::lock_guard < std::mutex > guard(m_cacheMutex);

	int res = check(privacyId, m_privacyCache);

	return res;
}

int
PrivacyChecker::check(const std::string pkgId, const std::string privacyId)
{
	if (!m_isInitialized)
		initialize();

	std::lock_guard < std::mutex > guard(m_cacheMutex);
	int res;

	std::map < std::string, std::map < std::string, bool > >::iterator iter = m_privacyInfoCache.find(pkgId);
	if (iter == m_privacyInfoCache.end() )
	{
		std::map < std::string, bool > pkgCacheMap;
		res = updateCache(pkgId, pkgCacheMap);
		TryReturn( res == PRIV_GUARD_ERROR_SUCCESS, PRIV_GUARD_ERROR_DB_ERROR, , "Failed to update cache : %d", res);

		m_privacyInfoCache.insert( std::map < std::string, std::map < std::string, bool > >::value_type(std::string(pkgId), pkgCacheMap));
		iter = m_privacyInfoCache.find(pkgId);
	}

	if (iter->second.size() == 0)
	{
		return PRIV_GUARD_ERROR_USER_NOT_CONSENTED;
	}

	res = check(privacyId, iter->second);

	return res;
}

int
PrivacyChecker::checkWithPrivilege(const std::string pkgId, const std::string privilege)
{
	std::string privacyId;
	int res = PrivacyIdInfo::getPrivacyIdFromPrivilege(privilege, privacyId);
	if (res == PRIV_GUARD_ERROR_NO_DATA) {
		return PRIV_GUARD_ERROR_SUCCESS;
	}

	TryReturn( res == PRIV_GUARD_ERROR_SUCCESS, res, , "getPrivacyIdFromPrivilege : %d", res);

	return check(pkgId, privacyId);
}

int
PrivacyChecker::checkWithPrivilege(const std::string privilege)
{
	std::string privacyId;
	int res = PrivacyIdInfo::getPrivacyIdFromPrivilege(privilege, privacyId);
	if (res == PRIV_GUARD_ERROR_NO_DATA) {
		return PRIV_GUARD_ERROR_SUCCESS;
	}

	TryReturn( res == PRIV_GUARD_ERROR_SUCCESS, res, , "getPrivacyIdFromPrivilege : %d", res);

	return check(privacyId);
}

int
PrivacyChecker::finalize(void)
{
	std::lock_guard <std::mutex> guard (m_cacheMutex);
	m_privacyCache.clear();
	m_privacyInfoCache.clear();

	if (m_pLoop != NULL)
	{
		g_main_loop_quit(m_pLoop);
		m_pLoop = NULL;
	}

	if (m_pHandlerGMainContext != NULL)
	{
		g_main_context_unref(m_pHandlerGMainContext);
		m_pHandlerGMainContext = NULL;
	}

	m_isInitialized = false;

	return PRIV_GUARD_ERROR_SUCCESS;
}

void
PrivacyChecker::printCache(void)
{
	std::map < std::string, bool >::const_iterator iter = m_privacyCache.begin();
	for (; iter != m_privacyCache.end(); ++iter)
	{
		PG_LOGD(" %s : %d", iter->first.c_str(), iter->second);
	}
}

int
PrivacyChecker::updateCache(const std::string pkgId, std::string privacyId, std::map < std::string, bool >& pkgCacheMap)
{
	static const std::string PrivacyQuery = "SELECT IS_ENABLED from PrivacyInfo where PKG_ID=? and PRIVACY_ID=?";

	openDb(PRIVACY_DB_PATH, pDbH, SQLITE_OPEN_READONLY);
	prepareDb(pDbH, PrivacyQuery.c_str(), pPrivacyStmt);
	int res = sqlite3_bind_text(pPrivacyStmt.get(), 1, pkgId.c_str(),  -1, SQLITE_TRANSIENT);
	TryReturn( res == 0, PRIV_GUARD_ERROR_DB_ERROR, , "sqlite3_bind_text : %d", res);

	res = sqlite3_bind_text(pPrivacyStmt.get(), 2, privacyId.c_str(),  -1, SQLITE_TRANSIENT);
	TryReturn( res == 0, PRIV_GUARD_ERROR_DB_ERROR, , "sqlite3_bind_text : %d", res);

	while ( sqlite3_step(pPrivacyStmt.get()) == SQLITE_ROW )
	{
		bool privacyEnabled = sqlite3_column_int(pPrivacyStmt.get(), 0) > 0 ? true : false;

		PG_LOGD("Set result : %s : %d", privacyId.c_str(), privacyEnabled );
		pkgCacheMap.erase(privacyId);
		pkgCacheMap.insert(std::map < std::string, bool >::value_type(privacyId, privacyEnabled));
	}

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyChecker::updateCache(std::string pkgId, std::map < std::string, bool >& pkgCacheMap)
{
	static const std::string PrivacyQuery = "SELECT PRIVACY_ID, IS_ENABLED from PrivacyInfo where PKG_ID=?";

	pkgCacheMap.clear();

	openDb(PRIVACY_DB_PATH, pDbH, SQLITE_OPEN_READONLY);
	prepareDb(pDbH, PrivacyQuery.c_str(), pPrivacyStmt);
	int res = sqlite3_bind_text(pPrivacyStmt.get(), 1, pkgId.c_str(), -1, SQLITE_TRANSIENT);
	TryReturn( res == SQLITE_OK, PRIV_GUARD_ERROR_DB_ERROR, , "sqlite3_bind_text : %d", res);

	while ( (res = sqlite3_step(pPrivacyStmt.get())) == SQLITE_ROW )
	{
		const char* privacyId =  reinterpret_cast < const char* > (sqlite3_column_text(pPrivacyStmt.get(), 0));
		bool privacyEnabled = sqlite3_column_int(pPrivacyStmt.get(), 1) > 0 ? true : false;

		pkgCacheMap.insert(std::map < std::string, bool >::value_type(std::string(privacyId), privacyEnabled));

		PG_LOGD("Privacy found : %s %d", privacyId, privacyEnabled);
	}
	return PRIV_GUARD_ERROR_SUCCESS;
}
