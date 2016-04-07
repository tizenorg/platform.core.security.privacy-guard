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

#include <sstream>
#include <fstream>
#include <sqlite3.h>
#include <pkgmgr-info.h>
#include <time.h>
#include "Utils.h"
#include "PrivacyGuardDb.h"
#include "PrivacyIdInfo.h"
#if 0
// [CYNARA]
#include "CynaraService.h"

//static cynara_monitor_configuration *p_conf;
static cynara_monitor *p_cynara_monitor;
static cynara_monitor_entry **monitor_entries;
#endif

std::mutex PrivacyGuardDb::m_singletonMutex;
PrivacyGuardDb* PrivacyGuardDb::m_pInstance = NULL;

static const char* privacy_list[5] = { "http://tizen.org/privacy/location",
								 "http://tizen.org/privacy/contact",
								 "http://tizen.org/privacy/calendar",
								 "http://tizen.org/privacy/messaging",
								 "http://tizen.org/privacy/callhistory" };

#ifdef __FILTER_LISTED_PKG
const std::string PrivacyGuardDb::PRIVACY_FILTER_LIST_FILE = std::string("/usr/share/privacy-guard/privacy-guard-list.ini");
const std::string PrivacyGuardDb::FILTER_KEY = std::string("package_id");
std::map < std::string, bool > PrivacyGuardDb::m_filteredPkgList;
#endif

void
PrivacyGuardDb::createDB(void)
{

}

void
PrivacyGuardDb::openSqliteDB(void)
{
	int res = -1;
	res = sqlite3_open_v2(PRIVACY_DB_PATH, &m_sqlHandler, SQLITE_OPEN_READWRITE, NULL);
	if(res == SQLITE_OK)	{
		PG_LOGI("monitor db is opened successfully");
//		sqlite3_wal_autocheckpoint(m_sqlHandler, 1);
		m_bDBOpen = true;
	}
	else {
		PG_LOGE("fail : monitor db open(%d)", res);
	}
}

int
PrivacyGuardDb::PgAddPrivacyAccessLog(const int userId, std::list < std::pair < std::string, std::string > > logInfoList)
{
	time_t current_date;
	struct tm tm;
	current_date = time(NULL);
	localtime_r(&current_date, &tm);

	if(current_date <= 0) {
		return PRIV_GUARD_ERROR_INVALID_PARAMETER;
	}

	int res = -1;

	static const std::string QUERY_INSERT = std::string("INSERT INTO StatisticsMonitorInfo(USER_ID, PKG_ID, PRIVACY_ID, USE_DATE) VALUES(?, ?, ?, ?)");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	PG_LOGD("addlogToDb m_sqlHandler : %p", m_sqlHandler);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, QUERY_INSERT.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	for (std::list <std::pair <std::string, std::string>>::iterator iter = logInfoList.begin(); iter != logInfoList.end(); ++iter) {
		PG_LOGD("packageID : %s, PrivacyID : %s", iter->first.c_str(), iter->second.c_str());

		// bind
		res = sqlite3_bind_int(m_stmt, 1, userId);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

		res = sqlite3_bind_text(m_stmt, 2, iter->first.c_str(), -1, SQLITE_TRANSIENT);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

		res = sqlite3_bind_text(m_stmt, 3, iter->second.c_str(), -1, SQLITE_TRANSIENT);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

		res = sqlite3_bind_int(m_stmt, 4, current_date);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

		res = sqlite3_step(m_stmt);
		TryCatchResLogReturn(res == SQLITE_DONE, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_step : %d", res);

		sqlite3_reset(m_stmt);
	}
	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgAddPrivacyAccessLogForCynara(const int userId, const std::string packageId, const std::string privilege, const timespec* timestamp)
{
	if(timestamp->tv_sec <= 0) {
		return PRIV_GUARD_ERROR_INVALID_PARAMETER;
	}

	int res = SQLITE_OK;

	// change from privilege to privacy
	std::string privacyId;
	res = PrivacyIdInfo::getPrivacyIdFromPrivilege(privilege, privacyId);
	if (res == PRIV_GUARD_ERROR_NO_DATA) {
		return PRIV_GUARD_ERROR_SUCCESS;
	}
	TryReturn( res == PRIV_GUARD_ERROR_SUCCESS, res, , "getPrivacyIdFromPrivilege : %d", res);

	// change from timespec to time_t
	time_t logging_date;
	logging_date = timestamp->tv_sec;

	static const std::string QUERY_INSERT = std::string("INSERT INTO StatisticsMonitorInfo(USER_ID, PKG_ID, PRIVACY_ID, USE_DATE) VALUES(?, ?, ?, ?)");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	PG_LOGD("addlogToDb m_sqlHandler : %p", m_sqlHandler);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, QUERY_INSERT.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	// bind
	res = sqlite3_bind_int(m_stmt, 1, userId);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	res = sqlite3_bind_text(m_stmt, 2, packageId.c_str(), -1, SQLITE_TRANSIENT);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

	res = sqlite3_bind_text(m_stmt, 3, privacyId.c_str(), -1, SQLITE_TRANSIENT);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

	res = sqlite3_bind_int(m_stmt, 4, logging_date);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	res = sqlite3_step(m_stmt);
	TryCatchResLogReturn(res == SQLITE_DONE, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_step : %d", res);

	sqlite3_reset(m_stmt);

	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgAddPrivacyAccessLogTest(const int userId, const std::string packageId, const std::string privacyId)
{
	time_t current_date;
	struct tm tm;
	current_date = time(NULL);
	localtime_r(&current_date, &tm);

	if(current_date <= 0) {
		return PRIV_GUARD_ERROR_INVALID_PARAMETER;
	}

	int res = SQLITE_OK;

	static const std::string QUERY_INSERT = std::string("INSERT INTO StatisticsMonitorInfo(USER_ID, PKG_ID, PRIVACY_ID, USE_DATE) VALUES(?, ?, ?, ?)");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	PG_LOGD("addlogToDb m_sqlHandler : %p", m_sqlHandler);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, QUERY_INSERT.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	// bind
	res = sqlite3_bind_int(m_stmt, 1, userId);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	res = sqlite3_bind_text(m_stmt, 2, packageId.c_str(), -1, SQLITE_TRANSIENT);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

	res = sqlite3_bind_text(m_stmt, 3, privacyId.c_str(), -1, SQLITE_TRANSIENT);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

	res = sqlite3_bind_int(m_stmt, 4, current_date);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	res = sqlite3_step(m_stmt);
	TryCatchResLogReturn(res == SQLITE_DONE, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_step : %d", res);

	sqlite3_reset(m_stmt);

	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}


int
PrivacyGuardDb::PgAddMonitorPolicy(const int userId, const std::string packageId, const std::list < std::string > privacyList, bool monitorPolicy)
{
	int res = -1;

	static const std::string QUERY_INSERT = std::string("INSERT INTO MonitorPolicy(USER_ID, PKG_ID, PRIVACY_ID, MONITOR_POLICY) VALUES(?, ?, ?, ?)");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	PG_LOGD("addlogToDb m_sqlHandler : %p", m_sqlHandler);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, QUERY_INSERT.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	for (std::list <std::string>::const_iterator iter = privacyList.begin(); iter != privacyList.end(); ++iter) {
		PG_LOGD("PrivacyID : %s", iter->c_str());

		// bind
		res = sqlite3_bind_int(m_stmt, 1, userId);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

		res = sqlite3_bind_text(m_stmt, 2, packageId.c_str(), -1, SQLITE_TRANSIENT);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

		res = sqlite3_bind_text(m_stmt, 3, iter->c_str(), -1, SQLITE_TRANSIENT);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

		res = sqlite3_bind_int(m_stmt, 4, monitorPolicy);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

		res = sqlite3_step(m_stmt);
		TryCatchResLogReturn(res == SQLITE_DONE, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_step : %d", res);

		sqlite3_reset(m_stmt);
	}
	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgCheckPrivacyPackage(const int userId, const std::string packageId, bool &isPrivacyPackage)
{
	int res = -1;
	static const std::string query = std::string("SELECT COUNT(*) FROM MonitorPolicy WHERE USER_ID=? AND PKG_ID=?");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, query.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn( res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	// bind
	res = sqlite3_bind_int(m_stmt, 1, userId);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	res = sqlite3_bind_text(m_stmt, 2, packageId.c_str(), -1, SQLITE_TRANSIENT);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

	int count = -1;

	// step
	if ((res = sqlite3_step(m_stmt)) == SQLITE_ROW) {
		count = sqlite3_column_int(m_stmt, 0);
	}
	m_dbMutex.unlock();

	if (count > 0) {
		isPrivacyPackage = true;
	}
	else {
		isPrivacyPackage = false;
	}

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgDeleteAllLogsAndMonitorPolicy(void)
{
	PG_LOGD("PgDeleteAllLogsAndMonitorPolicy");

	int res = -1;

	static const std::string LOG_DELETE = std::string("DELETE FROM StatisticsMonitorInfo");
	static const std::string POLICY_DELETE = std::string("DELETE FROM MonitorPolicy");
	static const std::string MAIN_POLICY_DELETE = std::string("DELETE FROM MainMonitorPolicy");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, LOG_DELETE.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	res = sqlite3_step(m_stmt);
	TryCatchResLogReturn(res == SQLITE_DONE, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_step : %d", res);

	res = sqlite3_prepare_v2(m_sqlHandler, POLICY_DELETE.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	res = sqlite3_step(m_stmt);
	TryCatchResLogReturn(res == SQLITE_DONE, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_step : %d", res);

	res = sqlite3_prepare_v2(m_sqlHandler, MAIN_POLICY_DELETE.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	res = sqlite3_step(m_stmt);
	TryCatchResLogReturn(res == SQLITE_DONE, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_step : %d", res);

	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}


int
PrivacyGuardDb::PgDeleteLogsByPackageId(const std::string packageId)
{
	PG_LOGD("PrivacyGuardDb::PgDeleteLogsByPackageId packageid : %s", packageId.c_str());

	int res = -1;

	static const std::string QUERY_DELETE = std::string("DELETE FROM StatisticsMonitorInfo WHERE PKG_ID=?");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, QUERY_DELETE.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	// bind
	res = sqlite3_bind_text(m_stmt, 1, packageId.c_str(), -1, SQLITE_TRANSIENT);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

	// step
	res = sqlite3_step(m_stmt);
	TryCatchResLogReturn(res == SQLITE_DONE, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_step : %d", res);

	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgDeleteMonitorPolicyByPackageId(const std::string packageId)
{
	PG_LOGD("PrivacyGuardDb::PgDeleteMonitorPolicyByPackageId packageid : %s", packageId.c_str());

	int res = -1;

	static const std::string QUERY_DELETE = std::string("DELETE FROM MonitorPolicy WHERE PKG_ID=?");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, QUERY_DELETE.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	// bind
	res = sqlite3_bind_text(m_stmt, 1, packageId.c_str(), -1, SQLITE_TRANSIENT);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

	// step
	res = sqlite3_step(m_stmt);
	TryCatchResLogReturn(res == SQLITE_DONE, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_step : %d", res);

	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgForeachTotalPrivacyCountOfPackage(const int userId, const int startDate, const int endDate,
		std::list < std::pair < std::string, int > >& packageInfoList)
{
	int res = -1;

#if 0
	// [CYNARA] Fluch Entries
	int ret= cynara_monitor_entries_flush(p_cynara_monitor);
	if(ret != CYNARA_API_SUCCESS){
		PG_LOGE("cynara_monitor_entries_flush FAIL");
		return PRIV_GUARD_ERROR_SYSTEM_ERROR;
	}

	// [CYNARA] Get Entries
	ret = cynara_monitor_entries_get(p_cynara_monitor, &monitor_entries);
	if(ret != CYNARA_API_SUCCESS){
		PG_LOGE("cynara_monitor_entries_get FAIL");
		return PRIV_GUARD_ERROR_SYSTEM_ERROR;
	}

	// [CYNARA] Update DB
	ret = CynaraService::updateDb(monitor_entries);
	if(ret != PRIV_GUARD_ERROR_SUCCESS){
		PG_LOGE("updateDb FAIL");
		return ret;
	}
#endif

	static const std::string PKGID_SELECT = std::string("SELECT DISTINCT PKG_ID FROM StatisticsMonitorInfo WHERE USER_ID=? AND USE_DATE>=? AND USE_DATE<=?");
	static const std::string PKGINFO_SELECT = std::string("SELECT COUNT(*) FROM StatisticsMonitorInfo WHERE USER_ID=? AND PKG_ID=? AND USE_DATE>=? AND USE_DATE<=?");
	sqlite3_stmt* infoStmt;

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, PKGID_SELECT.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	res = sqlite3_bind_int(m_stmt, 1, userId);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	res = sqlite3_bind_int(m_stmt, 2, startDate);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	res = sqlite3_bind_int(m_stmt, 3, endDate);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	while ((res = sqlite3_step(m_stmt)) == SQLITE_ROW) {
		const char* packageId = reinterpret_cast < const char* > (sqlite3_column_text(m_stmt, 0));
		if(packageId == NULL) {	continue; }

		// prepare
		res = sqlite3_prepare_v2(m_sqlHandler, PKGINFO_SELECT.c_str(), -1, &infoStmt, NULL);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

		res = sqlite3_bind_int(infoStmt, 1, userId);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

		res = sqlite3_bind_text(infoStmt, 2, packageId, -1, SQLITE_TRANSIENT);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

		res = sqlite3_bind_int(infoStmt, 3, startDate);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

		res = sqlite3_bind_int(infoStmt, 4, endDate);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

		while ((res = sqlite3_step(infoStmt)) == SQLITE_ROW) {
			int count = sqlite3_column_int(infoStmt, 0);
			if (count == 0) {
				continue;
			}
			packageInfoList.push_back(std::pair <std::string, int> (std::string(packageId), count));
		}
		sqlite3_reset(infoStmt);
	}
	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgForeachTotalPrivacyCountOfPrivacy(const int userId, const int startDate, const int endDate,
		std::list < std::pair < std::string, int > >& privacyInfoList)
{
	int res = -1;

#if 0
	// [CYNARA] Fluch Entries
	int ret= cynara_monitor_entries_flush(p_cynara_monitor);
	if(ret != CYNARA_API_SUCCESS){
		PG_LOGE("cynara_monitor_entries_flush FAIL");
		return PRIV_GUARD_ERROR_SYSTEM_ERROR;
	}

	// [CYNARA] Get Entries
	ret = cynara_monitor_entries_get(p_cynara_monitor, &monitor_entries);
	if(ret != CYNARA_API_SUCCESS){
		PG_LOGE("cynara_monitor_entries_get FAIL");
		return PRIV_GUARD_ERROR_SYSTEM_ERROR;
	}

	// [CYNARA] Update DB
	ret = CynaraService::updateDb(monitor_entries);
	if(ret != PRIV_GUARD_ERROR_SUCCESS){
		PG_LOGE("updateDb FAIL");
		return ret;
	}
#endif

	static const std::string PRIVACY_SELECT = std::string("SELECT COUNT(*) FROM StatisticsMonitorInfo WHERE USER_ID=? AND PRIVACY_ID=? AND USE_DATE>=? AND USE_DATE<=?");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	int i;
	int cnt_privacy = sizeof(privacy_list) / sizeof(privacy_list[0]);

	for (i = 0; i < cnt_privacy; i++) {
		// prepare
		res = sqlite3_prepare_v2(m_sqlHandler, PRIVACY_SELECT.c_str(), -1, &m_stmt, NULL);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

		// bind
		res = sqlite3_bind_int(m_stmt, 1, userId);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

		res = sqlite3_bind_text(m_stmt, 2, privacy_list[i], -1, SQLITE_TRANSIENT);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

		res = sqlite3_bind_int(m_stmt, 3, startDate);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

		res = sqlite3_bind_int(m_stmt, 4, endDate);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

		// step
		if ((res = sqlite3_step(m_stmt)) == SQLITE_ROW) {
			int count = sqlite3_column_int(m_stmt, 0);
			if (count == 0) {
				continue;
			}
			const char* privacyId = privacy_list[i];
			privacyInfoList.push_back(std::pair <std::string, int> (std::string(privacyId), count));
		}
		sqlite3_reset(m_stmt);
	}

	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgForeachPrivacyCountByPrivacyId(const int userId, const int startDate, const int endDate,
		const std::string privacyId, std::list < std::pair < std::string, int > >& packageInfoList)
{
	int res = -1;

#if 0
	// [CYNARA] Fluch Entries
	int ret= cynara_monitor_entries_flush(p_cynara_monitor);
	if(ret != CYNARA_API_SUCCESS){
		PG_LOGE("cynara_monitor_entries_flush FAIL");
		return PRIV_GUARD_ERROR_SYSTEM_ERROR;
	}

	// [CYNARA] Get Entries
	ret = cynara_monitor_entries_get(p_cynara_monitor, &monitor_entries);
	if(ret != CYNARA_API_SUCCESS){
		PG_LOGE("cynara_monitor_entries_get FAIL");
		return PRIV_GUARD_ERROR_SYSTEM_ERROR;
	}

	// [CYNARA] Update DB
	ret = CynaraService::updateDb(monitor_entries);
	if(ret != PRIV_GUARD_ERROR_SUCCESS){
		PG_LOGE("updateDb FAIL");
		return ret;
	}
#endif

	static const std::string PKGID_SELECT = std::string("SELECT DISTINCT PKG_ID FROM StatisticsMonitorInfo WHERE USER_ID=? AND PRIVACY_ID=? AND USE_DATE>=? AND USE_DATE<=?");
	static const std::string PKGINFO_SELECT = std::string("SELECT COUNT(*) FROM StatisticsMonitorInfo WHERE USER_ID=? AND PKG_ID=? AND PRIVACY_ID=? AND USE_DATE>=? AND USE_DATE<=?");
	sqlite3_stmt* infoStmt;

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, PKGID_SELECT.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	// bind
	res = sqlite3_bind_int(m_stmt, 1, userId);
	TryReturn(res == SQLITE_OK, PRIV_GUARD_ERROR_DB_ERROR, , "sqlite3_bind_int : %d", res);

	res = sqlite3_bind_text(m_stmt, 2, privacyId.c_str(), -1, SQLITE_TRANSIENT);
	TryReturn(res == SQLITE_OK, PRIV_GUARD_ERROR_DB_ERROR, , "sqlite3_bind_text : %d", res);

	res = sqlite3_bind_int(m_stmt, 3, startDate);
	TryReturn(res == SQLITE_OK, PRIV_GUARD_ERROR_DB_ERROR, , "sqlite3_bind_int : %d", res);

	res = sqlite3_bind_int(m_stmt, 4, endDate);
	TryReturn(res == SQLITE_OK, PRIV_GUARD_ERROR_DB_ERROR, , "sqlite3_bind_int : %d", res);

	while ((res = sqlite3_step(m_stmt)) == SQLITE_ROW) {
		const char* packageId =  reinterpret_cast < const char* > (sqlite3_column_text(m_stmt, 0));
		if(packageId == NULL) {	continue; }

		// prepare
		res = sqlite3_prepare_v2(m_sqlHandler, PKGINFO_SELECT.c_str(), -1, &infoStmt, NULL);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

		// bind
		res = sqlite3_bind_int(infoStmt, 1, userId);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

		res = sqlite3_bind_text(infoStmt, 2, packageId, -1, SQLITE_TRANSIENT);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

		res = sqlite3_bind_text(infoStmt, 3, privacyId.c_str(), -1, SQLITE_TRANSIENT);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

		res = sqlite3_bind_int(infoStmt, 4, startDate);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

		res = sqlite3_bind_int(infoStmt, 5, endDate);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

		if ((res = sqlite3_step(infoStmt)) == SQLITE_ROW) {
			int count = sqlite3_column_int(infoStmt, 0);
			if (count == 0) {
				continue;
			}
			packageInfoList.push_back(std::pair <std::string, int> (std::string(packageId), count));
		}
		sqlite3_reset(infoStmt);
	}

	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgForeachPrivacyCountByPackageId(const int userId, const int startDate, const int endDate,
		const std::string packageId, std::list < std::pair < std::string, int > >& privacyInfoList)
{
	int res = -1;

#if 0
	// [CYNARA] Fluch Entries
	int ret= cynara_monitor_entries_flush(p_cynara_monitor);
	if(ret != CYNARA_API_SUCCESS){
		PG_LOGE("cynara_monitor_entries_flush FAIL");
		return PRIV_GUARD_ERROR_SYSTEM_ERROR;
	}

	// [CYNARA] Get Entries
	ret = cynara_monitor_entries_get(p_cynara_monitor, &monitor_entries);
	if(ret != CYNARA_API_SUCCESS){
		PG_LOGE("cynara_monitor_entries_get FAIL");
		return PRIV_GUARD_ERROR_SYSTEM_ERROR;
	}

	// [CYNARA] Update DB
	ret = CynaraService::updateDb(monitor_entries);
	if(ret != PRIV_GUARD_ERROR_SUCCESS){
		PG_LOGE("updateDb FAIL");
		return ret;
	}
#endif

	static const std::string PRIVACY_SELECT = std::string("SELECT COUNT(*) FROM StatisticsMonitorInfo WHERE USER_ID=? AND PKG_ID=? AND PRIVACY_ID=? AND USE_DATE>=? AND USE_DATE<=?");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	int i;
	int cnt_privacy = sizeof(privacy_list) / sizeof(privacy_list[0]);

	for (i = 0; i < cnt_privacy; i++) {
		// prepare
		res = sqlite3_prepare_v2(m_sqlHandler, PRIVACY_SELECT.c_str(), -1, &m_stmt, NULL);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

		//bind
		res = sqlite3_bind_int(m_stmt, 1, userId);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

		res = sqlite3_bind_text(m_stmt, 2, packageId.c_str(), -1, SQLITE_TRANSIENT);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

		res = sqlite3_bind_text(m_stmt, 3, privacy_list[i], -1, SQLITE_TRANSIENT);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

		res = sqlite3_bind_int(m_stmt, 4, startDate);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

		res = sqlite3_bind_int(m_stmt, 5, endDate);
		TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

		if ((res = sqlite3_step(m_stmt)) == SQLITE_ROW) {
			int count = sqlite3_column_int(m_stmt, 0);
			if (count == 0) {
				continue;
			}
			const char* privacyId = privacy_list[i];
			privacyInfoList.push_back(std::pair <std::string, int> (std::string(privacyId), count));
		}
		sqlite3_reset(m_stmt);
	}

	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgGetMonitorPolicy(const int userId, const std::string packageId, const std::string privacyId, int& monitorPolicy)
{

	int res = -1;
	static const std::string query = std::string("SELECT MONITOR_POLICY FROM MonitorPolicy WHERE USER_ID=? AND PKG_ID=? AND PRIVACY_ID=?");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, query.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	// bind
	res = sqlite3_bind_int(m_stmt, 1, userId);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	res = sqlite3_bind_text(m_stmt, 2, packageId.c_str(), -1, SQLITE_TRANSIENT);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

	res = sqlite3_bind_text(m_stmt, 3, privacyId.c_str(), -1, SQLITE_TRANSIENT);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

	// step
	monitorPolicy = 0;
	if ((res = sqlite3_step(m_stmt)) == SQLITE_ROW) {
		monitorPolicy = sqlite3_column_int(m_stmt, 0);
	}
	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgGetAllMonitorPolicy(std::list < std::pair < std::string, int > >& monitorPolicyList)
{
	int res = -1;

	static const std::string MONITOR_POLICY_SELECT = std::string("SELECT * FROM MonitorPolicy");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, MONITOR_POLICY_SELECT.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	// step
	int monitorPolicy = 0;
	while ((res = sqlite3_step(m_stmt)) == SQLITE_ROW) {
		int userId = sqlite3_column_int(m_stmt, 0);
		char* tmpPkgId = (char*)sqlite3_column_text(m_stmt, 1);
		char* tmpPrivacyId = (char*)sqlite3_column_text(m_stmt, 2);
		if(tmpPkgId == NULL || tmpPrivacyId == NULL) {
			continue;
		}
		std::string userPkgIdPrivacyId = std::to_string(userId);
		userPkgIdPrivacyId.append("|").append(std::string(tmpPkgId));
		userPkgIdPrivacyId.append("|").append(std::string(tmpPrivacyId));
		monitorPolicy = sqlite3_column_int(m_stmt, 3);
		monitorPolicyList.push_back(std::pair < std::string, int > (userPkgIdPrivacyId, monitorPolicy));
	}

	m_dbMutex.unlock();
	if(monitorPolicyList.size() > 0) {
		res = PRIV_GUARD_ERROR_SUCCESS;
	}
	else {
		res = PRIV_GUARD_ERROR_NO_DATA;
	}

	return res;
}

int
PrivacyGuardDb::PgForeachMonitorPolicyByPackageId(const int userId, const std::string packageId, std::list <privacy_data_s>& privacyInfoList)
{
	int res = -1;
	static const std::string query = std::string("SELECT DISTINCT PRIVACY_ID, MONITOR_POLICY FROM MonitorPolicy WHERE USER_ID=? AND PKG_ID=?");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, query.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock();, PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	// bind
	res = sqlite3_bind_int(m_stmt, 1, userId);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	res = sqlite3_bind_text(m_stmt, 2, packageId.c_str(), -1, SQLITE_TRANSIENT);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

	// step
	while ((res = sqlite3_step(m_stmt)) == SQLITE_ROW) {

		char* tmp_data = (char*)sqlite3_column_text(m_stmt, 0);
		if(tmp_data == NULL) {
			continue;
		}
		privacy_data_s p_data;
		p_data.privacy_id = strdup(tmp_data);
		p_data.monitor_policy= sqlite3_column_int(m_stmt, 1);

		privacyInfoList.push_back(p_data);
	}
	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgForeachPrivacyPackageId(const int userId, std::list < std::string > &packageList)
{
	int res = -1;
	static const std::string query = std::string("SELECT DISTINCT PKG_ID FROM MonitorPolicy WHERE USER_ID=?");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, query.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock();, PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	// bind
	res = sqlite3_bind_int(m_stmt, 1, userId);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	// step
	while ((res = sqlite3_step(m_stmt)) == SQLITE_ROW) {
		char* p_data = (char*)sqlite3_column_text(m_stmt, 0);
		if(p_data == NULL) {
			continue;
		}
		packageList.push_back(std::string(p_data));
	}
	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgForeachPackageByPrivacyId(const int userId, const std::string privacyId, std::list < std::string > &packageList)
{
	int res = -1;
	static const std::string query = std::string("SELECT DISTINCT PKG_ID FROM MonitorPolicy WHERE USER_ID=? AND PRIVACY_ID=?");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, query.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock();, PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	// bind
	res = sqlite3_bind_int(m_stmt, 1, userId);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	res = sqlite3_bind_text(m_stmt, 2, privacyId.c_str(), -1, SQLITE_TRANSIENT);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

	// step
	while ((res = sqlite3_step(m_stmt)) == SQLITE_ROW) {
		char* p_data = (char*)sqlite3_column_text(m_stmt, 0);
		if(p_data == NULL) {
			continue;
		}
		packageList.push_back(std::string(p_data));
	}
	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgUpdateMonitorPolicy(const int userId, const std::string packageId, const std::string privacyId, const int monitorPolicy)
{
	int res = -1;
	static const std::string query = std::string("UPDATE MonitorPolicy SET MONITOR_POLICY=? WHERE USER_ID=? AND PKG_ID=? AND PRIVACY_ID=?");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, query.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	// bind
	res = sqlite3_bind_int(m_stmt, 1, monitorPolicy);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	res = sqlite3_bind_int(m_stmt, 2, userId);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	res = sqlite3_bind_text(m_stmt, 3, packageId.c_str(), -1, SQLITE_TRANSIENT);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

	res = sqlite3_bind_text(m_stmt, 4, privacyId.c_str(), -1, SQLITE_TRANSIENT);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_text : %d", res);

	// step
	res = sqlite3_step(m_stmt);
	TryCatchResLogReturn(res == SQLITE_DONE, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_step : %d", res);

	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgAddMainMonitorPolicy(const int userId)
{
	int res = -1;

	static const std::string QUERY_INSERT = std::string("INSERT INTO MainMonitorPolicy(USER_ID) VALUES(?)");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	PG_LOGD("addlogToDb m_sqlHandler : %p", m_sqlHandler);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, QUERY_INSERT.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	//bind
	res = sqlite3_bind_int(m_stmt, 1, userId);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	//step
	res = sqlite3_step(m_stmt);
	TryCatchResLogReturn(res == SQLITE_DONE, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_step : %d", res);

	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgUpdateMainMonitorPolicy(const int userId, const bool mainMonitorPolicy)
{
	int res = -1;
	static const std::string query = std::string("UPDATE MainMonitorPolicy SET MAIN_MONITOR_POLICY=? WHERE USER_ID=?");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, query.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	// bind
	res = sqlite3_bind_int(m_stmt, 1, mainMonitorPolicy);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	res = sqlite3_bind_int(m_stmt, 2, userId);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	// step
	res = sqlite3_step(m_stmt);
	TryCatchResLogReturn(res == SQLITE_DONE, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_step : %d", res);

	m_dbMutex.unlock();

#if 0
	// [CYNARA] Set Filter
	cynara_monitor_configuration_set_filter();
#endif

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgGetMainMonitorPolicy(const int userId, bool &mainMonitorPolicy)
{

	int res = -1;
	static const std::string query = std::string("SELECT MAIN_MONITOR_POLICY FROM MainMonitorPolicy WHERE USER_ID=?");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, query.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	// bind
	res = sqlite3_bind_int(m_stmt, 1, userId);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	// step
	mainMonitorPolicy = false;
	if ((res = sqlite3_step(m_stmt)) == SQLITE_ROW) {
		mainMonitorPolicy = sqlite3_column_int(m_stmt, 0);
		m_dbMutex.unlock();
	}
	else {
		m_dbMutex.unlock();
		res = PgAddMainMonitorPolicy(userId);
		TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "PgAddMainMonitorPolicy failed : %d", res);
	}

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
PrivacyGuardDb::PgDeleteMainMonitorPolicyByUserId(const int userId)
{
	int res = -1;

	static const std::string QUERY_DELETE = std::string("DELETE FROM MainMonitorPolicy WHERE USER_ID=?");

	m_dbMutex.lock();
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, QUERY_DELETE.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	// bind
	res = sqlite3_bind_int(m_stmt, 1, userId);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_bind_int : %d", res);

	// step
	res = sqlite3_step(m_stmt);
	TryCatchResLogReturn(res == SQLITE_DONE, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_step : %d", res);

	m_dbMutex.unlock();

	return PRIV_GUARD_ERROR_SUCCESS;
}

PrivacyGuardDb::PrivacyGuardDb(void)
{

	// open DB
	m_bDBOpen = false;
	m_sqlHandler = NULL;
	m_dbMutex.lock();
	openSqliteDB();
	m_dbMutex.unlock();
	m_stmt = NULL;
}

PrivacyGuardDb::~PrivacyGuardDb(void)
{
	// close DB
	if(m_bDBOpen == true) {
		m_dbMutex.lock();
		sqlite3_finalize(m_stmt);
		sqlite3_close(m_sqlHandler);
		m_bDBOpen = false;
		m_dbMutex.unlock();
	}
}

PrivacyGuardDb*
PrivacyGuardDb::getInstance(void)
{
	std::lock_guard < std::mutex > guard(m_singletonMutex);

	if (m_pInstance == NULL)
	{	
		m_pInstance = new PrivacyGuardDb();
	}

	return m_pInstance;
}
