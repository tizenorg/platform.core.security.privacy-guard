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
#include "Utils.h"
#include "PrivacyGuardClient.h"
#include "SocketClient.h"
#include "PrivacyIdInfo.h"

//#define COUNT 10
#define COUNT 1

#undef __READ_DB_IPC__

std::mutex PrivacyGuardClient::m_singletonMutex;
PrivacyGuardClient* PrivacyGuardClient::m_pInstance = NULL;
const std::string PrivacyGuardClient::INTERFACE_NAME("PrivacyInfoService");

PrivacyGuardClient::PrivacyGuardClient(void)
{
	std::unique_ptr<SocketClient> pSocketClient(new SocketClient(INTERFACE_NAME));
	m_pSocketClient = std::move(pSocketClient);
}

PrivacyGuardClient*
PrivacyGuardClient::getInstance(void)
{
	std::lock_guard<std::mutex> guard(m_singletonMutex);
	if (m_pInstance == NULL)
		m_pInstance = new PrivacyGuardClient();
	return m_pInstance;
}

void
PrivacyGuardClient::openSqliteDB(void)
{
	int res = -1;
	res = sqlite3_open_v2(PRIVACY_DB_PATH, &m_sqlHandler, SQLITE_OPEN_READWRITE, NULL);
	if(res == SQLITE_OK) {
		PG_LOGI("monitor db is opened successfully");
		m_bDBOpen = true;
	}
	else {
		PG_LOGE("fail : monitor db open(%d)", res);
	}
}

int
PrivacyGuardClient::PgAddMonitorPolicyOffline(const int userId, const std::string packageId, const std::list < std::string > privacyList, bool monitorPolicy)
{
	int res = -1;

	static const std::string QUERY_INSERT = std::string("INSERT INTO MonitorPolicy(USER_ID, PKG_ID, PRIVACY_ID, MONITOR_POLICY) VALUES(?, ?, ?, ?)");

	m_dbMutex.lock();
	m_sqlHandler = NULL;
	m_stmt = NULL;
	m_bDBOpen = false;
	
	// open db
	if(m_bDBOpen == false) {
		openSqliteDB();
	}
	TryCatchResLogReturn(m_bDBOpen == true, m_dbMutex.unlock(), PRIV_GUARD_ERROR_IO_ERROR, "openSqliteDB : %d", res);

	// prepare
	res = sqlite3_prepare_v2(m_sqlHandler, QUERY_INSERT.c_str(), -1, &m_stmt, NULL);
	TryCatchResLogReturn(res == SQLITE_OK, m_dbMutex.unlock(), PRIV_GUARD_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);

	for (std::list <std::string>::const_iterator iter = privacyList.begin(); iter != privacyList.end(); ++iter) {
		PG_LOGD("User ID: [%d], Package ID: [%s], PrivacyID: [%s], Monitor Policy: [%d]", userId, packageId.c_str(), iter->c_str(), monitorPolicy);

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
PrivacyGuardClient::PgAddPrivacyAccessLog(const int userId, const std::string packageId, const std::string privacyId)
{
	int result = PRIV_GUARD_ERROR_SUCCESS;
	m_logInfoList.push_back(std::pair <std::string, std::string> (packageId, privacyId));
	PG_LOGD("PrivacyGuardClient userId : %d, PgAddPrivacyAccessLog m_logInfoList.size() : %d", userId, m_logInfoList.size());

	if(m_logInfoList.size() >= COUNT) {
		int res = m_pSocketClient->connect();
		TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

		res = m_pSocketClient->call("PgAddPrivacyAccessLog", userId, m_logInfoList, &result);
		TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

		res = m_pSocketClient->disconnect();
		TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "disconnect : %d", res);
		m_logInfoList.clear();
	}

	return result;
}

int
PrivacyGuardClient::PgAddPrivacyAccessLogTest(const int userId, const std::string packageId, const std::string privacyId)
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgAddPrivacyAccessLogTest", userId, packageId, privacyId, &result);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "disconnect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgAddPrivacyAccessLogBeforeTerminate(void)
{
	int result = PRIV_GUARD_ERROR_SUCCESS;
	PG_LOGD("PgAddPrivacyAccessLogBeforeTerminate, m_logInfoList.size() : %d", m_logInfoList.size());

	if(m_logInfoList.size() > 0) {
		int res = m_pSocketClient->connect();
		TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

		res = m_pSocketClient->call("PgAddPrivacyAccessLog", m_logInfoList, &result);
		TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

		res = m_pSocketClient->disconnect();
		TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "disconnect : %d", res);
		m_logInfoList.clear();
	}

	return result;
}

int
PrivacyGuardClient::PgAddMonitorPolicy(const int userId, const std::string pkgId, const std::list < std::string >& list, int monitorPolicy)
{
	PG_LOGD("userID: [%d], packageID[%s], monitorPolicy: [%d]", userId, pkgId.c_str(), monitorPolicy);

	std::list < std::string > privacyList;

	int res = PrivacyIdInfo::getPrivacyIdListFromPrivilegeList(list, privacyList);
	if (res != PRIV_GUARD_ERROR_SUCCESS ) {
		PG_LOGD("PrivacyIdInfo::getPrivacyIdListFromPrivilegeList() is failed. [%d]", res);
		return res;
	}

	if (privacyList.size() == 0) {
		PG_LOGD("PrivacyGuardClient::PgAddMonitorPolicy: privacyList.size() is 0.");
		return PRIV_GUARD_ERROR_SUCCESS;
	}

	bool isServerOperation = false;

	res = m_pSocketClient->connect();
	if(res != PRIV_GUARD_ERROR_SUCCESS) {
		isServerOperation = false;
		PG_LOGD("Failed to connect. So change to the offline mode");
	}
	else {
		isServerOperation = true;
	}
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	if (isServerOperation == true) {
	int result = PRIV_GUARD_ERROR_SUCCESS;

	res = m_pSocketClient->call("PgAddMonitorPolicy", userId, pkgId, privacyList, monitorPolicy, &result);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "disconnect : %d", res);

	return result;
}
	else 	{
		return PgAddMonitorPolicyOffline(userId, pkgId, privacyList, monitorPolicy);
	}
}

int
PrivacyGuardClient::PgDeleteAllLogsAndMonitorPolicy(void)
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgDeleteAllLogsAndMonitorPolicy", &result);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "disconnect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgDeleteLogsByPackageId(const std::string packageId)
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgDeleteLogsByPackageId", packageId, &result);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "disconnect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgDeleteMonitorPolicyByPackageId(const std::string packageId)
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgDeleteMonitorPolicyByPackageId", packageId, &result);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "disconnect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgForeachTotalPrivacyCountOfPackage(const int userId, const int startDate, const int endDate, std::list < std::pair <std::string, int > > & packageInfoList) const
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgForeachTotalPrivacyCountOfPackage", userId, startDate, endDate, &result, &packageInfoList);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "disconnect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgForeachTotalPrivacyCountOfPrivacy(const int userId, const int startDate, const int endDate, std::list < std::pair <std::string, int > > & privacyInfoList) const
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgForeachTotalPrivacyCountOfPrivacy", userId, startDate, endDate, &result, &privacyInfoList);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "disconnect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgForeachPrivacyCountByPrivacyId(const int userId, const int startDate, const int endDate, const std::string privacyId, std::list < std::pair <std::string, int > > & packageInfoList) const
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	bool isValid = PrivacyIdInfo::isValidPrivacyId(privacyId);

	if (!isValid)
		return PRIV_GUARD_ERROR_INVALID_PARAMETER;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgForeachPrivacyCountByPrivacyId", userId, startDate, endDate, privacyId, &result, &packageInfoList);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "disconnect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgForeachPrivacyCountByPackageId(const int userId, const int startDate, const int endDate, const std::string packageId, std::list < std::pair <std::string, int > > & privacyInfoList) const
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgForeachPrivacyCountByPackageId", userId, startDate, endDate, packageId, &result, &privacyInfoList);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "disconnect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgForeachPrivacyPackageId(const int userId, std::list < std::string > & packageList) const
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgForeachPrivacyPackageId", userId, &result, &packageList);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgForeachPackageInfoByPrivacyId(const int userId, const std::string privacyId, std::list < package_data_s > & packageInfoList) const
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	bool isValid = PrivacyIdInfo::isValidPrivacyId(privacyId);

	if (!isValid)
		return PRIV_GUARD_ERROR_INVALID_PARAMETER;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgForeachPackageInfoByPrivacyId", userId, privacyId, &result, &packageInfoList);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgForeachMonitorPolicyByPackageId(const int userId, const std::string packageId,
		std::list <privacy_data_s> & privacyInfoList) const
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgForeachMonitorPolicyByPackageId", userId, packageId, &result, &privacyInfoList);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "disconnect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgGetMonitorPolicy(const int userId, const std::string packageId,
		const std::string privacyId, int &monitorPolicy) const
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	bool isValid = PrivacyIdInfo::isValidPrivacyId(privacyId);

	if (!isValid)
		return PRIV_GUARD_ERROR_INVALID_PARAMETER;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgGetMonitorPolicy", userId, packageId, privacyId, &result, &monitorPolicy);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgGetAllMonitorPolicy(std::list < std::pair < std::string, int > > & monitorPolicyList) const
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgGetAllMonitorPolicy", &result, &monitorPolicyList);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgCheckPrivacyPackage(const int userId, const std::string packageId, bool &isPrivacyPackage)
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgCheckPrivacyPackage", userId, packageId, &result, &isPrivacyPackage);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgUpdateMonitorPolicy(const int userId, const std::string packageId,
		const std::string privacyId, const int monitorPolicy)
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	bool isValid = PrivacyIdInfo::isValidPrivacyId(privacyId);

	if (!isValid)
		return PRIV_GUARD_ERROR_INVALID_PARAMETER;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgUpdateMonitorPolicy", userId, packageId, privacyId, monitorPolicy, &result);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgGetMainMonitorPolicy(const int userId, bool &mainMonitorPolicy) const
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgGetMainMonitorPolicy", userId, &result, &mainMonitorPolicy);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgUpdateMainMonitorPolicy(const int userId, const bool mainMonitorPolicy)
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgUpdateMainMonitorPolicy", userId, mainMonitorPolicy, &result);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	return result;
}

int
PrivacyGuardClient::PgDeleteMainMonitorPolicyByUserId(const int userId)
{
	int result = PRIV_GUARD_ERROR_SUCCESS;

	int res = m_pSocketClient->connect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "connect : %d", res);

	res = m_pSocketClient->call("PgDeleteMainMonitorPolicyByUserId", userId, &result);
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, m_pSocketClient->disconnect(), "call : %d", res);

	res = m_pSocketClient->disconnect();
	TryReturn(res == PRIV_GUARD_ERROR_SUCCESS, res, , "disconnect : %d", res);

	return result;
}
