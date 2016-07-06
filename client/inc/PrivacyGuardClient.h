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

#ifndef _PRIVACYGUARDCLIENT_H_
#define _PRIVACYGUARDCLIENT_H_

#include <string>
#include <mutex>
#include <list>
#include <vector>
#include <memory>
#include "PrivacyGuardTypes.h"
#include <sqlite3.h>

class SocketClient;

class EXTERN_API PrivacyGuardClient
{
private:
	std::mutex m_dbMutex;
	sqlite3* m_sqlHandler;
	sqlite3_stmt* m_stmt;
	bool m_bDBOpen;

	static PrivacyGuardClient* m_pInstance;
	static const std::string INTERFACE_NAME;

	std::unique_ptr< SocketClient > m_pSocketClient;

	static std::mutex m_singletonMutex;

	std::list <std::pair<std::string, std::string>> m_logInfoList;

	PrivacyGuardClient();
	~PrivacyGuardClient();

public:
	static PrivacyGuardClient* getInstance(void);

	virtual void openSqliteDB(void);

	int PgAddMonitorPolicyOffline(const int userId, const std::string packageId, const std::list < std::string > privacyList, bool monitorPolicy);

	int PgAddPrivacyAccessLogBeforeTerminate(void);

	int PgAddMonitorPolicy(const int userId, const std::string pkgId, const std::list < std::string >& list, int monitorPolicy);

	int PgDeleteAllLogsAndMonitorPolicy(void);

	int PgDeleteLogsByPackageId(const std::string packageId);

	int PgDeleteMonitorPolicyByPackageId(const std::string packageId);

	int PgForeachTotalPrivacyCountOfPackage(const int userId, const int startDate, const int endDate, std::list < std::pair <std::string, int > > & packageInfoList) const;

	int PgForeachTotalPrivacyCountOfPrivacy(const int userId, const int startDate, const int endDate, std::list < std::pair <std::string, int > > & privacyInfoList) const;

	int PgForeachPrivacyCountByPrivacyId(const int userId, const int startDate, const int endDate, const std::string privacyId, std::list < std::pair <std::string, int > > & packageInfoList) const;

	int PgForeachPrivacyCountByPackageId(const int userId, const int startDate, const int endDate, const std::string packageId, std::list < std::pair <std::string, int > > & privacyInfoList) const;

	int PgForeachPrivacyPackageId(const int userId, std::list < std::string > & packageList) const;

	int PgForeachPackageInfoByPrivacyId(const int userId, const std::string privacyId, std::list < package_data_s > & packageList) const;

	int PgForeachMonitorPolicyByPackageId(const int userId, const std::string packageId,
		std::list <privacy_data_s> & privacyInfoList) const;

	int PgGetMonitorPolicy(const int userId, const std::string packageId,
		const std::string privacyId, int& monitorPolicy) const;

	int PgGetAllMonitorPolicy(std::list < std::pair < std::string, int > > & monitorPolicyList) const;

	int PgCheckPrivacyPackage(const int userId, const std::string packageId, bool &isPrivacyPackage);

	int PgUpdateMonitorPolicy(const int userId, const std::string packageId,
		const std::string privacyId, const int monitorPolicy);

	int PgGetMainMonitorPolicy(const int userId, bool &mainMonitorPolicy) const;

	int PgUpdateMainMonitorPolicy(const int userId, const bool mainMonitorPolicy);

	int PgDeleteMainMonitorPolicyByUserId(const int userId);
};

#endif // _PRIVACYGUARDCLIENT_H_