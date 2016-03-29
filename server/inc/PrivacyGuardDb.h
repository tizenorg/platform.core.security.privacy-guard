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

#ifndef _PRIVACYGUARDDB_H_
#define _PRIVACYGUARDDB_H_

#include <string>
#include <memory>
#include <list>
#include <mutex>
#include "ICommonDb.h"
#include "privacy_guard_client_types.h"
#include "PrivacyGuardTypes.h"

#ifdef __FILTER_LISTED_PKG
#include <map>
#endif

class PrivacyGuardDb : public ICommonDb
{
private:
	static std::mutex m_singletonMutex;
	static PrivacyGuardDb* m_pInstance;
#ifdef __FILTER_LISTED_PKG
    const static std::string PRIVACY_FILTER_LIST_FILE;
    const static std::string FILTER_KEY;
    static std::map < std::string, bool > m_filteredPkgList;
#endif

private:
	void createDB(void);

	PrivacyGuardDb(void);

	~PrivacyGuardDb(void);

public:
	static PrivacyGuardDb* getInstance(void);

	virtual void openSqliteDB(void);

	int PgAddPrivacyAccessLog(const int userId, std::list < std::pair < std::string, std::string > > logInfoList);

	int PgAddPrivacyAccessLogForCynara(const int userId, const std::string packageId, const std::string privilege, const timespec *timestamp);

	int PgAddPrivacyAccessLogTest(const int userId, const std::string packageId, const std::string privacyId);

	int PgAddMonitorPolicy(const int userId, const std::string packageId, const std::list < std::string > privacyList, bool monitorPolicy);

	int PgCheckPrivacyPackage(const int userId, const std::string packageId, bool &isPrivacyPackage);

	int PgDeleteAllLogsAndMonitorPolicy(void);

	int PgDeleteLogsByPackageId(const std::string packageId);

	int PgDeleteMonitorPolicyByPackageId(const std::string packageId);

	int PgForeachTotalPrivacyCountOfPackage(const int userId, const int startDate, const int endDate,
				std::list < std::pair < std::string, int > >& packageInfoList);

	int PgForeachTotalPrivacyCountOfPrivacy(const int userId, const int startDate, const int endDate,
				std::list < std::pair < std::string, int > >& privacyInfoList);

	int PgForeachPrivacyCountByPrivacyId(const int userId, const int startDate, const int endDate,
				const std::string privacyId, std::list < std::pair < std::string, int > >& packageInfoList);

	int PgForeachPrivacyCountByPackageId(const int userId, const int startDate, const int endDate,
				const std::string packageId, std::list < std::pair < std::string, int > >& privacyInfoList);

	int PgGetMonitorPolicy(const int userId, const std::string packageId, const std::string privacyId, int& monitorPolicy);

	int PgGetAllMonitorPolicy(std::list < std::pair < std::string, int > >& monitorPolicyList);

	int PgForeachMonitorPolicyByPackageId(const int userId, const std::string packageId, std::list <privacy_data_s>& privacyInfoList);

	int PgForeachPrivacyPackageId(const int userId, std::list < std::string > & packageList);

	int PgForeachPackageByPrivacyId(const int userId, const std::string privacyId, std::list < std::string > &packageList);

	int PgUpdateMonitorPolicy(const int userId, const std::string packageId, const std::string privacyId, const int monitorPolicy);

	int PgAddMainMonitorPolicy(const int userId);

	int PgUpdateMainMonitorPolicy(const int userId, const bool mainMonitorPolicy);

	int PgGetMainMonitorPolicy(const int userId, bool &mainMonitorPolicy);

	int PgDeleteMainMonitorPolicyByUserId(const int userId);
};


#endif // _PRIVACYGUARDDB_H_
