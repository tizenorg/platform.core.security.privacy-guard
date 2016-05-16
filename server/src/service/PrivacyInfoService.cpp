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

#include "PrivacyInfoService.h"
#include "PrivacyGuardDb.h"
#include "Utils.h"

void
PrivacyInfoService::PgAddPrivacyAccessLog(SocketConnection* pConnector)
{
	int userId = 0;
	std::list <std::pair<std::string, std::string>> logInfoList;

	pConnector->read(&userId, &logInfoList);

	int result = PrivacyGuardDb::getInstance()->PgAddPrivacyAccessLog(userId, logInfoList);

	pConnector->write(result);
}

void
PrivacyInfoService::PgAddPrivacyAccessLogTest(SocketConnection* pConnector)
{
	int userId = 0;
	std::string packageId;
	std::string privacyId;

	pConnector->read(&userId, &packageId, &privacyId);

	int result = PrivacyGuardDb::getInstance()->PgAddPrivacyAccessLogTest(userId, packageId, privacyId);

	pConnector->write(result);
}

void
PrivacyInfoService::PgAddMonitorPolicy(SocketConnection* pConnector)
{
	int userId = 0;
	std::string pkgId;
	std::list < std::string > list;
	bool privacyPopupRequired = true;

	pConnector->read(&userId, &pkgId, &list, &privacyPopupRequired);

	int result = PrivacyGuardDb::getInstance()->PgAddMonitorPolicy(userId, pkgId, list, privacyPopupRequired);

	pConnector->write(result);
}

void
PrivacyInfoService::PgDeleteAllLogsAndMonitorPolicy(SocketConnection* pConnector)
{
	int result = PrivacyGuardDb::getInstance()->PgDeleteAllLogsAndMonitorPolicy();

	pConnector->write(result);
}

void
PrivacyInfoService::PgDeleteLogsByPackageId(SocketConnection* pConnector)
{
	std::string packageId;

	pConnector->read(&packageId);

	int result = PrivacyGuardDb::getInstance()->PgDeleteLogsByPackageId(packageId);

	pConnector->write(result);
}

void
PrivacyInfoService::PgDeleteMonitorPolicyByPackageId(SocketConnection* pConnector)
{
	std::string packageId;

	pConnector->read(&packageId);

	int result = PrivacyGuardDb::getInstance()->PgDeleteMonitorPolicyByPackageId(packageId);

	pConnector->write(result);
}

void
PrivacyInfoService::PgForeachTotalPrivacyCountOfPackage(SocketConnection* pConnector)
{
	int userId = 0;
	int startDate = -1;
	int endDate = -1;
	std::list < std::pair < std::string, int > > packageInfoList;

	pConnector->read(&userId, &startDate, &endDate);

	int result = PrivacyGuardDb::getInstance()->PgForeachTotalPrivacyCountOfPackage(userId, startDate, endDate, packageInfoList);

	pConnector->write(result);
	pConnector->write(packageInfoList);
}

void
PrivacyInfoService::PgForeachTotalPrivacyCountOfPrivacy(SocketConnection* pConnector)
{
	int userId = 0;
	int startDate = -1;
	int endDate = -1;
	std::list < std::pair < std::string, int > > privacyInfoList;

	pConnector->read(&userId, &startDate, &endDate);

	int result = PrivacyGuardDb::getInstance()->PgForeachTotalPrivacyCountOfPrivacy(userId, startDate, endDate, privacyInfoList);

	pConnector->write(result);
	pConnector->write(privacyInfoList);
}

void
PrivacyInfoService::PgForeachPrivacyCountByPrivacyId(SocketConnection* pConnector)
{
	int userId = 0;
	int startDate = -1;
	int endDate = -1;
	std::string privacyId;
	std::list < std::pair < std::string, int > > packageInfoList;

	pConnector->read(&userId, &startDate, &endDate, &privacyId);

	int result = PrivacyGuardDb::getInstance()->PgForeachPrivacyCountByPrivacyId(userId, startDate, endDate, privacyId, packageInfoList);

	pConnector->write(result);
	pConnector->write(packageInfoList);
}

void
PrivacyInfoService::PgForeachPrivacyCountByPackageId(SocketConnection* pConnector)
{
	int userId = 0;
	int startDate = -1;
	int endDate = -1;
	std::string packageId;
	std::list < std::pair < std::string, int > > privacyInfoList;

	pConnector->read(&userId, &startDate, &endDate, &packageId);

	int result = PrivacyGuardDb::getInstance()->PgForeachPrivacyCountByPackageId(userId, startDate, endDate, packageId, privacyInfoList);

	pConnector->write(result);
	pConnector->write(privacyInfoList);
}

void
PrivacyInfoService::PgForeachPrivacyPackageId(SocketConnection* pConnector)
{
	int userId = 0;
	std::list < std::string > packageList;

	pConnector->read(&userId);

	int result = PrivacyGuardDb::getInstance()->PgForeachPrivacyPackageId(userId, packageList);

	pConnector->write(result);
	pConnector->write(packageList);
}

void
PrivacyInfoService::PgForeachMonitorPolicyByPackageId(SocketConnection* pConnector)
{
	int userId = 0;
	std::string packageId;
	std::list <privacy_data_s> privacyInfoList;

	pConnector->read(&userId, &packageId);

	int result = PrivacyGuardDb::getInstance()->PgForeachMonitorPolicyByPackageId(userId, packageId, privacyInfoList);

	pConnector->write(result);
	pConnector->write(privacyInfoList);
}

void
PrivacyInfoService::PgGetMonitorPolicy(SocketConnection* pConnector)
{
	int userId = 0;
	std::string packageId;
	std::string privacyId;
	int monitorPolicy = 1;

	pConnector->read(&userId, &packageId, &privacyId);

	int result = PrivacyGuardDb::getInstance()->PgGetMonitorPolicy(userId, packageId, privacyId, monitorPolicy);

	pConnector->write(result);
	pConnector->write(monitorPolicy);
}

void
PrivacyInfoService::PgGetAllMonitorPolicy(SocketConnection* pConnector)
{
	std::list < std::pair < std::string, int > > monitorPolicyList;

	int result = PrivacyGuardDb::getInstance()->PgGetAllMonitorPolicy(monitorPolicyList);

	pConnector->write(result);
	pConnector->write(monitorPolicyList);
}

void
PrivacyInfoService::PgForeachPackageInfoByPrivacyId(SocketConnection* pConnector)
{
	int userId = 0;
	std::string privacyId;
	std::list < package_data_s > packageInfoList;

	pConnector->read(&userId, &privacyId);

	int result = PrivacyGuardDb::getInstance()->PgForeachPackageInfoByPrivacyId(userId, privacyId, packageInfoList);

	pConnector->write(result);
	pConnector->write(packageInfoList);
}

void
PrivacyInfoService::PgCheckPrivacyPackage(SocketConnection* pConnector)
{
	int userId = 0;
	std::string packageId;
	bool isPrivacyPackage = false;

	pConnector->read(&userId, &packageId);

	int result = PrivacyGuardDb::getInstance()->PgCheckPrivacyPackage(userId, packageId, isPrivacyPackage);

	pConnector->write(result);
	pConnector->write(isPrivacyPackage);
}

void
PrivacyInfoService::PgUpdateMonitorPolicy(SocketConnection* pConnector)
{
	int userId = 0;
	std::string packageId;
	std::string privacyId;
	int monitorPolicy = 1;

	pConnector->read(&userId, &packageId, &privacyId, &monitorPolicy);

	int result = PrivacyGuardDb::getInstance()->PgUpdateMonitorPolicy(userId, packageId, privacyId, monitorPolicy);

	pConnector->write(result);
}

void
PrivacyInfoService::PgUpdateMainMonitorPolicy(SocketConnection* pConnector)
{
	int userId = 0;
	bool mainMonitorPolicy = false;

	pConnector->read(&userId, &mainMonitorPolicy);

	int result = PrivacyGuardDb::getInstance()->PgUpdateMainMonitorPolicy(userId, mainMonitorPolicy);

	pConnector->write(result);
}

void
PrivacyInfoService::PgGetMainMonitorPolicy(SocketConnection* pConnector)
{
	int userId = 0;
	bool mainMonitorPolicy = false;

	pConnector->read(&userId);

	int result = PrivacyGuardDb::getInstance()->PgGetMainMonitorPolicy(userId, mainMonitorPolicy);

	pConnector->write(result);
	pConnector->write(mainMonitorPolicy);
}

void
PrivacyInfoService::PgDeleteMainMonitorPolicyByUserId(SocketConnection* pConnector)
{
	int userId = 0;

	pConnector->read(&userId);

	int result = PrivacyGuardDb::getInstance()->PgDeleteMainMonitorPolicyByUserId(userId);

	pConnector->write(result);
}
