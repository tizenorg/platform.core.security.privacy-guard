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

#ifndef _PRIVACYINFOSERVICE_H_
#define _PRIVACYINFOSERVICE_H_

#include "SocketConnection.h"
#include "SocketService.h"

class PrivacyInfoService {
private:
	inline static std::string getInterfaceName(void)
	{
		return "PrivacyInfoService";
	}

public:
	static void registerCallbacks(SocketService* pSocketService)
	{
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgAddPrivacyAccessLog"), PgAddPrivacyAccessLog);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgAddPrivacyAccessLogTest"), PgAddPrivacyAccessLogTest);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgAddMonitorPolicy"), PgAddMonitorPolicy);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgDeleteAllLogsAndMonitorPolicy"), PgDeleteAllLogsAndMonitorPolicy);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgDeleteLogsByPackageId"), PgDeleteLogsByPackageId);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgDeleteMonitorPolicyByPackageId"), PgDeleteMonitorPolicyByPackageId);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgForeachTotalPrivacyCountOfPackage"), PgForeachTotalPrivacyCountOfPackage);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgForeachTotalPrivacyCountOfPrivacy"), PgForeachTotalPrivacyCountOfPrivacy);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgForeachPrivacyCountByPrivacyId"), PgForeachPrivacyCountByPrivacyId);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgForeachPrivacyCountByPackageId"), PgForeachPrivacyCountByPackageId);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgForeachPrivacyPackageId"), PgForeachPrivacyPackageId);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgForeachPackageByPrivacyId"), PgForeachPackageByPrivacyId);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgForeachMonitorPolicyByPackageId"), PgForeachMonitorPolicyByPackageId);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgGetMonitorPolicy"), PgGetMonitorPolicy);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgGetAllMonitorPolicy"), PgGetAllMonitorPolicy);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgCheckPrivacyPackage"), PgCheckPrivacyPackage);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgUpdateMonitorPolicy"), PgUpdateMonitorPolicy);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgGetMainMonitorPolicy"), PgGetMainMonitorPolicy);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgUpdateMainMonitorPolicy"), PgUpdateMainMonitorPolicy);
		pSocketService->registerServiceCallback(getInterfaceName(), std::string("PgDeleteMainMonitorPolicyByUserId"), PgDeleteMainMonitorPolicyByUserId);
	}

	static void PgAddPrivacyAccessLog(SocketConnection* pConnector);
	static void PgAddPrivacyAccessLogTest(SocketConnection* pConnector);
	static void PgAddMonitorPolicy(SocketConnection* pConnector);
	static void PgDeleteAllLogsAndMonitorPolicy(SocketConnection* pConnector);
	static void PgDeleteLogsByPackageId(SocketConnection* pConnector);
	static void PgDeleteMonitorPolicyByPackageId(SocketConnection* pConnector);
	static void PgForeachTotalPrivacyCountOfPackage(SocketConnection* pConnector);
	static void PgForeachTotalPrivacyCountOfPrivacy(SocketConnection* pConnector);
	static void PgForeachPrivacyCountByPrivacyId(SocketConnection* pConnector);
	static void PgForeachPrivacyCountByPackageId(SocketConnection* pConnector);
	static void PgForeachPrivacyPackageId(SocketConnection* pConnector);
	static void PgForeachPackageByPrivacyId(SocketConnection* pConnector);
	static void PgForeachMonitorPolicyByPackageId(SocketConnection* pConnector);
	static void PgGetMonitorPolicy(SocketConnection* pConnector);
	static void PgGetAllMonitorPolicy(SocketConnection* pConnector);
	static void PgCheckPrivacyPackage(SocketConnection* pConnector);
	static void PgUpdateMonitorPolicy(SocketConnection* pConnector);
	static void PgGetMainMonitorPolicy(SocketConnection* pConnector);
	static void PgUpdateMainMonitorPolicy(SocketConnection* pConnector);
	static void PgDeleteMainMonitorPolicyByUserId(SocketConnection* pConnector);
};
#endif // _PRIVACYINFOSERVICE_H_