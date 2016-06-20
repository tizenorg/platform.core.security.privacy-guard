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

#include <string>
#include "PrivacyGuardDaemon.h"
#include "PrivacyInfoService.h"
#include "SocketService.h"
// [CYNARA]
#include <CynaraService.h>

PrivacyGuardDaemon* PrivacyGuardDaemon::pInstance = NULL;

PrivacyGuardDaemon::PrivacyGuardDaemon(void)
	: pSocketService(NULL)
{
}

PrivacyGuardDaemon::~PrivacyGuardDaemon(void)
{
}

PrivacyGuardDaemon*
PrivacyGuardDaemon::getInstance(void)
{
	PG_LOGD("called");

	if (pInstance == NULL)
		pInstance = new PrivacyGuardDaemon();
	return pInstance;
}

int
PrivacyGuardDaemon::initialize(void)
{
	PG_LOGD("called");

	if (pSocketService == NULL)
		pSocketService = new SocketService();

	PG_LOGD("calling pSocketService->initialize()");
	pSocketService->initialize();

	PG_LOGD("calling PrivacyInfoService::registerCallbacks(pSocketService)");
	PrivacyInfoService::registerCallbacks(pSocketService);

	// [CYNARA]
	if (pCynaraService == NULL)
		pCynaraService = new CynaraService();

	PG_LOGD("calling pCynaraService->initialize()");
	pCynaraService->initialize();

	return 0;
}

int
PrivacyGuardDaemon::start(void)
{
	int res = 0;

	PG_LOGD("calling pSocketService->start()");
	if (pSocketService == NULL)
		return PRIV_GUARD_ERROR_NOT_INITIALIZED;
	res = pSocketService->start();
	if(res != PRIV_GUARD_ERROR_SUCCESS){
		PG_LOGE("FAIL");
	}

	// [CYNARA]
	PG_LOGD("calling pCynaraService->start()");
	if (pCynaraService == NULL)
		return PRIV_GUARD_ERROR_NOT_INITIALIZED;
	res = pCynaraService->start();
	if(res != PRIV_GUARD_ERROR_SUCCESS){
		PG_LOGE("FAIL");
	}

	return res;
}

int
PrivacyGuardDaemon::stop(void)
{
	PG_LOGD("calling pSocketService->stop()");
	pSocketService->stop();

	PG_LOGD("calling pCynaraService->stop()");
	pCynaraService->stop();

	return 0;
}

int
PrivacyGuardDaemon::shutdown(void)
{
	PG_LOGD("calling pSocketService->shutdown()");
	pSocketService->shutdown();

	PG_LOGD("calling pCynaraService->shutdown()");
	pCynaraService->shutdown();

	return 0;
}
