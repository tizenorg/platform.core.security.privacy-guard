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
#if 0
// [CYNARA]
#include <CynaraService.h>
#endif

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
	if (pInstance == NULL)
		pInstance = new PrivacyGuardDaemon();
	return pInstance;
}

int
PrivacyGuardDaemon::initialize(void)
{
	if (pSocketService == NULL)
		pSocketService = new SocketService();
#if 0
	// [CYNARA]
	if (pCynaraService == NULL)
		pCynaraService = new CynaraService();
#endif
	pSocketService->initialize();
#if 0
	// [CYNARA]
	pCynaraService->initialize();
#endif

	PrivacyInfoService::registerCallbacks(pSocketService);

	return 0;
}

int
PrivacyGuardDaemon::start(void)
{
	int res = 0;
	
	if (pSocketService == NULL)
		return PRIV_FLTR_ERROR_NOT_INITIALIZED;
	res = pSocketService->start();
	if(res != PRIV_FLTR_ERROR_SUCCESS){
		PF_LOGE("FAIL");
	}
#if 0
	// [CYNARA]
	if (pCynaraService == NULL)
		return PRIV_FLTR_ERROR_NOT_INITIALIZED;
	res = pCynaraService->start();
	if(res != PRIV_FLTR_ERROR_SUCCESS){
		PF_LOGE("FAIL");
	}	
#endif
	return res;
}

int
PrivacyGuardDaemon::stop(void)
{
	pSocketService->stop();
#if 0
	// [CYNARA]	
	pCynaraService->stop();
#endif
	
	return 0;
}

int
PrivacyGuardDaemon::shutdown(void)
{
	pSocketService->shutdown();
	return 0;
}
