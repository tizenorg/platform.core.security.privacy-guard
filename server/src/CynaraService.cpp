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

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <memory>
#include <dlog.h>
#include <thread>
#include <cynara-monitor.h>
#include "PrivacyGuardTypes.h"
#include "Utils.h"
#include "CynaraService.h"
#include "PrivacyGuardDb.h"

static cynara_monitor_configuration *p_conf;
static cynara_monitor *p_cynara_monitor;
static cynara_monitor_entry **monitor_entries;

CynaraService::CynaraService(void)
	: m_signalToClose(-1)
	, m_cynaraThread(-1)
{

}

CynaraService::~CynaraService(void)
{

}

int
CynaraService::initialize(void)
{
	LOGI("CynaraService initializing");

	int res = cynara_monitor_configuration_create(&p_conf);
	if(res != CYNARA_API_SUCCESS){
		LOGE("cynara_monitor_configuration_create FAIL");
		return PRIV_FLTR_ERROR_SYSTEM_ERROR;
	}
//	cynara_monitor_configuration_set_buffer_size(p_conf, buffer_size);
//	res = cynara_monitor_initialize(&p_cynara_monitor, p_conf);
	res = cynara_monitor_initialize(&p_cynara_monitor, nullptr);
	if(res != CYNARA_API_SUCCESS){
		LOGE("cynara_monitor_initialize FAIL");
		return PRIV_FLTR_ERROR_SYSTEM_ERROR;
	}

//	cynara_monitor_configuration_set_filter

	LOGI("CynaraService initialized");

	return PRIV_FLTR_ERROR_SUCCESS;
}

int
CynaraService::start(void)
{
	LOGI("CynaraService starting");

	int res = 0;

	sigset_t sigset;
	sigemptyset(&sigset);
	res = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
	TryReturn( res >= 0, PRIV_FLTR_ERROR_SYSTEM_ERROR, , "pthread_sigmask : %s", strerror(errno));

	pthread_t cynaraThread;
	res = pthread_create(&cynaraThread, NULL, &getEntriesThread, this);
	TryReturn( res >= 0, PRIV_FLTR_ERROR_SYSTEM_ERROR, errno = res, "pthread_create : %s", strerror(res));

	m_cynaraThread = cynaraThread;

	LOGI("CynaraService started");

	return PRIV_FLTR_ERROR_SUCCESS;
}

void*
CynaraService::getEntriesThread(void* pData)
{
	pthread_detach(pthread_self());
	LOGI("Running get entries thread");

	pthread_t testThread;
	int result = pthread_create(&testThread, NULL, &flushThread, NULL);
	if(result){
		LOGE("pthread_create FAIL");
		return (void*) PRIV_FLTR_ERROR_SYSTEM_ERROR;
	}

//	while(1)
//	{
		// cynara_monitor_entries_get
		int res = cynara_monitor_entries_get(p_cynara_monitor, &monitor_entries);
		if(res != CYNARA_API_SUCCESS){
			LOGE("cynara_monitor_entries_get FAIL");
			return (void*) PRIV_FLTR_ERROR_SYSTEM_ERROR;
		}

		res = CynaraService::updateDb(monitor_entries);
		if(res != PRIV_FLTR_ERROR_SUCCESS){
			LOGE("updateDb FAIL");
			return (void*) res;
		}
//	}

	pthread_join(testThread, NULL);

	cynara_monitor_entries_free(monitor_entries);

	return (void*) 0;
}

void*
CynaraService::flushThread(void* pData)
	{
	pthread_detach(pthread_self());
	LOGI("Running get flush thread");

	for(int i = 0; i < 1000000000;i++);
	
	int ret= cynara_monitor_entries_flush(p_cynara_monitor);
	if(ret != CYNARA_API_SUCCESS){
		LOGE("cynara_monitor_entries_flush FAIL");
		return (void*) PRIV_FLTR_ERROR_SYSTEM_ERROR;
	}
	else{
		LOGI("cynara_monitor_entries_flush SUCCESS");	
	}
	
	return (void*) 0;
}

int
CynaraService::updateDb(cynara_monitor_entry** monitor_entries)
{
	cynara_monitor_entry **entryIter = monitor_entries;

	LOGI("entryIter = %x", entryIter);

// DB update
		int userId = 0;
		std::string packageId;
	std::string privilege;
	const timespec *timestamp = { 0 };;

	while (*entryIter != nullptr) {
		packageId = cynara_monitor_entry_get_client(*entryIter);
		userId = (int)*cynara_monitor_entry_get_user(*entryIter);
		privilege = cynara_monitor_entry_get_privilege(*entryIter);
		timestamp = cynara_monitor_entry_get_timestamp(*entryIter);

		int ret = PrivacyGuardDb::getInstance()->PgAddPrivacyAccessLogForCynara(userId, packageId, privilege, timestamp);
		if(ret != PRIV_FLTR_ERROR_SUCCESS){
			LOGE("PgAddPrivacyAccessLogForCynara FAIL");
		}
		else{
			LOGI("PgAddPrivacyAccessLogForCynara SUCCESS");
		}

		++entryIter;
	}

	return PRIV_FLTR_ERROR_SUCCESS;
}


int
CynaraService::stop(void)
{
	LOGI("Stopping");

	int returned_value;
	if((returned_value = pthread_kill(m_cynaraThread, m_signalToClose)) < 0)
	{
		errno = returned_value;
		LOGE("pthread_kill() : %s", strerror(errno));
		return PRIV_FLTR_ERROR_IPC_ERROR;
	}
	pthread_join(m_cynaraThread, NULL);	

	LOGI("Stopped");
	return PRIV_FLTR_ERROR_SUCCESS;
}

int
CynaraService::shutdown(void)
{
	return PRIV_FLTR_ERROR_SUCCESS;
}
