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
#include <thread>
#include <cynara-monitor.h>
#include "PrivacyGuardTypes.h"
#include "Utils.h"
#include "CynaraService.h"
#include "PrivacyGuardDb.h"

#define BUF_SIZE 256

static cynara_monitor_configuration *p_conf;
static cynara_monitor *p_cynara_monitor;
static cynara_monitor_entry **monitor_entries;
static bool exit_flag;

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
	PG_LOGD("[cynara_service] CynaraService initializing");

	int res = cynara_monitor_configuration_create(&p_conf);
	if(res != CYNARA_API_SUCCESS){
		PG_LOGE("cynara_monitor_configuration_create() is failed.");
		return PRIV_GUARD_ERROR_SYSTEM_ERROR;
	}

	res = cynara_monitor_configuration_set_buffer_size(p_conf, CYNARA_BUFFER_SIZE);
	if(res != CYNARA_API_SUCCESS){
		PG_LOGE("cynara_monitor_configuration_set_buffer_size() is failed.");
		return PRIV_GUARD_ERROR_SYSTEM_ERROR;
	}

	res = cynara_monitor_initialize(&p_cynara_monitor, p_conf);
	if(res != CYNARA_API_SUCCESS){
		PG_LOGE("cynara_monitor_initialize() is failed.");
		return PRIV_GUARD_ERROR_SYSTEM_ERROR;
	}

//	cynara_monitor_configuration_set_filter

	PG_LOGI("CynaraService initialized");

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
CynaraService::start(void)
{
	PG_LOGI("[cynara_service] CynaraService starting");

	int res = 0;
	char buf[256];

	sigset_t sigset;
	sigemptyset(&sigset);
	res = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
	TryReturn( res >= 0, PRIV_GUARD_ERROR_SYSTEM_ERROR, , "pthread_sigmask : %s", strerror_r(errno, buf, sizeof(buf)));

	pthread_t cynaraThread;
	PG_LOGD("starting new thread (getEntriesThread)");
	res = pthread_create(&cynaraThread, NULL, &getEntriesThread, this);
	TryReturn( res >= 0, PRIV_GUARD_ERROR_SYSTEM_ERROR, errno = res, "pthread_create : %s", strerror_r(errno, buf, sizeof(buf)));
	PG_LOGD("new thread (getEntriesThread) started");

	m_cynaraThread = cynaraThread;

	exit_flag = false;

	PG_LOGD("CynaraService started");

	return PRIV_GUARD_ERROR_SUCCESS;
}

void*
CynaraService::getEntriesThread(void* pData)
{
	PG_LOGD("[cynara_service] Running get entries thread");

	int res = -1;
	pthread_detach(pthread_self());

	while (exit_flag == false) {
		PG_LOGD("[cynara_service] waiting for monitor entries");

		// cynara_monitor_entries_get
		// returned when the cynara buffer is full or cynara_monitor_entries_flush() is called from another thread
		res = cynara_monitor_entries_get(p_cynara_monitor, &monitor_entries);
		if(res != CYNARA_API_SUCCESS){
			PG_LOGE("cynara_monitor_entries_get() is failed. [%d]", res);
			return (void*) PRIV_GUARD_ERROR_SYSTEM_ERROR;
		}

		res = CynaraService::updateDb(monitor_entries);
		if(res != PRIV_GUARD_ERROR_SUCCESS){
			PG_LOGE("updateDb FAIL");
			return (void*) res;
		}

	//	pthread_join(testThread, NULL);

		cynara_monitor_entries_free(monitor_entries);
	}

	cynara_monitor_entries_free(monitor_entries);

	return (void*) PRIV_GUARD_ERROR_SUCCESS;
}

/*void*
CynaraService::flushThread(void* pData)
{
	pthread_detach(pthread_self());
	PG_LOGD("Running get flush thread");

	for(int i = 0; i < 1000000000;i++);

	int ret= cynara_monitor_entries_flush(p_cynara_monitor);
	if(ret != CYNARA_API_SUCCESS){
		PG_LOGE("cynara_monitor_entries_flush FAIL");
		return (void*) PRIV_GUARD_ERROR_SYSTEM_ERROR;
	}
	else{
		PG_LOGD("cynara_monitor_entries_flush SUCCESS");
	}

	return (void*) 0;
}*/

int
CynaraService::updateDb(cynara_monitor_entry **monitor_entries)
{
	PG_LOGD("[cynara_service] updateDb called");

	cynara_monitor_entry **entryIter = monitor_entries;

	//PG_LOGD("entryIter = %x", entryIter);

	// DB update
	const char *user = NULL, *client = NULL, *privilege = NULL;
	const timespec *timestamp = NULL;
	int userId;
	std::string packageId, privilegeId;
	time_t date;

	while (*entryIter != nullptr) {
		user = cynara_monitor_entry_get_user(*entryIter);
		TryReturn(user != NULL, PRIV_GUARD_ERROR_SYSTEM_ERROR, , "User Id in the entry is NULL");
		PG_LOGD("@@ userid: [%s]", user);
		client = cynara_monitor_entry_get_client(*entryIter);
		TryReturn(user != NULL, PRIV_GUARD_ERROR_SYSTEM_ERROR, , "Package Id in the entry is NULL");
		PG_LOGD("@@ client: [%s]", client);
		privilege = cynara_monitor_entry_get_privilege(*entryIter);
		TryReturn(user != NULL, PRIV_GUARD_ERROR_SYSTEM_ERROR, , "Privilege Id in the entry is NULL");
		PG_LOGD("@@ privilege: [%s]", privilege);
		timestamp = cynara_monitor_entry_get_timestamp(*entryIter);
		TryReturn(user != NULL, PRIV_GUARD_ERROR_SYSTEM_ERROR, , "timestamp in the entry is NULL");

		userId = atoi(user);
		PG_LOGD("## userId: [%d]", userId);
		std::string tempPackageId = client;
		if (tempPackageId.substr(0, 11).compare("User::App::") == 0) {
			packageId = tempPackageId.substr(11, tempPackageId.length() - 11);
		} else {
			packageId = client;
		}
		PG_LOGD("## packageId: [%s]", packageId.c_str());
		privilegeId = privilege;
		PG_LOGD("## privilegeId: [%s]", privilegeId.c_str());
		date = timestamp->tv_sec;

		// add access log
		int ret = PrivacyGuardDb::getInstance()->PgAddPrivacyAccessLogForCynara(userId, packageId, privilegeId, date);
		if(ret != PRIV_GUARD_ERROR_SUCCESS){
			PG_LOGE("PgAddPrivacyAccessLogForCynara FAIL");
		}
		else{
			PG_LOGD("PgAddPrivacyAccessLogForCynara SUCCESS");
		}

		++entryIter;
	}

	return PRIV_GUARD_ERROR_SUCCESS;
}


int
CynaraService::stop(void)
{
	PG_LOGD("begin");

	char buf[BUF_SIZE];
	int ret;

	// set thread exit condition
	exit_flag = true;

	// [CYNARA] Fluch Entries
	ret = cynara_monitor_entries_flush(p_cynara_monitor);
	if(ret != CYNARA_API_SUCCESS){
		if (ret == CYNARA_API_OPERATION_NOT_ALLOWED) {
			PG_LOGD("There is no logs in the cynara buffer.");
		} else {
			PG_LOGE("cynara_monitor_entries_flush FAIL [%d]", ret);
			return PRIV_GUARD_ERROR_SYSTEM_ERROR;
		}
	}

	if((ret = pthread_kill(m_cynaraThread, m_signalToClose)) < 0)
	{
		//errno = ret;
		//PG_LOGE("pthread_kill() : %s", strerror_r(errno, buf, sizeof(buf)));
		PG_LOGE("pthread_kill() : %s", strerror_r(ret, buf, sizeof(buf)));
		return PRIV_GUARD_ERROR_IPC_ERROR;
	}
	pthread_join(m_cynaraThread, NULL);

	ret = cynara_monitor_finish(p_cynara_monitor);
	if(ret != CYNARA_API_SUCCESS){
		PG_LOGE("cynara_monitor_finish() is failed. [%d]", ret);
		return PRIV_GUARD_ERROR_SYSTEM_ERROR;
	}

	PG_LOGD("end");
	return PRIV_GUARD_ERROR_SUCCESS;
}

int
CynaraService::shutdown(void)
{
	PG_LOGD("begin");

	cynara_monitor_configuration_destroy(p_conf);

	PG_LOGD("end");

	return PRIV_GUARD_ERROR_SUCCESS;
}
