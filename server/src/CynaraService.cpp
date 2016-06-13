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
#if defined(USE_PTHREAD_WAITING)
#include <sys/time.h>
#endif
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
#include "PrivacyIdInfo.h"

#define BUF_SIZE 256

static cynara_monitor_configuration *p_conf;
static cynara_monitor *p_cynara_monitor;
static cynara_monitor_entry **monitor_entries;
static bool exit_flag;

#if defined(USE_PTHREAD_WAITING)
static pthread_cond_t g_condition;
static pthread_mutex_t g_mutex;
#endif

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

#if defined(USE_PTHREAD_WAITING)
	pthread_mutex_init(&g_mutex, NULL);
	pthread_cond_init(&g_condition, NULL);
#endif

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
		if (monitor_entries) {
			cynara_monitor_entries_free(monitor_entries);
			monitor_entries = NULL;
		}

		// returned when the cynara buffer is full or cynara_monitor_entries_flush() is called from another thread
		res = cynara_monitor_entries_get(p_cynara_monitor, &monitor_entries);
		if(res != CYNARA_API_SUCCESS){
			PG_LOGE("cynara_monitor_entries_get() is failed. [%d]", res);
#if defined(USE_PTHREAD_WAITING)
			struct timeval now;
			struct timespec ts;
			gettimeofday(&now, NULL);
			ts.tv_sec = now.tv_sec + 1;
			ts.tv_nsec = now.tv_usec * 1000;

			pthread_mutex_lock(&g_mutex);
			PG_LOGD("now waiting wakeup signal about 1 sec..");
			pthread_cond_timedwait(&g_condition, &g_mutex, &ts);
			PG_LOGD("ok, i'm wakeup..");
			pthread_mutex_unlock(&g_mutex);
#else
			usleep(SLEEP_TIME * 20);	// 1 SEC
#endif
		} else {
			res = CynaraService::updateDb(monitor_entries);
			if(res != PRIV_GUARD_ERROR_SUCCESS){
				PG_LOGE("CynaraService::updateDb() is failed. [%d]", res);
			}
		}

		if (monitor_entries) {
			cynara_monitor_entries_free(monitor_entries);
			monitor_entries = NULL;
		}
	}

	return (void*) PRIV_GUARD_ERROR_SUCCESS;
}

int
CynaraService::updateDb(cynara_monitor_entry **monitor_entries)
{
	cynara_monitor_entry **entryIter = monitor_entries;

	// DB update
	const char *user = NULL, *client = NULL, *privilege = NULL;
	const timespec *timestamp = NULL;
	int userId;
	std::string packageId, privacyId;
	time_t date;
	int res = -1;

	while (*entryIter != nullptr) {
		privilege = cynara_monitor_entry_get_privilege(*entryIter);
		TryReturn(privilege != NULL, PRIV_GUARD_ERROR_SYSTEM_ERROR, , "Privilege Id in the entry is NULL");

		// change from privilege to privacy
		res = PrivacyIdInfo::getPrivacyIdFromPrivilege(privilege, privacyId);
		if (res != PRIV_GUARD_ERROR_NO_DATA) {
			// User ID - string
			user = cynara_monitor_entry_get_user(*entryIter);
			TryReturn(user != NULL, PRIV_GUARD_ERROR_SYSTEM_ERROR, , "User Id in the entry is NULL");

			// Package ID - string
			client = cynara_monitor_entry_get_client(*entryIter);
			TryReturn(client != NULL, PRIV_GUARD_ERROR_SYSTEM_ERROR, , "Package Id in the entry is NULL");

			// timestamp
			timestamp = cynara_monitor_entry_get_timestamp(*entryIter);
			TryReturn(timestamp != NULL, PRIV_GUARD_ERROR_SYSTEM_ERROR, , "timestamp in the entry is NULL");

			// convert string to integer
			userId = atoi(user);

			// check package ID
			std::string tempPackageId = client;
			if (tempPackageId.substr(0, USER_APP_PREFIX_LEN).compare(USER_APP_PREFIX) == 0) {
				packageId = tempPackageId.substr(USER_APP_PREFIX_LEN, tempPackageId.length() - USER_APP_PREFIX_LEN);
			} else {
				packageId = client;
			}

			// datetime
			date = timestamp->tv_sec;

			// add access log
			int ret = PrivacyGuardDb::getInstance()->PgAddPrivacyAccessLogForCynara(userId, packageId, privacyId, date);
			if(ret == PRIV_GUARD_ERROR_SUCCESS){
				PG_LOGD("Succeeded to add access log to DB. UserID:[%d], PackageID:[%s], Privacy:[%s]", userId, packageId.c_str(), privacyId.c_str());
			}
			else{
				PG_LOGE("Failed to add access log to DB. UserID:[%d], PackageID:[%s], Privacy:[%s]", userId, packageId.c_str(), privacyId.c_str());				
			}
		}
		++entryIter;
	}

	return PRIV_GUARD_ERROR_SUCCESS;
}


int
CynaraService::stop(void)
{
	char buf[BUF_SIZE];
	int ret;

	// set thread exit condition
	exit_flag = true;

	// [CYNARA] Flush Entries
	ret = cynara_monitor_entries_flush(p_cynara_monitor);
	if(ret != CYNARA_API_SUCCESS) {
		if (ret == CYNARA_API_OPERATION_NOT_ALLOWED) {
			PG_LOGD("There is no logs in the cynara buffer.");
		} else {
			PG_LOGE("cynara_monitor_entries_flush FAIL [%d]", ret);
			return PRIV_GUARD_ERROR_SYSTEM_ERROR;
		}
	}

	if((ret = pthread_kill(m_cynaraThread, m_signalToClose)) < 0) {
		PG_LOGE("pthread_kill(): %s", strerror_r(ret, buf, sizeof(buf)));
		return PRIV_GUARD_ERROR_IPC_ERROR;
	}
	pthread_join(m_cynaraThread, NULL);

#if defined(USE_PTHREAD_WAITING)
	pthread_cond_destroy(&g_condition);
	pthread_mutex_destroy(&g_mutex);
#endif

	ret = cynara_monitor_finish(p_cynara_monitor);
	if(ret != CYNARA_API_SUCCESS) {
		PG_LOGE("cynara_monitor_finish() is failed. [%d]", ret);
		return PRIV_GUARD_ERROR_SYSTEM_ERROR;
	}

	return PRIV_GUARD_ERROR_SUCCESS;
}

int
CynaraService::shutdown(void)
{
	cynara_monitor_configuration_destroy(p_conf);

	return PRIV_GUARD_ERROR_SUCCESS;
}
