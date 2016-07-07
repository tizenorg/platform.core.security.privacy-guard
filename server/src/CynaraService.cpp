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
#include <pkgmgr-info.h>
#include "PrivacyGuardTypes.h"
#include "Utils.h"
#include "CynaraService.h"
#include "PrivacyGuardDb.h"
#include "PrivacyIdInfo.h"

#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

#define BUF_SIZE 256
#define ONE_SEC (SLEEP_TIME * 20)

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
	PG_LOGD("initializing CynaraService..");

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
	PG_LOGI("starting CynaraService..");

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
	PG_LOGD("Running get entries thread");

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
			usleep(ONE_SEC);	// 1 SEC
#endif
		} else {
			if (monitor_entries) {
				res = CynaraService::updateDb(monitor_entries);
				if(res != PRIV_GUARD_ERROR_SUCCESS) {
					PG_LOGE("CynaraService::updateDb() is failed. [%d]", res);
				}
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
	char *package_id = NULL, *package_id_dup = NULL;
	const timespec *timestamp = NULL;
	uid_t userId;
	std::string appId, privacyId, packageId;
	time_t date;
	int res = -1;
	pkgmgrinfo_pkginfo_h pkg_handle;
	bool is_global = false;

	while (*entryIter != nullptr) {
		privilege = cynara_monitor_entry_get_privilege(*entryIter);
		TryReturn(privilege != NULL, PRIV_GUARD_ERROR_SYSTEM_ERROR, , "Privilege Id in the entry is NULL");

		// change from privilege to privacy
		res = PrivacyIdInfo::getPrivacyIdFromPrivilege(privilege, privacyId);
		if (res != PRIV_GUARD_ERROR_NO_DATA) {
			// User ID - string
			user = cynara_monitor_entry_get_user(*entryIter);
			TryReturn(user != NULL, PRIV_GUARD_ERROR_SYSTEM_ERROR, , "User Id in the entry is NULL");

			// App ID - string
			client = cynara_monitor_entry_get_client(*entryIter);
			TryReturn(client != NULL, PRIV_GUARD_ERROR_SYSTEM_ERROR, , "App Id in the entry is NULL");

			// timestamp
			timestamp = cynara_monitor_entry_get_timestamp(*entryIter);
			TryReturn(timestamp != NULL, PRIV_GUARD_ERROR_SYSTEM_ERROR, , "timestamp in the entry is NULL");

			// convert string to integer
			userId = atoi(user);

			// check app ID
			std::string tempAppId = client;
			PG_LOGD("App ID from cynara: [%s]", client);
			if (tempAppId.substr(0, USER_APP_PREFIX_LEN).compare(USER_APP_PREFIX) == 0) {
				appId = tempAppId.substr(USER_APP_PREFIX_LEN, tempAppId.length() - USER_APP_PREFIX_LEN);
				PG_LOGD("App ID: [%s]", appId.c_str());
			} else {
				appId = client;
				PG_LOGD("App ID: [%s]", client);
			}

			// get package ID from app ID			
			pkgmgrinfo_appinfo_h pkgmgrinfo_appinfo;
			PG_LOGD("User ID: [%d], Global User ID: [%d]", userId, GLOBAL_USER);
			if (userId == GLOBAL_USER) {
				res = pkgmgrinfo_appinfo_get_appinfo(appId.c_str(), &pkgmgrinfo_appinfo);
			} else {
				res = pkgmgrinfo_appinfo_get_usr_appinfo(appId.c_str(), userId, &pkgmgrinfo_appinfo);
			}
			if (res != PMINFO_R_OK) {
				PG_LOGE("Failed to do pkgmgrinfo_appinfo_get_appinfo or pkgmgrinfo_appinfo_get_usr_appinfo [%d] for the app [%s] with user [%d]. So set the package ID to app ID.", res, appId.c_str(), userId);
				packageId = appId;
			} else {
				res = pkgmgrinfo_appinfo_get_pkgname(pkgmgrinfo_appinfo, &package_id);
				if (res != PMINFO_R_OK) {
					PG_LOGE("Failed to do pkgmgrinfo_appinfo_get_pkgname [%d] for the app [%s]. So set the package ID to app ID.", res, appId.c_str());
					packageId = appId;
				}
				PG_LOGD("Package ID of [%s] is [%s]", appId.c_str(), package_id);
				package_id_dup = strdup(package_id);
				packageId = package_id_dup;
				pkgmgrinfo_appinfo_destroy_appinfo(pkgmgrinfo_appinfo);
			}

			// check this package is global app
			if (userId == GLOBAL_USER) {
				res = pkgmgrinfo_pkginfo_get_pkginfo(packageId.c_str(), &pkg_handle);
			} else {
				res = pkgmgrinfo_pkginfo_get_usr_pkginfo(packageId.c_str(), userId, &pkg_handle);
			}
			if (res != PMINFO_R_OK) {
				PG_LOGE("Failed to do pkgmgrinfo_pkginfo_get_pkginfo or pkgmgrinfo_pkginfo_get_usr_pkginfo [%d] for the package [%s] with user [%d]", res, packageId.c_str(), userId);
			} else {
				res = pkgmgrinfo_pkginfo_is_global(pkg_handle, &is_global);
				if (res != PMINFO_R_OK) {
					PG_LOGE("Failed to do pkgmgrinfo_pkginfo_is_global [%d]", res);
				} else {
					if (is_global == true) {
						PG_LOGD("[%s] is a global app. So set the user_id to 0.", packageId.c_str());
						userId = GLOBAL_APP_USER_ID;
					}
				}
				pkgmgrinfo_pkginfo_destroy_pkginfo(pkg_handle);
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
