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

#ifndef _UTILS_H_
#define _UTILS_H_

#include <vector>
#include <iostream>
#include <algorithm>
#include <dlog.h>
#include <sqlite3.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <db-util.h>

// debug print /////////////////////////////////////////////

#if defined(_PRIVACY_GUARD_DEBUG) || defined(_PRIVACY_GUARD_DEBUG_INFO) || defined(_PRIVACY_GUARD_DEBUG_ERROR)
#ifdef _PRIVACY_GUARD_DEBUG
#define PF_LOGD(fmt, arg...)	LOGD(fmt, ##arg)
#define PF_LOGI(fmt, arg...)	LOGI(fmt, ##arg)
#define PF_LOGE(fmt, arg...)	LOGE(fmt, ##arg)

// _PRIVACY_GUARD_DEBUG_INFO
#elif _PRIVACY_GUARD_DEBUG_INFO
#define PF_LOGD(fmt, arg...)
#define PF_LOGI(fmt, arg...)	LOGI(fmt, ##arg)
#define PF_LOGE(fmt, arg...)	LOGE(fmt, ##arg)

// _PRIVACY_GUARD_DEBUG_ERROR
#elif _PRIVACY_GUARD_DEBUG_ERROR
#define PF_LOGD(fmt, arg...)
#define PF_LOGI(fmt, arg...)
#define PF_LOGE(fmt, arg...)	LOGE(fmt, ##arg)
#endif

#else
#define PF_LOGD(fmt, arg...)
#define PF_LOGI(fmt, arg...)
#define PF_LOGE(fmt, arg...)
#endif

//////////////////////////////////////////////////////////////////////////


#define IF_MATCH_RET_ERROR(condition, msgFormat, error)	\
	if (condition) { \
		PF_LOGE(msgFormat, error); \
		return error; \
	} else {;}
#define	TryCatchLogReturn(condition, expr, r, logFormat)	if (!(condition)) { \
		LOGE(logFormat); \
		expr; \
		return r; \
	} else {;}

#define	TryCatchResLogReturn(condition, expr, r, logFormat, res)	if (!(condition)) { \
		LOGE(logFormat, res); \
		expr; \
		return r; \
	} else {;}


#define TryReturn(condition, r, expr, ...) \
	if ( !(condition) ) { \
		LOGE(__VA_ARGS__); \
		expr; \
		return r; \
	} else {;}

#define SAFE_FREE(var)		\
		if(var != NULL) { \
			free(var);		\
			var = NULL;	\
		}

auto StmtDeleter = [&](sqlite3_stmt* pPtr) {  sqlite3_reset (pPtr); sqlite3_finalize(pPtr); };
auto DbDeleter = [&](sqlite3* pPtr) { /*sqlite3_close(pPtr);*/ db_util_close(pPtr); };

#define setStmtToUniquePtr(x, y)		std::unique_ptr < sqlite3_stmt, decltype(StmtDeleter) > x (y, StmtDeleter);
#define setDbToUniquePtr(x, y)			std::unique_ptr < sqlite3, decltype(DbDeleter) > x (y, DbDeleter);

#define openDb(dbpath, pHandler, mode)	sqlite3* pHandler##Temp = NULL;\
	{\
		/*int res = sqlite3_open_v2(dbpath, &pHandler##Temp, mode , NULL);*/\
		int res = db_util_open_with_options(dbpath, &pHandler##Temp, mode, NULL);\
		TryCatchResLogReturn(res == SQLITE_OK, , PRIV_FLTR_ERROR_DB_ERROR, "db_util_open_with_options : %d", res);\
	}\
	setDbToUniquePtr(pHandler, pHandler##Temp);\

static const int MAX_DATABASE_RETRY_COUNT = 5;
static const int SLEEP_TIME = 50000;
#define prepareDb(pHandler, sql, pStmt)	sqlite3_stmt* pStmt##Temp;\
	{\
		int res = SQLITE_OK;\
		for (int dbRetryCount = 0; dbRetryCount < MAX_DATABASE_RETRY_COUNT; dbRetryCount++)\
		{\
			res = sqlite3_prepare_v2(pHandler.get(), sql, -1, & pStmt##Temp, NULL);\
			if (res != SQLITE_BUSY)\
			{\
				break;\
			}\
			else\
			{\
				LOGE("[DbRetryCount][%d]: Database is busy!", dbRetryCount); \
				usleep(SLEEP_TIME);\
			}\
		}\
		TryCatchResLogReturn(res == SQLITE_OK, , PRIV_FLTR_ERROR_DB_ERROR, "sqlite3_prepare_v2 : %d", res);\
	}\
	setStmtToUniquePtr(pStmt, pStmt##Temp);

class Utils
{
public:
	static std::string toHash (std::string src);
};
#endif //_UTILS_H_
