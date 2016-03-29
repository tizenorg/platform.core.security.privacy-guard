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

#ifndef _ICOMMONDB_H_
#define _ICOMMONDB_H_

#include "PrivacyGuardCommon.h"

class ICommonDb
{
public:

	std::mutex m_dbMutex;
	sqlite3* m_sqlHandler;
	sqlite3_stmt* m_stmt;
	bool m_bDBOpen;

	ICommonDb() {
		m_sqlHandler = NULL;
		m_stmt = NULL;
		m_bDBOpen = false;
	}

	virtual ~ICommonDb() {}

	virtual void openSqliteDB(void) = 0;

};

#endif // _ICOMMONDB_H_
