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

#ifndef _CYNARASERVICE_H_
#define _CYNARASERVICE_H_

#include <string>
#include <mutex>
#include <list>
#include <map>
#include <memory>
#include <pthread.h>
#include <cynara-monitor.h>

class CynaraService
{
private:
	int m_signalToClose;
	pthread_t m_cynaraThread;

private:
	static void* getEntriesThread(void* );
	static void* flushThread(void* );
public:
	CynaraService(void);
	~CynaraService(void);
	int initialize(void);
	int start(void);
	int stop(void);
	int shutdown(void);
	static int updateDb(cynara_monitor_entry** monitor_entries);
};

#endif //_CYNARASERVICE_H_
