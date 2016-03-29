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

#ifndef _SOCKETSTREAM_H_
#define _SOCKETSTREAM_H_

#include <string>
#include "PrivacyGuardTypes.h"

class EXTERN_API SocketStream
{
public:
	explicit SocketStream(int socket_fd)
		: m_socketFd(socket_fd)
		, m_bytesRead(0)
		,m_bytesWrote(0)
	{
		LOGI("Created");
	}

	int readStream(size_t num, void * bytes);
	int writeStream(size_t num, const void * bytes);
private:
	int throwWithErrnoMessage(std::string specificInfo);
	int m_socketFd;
	int m_bytesRead;
	int m_bytesWrote;
};

#endif //_SOCKETSTREAM_H_