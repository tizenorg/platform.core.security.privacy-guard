/*
 * Copyright (c) 2012 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <sys/socket.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>
#include "PrivacyGuardTypes.h"
#include "SocketClient.h"
#include "Utils.h"

#define throwWithErrnoMessage(specificInfo)	do {\
												PG_LOGE("%s : %s", specificInfo, strerror(errno)); \
												return -1; \
											} while(0)

SocketClient::SocketClient(const std::string& interfaceName)
{
	m_interfaceName = interfaceName;
	m_serverAddress = SERVER_ADDRESS;
	PG_LOGI("Client created m_interfaceName : %s, m_serverAddress : %s", m_interfaceName.c_str(), m_serverAddress.c_str());
}

int SocketClient::connect()
{
	struct sockaddr_un remote;
	m_socketFd = socket(AF_UNIX, SOCK_STREAM,0);
	TryReturn( m_socketFd != -1, PRIV_GUARD_ERROR_IPC_ERROR, , "socket : %s", strerror(errno));

	int res;
	//socket needs to be nonblocking, because read can block after select
	int flags;
	if ( (flags = fcntl(m_socketFd, F_GETFL, 0)) == -1 )
		flags = 0;
	res = fcntl(m_socketFd, F_SETFL, flags | O_NONBLOCK);
	TryReturn( m_socketFd != -1, PRIV_GUARD_ERROR_IPC_ERROR, , "fcntl : %s", strerror(errno));

	bzero(&remote, sizeof(remote));
	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, m_serverAddress.c_str());
	res = ::connect(m_socketFd, (struct sockaddr *)&remote, SUN_LEN(&remote));
	TryReturn( res != -1, PRIV_GUARD_ERROR_IPC_ERROR, , "connect : %s", strerror(errno));

	m_socketConnector.reset(new SocketConnection(m_socketFd));

	PG_LOGI("Client connected");

	return PRIV_GUARD_ERROR_SUCCESS;
}

int SocketClient::disconnect()
{
	//Socket should be already closed by server side,
	//even though we should close it in case of any errors
	close(m_socketFd);
	PG_LOGI("Client disconnected");

	return PRIV_GUARD_ERROR_SUCCESS;
}
