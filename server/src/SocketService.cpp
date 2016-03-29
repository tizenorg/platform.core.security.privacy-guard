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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/signalfd.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <memory>
#include <dlog.h>
#include "PrivacyGuardTypes.h"
#include "Utils.h"
#include "SocketService.h"
#include "SocketConnection.h"

const int SocketService::MAX_LISTEN = 5;

SocketService::SocketService(void)
	: m_listenFd(-1)
	, m_signalToClose(-1)
	, m_mainThread(-1)
{

}

SocketService::~SocketService(void)
{

}

int
SocketService::initialize(void)
{
	LOGI("SocketService initializing");

	m_listenFd = socket(AF_UNIX, SOCK_STREAM, 0);
	TryReturn( m_listenFd != -1, PRIV_FLTR_ERROR_SYSTEM_ERROR, , "socket : %s", strerror(errno));

	int flags = -1;
	int res;
	if ( (flags = fcntl(m_listenFd, F_GETFL, 0)) == -1)
		flags = 0;
	res = fcntl(m_listenFd, F_SETFL, flags | O_NONBLOCK);
	TryReturn( res != -1, PRIV_FLTR_ERROR_SYSTEM_ERROR, , "fcntl : %s", strerror(errno));

	sockaddr_un server_address;
	bzero(&server_address, sizeof(server_address));
	server_address.sun_family = AF_UNIX;
	strcpy(server_address.sun_path, SERVER_ADDRESS.c_str());
	unlink(server_address.sun_path);

	mode_t socket_umask, original_umask;
	socket_umask = 0;
	original_umask = umask(socket_umask);

	res = bind(m_listenFd, (struct sockaddr*)&server_address, SUN_LEN(&server_address));
	TryReturn( res != -1, PRIV_FLTR_ERROR_SYSTEM_ERROR, , "bind : %s", strerror(errno));

	umask(original_umask);

	LOGI("SocketService initialized");

	return PRIV_FLTR_ERROR_SUCCESS;
}

int
SocketService::start(void)
{
	LOGI("SocketService starting");

	sigset_t sigset;
	sigemptyset(&sigset);
//	if ( sigaddset(&sigset, m_signalToClose) == -1 )
//	{
//		LOGE("Failed to sigaddset : %s", strerror(errno));
//		return -1;
//	}

	int res = 0;
	res = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
	TryReturn( res >= 0, PRIV_FLTR_ERROR_SYSTEM_ERROR, , "pthread_sigmask : %s", strerror(errno));

	pthread_t mainThread;
	res = pthread_create(&mainThread, NULL, &serverThread, this);
	TryReturn( res >= 0, PRIV_FLTR_ERROR_SYSTEM_ERROR, errno = res, "pthread_create : %s", strerror(res));

	m_mainThread = mainThread;

	LOGI("SocketService started");

	return PRIV_FLTR_ERROR_SUCCESS;
}

void*
SocketService::serverThread(void* pData)
{
	pthread_detach(pthread_self());
	SocketService &t = *static_cast< SocketService* > (pData);
	LOGI("Running main thread");
	int ret = t.mainloop();
	if (ret < 0)
	{
		return (void*) 1;
	}
	return (void*) 0;
}

int
SocketService::mainloop(void)
{
	if( listen(m_listenFd, MAX_LISTEN) == -1 ){
		LOGE("listen : %s", strerror(errno));
		return PRIV_FLTR_ERROR_IPC_ERROR;
	}

	//Settings to catch closing signal in select
	int signal_fd;
	sigset_t sigset;
	int res;
	res = sigemptyset(&sigset);
	TryReturn( res != -1, PRIV_FLTR_ERROR_SYSTEM_ERROR, , "sigemptyset : %s", strerror(errno));

//	if( sigaddset(&sigset, m_signalToClose) == -1) {
//		LOGE("sigaddset : %s", strerror(errno));
//		return -1;
//	}
	signal_fd = signalfd(-1, &sigset, 0);
	TryReturn( signal_fd >= 0, PRIV_FLTR_ERROR_SYSTEM_ERROR, , "signalfd : %s", strerror(errno));

	//Setting descriptors for pselect
	fd_set allset, rset;
	int maxfd;
	FD_ZERO(&allset);
	FD_SET(m_listenFd, &allset);
	FD_SET(signal_fd, &allset);
	maxfd = (m_listenFd > signal_fd) ? (m_listenFd) : (signal_fd);
	++maxfd;
	//this will block SIGPIPE for this thread and every thread created in it
	//reason : from here on we don't won't to receive SIGPIPE on writing to closed socket
	//instead of signal we want to receive error from write - hence blocking SIGPIPE
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	while(1)
	{
		rset = allset;
		if(pselect(maxfd, &rset, NULL, NULL, NULL, NULL) == -1)
		{
			closeConnections();
			LOGE("pselect()");
			return PRIV_FLTR_ERROR_SYSTEM_ERROR;
		}

		if(FD_ISSET(signal_fd, &rset))
		{
			LOGI("Got signal to close");
			signalfd_siginfo siginfo;
			ssize_t res;
			res = read(signal_fd, &siginfo, sizeof(siginfo));
			TryReturn( res > 0, PRIV_FLTR_ERROR_IPC_ERROR, closeConnections();, "read : %s", strerror(errno));
			TryReturn( (size_t)res == sizeof(siginfo), PRIV_FLTR_ERROR_IPC_ERROR, closeConnections();, "couldn't read whole siginfo");

			if((int)siginfo.ssi_signo == m_signalToClose)
			{
				LOGI("Server thread got signal to close");
				closeConnections();
				return PRIV_FLTR_ERROR_SUCCESS;
			}
			else
			{
				LOGI("Got not handled signal");
			}
		}
		if(FD_ISSET(m_listenFd, &rset))
		{
			int clientFd;
			clientFd = accept(m_listenFd, NULL, NULL);
			TryReturn( clientFd != -1, PRIV_FLTR_ERROR_IPC_ERROR, closeConnections();, "accept : %s", strerror(errno));

			LOGI("Got incoming connection");
			ConnectionInfo * connection = new ConnectionInfo(clientFd, (void *)this);
			int res;
			pthread_t client_thread;
			if((res = pthread_create(&client_thread, NULL, &connectionThread, connection)) < 0)
			{
				delete connection;
				errno = res;
				closeConnections();
				LOGE("pthread_create()");
				return PRIV_FLTR_ERROR_SYSTEM_ERROR;
			}
			addClientSocket(clientFd);
		}
	}
}

void*
SocketService::connectionThread(void* pData)
{
	pthread_detach(pthread_self());
	std::unique_ptr<ConnectionInfo> connectionInfo (static_cast<ConnectionInfo *>(pData));
	SocketService &t = *static_cast<SocketService *>(connectionInfo->pData);
	LOGI("Starting connection thread");
	int ret = t.connectionService(connectionInfo->connFd);
	if (ret < 0)
	{
		LOGE("Connection thread error");
		t.removeClientSocket(connectionInfo->connFd);
		close(connectionInfo->connFd);
		return (void*)1;
	}
	LOGI("Client serviced");
	return (void*)0;
}

int
SocketService::connectionService(int fd)
{

	SocketConnection connector = SocketConnection(fd);
	std::string interfaceName, methodName;

	int res = connector.read(&interfaceName, &methodName);
	if (res != PRIV_FLTR_ERROR_SUCCESS)
	{
		LOGE("read : %d", res);
		return res;
	}

	LOGD("Got interface : %s", interfaceName.c_str());
	LOGD("Got method : %s",  methodName.c_str());

	if( m_callbackMap.find(interfaceName) == m_callbackMap.end())
	{
		LOGE("Unknown interface : %s", interfaceName.c_str());
		return PRIV_FLTR_ERROR_NO_DATA;
	}

	if(m_callbackMap[interfaceName].find(methodName) == m_callbackMap[interfaceName].end())
	{
		LOGE("Unknown method : %s", methodName.c_str());
		return PRIV_FLTR_ERROR_NO_DATA;
	}

//	if(m_callbackMap[interfaceName][methodName]->securityCallback != NULL){
//		if(!m_callbackMap[interfaceName][methodName]->securityCallback(fd)){
//			LOGE("Security check returned false");
//			return -1;
//		}
//	}

	LOGI("Calling service");
	m_callbackMap[interfaceName][methodName]->serviceCallback(&connector);
   
	LOGI("Removing client");
	removeClientSocket(fd);
	close(fd);

	LOGI("Call served");

	return PRIV_FLTR_ERROR_SUCCESS;
}

int
SocketService::stop(void)
{
	LOGI("Stopping");
	if(close(m_listenFd) == -1)
		if(errno != ENOTCONN)
		{
			LOGE("close() : %s", strerror(errno));
			return PRIV_FLTR_ERROR_IPC_ERROR;
		}

	int returned_value;
	if((returned_value = pthread_kill(m_mainThread, m_signalToClose)) < 0)
	{
		errno = returned_value;
		LOGE("pthread_kill() : %s", strerror(errno));
		return PRIV_FLTR_ERROR_IPC_ERROR;
	}
	pthread_join(m_mainThread, NULL);

	LOGI("Stopped");
	return PRIV_FLTR_ERROR_SUCCESS;
}

int
SocketService::shutdown(void)
{
	return PRIV_FLTR_ERROR_SUCCESS;
}

int
SocketService::registerServiceCallback(const std::string &interfaceName,  const std::string &methodName, socketServiceCallback callbackMethod)
{
	if(NULL == callbackMethod)
	{
		LOGE("Null callback");
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;
	}
	if(interfaceName.empty() || methodName.empty())
	{
		LOGE("Interface and method name cannot be empty");
		return PRIV_FLTR_ERROR_INVALID_PARAMETER;
	}

	auto serviceCallbackPtr = std::make_shared<ServiceCallback>(ServiceCallback(callbackMethod));
	m_callbackMap[interfaceName][methodName] = serviceCallbackPtr;

	return PRIV_FLTR_ERROR_SUCCESS;
}

void
SocketService::addClientSocket(int clientSocket)
{
	std::lock_guard<std::mutex> guard(m_clientSocketListMutex);
	m_clientSocketList.push_back(clientSocket);
}

void
SocketService::removeClientSocket(int clientSocket)
{
	std::lock_guard<std::mutex> guard(m_clientSocketListMutex);
	m_clientSocketList.remove(clientSocket);
}

bool
SocketService::popClientSocket(int * pClientSocket)
{
	std::lock_guard<std::mutex> guard(m_clientSocketListMutex);
	if(m_clientSocketList.empty())
		return false;
	*pClientSocket = m_clientSocketList.front();
	m_clientSocketList.pop_front();
	return true;
}


void
SocketService::closeConnections(void)
{
	int clientSocket;
	LOGI("Closing client sockets");
	while(popClientSocket(&clientSocket))
	{
		if(close(clientSocket) == -1)
		{
			LOGE("close() : %s", strerror(errno));
		}
	}

	LOGI("Connections closed");
}
