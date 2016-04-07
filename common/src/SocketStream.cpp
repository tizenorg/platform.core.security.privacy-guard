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


#include <sys/socket.h>
#include <sys/select.h>
#include <errno.h>
#include <cstring>
#include <unistd.h>
#include "Utils.h"
#include "SocketStream.h"

#define READ_TIEMOUT_SEC 1
#define READ_TIMEUOT_NSEC 0
#define WRITE_TIMEOUT_SEC 0
#define WRITE_TIMEOUT_NSEC 100000000
#define MAX_BUFFER 10240
#define BUF_SIZE 256

int
SocketStream::throwWithErrnoMessage(std::string function_name)
{
	char buf[BUF_SIZE];
	PG_LOGE("%s : %s", function_name.c_str(), strerror_r(errno, buf, sizeof(buf)));
	return errno;
}

int
SocketStream::readStream(size_t num, void* pBytes)
{
	TryReturn(pBytes != NULL, -1, , "Null pointer to buffer");

	m_bytesRead += num;

	TryReturn(m_bytesRead <= MAX_BUFFER, -1, , "Too big buffer requested!");

	char partBuffer[MAX_BUFFER];
	std::string wholeBuffer;
	char buf[BUF_SIZE];

	fd_set rset, allset;
	int maxFd;
	ssize_t bytesRead = 0;
	ssize_t bytesToRead = (ssize_t) num;

	timespec timeout;

	maxFd = m_socketFd;
	++maxFd;

	FD_ZERO(&allset);
	FD_SET(m_socketFd, &allset);

	int ret = -1;

	while(bytesToRead != 0)
	{
		timeout.tv_sec = READ_TIEMOUT_SEC;
		timeout.tv_nsec = READ_TIMEUOT_NSEC;
		rset = allset;

		if ( (ret = pselect(maxFd, &rset, NULL, NULL, &timeout, NULL)) == -1 )
		{
			if (errno == EINTR)
				continue;
			PG_LOGD("pselect : %s", strerror_r(errno, buf, sizeof(buf)));
			return -1;
		}
		//This means pselect got timedout
		//This is not a proper behavior in reading data from UDS
		//And could mean we got corrupted connection
		TryReturn(ret != 0, -1, , "Couldn't read whole data");

		if ( FD_ISSET(m_socketFd, &rset) )
		{
			bytesRead = read(m_socketFd, partBuffer, num);
			if ( bytesRead <= 0 )
			{
				if(errno == ECONNRESET || errno == ENOTCONN || errno == ETIMEDOUT)
				{
					PG_LOGI("Connection closed : %s", strerror_r(errno, buf, sizeof(buf)));
					return -1;
				}
				else if (errno != EAGAIN && errno != EWOULDBLOCK){
					PG_LOGI("read()");
					return -1;
				}
			}

			wholeBuffer.append(partBuffer, bytesRead);
			bytesToRead -= bytesRead;
			bytesRead = 0;
			continue;
		}

	}
	memcpy(pBytes, wholeBuffer.c_str(), num);

	return 0;
}

int
SocketStream::writeStream(size_t num, const void* pBytes)
{
	TryReturn(pBytes != NULL, -1, , "Null pointer to buffer");

	m_bytesWrote += num;

	TryReturn(m_bytesRead <= MAX_BUFFER, -1, , "Too big buffer requested!");

	fd_set wset, allset;
	int maxFd;
	char buf[BUF_SIZE];

	timespec timeout;

	maxFd = m_socketFd;
	++maxFd;

	FD_ZERO(&allset);
	FD_SET(m_socketFd, &allset);

	int res;
	int writeRes;
	int bytesToWrite = num;
	unsigned int currentOffset = 0;

	while(currentOffset != num)
	{
		timeout.tv_sec = WRITE_TIMEOUT_SEC;
		timeout.tv_nsec = WRITE_TIMEOUT_NSEC;
		wset = allset;

		if ( (res = pselect(maxFd, NULL, &wset, NULL, &timeout, NULL)) == -1 )
		{
			if(errno == EINTR)
				continue;
			PG_LOGD("pselect : %s", strerror_r(errno, buf, sizeof(buf)));
			return -1;
		}

		if(FD_ISSET(m_socketFd, &wset))
		{
			if ( (writeRes = write(m_socketFd, reinterpret_cast<const char *>(pBytes) + currentOffset, bytesToWrite)) == -1)
			{
				if(errno == ECONNRESET || errno == EPIPE)
				{
					PG_LOGI("Connection closed : %s", strerror_r(errno, buf, sizeof(buf)));
					return -1;

				}
				else if(errno != EAGAIN && errno != EWOULDBLOCK)
				{
					PG_LOGE("write()");
					return -1;
				}
			}
			currentOffset += writeRes;
			bytesToWrite -= writeRes;
		}
	}
	return 0;
}