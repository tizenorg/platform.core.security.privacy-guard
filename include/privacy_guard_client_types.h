/*
 * Copyright (c) 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _PRIVACY_GUARD_CLIENT_TYPES_H_
#define _PRIVACY_GUARD_CLIENT_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef EXTERN_API
#define EXTERN_API __attribute__((visibility("default")))
#endif

enum {
	PRIV_GUARD_ERROR_SUCCESS = 0,

	PRIV_GUARD_ERROR_NOT_INITIALIZED = -10,
	PRIV_GUARD_ERROR_INVALID_PARAMETER = -11,
	PRIV_GUARD_ERROR_OUT_OF_MEMORY = -12,
	PRIV_GUARD_ERROR_IO_ERROR = -13,
	PRIV_GUARD_ERROR_NO_DATA = -14,
	PRIV_GUARD_ERROR_DB_ERROR = -15,
	PRIV_GUARD_ERROR_IPC_ERROR = -16,
	PRIV_GUARD_ERROR_INVALID_STATE = -17,
	PRIV_GUARD_ERROR_SYSTEM_ERROR = -18,
	PRIV_GUARD_ERROR_USER_NOT_CONSENTED = -19,

	PRIV_GUARD_ERROR_UNKNOWN = -(0x99),
};


#ifdef __cplusplus
}
#endif

#endif //_PRIVACY_GUARD_CLIENT_TYPES_H_
