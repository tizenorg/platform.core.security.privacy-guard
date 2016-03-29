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

#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include "NotificationServer.h"
#include "PrivacyGuardTypes.h"
#include "Utils.h"

auto DBusConnectionDeleter = [&](DBusConnection* pPtr) { dbus_connection_close(pPtr); pPtr = NULL;};
const int MAX_LOCAL_BUF_SIZE = 128;

NotificationServer::NotificationServer(void)
	: m_initialized(false)
	, m_pDBusConnection(NULL)
{

}

NotificationServer::~NotificationServer(void)
{
	if (m_pDBusConnection)
	{
		dbus_connection_close(m_pDBusConnection);
		m_pDBusConnection = NULL;
	}
}

int
NotificationServer::initialize(void)
{
	if (m_initialized)
		return PRIV_FLTR_ERROR_SUCCESS;
	
	DBusError error;
	dbus_error_init(&error);

	m_pDBusConnection = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
	TryReturn(m_pDBusConnection != NULL, PRIV_FLTR_ERROR_SYSTEM_ERROR, dbus_error_free(&error), "dbus_bus_get_private : %s", error.message);

	dbus_connection_setup_with_g_main(m_pDBusConnection, NULL);
	std::unique_ptr < char[] > pRule(new char[MAX_LOCAL_BUF_SIZE]);

	snprintf(pRule.get(), MAX_LOCAL_BUF_SIZE, "path='%s',type='signal',interface='%s'", DBUS_PATH.c_str(), DBUS_SIGNAL_INTERFACE.c_str());

	dbus_bus_add_match(m_pDBusConnection, pRule.get(), &error);
	TryReturn(!dbus_error_is_set(&error), PRIV_FLTR_ERROR_SYSTEM_ERROR, dbus_error_free(&error), "dbus_bus_add_match : %s", error.message);

	m_initialized = true;
	return PRIV_FLTR_ERROR_SUCCESS;
}

int
NotificationServer::notifySettingChanged(const std::string pkgId, const std::string privacyId)
{
	if (!m_initialized)
		return PRIV_FLTR_ERROR_INVALID_STATE;

	char* pPkgId = const_cast <char*> (pkgId.c_str());
	char* pPrivacyId = const_cast <char*> (privacyId.c_str());

	DBusMessage* pMessage = dbus_message_new_signal(DBUS_PATH.c_str(), DBUS_SIGNAL_INTERFACE.c_str(), DBUS_SIGNAL_SETTING_CHANGED.c_str());
	TryReturn(pMessage != NULL, PRIV_FLTR_ERROR_IPC_ERROR, , "dbus_message_new_signal");

	dbus_bool_t r;
	r = dbus_message_append_args(pMessage,
		DBUS_TYPE_STRING, &pPkgId,
		DBUS_TYPE_STRING, &pPrivacyId,
		DBUS_TYPE_INVALID);
	TryReturn(r, PRIV_FLTR_ERROR_IPC_ERROR, , "dbus_message_append_args");

	r = dbus_connection_send(m_pDBusConnection, pMessage, NULL);
	TryReturn(r, PRIV_FLTR_ERROR_IPC_ERROR, dbus_message_unref(pMessage);, "dbus_connection_send");

	dbus_connection_flush(m_pDBusConnection);
	dbus_message_unref(pMessage);

	return PRIV_FLTR_ERROR_SUCCESS;
}

int
NotificationServer::notifyPkgRemoved(const std::string pkgId)
{
	if (!m_initialized)
		return PRIV_FLTR_ERROR_INVALID_STATE;

	char* pPkgId = const_cast <char*> (pkgId.c_str());

	DBusMessage* pMessage = dbus_message_new_signal(DBUS_PATH.c_str(), DBUS_SIGNAL_INTERFACE.c_str(), DBUS_SIGNAL_PKG_REMOVED.c_str());
	TryReturn(pMessage != NULL, PRIV_FLTR_ERROR_IPC_ERROR, , "dbus_message_new_signal");

	dbus_bool_t r;
	r = dbus_message_append_args(pMessage,
		DBUS_TYPE_STRING, &pPkgId,
		DBUS_TYPE_INVALID);
	TryReturn(r, PRIV_FLTR_ERROR_IPC_ERROR, , "dbus_message_append_args");

	r = dbus_connection_send(m_pDBusConnection, pMessage, NULL);
	TryReturn(r, PRIV_FLTR_ERROR_IPC_ERROR, dbus_message_unref(pMessage);, "dbus_connection_send");

	dbus_connection_flush(m_pDBusConnection);
	dbus_message_unref(pMessage);

	return PRIV_FLTR_ERROR_SUCCESS;
}
