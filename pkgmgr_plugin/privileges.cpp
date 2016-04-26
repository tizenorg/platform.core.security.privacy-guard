//
// Open Service Platform
// Copyright (c) 2013 Samsung Electronics Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <errno.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <dlog.h>
#include <list>
#include <string>
#include "privacy_guard_client_internal.h"
#include "PrivacyGuardClient.h"

static const xmlChar _NODE_PRIVILEGES[]		= "privileges";
static const xmlChar _NODE_PRIVILEGE[]		= "privilege";

void destroy_char_list(char** ppList, int size)
{
	int i;
	for (i = 0; i < size; ++i)
	{
		if (ppList[i])
			free(ppList[i]);
	}
	free(ppList);
}

extern "C"
__attribute__ ((visibility("default")))
int PKGMGR_PARSER_PLUGIN_INSTALL(xmlDocPtr docPtr, const char* packageId)
{
	LOGD("[STHAN] PKGMGR_PARSER_PLUGIN_INSTALL - START");

	int ret = 0;

	// Node: <privileges>
	xmlNodePtr curPtr = xmlFirstElementChild(xmlDocGetRootElement(docPtr));

	curPtr = curPtr->xmlChildrenNode;
	if (curPtr == NULL)
	{
		LOGD("No privileges");
		return 0;
	}

	std::list <std::string> privilegeList;
	while (curPtr != NULL)
	{
		if (xmlStrcmp(curPtr->name, _NODE_PRIVILEGE) == 0)
		{
			xmlChar* pPrivilege = xmlNodeListGetString(docPtr, curPtr->xmlChildrenNode, 1);

			if (pPrivilege == NULL)
			{
				LOGE("Failed to get value");
				return -EINVAL;
			}
            else
			{
				privilegeList.push_back(std::string( reinterpret_cast<char*> (pPrivilege)));
			}
		}
		curPtr = curPtr->next;
	}

	char** ppPrivilegeList = (char**) calloc(privilegeList.size() + 1, sizeof(char*));
	std::list <std::string>::iterator iter = privilegeList.begin();
	for (size_t i = 0; i < privilegeList.size(); ++i)
	{
		ppPrivilegeList[i] = (char*)calloc (strlen(iter->c_str()) + 1, sizeof(char));
		if (ppPrivilegeList[i] == NULL)
		{
			destroy_char_list(ppPrivilegeList, privilegeList.size() + 1);
			return -ENOMEM;
		}
		memcpy(ppPrivilegeList[i], iter->c_str(), strlen(iter->c_str()));
		++iter;
	}

	ppPrivilegeList[privilegeList.size()] = (char*)calloc (2, sizeof(char));
	memcpy(ppPrivilegeList[privilegeList.size()], "\0", 1);

	// TO DO : get user id
	int user_id = 1;
	int monitor_policy = 1;

	if (user_id < 0 || packageId == NULL)
		return -EINVAL;

	PrivacyGuardClient *pInst = PrivacyGuardClient::getInstance();
	std::list < std::string > privilege_List;

	while (*ppPrivilegeList[0] != '\0')
	{
		LOGD("privacyList : %s", *ppPrivilegeList);
		privilege_List.push_back(std::string(*ppPrivilegeList++));
	}
	ret = pInst->PgAddMonitorPolicy(user_id, std::string(packageId), privilege_List, monitor_policy);
	destroy_char_list(ppPrivilegeList, privilegeList.size() + 1);
	if (ret != PRIV_GUARD_ERROR_SUCCESS)
	{
		LOGD("Failed to install monitor policy: %d", ret);
		return -EINVAL;
	}

    return 0;
}

extern "C"
__attribute__ ((visibility("default")))
int PKGMGR_PARSER_PLUGIN_UNINSTALL(xmlDocPtr docPtr, const char* packageId)
{
	LOGD("[STHAN] PKGMGR_PARSER_PLUGIN_UNINSTALL - START");

	if (packageId == NULL)
		return PRIV_GUARD_ERROR_INVALID_PARAMETER;

	PrivacyGuardClient *pInst = PrivacyGuardClient::getInstance();

	int res = pInst->PgDeleteLogsByPackageId(std::string(packageId));
	if (res != PRIV_GUARD_ERROR_SUCCESS)
	{
		LOGD("Failed to delete logs");
		return 0;
	}

	res = pInst->PgDeleteMonitorPolicyByPackageId(std::string(packageId));
	if (res != PRIV_GUARD_ERROR_SUCCESS)
	{
		LOGD("Failed to delete monitor policy");
	}

	return 0;
}

extern "C"
__attribute__ ((visibility("default")))
int PKGMGR_PARSER_PLUGIN_UPGRADE(xmlDocPtr docPtr, const char* packageId)
{
	LOGD("[STHAN] PKGMGR_PARSER_PLUGIN_UPGRADE - START");

	int res = 0;

    LOGD("Update privacy Info");

	res = PKGMGR_PARSER_PLUGIN_UNINSTALL(docPtr, packageId);
	if (res != 0)
	{
		LOGD("Privacy info can be already uninstalled");
	}

	res = PKGMGR_PARSER_PLUGIN_INSTALL(docPtr, packageId);
	if (res != 0)
	{
		LOGD("Failed to install privacy Info: %d", res);
	}
	return res;
}
