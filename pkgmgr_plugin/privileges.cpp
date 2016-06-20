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
#include <unistd.h>
#include "privacy_guard_client_internal.h"
#include "PrivacyGuardClient.h"

#define DEFAULT_MONITOR_POLICY 1

static const xmlChar _NODE_PRIVILEGES[]		= "privileges";
static const xmlChar _NODE_PRIVILEGE[]		= "privilege";

void destroy_char_list(char** ppList, int size)
{
	int i = 0;

	if (ppList) {
		for (i = 0; i < size; ++i) {
			if (ppList[i]) {
				free(ppList[i]);
			}
		}
		if (ppList) {
			free(ppList);
		}
	}
}

extern "C"
__attribute__ ((visibility("default")))
int PKGMGR_PARSER_PLUGIN_PRE_INSTALL(const char *packageId)
{
	return 0;
}

extern "C"
__attribute__ ((visibility("default")))
int PKGMGR_PARSER_PLUGIN_INSTALL(xmlDocPtr docPtr, const char* packageId)
{
	if (packageId == NULL) {
		LOGE("Package ID is NULL");
		return -EINVAL;
	}

	LOGD("PKGMGR_PARSER_PLUGIN_INSTALL() called with [%s].", packageId);

	uid_t user_id = getuid();
	LOGD("Current userid is %d.", user_id);

	int ret = 0;

	// Node: <privileges>
	xmlNodePtr curPtr = xmlFirstElementChild(xmlDocGetRootElement(docPtr));
	if (curPtr == NULL) {
		LOGE("Failed to get the element. xmlFirstElementChild() returned NULL.");
		return -EINVAL;
	}
	curPtr = curPtr->xmlChildrenNode;
	if (curPtr == NULL) {
		LOGE("No privileges");
		return -EINVAL;
	}

	std::list <std::string> privilegeList;
	while (curPtr != NULL) {
		if (xmlStrcmp(curPtr->name, _NODE_PRIVILEGE) == 0) {
			xmlChar* pPrivilege = xmlNodeListGetString(docPtr, curPtr->xmlChildrenNode, 1);
			if (pPrivilege == NULL) {
				LOGE("Failed to get privilege value.");
				return -EINVAL;
			} else {
				privilegeList.push_back(std::string( reinterpret_cast<char*> (pPrivilege)));
			}
		}
		curPtr = curPtr->next;
	}

	char** ppPrivilegeList = (char**) calloc(privilegeList.size() + 1, sizeof(char*));
	char** temp = ppPrivilegeList;
	std::list <std::string>::iterator iter = privilegeList.begin();
	for (size_t i = 0; i < privilegeList.size(); ++i) {
		ppPrivilegeList[i] = (char*)calloc(strlen(iter->c_str()) + 1, sizeof(char));
		if (ppPrivilegeList[i] == NULL) {
			LOGE("Failed allocate memory.");
			destroy_char_list(ppPrivilegeList, privilegeList.size() + 1);
			return -ENOMEM;
		}
		memcpy(ppPrivilegeList[i], iter->c_str(), strlen(iter->c_str()));
		++iter;
	}

	ppPrivilegeList[privilegeList.size()] = (char*)calloc (2, sizeof(char));
	memcpy(ppPrivilegeList[privilegeList.size()], "\0", 1);

	PrivacyGuardClient *pInst = PrivacyGuardClient::getInstance();
	std::list < std::string > privilege_List;

	while (*ppPrivilegeList[0] != '\0') {
		LOGD("privilege in the List: %s", *ppPrivilegeList);
		privilege_List.push_back(std::string(*ppPrivilegeList++));
	}

	int monitor_policy = DEFAULT_MONITOR_POLICY;
	ret = pInst->PgAddMonitorPolicy(user_id, std::string(packageId), privilege_List, monitor_policy);
	if (ret != PRIV_GUARD_ERROR_SUCCESS) {
		LOGE("Failed to add monitor policy: [%d]", ret);
		return -EIO;
	}

	if (temp)
		destroy_char_list(temp, privilegeList.size() + 1);

    return 0;
}

extern "C"
__attribute__ ((visibility("default")))
int PKGMGR_PARSER_PLUGIN_POST_INSTALL(const char *packageId)
{
	return 0;
}

extern "C"
__attribute__ ((visibility("default")))
int PKGMGR_PARSER_PLUGIN_PRE_UNINSTALL(const char *packageId)
{
	return 0;
}

extern "C"
__attribute__ ((visibility("default")))
int PKGMGR_PARSER_PLUGIN_UNINSTALL(xmlDocPtr docPtr, const char* packageId)
{
	if (packageId == NULL) {
		LOGE("Package ID is NULL");
		return -EINVAL;
	}

	PrivacyGuardClient *pInst = PrivacyGuardClient::getInstance();

	int res = pInst->PgDeleteLogsByPackageId(std::string(packageId));
	if (res != PRIV_GUARD_ERROR_SUCCESS) {
		LOGE("Failed to delete logs using PgDeleteLogsByPackageId() [%d]", res);
		return -EIO;
	}

	res = pInst->PgDeleteMonitorPolicyByPackageId(std::string(packageId));
	if (res != PRIV_GUARD_ERROR_SUCCESS) {
		LOGE("Failed to delete monitor policy using PgDeleteMonitorPolicyByPackageId() [%d]", res);
		return -EIO;
	}

	return 0;
}

extern "C"
__attribute__ ((visibility("default")))
int PKGMGR_PARSER_PLUGIN_POST_UNINSTALL(const char *packageId)
{
	return 0;
}

extern "C"
__attribute__ ((visibility("default")))
int PKGMGR_PARSER_PLUGIN_PRE_UPGRADE(const char *packageId)
{
	return 0;
}

extern "C"
__attribute__ ((visibility("default")))
int PKGMGR_PARSER_PLUGIN_UPGRADE(xmlDocPtr docPtr, const char* packageId)
{
	if (packageId == NULL) {
		LOGE("Package ID is NULL");
		return -EINVAL;
	}

	int res = PKGMGR_PARSER_PLUGIN_UNINSTALL(docPtr, packageId);
	if (res != 0) {
		LOGE("PKGMGR_PARSER_PLUGIN_UNINSTALL is failed. [%d]", res);
		return res;
	}

	res = PKGMGR_PARSER_PLUGIN_INSTALL(docPtr, packageId);
	if (res != 0) {
		LOGE("PKGMGR_PARSER_PLUGIN_INSTALL is failed. [%d]", res);
		return res;
	}

	return res;
}

extern "C"
__attribute__ ((visibility("default")))
int PKGMGR_PARSER_PLUGIN_POST_UPGRADE(const char *packageId)
{
	return 0;
}

