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

#ifndef _IPRIVACYGUARD_H_
#define _IPRIVACYGUARD_H_

#include <string>
#include <mutex>
#include <list>
#include <vector>
#include <memory>
#include "PrivacyGuardTypes.h"

class SocketClient;

class EXTERN_API IPrivacyGuard
{
public:
	int addAppPackagePrivacyInfo(const std::string pkgId, const std::list < std::string >& pList, bool privacyPopupRequired);

	int removeAppPackagePrivacyInfo(const std::string pkgId);

	int setPrivacySetting(const std::string pkgId, const std::string privacyId, bool isEnabled);

	int getPrivacyAppPackages(std::list < std::string >& pList);

	int getAppPackagePrivacyInfo(const std::string pkgId, std::list < std::pair <std::string, bool > > & pList);
};

#endif // _IPRIVACYGUARD_H_