#!/bin/sh
# Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
TZ_SYS_DB=/opt/dbspace
TZ_SYS_BIN=/usr/bin
source /etc/tizen-platform.conf
for name in privacy_guard
do
    rm -f ${TZ_SYS_DB}/.$name.db
    rm -f ${TZ_SYS_DB}/.$name.db-journal
    SQL="PRAGMA journal_mode = PERSIST;"
    sqlite3 ${TZ_SYS_DB}/.$name.db "$SQL"
    SQL=".read ${TZ_SYS_BIN}/"$name"_db.sql"
    sqlite3 ${TZ_SYS_DB}/.$name.db "$SQL"
    touch ${TZ_SYS_DB}/.$name.db-journal
    chown security_fw:security_fw ${TZ_SYS_DB}/.$name.db
    chown security_fw:security_fw ${TZ_SYS_DB}/.$name.db-journal
    chmod 666 ${TZ_SYS_DB}/.$name.db
    chmod 666 ${TZ_SYS_DB}/.$name.db-journal
done


