/*
 * app2ext
 *
 * Copyright (c) 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _APP2EXT_UTILS_H
#define _APP2EXT_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <dlog.h>
#include <glib.h>
#include <sys/stat.h>
#include <tzplatform_config.h>
#include <storage-internal.h>

#define _E(fmt, arg...) LOGE(fmt, ##arg)
#define _D(fmt, arg...) LOGD(fmt, ##arg)
#define _W(fmt, arg...) LOGW(fmt, ##arg)
#define _I(fmt, arg...) LOGI(fmt, ##arg)

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "APP2EXT"

#define APP2EXT_SUCCESS 0

#define OWNER_ROOT 0
#define REGULAR_USER 5000
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
#define EXTIMG_DIR "app2sd"

#define APP2SD_BUS_NAME "org.tizen.app2sd"
#define APP2SD_OBJECT_PATH "/org/tizen/app2sd"
#define APP2SD_INTERFACE_NAME "org.tizen.app2sd"

#define DIR_PERMS (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)

int _is_global(uid_t uid);

char *_app2sd_get_encoded_name(const char *pkgid, uid_t uid);

int _app2sd_delete_directory(const char *dirname);

#ifdef __cplusplus
}
#endif
#endif
