/*
 * app2ext
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Garima Shrivastava<garima.s@samsung.com>
 *	Jyotsna Dhumale <jyotsna.a@samsung.com>
 *	Venkatesha Sarpangala <sarpangala.v@samsung.com>
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

#ifndef __APPTOSD_INTERFACE_H__
#define __APPTOSD_INTERFACE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <app2ext_interface.h>

int app2sd_usr_pre_app_install(const char *pkgid,
		GList* dir_list, int size, uid_t uid);

int app2sd_usr_post_app_install(const char *pkgid,
		app2ext_status install_status, uid_t uid);

int app2sd_usr_pre_app_upgrade(const char *pkgid,
		GList* dir_list, int size, uid_t uid);

int app2sd_usr_post_app_upgrade(const char *pkgid,
		app2ext_status upgrade_status, uid_t uid);

int app2sd_usr_pre_app_uninstall(const char *pkgid, uid_t uid);

int app2sd_usr_post_app_uninstall(const char *pkgid, uid_t uid);

int app2sd_usr_move_installed_app(const char *pkgid,
		GList* dir_list, app2ext_move_type move_type, uid_t uid);

int app2sd_usr_on_demand_setup_init(const char *pkgid, uid_t uid);

int app2sd_usr_on_demand_setup_exit(const char *pkgid, uid_t uid);

int app2sd_usr_force_clean(const char *pkgid, uid_t uid);

#ifdef __cplusplus
}
#endif
#endif
