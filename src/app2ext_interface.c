/*
 * app2ext
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jyotsna Dhumale <jyotsna.a@samsung.com>
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

#include <app2ext_interface.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>

#define APP2EXT_SD_PLUGIN_PATH	LIBPREFIX "/libapp2sd.so"

int _is_global(uid_t uid)
{
	if (uid == OWNER_ROOT || uid == GLOBAL_USER)
		return 1;
	else
		return 0;
}

app2ext_handle *app2ext_init(int storage_type)
{
	void *dl_handle = NULL;
	int (*dl_on_load)(app2ext_interface *) = NULL;

	/* validate the function parameter recieved */
	if (storage_type < APP2EXT_INTERNAL_MEM ||
		storage_type > APP2EXT_CLOUD) {
		app2ext_print("app2ext error : invalid function arguments\n");
		return NULL;
	}
	if (storage_type != APP2EXT_SD_CARD ) {
		app2ext_print("app2ext error : storage type currently not supported\n");
		return NULL;
	}

	/* allocate memory for app2ext handle*/
	app2ext_handle *handle = (app2ext_handle *)calloc(1, sizeof(app2ext_handle));
	if (handle == NULL) {
		app2ext_print("app2ext error : memory allocation failed\n");
		return NULL;
	}

	/* load SD plugin*/
	handle->type = APP2EXT_SD_CARD;
	dl_handle = dlopen(APP2EXT_SD_PLUGIN_PATH, RTLD_LAZY|RTLD_GLOBAL);
	if (NULL == dl_handle) {
		app2ext_print("app2ext error : dlopen(%s) failed\n", APP2EXT_SD_PLUGIN_PATH);
		free(handle);
		return NULL;
	}

	handle->plugin_handle = dl_handle;
	dl_on_load = dlsym(dl_handle, "app2ext_on_load");
	if (NULL == dl_on_load) {
		app2ext_print("app2ext error : Cannot find app2ext_on_load symbol in (%s)", APP2EXT_SD_PLUGIN_PATH);
		dlclose(dl_handle);
		free(handle);
		return NULL;
	}

	/* initialize the SD plugin*/
	if (!dl_on_load(&(handle->interface))) {
		app2ext_print("app2ext error : app2ext_on_load() failed in (%s)", APP2EXT_SD_PLUGIN_PATH);
		dlclose(dl_handle);
		free(handle);
		return NULL;
	}

	app2ext_print("app2ext: plugin(%s) loaded\n", APP2EXT_SD_PLUGIN_PATH);

	return handle;
}

int app2ext_deinit(app2ext_handle *handle)
{
	/* validate the function parameter recieved */
	if (handle == NULL || handle->plugin_handle == NULL){
		app2ext_print("App2Ext Error : Invalid function arguments\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* close the plugin handle*/
	dlclose(handle->plugin_handle);

	/* free allocated memory during installtion*/
	free(handle);

	return APP2EXT_SUCCESS;
}

int app2ext_usr_get_app_location(const char *pkgid, uid_t uid)
{
	FILE *fp = NULL;
	char loopback_device[FILENAME_MAX] = { 0, };
	char application_path[FILENAME_MAX] = { 0, };
	char application_mmc_path[FILENAME_MAX] = { 0, };

	/* validate the function parameter received */
	if (pkgid == NULL) {
		app2ext_print("invalid func parameters\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(application_mmc_path, FILENAME_MAX - 1, "%s/%s/.mmc",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(application_mmc_path, FILENAME_MAX - 1, "%s/%s/.mmc",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s/%s",
			APP2SD_PATH, tzplatform_getenv(TZ_USER_NAME), pkgid);
		tzplatform_reset_user();
	}
	_D("application_path = (%s)", application_path);
	_D("application_mmc_path = (%s)", application_mmc_path);
	_D("loopback_device = (%s)", loopback_device);

	/*check whether application is in external memory or not */
	fp = fopen(loopback_device, "r");
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
		return APP2EXT_SD_CARD;
	}

	/*check whether application is in internal or not */
	fp = fopen(application_path, "r");
	if (fp == NULL) {
		app2ext_print("app_dir_path open failed, "
			"package not installed\n");
		return APP2EXT_NOT_INSTALLED;
	} else {
		fclose(fp);
		/* check whether the application is installed in SD card
		 * but SD card is not present
		 */
		fp = fopen(application_mmc_path, "r");
		if (fp == NULL) {
			app2ext_print("internal mem\n");
			return APP2EXT_INTERNAL_MEM;
		} else {
			fclose(fp);
			app2ext_print("app_mmc_internal_path exists, "
				"error mmc status\n");
			return APP2EXT_ERROR_MMC_STATUS;
		}
	}
}

int app2ext_usr_enable_external_pkg(const char *pkgid, uid_t uid)
{
	FILE *fp = NULL;
	app2ext_handle *app2_handle = NULL;
	char loopback_device[FILENAME_MAX] = { 0, };

	/* validate the function parameter received */
	if (pkgid == NULL) {
		app2ext_print("invalid func parameters\n");
		return -1;
	}

	if (_is_global(uid)) {
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s/%s",
			APP2SD_PATH, tzplatform_getenv(TZ_USER_NAME), pkgid);
		tzplatform_reset_user();
	}

	_D("loopback_device = (%s)", loopback_device);

	/* check whether application is in external memory or not */
	fp = fopen(loopback_device, "r");
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;

		app2_handle = app2ext_init(APP2EXT_SD_CARD);
		if (app2_handle == NULL) {
			app2ext_print("app2_handle : app2ext init failed\n");
			return -2;
		}

		app2_handle->interface.client_usr_enable(pkgid, uid);
		app2ext_deinit(app2_handle);
		app2ext_print("App2Ext enable_external_pkg [%s]\n", pkgid);
	}
	return 0;
}

int app2ext_usr_disable_external_pkg(const char *pkgid, uid_t uid)
{
	FILE *fp = NULL;
	app2ext_handle *app2_handle = NULL;
	char loopback_device[FILENAME_MAX] = { 0, };

	/* validate the function parameter received */
	if (pkgid == NULL) {
		app2ext_print("invalid func parameters\n");
		return -1;
	}

	if (_is_global(uid)) {
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s/%s",
			APP2SD_PATH, tzplatform_getenv(TZ_USER_NAME), pkgid);
		tzplatform_reset_user();
	}

	_D("loopback_device = (%s)", loopback_device);

	/* check whether application is in external memory or not */
	fp = fopen(loopback_device, "r");
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;

		app2_handle = app2ext_init(APP2EXT_SD_CARD);
		if (app2_handle == NULL) {
			app2ext_print("app2_handle : app2ext init failed\n");
			return -2;
		}

		app2_handle->interface.client_usr_disable(pkgid, uid);
		app2ext_deinit(app2_handle);
		app2ext_print("App2Ext disable_external_pkg [%s]\n", pkgid);
	}
	return 0;
}

int app2ext_usr_enable_external_dir(uid_t uid)
{
	int ret = 0;
	DIR *dir = NULL;
	char app2sd_pkgs_path[FILENAME_MAX] = { 0, };
	char buf[FILENAME_MAX] = { 0, };
	struct dirent entry, *result = NULL;

	if (_is_global(uid)) {
		snprintf(app2sd_pkgs_path, FILENAME_MAX - 1, "%s",
			APP2SD_PATH);
	} else {
		tzplatform_set_user(uid);
		snprintf(app2sd_pkgs_path, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, tzplatform_getenv(TZ_USER_NAME));
		tzplatform_reset_user();
	}
	_D("app2sd_pkgs_path = (%s)", app2sd_pkgs_path);

	dir = opendir(app2sd_pkgs_path);
	if (!dir) {
		if (strerror_r(errno, buf, sizeof(buf)) == 0)
			app2ext_print("App2Ext Error :Failed to access the because %s", buf);
		return -1;
	}

	/* TODO */
	for (ret = readdir_r(dir, &entry, &result); ret == 0 && result != NULL;
		ret = readdir_r(dir, &entry, &result)) {
		ret = app2ext_usr_enable_external_pkg(entry.d_name, uid);
		if (ret != 0)
			app2ext_print("App2Ext Error : fail enable pkg[%s]\n", entry.d_name);
	}

	closedir(dir);
	return 0;
}

int app2ext_usr_disable_external_dir(uid_t uid)
{
	int ret = 0;
	DIR *dir = NULL;
	char app2sd_pkgs_path[FILENAME_MAX] = { 0, };
	char buf[FILENAME_MAX] = { 0, };
	struct dirent entry, *result = NULL;

	if (_is_global(uid)) {
		snprintf(app2sd_pkgs_path, FILENAME_MAX - 1, "%s",
			APP2SD_PATH);
	} else {
		tzplatform_set_user(uid);
		snprintf(app2sd_pkgs_path, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, tzplatform_getenv(TZ_USER_NAME));
		tzplatform_reset_user();
	}
	_D("app2sd_pkgs_path = (%s)", app2sd_pkgs_path);

	dir = opendir(app2sd_pkgs_path);
	if (!dir) {
		if (strerror_r(errno, buf, sizeof(buf)) == 0)
			app2ext_print("App2Ext Error :Failed to access the because %s", buf);
		return -1;
	}

	/* TODO */
	for (ret = readdir_r(dir, &entry, &result); ret == 0 && result != NULL;
		ret = readdir_r(dir, &entry, &result)) {
		ret = app2ext_usr_disable_external_pkg(entry.d_name, uid);
		if (ret != 0)
			app2ext_print("App2Ext Error : fail disable pkg[%s]\n", entry.d_name);
	}

	closedir(dir);
	return 0;
}

int app2ext_usr_force_clean_pkg(const char *pkgid, uid_t uid)
{
	FILE *fp = NULL;
	app2ext_handle *app2_handle = NULL;
	char application_mmc_path[FILENAME_MAX] = { 0, };

	/* validate the function parameter received */
	if (pkgid == NULL) {
		app2ext_print("invalid func parameters\n");
		return 0;
	}

	if (_is_global(uid)) {
		snprintf(application_mmc_path, FILENAME_MAX - 1, "%s/%s/.mmc",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_mmc_path, FILENAME_MAX - 1, "%s/%s/.mmc",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		tzplatform_reset_user();
	}
	_D("application_mmc_path = (%s)", application_mmc_path);

	fp = fopen(application_mmc_path, "r");
	if (fp == NULL) {
		return 0;
	} else {
		fclose(fp);
	}

	app2_handle = app2ext_init(APP2EXT_SD_CARD);
	if (app2_handle == NULL) {
		app2ext_print("app2_handle : app2ext init failed\n");
		return 0;
	}

	app2_handle->interface.client_usr_force_clean(pkgid, uid);
	app2ext_deinit(app2_handle);
	app2ext_print("App2Ext force_clean_pkg [%s]\n", pkgid);
	return 0;
}

