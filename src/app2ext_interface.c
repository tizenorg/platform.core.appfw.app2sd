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

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>

#include "app2ext_interface.h"
#include "app2ext_utils.h"

#define APP2EXT_SD_PLUGIN_PATH	LIBPREFIX "/libapp2sd.so"

app2ext_handle *app2ext_init(int storage_type)
{
	void *dl_handle = NULL;
	int (*dl_on_load)(app2ext_interface *) = NULL;

	/* validate the function parameter recieved */
	if (storage_type < APP2EXT_INTERNAL_MEM ||
		storage_type > APP2EXT_CLOUD) {
		_E("invalid function arguments");
		return NULL;
	}
	if (storage_type != APP2EXT_SD_CARD) {
		_E("storage type currently not supported");
		return NULL;
	}

	/* allocate memory for app2ext handle*/
	app2ext_handle *handle = (app2ext_handle *)calloc(1, sizeof(app2ext_handle));
	if (handle == NULL) {
		_E("memory allocation failed");
		return NULL;
	}

	/* load SD plugin*/
	handle->type = APP2EXT_SD_CARD;
	dl_handle = dlopen(APP2EXT_SD_PLUGIN_PATH, RTLD_LAZY|RTLD_GLOBAL);
	if (NULL == dl_handle) {
		_E("dlopen(%s) failed", APP2EXT_SD_PLUGIN_PATH);
		free(handle);
		return NULL;
	}

	handle->plugin_handle = dl_handle;
	dl_on_load = dlsym(dl_handle, "app2ext_on_load");
	if (NULL == dl_on_load) {
		_E("cannot find app2ext_on_load symbol in (%s)", APP2EXT_SD_PLUGIN_PATH);
		dlclose(dl_handle);
		free(handle);
		return NULL;
	}

	/* initialize the SD plugin*/
	if (!dl_on_load(&(handle->interface))) {
		_E("app2ext_on_load() failed in (%s)", APP2EXT_SD_PLUGIN_PATH);
		dlclose(dl_handle);
		free(handle);
		return NULL;
	}

	_D("plugin(%s) loaded", APP2EXT_SD_PLUGIN_PATH);

	return handle;
}

int app2ext_deinit(app2ext_handle *handle)
{
	/* validate the function parameter recieved */
	if (handle == NULL || handle->plugin_handle == NULL) {
		_E("invalid function arguments");
		return -1;
	}

	/* close the plugin handle*/
	dlclose(handle->plugin_handle);

	/* free allocated memory during installtion*/
	free(handle);

	return 0;
}

int app2ext_usr_get_app_location(const char *pkgid, uid_t uid)
{
	FILE *fp = NULL;
	char loopback_device[FILENAME_MAX] = { 0, };
	char application_path[FILENAME_MAX] = { 0, };
	char application_mmc_path[FILENAME_MAX] = { 0, };
	char *encoded_id = NULL;

	/* validate the function parameter received */
	if (pkgid == NULL) {
		_E("invalid func parameters");
		return -1;
	}

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(application_mmc_path, FILENAME_MAX - 1, "%s/%s/.mmc",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(application_mmc_path, FILENAME_MAX - 1, "%s/%s/.mmc",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		tzplatform_reset_user();
	}
	encoded_id = _app2sd_get_encoded_name(pkgid, uid);
	if (encoded_id == NULL)
		return -1;

	snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
		APP2SD_PATH, encoded_id);
	free(encoded_id);

	/* check whether application is in external memory or not */
	fp = fopen(loopback_device, "r");
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
		_D("sd card");
		return APP2EXT_SD_CARD;
	}

	/* check whether application is in internal or not */
	fp = fopen(application_path, "r");
	if (fp == NULL) {
		_D("app_dir_path open failed, " \
			"package not installed");
		return APP2EXT_NOT_INSTALLED;
	} else {
		fclose(fp);
		/* check whether the application is installed in SD card
		 * but SD card is not present
		 */
		fp = fopen(application_mmc_path, "r");
		if (fp == NULL) {
			_D("internal mem");
			return APP2EXT_INTERNAL_MEM;
		} else {
			fclose(fp);
			_E("app_mmc_internal_path exists, " \
				"error mmc status");
			return -1;
		}
	}
}

int app2ext_get_app_location(const char *pkgid)
{
	int ret = 0;

	ret = app2ext_usr_get_app_location(pkgid, getuid());

	return ret;
}

int app2ext_usr_enable_external_pkg(const char *pkgid, uid_t uid)
{
	FILE *fp = NULL;
	app2ext_handle *handle = NULL;
	char loopback_device[FILENAME_MAX] = { 0, };
	char *encoded_id = NULL;

	/* validate the function parameter received */
	if (pkgid == NULL) {
		_E("invalid func parameters");
		return -1;
	}

	encoded_id = _app2sd_get_encoded_name(pkgid, uid);
	if (encoded_id == NULL)
		return -1;

	snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
		APP2SD_PATH, encoded_id);
	free(encoded_id);

	/* check whether application is in external memory or not */
	fp = fopen(loopback_device, "r");
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;

		handle = app2ext_init(APP2EXT_SD_CARD);
		if (handle == NULL) {
			_E("app2ext init failed");
			return -1;
		}

		handle->interface.client_usr_enable(pkgid, uid);
		app2ext_deinit(handle);
	}

	return 0;
}

int app2ext_enable_external_pkg(const char *pkgid)
{
	int ret = 0;

	ret = app2ext_usr_enable_external_pkg(pkgid, getuid());

	return ret;
}

int app2ext_usr_disable_external_pkg(const char *pkgid, uid_t uid)
{
	FILE *fp = NULL;
	app2ext_handle *handle = NULL;
	char loopback_device[FILENAME_MAX] = { 0, };
	char *encoded_id = NULL;

	/* validate the function parameter received */
	if (pkgid == NULL || uid < 0) {
		_E("invalid func parameters");
		return -1;
	}

	encoded_id = _app2sd_get_encoded_name(pkgid, uid);
	if (encoded_id == NULL)
		return -1;

	snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
		APP2SD_PATH, encoded_id);
	free(encoded_id);

	/* check whether application is in external memory or not */
	fp = fopen(loopback_device, "r");
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;

		handle = app2ext_init(APP2EXT_SD_CARD);
		if (handle == NULL) {
			_E("app2ext init failed");
			return -1;
		}

		handle->interface.client_usr_disable(pkgid, uid);
		app2ext_deinit(handle);
	}

	return 0;
}

int app2ext_disable_external_pkg(const char *pkgid)
{
	int ret = 0;

	ret = app2ext_usr_disable_external_pkg(pkgid, getuid());

	return ret;
}

int app2ext_enable_all_external_pkgs(void)
{
	int ret = 0;
	app2ext_handle *handle = NULL;

	if (getuid() >= REGULAR_USER)
		return 0;

	handle = app2ext_init(APP2EXT_SD_CARD);
	if (handle == NULL) {
		_E("app2ext init failed");
		return -1;
	}

	ret = handle->interface.client_enable_full_pkg();
	if (ret != 0)
		_E("failed to enable entire pkgs");

	app2ext_deinit(handle);

	return 0;
}

int app2ext_disable_all_external_pkgs(void)
{
	int ret = 0;
	app2ext_handle *handle = NULL;

	if (getuid() >= REGULAR_USER)
		return 0;

	handle = app2ext_init(APP2EXT_SD_CARD);
	if (handle == NULL) {
		_E("app2ext init failed");
		return -1;
	}

	ret = handle->interface.client_disable_full_pkg();
	if (ret != 0)
		_E("failed to disable entire pkgs");

	app2ext_deinit(handle);

	return 0;
}

int app2ext_usr_force_clean_pkg(const char *pkgid, uid_t uid)
{
	app2ext_handle *handle = NULL;

	/* validate the function parameter received */
	if (pkgid == NULL || uid < 0) {
		_E("invalid func parameters");
		return -1;
	}

	handle = app2ext_init(APP2EXT_SD_CARD);
	if (handle == NULL) {
		_E("app2ext init failed");
		return -1;
	}

	handle->interface.client_usr_force_clean(pkgid, uid);
	app2ext_deinit(handle);

	return 0;
}

int app2ext_force_clean_pkg(const char *pkgid)
{
	int ret = 0;

	ret = app2ext_usr_force_clean_pkg(pkgid, getuid());

	return ret;
}
