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

app2ext_handle *app2ext_init(int storage_type)
{
	/*Validate the function parameter recieved */
	if (storage_type < APP2EXT_INTERNAL_MEM ||
		storage_type > APP2EXT_CLOUD) {
		app2ext_print("App2Ext Error : Invalid function arguments\n");
		return NULL;
	}
	if (storage_type != APP2EXT_SD_CARD ) {
		app2ext_print("App2Ext Error : Storage type currently not supported\n");
		return NULL;
	}

	/* allocate memory for app2ext handle*/
	app2ext_handle *handle = (app2ext_handle *)calloc(1, sizeof(app2ext_handle));
	if (handle == NULL) {
		app2ext_print("App2Ext Error : Memory allocation failure\n");
		return NULL;
	}
	void *dl_handle = NULL;
	int (*dl_on_load)(app2ext_interface *)=NULL;

	/* Load SD plugin*/
	handle->type = APP2EXT_SD_CARD;
	dl_handle = dlopen(APP2EXT_SD_PLUGIN_PATH, RTLD_LAZY|RTLD_GLOBAL);
	if (NULL == dl_handle)
	{
		app2ext_print("App2Ext Error : dlopen(%s) failed.\n", APP2EXT_SD_PLUGIN_PATH);
		free(handle);
		return NULL;
	}
	handle->plugin_handle = dl_handle;
	dl_on_load = dlsym(dl_handle, "app2ext_on_load");
	if (NULL == dl_on_load)
	{
		app2ext_print("App2Ext Error : Cannot find app2ext_on_load symbol in %s.", APP2EXT_SD_PLUGIN_PATH);
		dlclose(dl_handle);
		free(handle);
		return NULL;
	}

	/*Initialize the SD plugin*/
	if(!dl_on_load(&(handle->interface)))
	{
		app2ext_print("App2Ext Error : [%s] app2ext_on_load() failed.", APP2EXT_SD_PLUGIN_PATH);
		dlclose(dl_handle);
		free(handle);
		return NULL;
	}

	app2ext_print("App2Ext: %s plugin loaded\n", APP2EXT_SD_PLUGIN_PATH);

	return handle;
}

int app2ext_deinit(app2ext_handle *handle)
{
	/*Validate the function parameter recieved */
	if (handle == NULL || handle->plugin_handle == NULL){
		app2ext_print("App2Ext Error : Invalid function arguments\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* Close the plugin handle*/
	dlclose(handle->plugin_handle);

	/* Free allocated memory during installtion*/
	free(handle);
	return APP2EXT_SUCCESS;
}

int app2ext_get_app_location(const char *appname)
{
	/*Validate the function parameter received */
	if (appname == NULL) {
		app2ext_print("invalid func parameters\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}
	FILE *fp = NULL;
	char app_mmc_path[FILENAME_MAX] = { 0, };
	char app_dir_path[FILENAME_MAX] = { 0, };
	char app_mmc_internal_path[FILENAME_MAX] = { 0, };
	snprintf(app_dir_path, FILENAME_MAX,
	"%s%s", APP_INSTALLATION_PATH, appname);
	snprintf(app_mmc_path, FILENAME_MAX,
	"%s%s", APP2SD_PATH, appname);
	snprintf(app_mmc_internal_path, FILENAME_MAX,
	"%s%s/.mmc", APP_INSTALLATION_PATH, appname);

	app2ext_print("MMC_PATH = (%s)\n", MMC_PATH);
	app2ext_print("APP2SD_PATH = (%s)\n", APP2SD_PATH);
	app2ext_print("APP_INSTALLATION_PATH = (%s)\n", APP_INSTALLATION_PATH);
	app2ext_print("APP_INSTALLATION_USER_PATH = (%s)\n", APP_INSTALLATION_USER_PATH);
	app2ext_print("app_dir_path = (%s)\n", app_dir_path);
	app2ext_print("app_mmc_path = (%s)\n", app_mmc_path);
	app2ext_print("app_mmc_internal_path = (%s)\n", app_mmc_internal_path);

	/*check whether application is in external memory or not */
	fp = fopen(app_mmc_path, "r");
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
		return APP2EXT_SD_CARD;
	}

	/*check whether application is in internal or not */
	fp = fopen(app_dir_path, "r");
	if (fp == NULL) {
		app2ext_print("app_dir_path open failed, package not installed\n");
		return APP2EXT_NOT_INSTALLED;
	} else {
		fclose(fp);
		/*check whether the application is installed in SD card
			but SD card is not present*/
		fp = fopen(app_mmc_internal_path, "r");
		if (fp == NULL) {
			app2ext_print("internal mem\n");
			return APP2EXT_INTERNAL_MEM;
		} else {
			fclose(fp);
			app2ext_print("app_mmc_internal_path exists, error mmc status\n");
			return APP2EXT_ERROR_MMC_STATUS;
		}
	}
}

int app2ext_enable_external_pkg(const char *pkgid)
{
	/*Validate the function parameter received */
	if (pkgid == NULL) {
		app2ext_print("invalid func parameters\n");
		return -1;
	}
	FILE *fp = NULL;
	app2ext_handle *app2_handle = NULL;
	char app_mmc_path[FILENAME_MAX] = { 0, };
	snprintf(app_mmc_path, FILENAME_MAX, "%s%s", APP2SD_PATH, pkgid);

	/*check whether application is in external memory or not */
	fp = fopen(app_mmc_path, "r");
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;

		app2_handle = app2ext_init(APP2EXT_SD_CARD);
		if (app2_handle == NULL) {
			app2ext_print("app2_handle : app2ext init failed\n");
			return -2;
		}

		app2_handle->interface.enable(pkgid);
		app2ext_deinit(app2_handle);
		app2ext_print("App2Ext enable_external_pkg [%s]\n", pkgid);
	}
	return 0;
}

int app2ext_disable_external_pkg(const char *pkgid)
{
	/*Validate the function parameter received */
	if (pkgid == NULL) {
		app2ext_print("invalid func parameters\n");
		return -1;
	}
	FILE *fp = NULL;
	app2ext_handle *app2_handle = NULL;
	char app_mmc_path[FILENAME_MAX] = { 0, };
	snprintf(app_mmc_path, FILENAME_MAX, "%s%s", APP2SD_PATH, pkgid);

	/*check whether application is in external memory or not */
	fp = fopen(app_mmc_path, "r");
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;

		app2_handle = app2ext_init(APP2EXT_SD_CARD);
		if (app2_handle == NULL) {
			app2ext_print("app2_handle : app2ext init failed\n");
			return -2;
		}

		app2_handle->interface.disable(pkgid);
		app2ext_deinit(app2_handle);
		app2ext_print("App2Ext disable_external_pkg [%s]\n", pkgid);
	}
	return 0;
}

int app2ext_enable_external_dir(void)
{
	int ret = 0;
	DIR *dir = NULL;
	char buf[FILENAME_MAX] = { 0, };
	struct dirent entry, *result = NULL;

	dir = opendir(APP2SD_PATH);
	if (!dir) {
		if (strerror_r(errno, buf, sizeof(buf)) == 0)
			app2ext_print("App2Ext Error :Failed to access the because %s", buf);
		return -1;
	}

	for (ret = readdir_r(dir, &entry, &result); ret == 0 && result != NULL; ret = readdir_r(dir, &entry, &result)) {
		ret = app2ext_enable_external_pkg(entry.d_name);
		if (ret != 0)
			app2ext_print("App2Ext Error : fail enable pkg[%s]\n", entry.d_name);
	}

	closedir(dir);
	return 0;
}

int app2ext_disable_external_dir(void)
{
	int ret = 0;
	DIR *dir = NULL;
	char buf[FILENAME_MAX] = { 0, };
	struct dirent entry, *result = NULL;

	dir = opendir(APP2SD_PATH);
	if (!dir) {
		if (strerror_r(errno, buf, sizeof(buf)) == 0)
			app2ext_print("App2Ext Error :Failed to access the because %s", buf);
		return -1;
	}

	for (ret = readdir_r(dir, &entry, &result); ret == 0 && result != NULL; ret = readdir_r(dir, &entry, &result)) {
		ret = app2ext_disable_external_pkg(entry.d_name);
		if (ret != 0)
			app2ext_print("App2Ext Error : fail disable pkg[%s]\n", entry.d_name);
	}

	closedir(dir);
	return 0;
}

int app2ext_force_clean_pkg(const char *pkgid)
{
	/*Validate the function parameter received */
	if (pkgid == NULL) {
		app2ext_print("invalid func parameters\n");
		return 0;
	}

	FILE *fp = NULL;
	app2ext_handle *app2_handle = NULL;
	char app_mmc_path[FILENAME_MAX] = { 0, };
	snprintf(app_mmc_path, FILENAME_MAX, "%s%s/.mmc", APP_INSTALLATION_PATH, pkgid);

	fp = fopen(app_mmc_path, "r");
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

	app2_handle->interface.force_clean(pkgid);
	app2ext_deinit(app2_handle);
	app2ext_print("App2Ext force_clean_pkg [%s]\n", pkgid);
	return 0;
}

