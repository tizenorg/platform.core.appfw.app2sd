/*
 * app2sd-server
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

#include <app2sd_interface.h>

#if 0
int app2sd_server_pre_app_install(const char *pkgid, GList* dir_list, int size)
{
	int ret = 0;
	int free_mmc_mem = 0;
	char *device_node = NULL;
	char *devi = NULL;
	char *result = NULL;
	int reqd_disk_size = size + ceil(size*0.2);

	/* debug path */
	app2ext_print("MMC_PATH = (%s)\n", MMC_PATH);
	app2ext_print("APP2SD_PATH = (%s)\n", APP2SD_PATH);
	app2ext_print("APP_INSTALLATION_PATH = (%s)\n", APP_INSTALLATION_PATH);
	app2ext_print("APP_INSTALLATION_USER_PATH = (%s)\n", APP_INSTALLATION_USER_PATH);

	/* Validate the function parameter recieved */
	if (pkgid == NULL || dir_list == NULL || size <= 0) {
		app2ext_print("App2Sd Error : Invalid function arguments\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}
	/* Check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR Not ready %d\n",
			ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}
	/* Find available free memory in the MMC card */
	ret = _app2sd_get_available_free_memory(MMC_PATH,
						&free_mmc_mem);
	if (ret) {
		app2ext_print("App2Sd Error : Unable to get available free memory in MMC %d\n", ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}
	app2ext_print("Size details for application installation:size=%dMB, reqd_disk_size=%dMB, free_mmc_size=%dMB\n",
			 size, reqd_disk_size, free_mmc_mem);
	/* If avaialalbe free memory in MMC is less than required size + 5MB , return error */
	if ((reqd_disk_size + PKG_BUF_SIZE + MEM_BUF_SIZE) > free_mmc_mem) {
		app2ext_print("Insufficient memory in MMC for application installation %d\n", ret);
		return APP2EXT_ERROR_MMC_INSUFFICIENT_MEMORY;
	}
	/* Create a loopback device */
	ret = _app2sd_create_loopback_device(pkgid, (reqd_disk_size+PKG_BUF_SIZE));
	if (ret) {
		app2ext_print("App2Sd Error : Package already present\n");
		char buf_dir[FILENAME_MAX] = { 0, };
		memset((void *)&buf_dir, '\0', FILENAME_MAX);
		snprintf(buf_dir, FILENAME_MAX, "%s%s", APP_INSTALLATION_PATH, pkgid);
		ret = _app2sd_delete_directory(buf_dir);
		if (ret) {
			app2ext_print
				("App2Sd Error : Unable to delete the directory %s\n",
				 buf_dir);
		}
	}
	/* Perform Loopback encryption setup */
	device_node = _app2sd_do_loopback_encryption_setup(pkgid);
	if (!device_node) {
		app2ext_print("App2Sd Error : Loopback encryption setup failed\n");
		_app2sd_delete_loopback_device(pkgid);
		return APP2EXT_ERROR_DO_LOSETUP;
	}
	/* Check whether loopback device is associated with device node or not */
	devi = _app2sd_find_associated_device_node(pkgid);
	if (devi == NULL) {
		app2ext_print("App2Sd Error : finding associated device node failed\n");
		ret = APP2EXT_ERROR_DO_LOSETUP;
		goto FINISH_OFF;
	}

	/* Format the loopback file system */
	ret = _app2sd_create_file_system(device_node);
	if (ret) {
		app2ext_print("App2Sd Error : creating FS failed failed\n");
		ret = APP2EXT_ERROR_CREATE_FS;
		goto FINISH_OFF;
	}

	/* Mount the loopback encrypted pseudo device on application installation path as with Read Write permission */
	ret =_app2sd_mount_app_content(pkgid, device_node, MOUNT_TYPE_RW,
					dir_list, APP2SD_PRE_INSTALL);
	if (ret) {
		app2ext_print("App2Sd Error : mounting dev path to app install path failed\n");
		ret = APP2EXT_ERROR_MOUNT_PATH;
		goto FINISH_OFF;
	}

	/* Success */
	ret = APP2EXT_SUCCESS;
	goto END;

FINISH_OFF:

	if (device_node) {
		result = _app2sd_detach_loop_device(device_node);
		if (result) {
			free(result);
			result = NULL;
		}
		_app2sd_delete_loopback_device(pkgid);
	}
END:
	if (device_node) {
		free(device_node);
		device_node = NULL;
	}
	if (devi) {
		free(devi);
		devi = NULL;
	}
	return ret;
}
#endif

int main(int argc, char *argv[])
{
	app2ext_print("app2sd_server : start\n");

	app2ext_print("app2sd_server : end\n");

	return 0;
}
