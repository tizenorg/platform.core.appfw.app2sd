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

#include <app2sd_internals.h>
#include <app2sd_interface.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pkgmgr-info.h>

static int __app2sd_create_app2sd_directories(uid_t uid)
{
	int ret = 0;
	char app2sd_user_path[FILENAME_MAX] = { 0, };
	mode_t mode = DIR_PERMS;

	ret = mkdir(APP2SD_PATH, mode);
	if (ret) {
		if (errno != EEXIST) {
			_E("create directory failed," \
				" error no is (%d)", errno);
			return APP2EXT_ERROR_CREATE_DIRECTORY;
		}
	}

	if (!_is_global(uid)) {
		tzplatform_set_user(uid);
		snprintf(app2sd_user_path, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, tzplatform_getenv(TZ_USER_NAME));
		tzplatform_reset_user();

		ret = mkdir(app2sd_user_path, mode);
		if (ret) {
			if (errno != EEXIST) {
				_E("create directory failed," \
					" error no is (%d)", errno);
				return APP2EXT_ERROR_CREATE_DIRECTORY;
			}
		}
	}

	return APP2EXT_SUCCESS;
}

static int __app2sd_check_operation_permission()
{
	if (getuid() != 0)
		return -1;
	return 0;
}

int app2sd_usr_pre_app_install(const char *pkgid, GList* dir_list, int size, uid_t uid)
{
	int ret = 0;
	int free_mmc_mem = 0;
	char *device_node = NULL;
	char *devi = NULL;
	char *result = NULL;
	char application_path[FILENAME_MAX] = { 0, };
	char loopback_device[FILENAME_MAX] = { 0, };
	int reqd_disk_size = size + ceil(size*0.2);

	if (__app2sd_check_operation_permission() < 0) {
		_E("operation not permitted");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate the function parameter recieved */
	if (pkgid == NULL || dir_list == NULL || size <= 0) {
		_E("invalid function arguments");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		_E("MMC not preset OR Not ready (%d)", ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}

	/* find available free memory in the MMC card */
	ret = _app2sd_get_available_free_memory(MMC_PATH, &free_mmc_mem);
	if (ret) {
		_E("unable to get available free memory in MMC (%d)",
			ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}
	_D("size details for application installation:" \
		" size=(%d)MB, reqd_disk_size=(%d)MB, free_mmc_size=(%d)MB",
		size, reqd_disk_size, free_mmc_mem);

	/* if avaialalbe free memory in MMC is less than required size + 5MB,
	 * return error
	 */
	if ((reqd_disk_size + PKG_BUF_SIZE + MEM_BUF_SIZE) > free_mmc_mem) {
		_E("insufficient memory in MMC for"
			" application installation (%d)", ret);
		return APP2EXT_ERROR_MMC_INSUFFICIENT_MEMORY;
	}

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s/%s",
			APP2SD_PATH, tzplatform_getenv(TZ_USER_NAME), pkgid);
		tzplatform_reset_user();
	}
	_D("application_path = (%s)", application_path);
	_D("loopback_device = (%s)", loopback_device);

	ret = __app2sd_create_app2sd_directories(uid);
	if (ret) {
		_E("failed to create app2sd dirs");
		return ret;
	}

	/* check same loopback_device existence */
	result = (char *)_app2sd_find_associated_device(loopback_device);
	if (result != NULL) {
		_E("there is same associated File (%s)", loopback_device);
		return APP2EXT_ERROR_SAME_LOOPBACK_DEVICE_EXISTS;
	}

	/* create a loopback device */
	ret = _app2sd_create_loopback_device(pkgid, loopback_device,
		(reqd_disk_size + PKG_BUF_SIZE));
	if (ret) {
		_E("package already present");
		ret = _app2sd_delete_directory(application_path);
		if (ret) {
			_E("unable to delete the directory (%s)",
				application_path);
			return ret;
		}
	}

	/* perform Loopback encryption setup */
	device_node = _app2sd_do_loopback_encryption_setup(pkgid,
		loopback_device);
	if (!device_node) {
		_E("loopback encryption setup failed");
		_app2sd_delete_loopback_device(loopback_device);
		return APP2EXT_ERROR_DO_LOSETUP;
	}

	/* check whether loopback device is associated
	 * with device node or not
	 */
	devi = _app2sd_find_associated_device_node(loopback_device);
	if (devi == NULL) {
		_E("finding associated device node failed");
		ret = APP2EXT_ERROR_DO_LOSETUP;
		goto FINISH_OFF;
	}

	/* format the loopback file system */
	ret = _app2sd_create_file_system(device_node);
	if (ret) {
		_E("creating FS failed failed");
		ret = APP2EXT_ERROR_CREATE_FS;
		goto FINISH_OFF;
	}

	/* mount the loopback encrypted pseudo device on application
	 * installation path as with Read Write permission
	 */
	ret =_app2sd_mount_app_content(application_path, pkgid,
		device_node, MOUNT_TYPE_RW, dir_list,
		APP2SD_PRE_INSTALL, uid);
	if (ret) {
		_E("mounting dev path to app install path failed");
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
		_app2sd_delete_loopback_device(loopback_device);
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

int app2sd_usr_post_app_install(const char *pkgid,
		app2ext_status install_status, uid_t uid)
{
	char *device_name = NULL;
	char application_path[FILENAME_MAX] = { 0, };
	char loopback_device[FILENAME_MAX] = { 0, };
	int ret = APP2EXT_SUCCESS;
	int pkgmgr_ret = 0;

	if (__app2sd_check_operation_permission() < 0) {
		_E("operation not permitted");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate the function parameter recieved */
	if (pkgid == NULL || install_status < APP2EXT_STATUS_FAILED
		|| install_status > APP2EXT_STATUS_SUCCESS) {
		_E("invalid func parameters");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		_E("MMC not present OR Not ready (%d)", ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}
	sync();

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s/%s",
			APP2SD_PATH, tzplatform_getenv(TZ_USER_NAME), pkgid);
		tzplatform_reset_user();
	}
	_D("application_path = (%s)", application_path);
	_D("loopback_device = (%s)", loopback_device);

	/* get the associated device node for SD card applicationer */
	device_name = _app2sd_find_associated_device_node(loopback_device);
	if (NULL == device_name) {
		return APP2EXT_ERROR_FIND_ASSOCIATED_DEVICE_NODE;
	}

	ret = _app2sd_unmount_app_content(application_path);
	if (ret) {
		if (device_name) {
			free(device_name);
			device_name = NULL;
		}
		_E("unable to unmount the app content (%d)", ret);
		return APP2EXT_ERROR_UNMOUNT;
	}

	ret = _app2sd_remove_loopback_encryption_setup(loopback_device);
	if (ret) {
		if (device_name) {
			free(device_name);
			device_name = NULL;
		}
		_E("unable to detach the loopback encryption setup" \
			" for the application");
		return APP2EXT_ERROR_UNMOUNT;
	}

	if (device_name) {
		free(device_name);
		device_name = NULL;
	}

	/* take appropriate action based on
	 * installation status of application package
	 */
	if (install_status == APP2EXT_STATUS_FAILED) {
		/* delete the loopback device from the SD card */
		ret = _app2sd_delete_loopback_device(loopback_device);
		if (ret) {
			_E("unable to delete the loopback device from the SD Card");
			return APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
		}
		ret = _app2sd_remove_password_from_db(pkgid);

		if (ret)
			_E("unable to delete the password");

		ret = _app2sd_delete_directory(application_path);

		if (ret)
			_E("unable to delete the directory (%s)", application_path);
	} else {
		/* if the status is success, then update installed storage
		 * to pkgmgr_parser db
		 */
		pkgmgr_ret = pkgmgrinfo_pkginfo_set_usr_installed_storage(pkgid,
			INSTALL_EXTERNAL, uid);
		if (pkgmgr_ret < 0) {
			_E("fail to update installed location " \
				"to db[%s, %d] of uid(%d), pkgmgr ret(%d)",
				pkgid, INSTALL_EXTERNAL, uid, pkgmgr_ret);
			return APP2EXT_ERROR_PKGMGR_ERROR;
		}
	}

	return ret;
}

int app2sd_usr_on_demand_setup_init(const char *pkgid, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;
	char application_path[FILENAME_MAX] = { 0, };
	char loopback_device[FILENAME_MAX] = { 0, };
	char *device_node = NULL;
	char *result = NULL;
	FILE *fp = NULL;

	if (__app2sd_check_operation_permission() < 0) {
		_E("operation not permitted");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		_E("invalid function arguments to app launch setup");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		_E("MMC not preset OR Not ready (%d)", ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}

	/* check app entry is there in sd card or not. */
	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s/%s",
			APP2SD_PATH, tzplatform_getenv(TZ_USER_NAME), pkgid);
		tzplatform_reset_user();
	}
	_D("application_path = (%s)", application_path);
	_D("loopback_device = (%s)", loopback_device);

	fp = fopen(loopback_device, "r+");
	if (fp == NULL) {
		_E("app entry is not present in SD Card");
		return APP2EXT_ERROR_INVALID_PACKAGE;
	}
	fclose(fp);

	result = (char *)_app2sd_find_associated_device(loopback_device);
	/* process the string */
	if ((result != NULL) && strstr(result, "/dev") != NULL) {
		_E("already associated");
		free(result);
		result = NULL;
		return APP2EXT_ERROR_ALREADY_MOUNTED;
	}

	/* do loopback setup */
	device_node = _app2sd_do_loopback_encryption_setup(pkgid,
		loopback_device);
	if (device_node == NULL) {
		_E("loopback encryption setup failed");
		return APP2EXT_ERROR_DO_LOSETUP;
	}

	/* do mounting */
	ret = _app2sd_mount_app_content(application_path, pkgid,
		device_node, MOUNT_TYPE_RD, NULL, APP2SD_APP_LAUNCH, uid);
	if (ret) {
		_E("mount failed");
		if (device_node) {
			free(device_node);
			device_node = NULL;
		}
		return APP2EXT_ERROR_MOUNT_PATH;
	}

	if (device_node) {
		free(device_node);
		device_node = NULL;
	}

	return ret;
}

int app2sd_usr_on_demand_setup_exit(const char *pkgid, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;
	char application_path[FILENAME_MAX] = { 0, };
	char loopback_device[FILENAME_MAX] = { 0, };
	FILE *fp = NULL;

	if (__app2sd_check_operation_permission() < 0) {
		_E("operation not permitted");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		_E("invalid function arguments to app launch setup");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		_E("MMC not preset OR Not ready (%d)", ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}

	/* check app entry is there in sd card or not. */
	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s/%s",
			APP2SD_PATH, tzplatform_getenv(TZ_USER_NAME), pkgid);
		tzplatform_reset_user();
	}
	_D("application_path = (%s)", application_path);
	_D("loopback_device = (%s)", loopback_device);

	fp = fopen(loopback_device, "r+");
	if (fp == NULL) {
		_E("app entry is not present in SD Card");
		return APP2EXT_ERROR_INVALID_PACKAGE;
	}
	fclose(fp);

	ret = _app2sd_unmount_app_content(application_path);
	if (ret) {
		_E("unable to unmount the SD application");
		return APP2EXT_ERROR_UNMOUNT;
	}

	ret = _app2sd_remove_loopback_encryption_setup(loopback_device);
	if (ret) {
		_E("unable to remove loopback setup");
		return APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
	}

	return ret;
}

int app2sd_usr_pre_app_uninstall(const char *pkgid, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;
	char application_path[FILENAME_MAX] = { 0, };
	char loopback_device[FILENAME_MAX] = { 0, };
	char *device_node = NULL;
	FILE *fp = NULL;

	if (__app2sd_check_operation_permission() < 0) {
		_E("operation not permitted");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		_E("invalid function arguments to app launch setup");
		ret = APP2EXT_ERROR_INVALID_ARGUMENTS;
		goto END;
	}

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		_E("MMC not preset OR Not ready (%d)", ret);
		ret = APP2EXT_ERROR_MMC_STATUS;
		goto END;
	}

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s/%s",
			APP2SD_PATH, tzplatform_getenv(TZ_USER_NAME), pkgid);
		tzplatform_reset_user();
	}
	_D("application_path = (%s)", application_path);
	_D("loopback_device = (%s)", loopback_device);

	/* check app entry is there in sd card or not. */
	fp = fopen(loopback_device, "r+");
	if (fp == NULL) {
		_E("app entry is not present in SD Card");
		ret = APP2EXT_ERROR_INVALID_PACKAGE;
		goto END;
	}
	fclose(fp);

	/* get the associated device node for SD card applicationer */
	device_node = _app2sd_find_associated_device_node(loopback_device);
	if (NULL == device_node) {
		/* do loopback setup */
		device_node = _app2sd_do_loopback_encryption_setup(pkgid,
			loopback_device);
		if (device_node == NULL) {
			_E("loopback encryption setup failed");
			ret = APP2EXT_ERROR_DO_LOSETUP;
			goto END;
		}
		/* do mounting */
		ret = _app2sd_mount_app_content(application_path, pkgid,
			device_node, MOUNT_TYPE_RW, NULL,
			APP2SD_PRE_UNINSTALL, uid);
		if (ret) {
			_E("mount failed");
			if (device_node) {
				free(device_node);
				device_node = NULL;
			}
			ret = APP2EXT_ERROR_MOUNT_PATH;
			goto END;
		}
	} else {
		/* do re-mounting */
		ret = _app2sd_mount_app_content(application_path, pkgid,
			device_node, MOUNT_TYPE_RW_REMOUNT, NULL,
			APP2SD_PRE_UNINSTALL, uid);
		if (ret) {
			_E("remount failed");
			if (device_node) {
				free(device_node);
				device_node = NULL;
			}
			ret = APP2EXT_ERROR_MOUNT_PATH;
			goto END;
		}
	}
	if (device_node) {
		free(device_node);
		device_node = NULL;
	}

END:
	return ret;
}

int app2sd_usr_post_app_uninstall(const char *pkgid, uid_t uid)
{
	char application_path[FILENAME_MAX] = { 0, };
	char loopback_device[FILENAME_MAX] = { 0, };
	int ret = APP2EXT_SUCCESS;

	if (__app2sd_check_operation_permission() < 0) {
		_E("operation not permitted");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		_E("invalid function arguments");
		ret = APP2EXT_ERROR_INVALID_ARGUMENTS;
		goto END;
	}

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		_E("MMC not preset OR Not ready (%d)", ret);
		ret = APP2EXT_ERROR_MMC_STATUS;
		goto END;
	}

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s/%s",
			APP2SD_PATH, tzplatform_getenv(TZ_USER_NAME), pkgid);
		tzplatform_reset_user();
	}
	_D("application_path = (%s)", application_path);
	_D("loopback_device = (%s)", loopback_device);

	/* unmount the loopback encrypted pseudo device from
	 * the application installation path
	 */
	ret = _app2sd_unmount_app_content(application_path);
	if (ret) {
		_E("unable to unmount the app content (%d)", ret);
		ret = APP2EXT_ERROR_UNMOUNT;
		goto END;
	}
	/* detach the loopback encryption setup for the application */
	ret = _app2sd_remove_loopback_encryption_setup(loopback_device);
	if (ret) {
		_E("unable to Detach the loopback encryption setup" \
			" for the application");
		ret = APP2EXT_ERROR_DETACH_LOOPBACK_DEVICE;
		goto END;
	}

	/* delete the loopback device from the SD card */
	ret = _app2sd_delete_loopback_device(loopback_device);
	if (ret) {
		_E("unable to delete the " \
			"loopback device from the SD Card");
		ret =  APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
		goto END;
	}

	ret = _app2sd_delete_directory(application_path);
	if (ret) {
		_E("unable to delete the directory (%s)",
		application_path);
		goto END;
	}

	/* remove encryption password from DB */
	ret = _app2sd_initialize_db();
	if (ret) {
		_E("app2sd db initialize failed");
		ret = APP2EXT_ERROR_SQLITE_REGISTRY;
		goto END;
	}

	ret = _app2sd_remove_password_from_db(pkgid);
	if (ret) {
		_E("cannot remove password from db");
		ret = APP2EXT_ERROR_SQLITE_REGISTRY;
		goto END;
	}

END:
	return ret;
}

int app2sd_usr_move_installed_app(const char *pkgid, GList* dir_list,
		app2ext_move_type move_type, uid_t uid)
{
	int ret = 0;
	int pkgmgr_ret = 0;

	if (__app2sd_check_operation_permission() < 0) {
		_E("operation not permitted");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate function arguments */
	if (pkgid == NULL || dir_list == NULL
		|| move_type < APP2EXT_MOVE_TO_EXT
		|| move_type > APP2EXT_MOVE_TO_PHONE) {
		_E("invalid function arguments");
		ret = APP2EXT_ERROR_INVALID_ARGUMENTS;
		goto END;
	}

	pkgmgrinfo_pkginfo_h info_handle = NULL;
	pkgmgrinfo_installed_storage storage = PMINFO_INTERNAL_STORAGE;
	pkgmgr_ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &info_handle);
	if (pkgmgr_ret < 0) {
		_E("failed to get pkginfo for pkg(%s), uid(%d), pkgmgr_ret(%d)",
			pkgid, uid, pkgmgr_ret);
	}
	pkgmgr_ret = pkgmgrinfo_pkginfo_get_installed_storage(info_handle, &storage);
	if (pkgmgr_ret < 0) {
		_E("failed to get installed storage for pkg(%s) of uid(%d), pkgmgr_ret(%d)",
			pkgid, uid, pkgmgr_ret);
		pkgmgrinfo_pkginfo_destroy_pkginfo(info_handle);
		goto END;
	}

	if ((move_type == APP2EXT_MOVE_TO_EXT && storage == PMINFO_EXTERNAL_STORAGE)
		|| (move_type == APP2EXT_MOVE_TO_PHONE && storage == PMINFO_INTERNAL_STORAGE)) {
			ret = APP2EXT_ERROR_PKG_EXISTS;
			_E("PKG_EXISTS in [%d] STORAGE", storage);
			pkgmgrinfo_pkginfo_destroy_pkginfo(info_handle);
			goto END;
	} else {
		_D("pkgid[%s] move to STORAGE [%d]", pkgid, storage);
	}
	pkgmgrinfo_pkginfo_destroy_pkginfo(info_handle);

	ret = _app2sd_usr_move_app(pkgid, move_type, dir_list, uid);
	if (ret) {
		_D("unable to move application");
		goto END;
	}

	/* if move is completed, then update installed storage to pkgmgr_parser db */
	if (move_type == APP2EXT_MOVE_TO_EXT) {
		pkgmgr_ret = pkgmgrinfo_pkginfo_set_usr_installed_storage(pkgid,
				INSTALL_EXTERNAL, uid);
		if (pkgmgr_ret < 0) {
			_E("failed to update installed location to db " \
				"[%s, %s] of uid(%d), pkgmgr_ret(%d)",
				pkgid, INSTALL_EXTERNAL, uid, pkgmgr_ret);
			return APP2EXT_ERROR_PKGMGR_ERROR;
		}
	} else {
		pkgmgr_ret = pkgmgrinfo_pkginfo_set_usr_installed_storage(pkgid,
				INSTALL_INTERNAL, uid);
		if (pkgmgr_ret < 0) {
			_E("failed to update installed location to db " \
				"[%s, %s] of uid(%d), pkgmgr_ret(%d)",
				pkgid, INSTALL_INTERNAL, uid, pkgmgr_ret);
			return APP2EXT_ERROR_PKGMGR_ERROR;
		}
	}

END:
	_app2sd_make_result_info_file((char*)pkgid, ret, uid);

	return ret;
}

int app2sd_usr_pre_app_upgrade(const char *pkgid, GList* dir_list,
		int size, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;
	char loopback_device[FILENAME_MAX] = { 0, };
	char application_path[FILENAME_MAX] = { 0, };
	char temp_pkgid[FILENAME_MAX] = { 0, };
	char temp_loopback_device[FILENAME_MAX] = { 0, };
	char temp_application_path[FILENAME_MAX] = { 0, };
	char *device_node = NULL;
	unsigned long long curr_size = 0;
	FILE *fp = NULL;
	int reqd_disk_size = size + ceil(size*0.2);

	if (__app2sd_check_operation_permission() < 0) {
		_E("operation not permitted");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate function arguments*/
	if (pkgid == NULL || dir_list == NULL || size<=0) {
		_E("invalid function arguments");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		_E("MMC not preset OR Not ready (%d)", ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s/%s",
			APP2SD_PATH, tzplatform_getenv(TZ_USER_NAME), pkgid);
		tzplatform_reset_user();
	}
	_D("application_path = (%s)", application_path);
	_D("loopback_device = (%s)", loopback_device);

	/* check app entry is there in sd card or not. */
	fp = fopen(loopback_device, "r+");
	if (fp == NULL) {
		_E("app entry is not present in SD Card");
		return APP2EXT_ERROR_INVALID_PACKAGE;
	}
	fclose(fp);

	/* get installed app size*/
	curr_size = _app2sd_calculate_file_size(loopback_device);
	curr_size = (curr_size) / (1024 * 1024);
	if (curr_size == 0) {
		_E("app entry is not present in SD Card");
		return APP2EXT_ERROR_LOOPBACK_DEVICE_UNAVAILABLE;
	}
	if ((int)curr_size < reqd_disk_size) {
		snprintf(temp_pkgid, FILENAME_MAX - 1, "%s.new", pkgid);
		if (_is_global(uid)) {
			snprintf(temp_application_path, FILENAME_MAX - 1,
				"%s/%s", tzplatform_getenv(TZ_SYS_RW_APP), temp_pkgid);
			snprintf(temp_loopback_device, FILENAME_MAX - 1,
				"%s/%s", APP2SD_PATH, temp_pkgid);
		} else {
			tzplatform_set_user(uid);
			snprintf(temp_application_path, FILENAME_MAX - 1,
				"%s/%s", tzplatform_getenv(TZ_USER_APP), temp_pkgid);
			snprintf(temp_loopback_device, FILENAME_MAX - 1,
				"%s/%s/%s", APP2SD_PATH,
				tzplatform_getenv(TZ_USER_NAME), temp_pkgid);
			tzplatform_reset_user();
		}
		ret = _app2sd_update_loopback_device_size(pkgid,
			loopback_device, application_path, temp_pkgid,
			temp_loopback_device, temp_application_path,
			reqd_disk_size, dir_list, uid);
		if (APP2EXT_SUCCESS != ret) {
			_E("failed to update loopback device size");
			return ret;
		}
	}

	/* get the associated device node for SD card applicationer */
	device_node = _app2sd_find_associated_device_node(loopback_device);
	if (NULL == device_node) {
		/* do loopback setup */
		device_node = _app2sd_do_loopback_encryption_setup(pkgid,
			loopback_device);
		if (device_node == NULL) {
			_E("loopback encryption setup failed");
			return APP2EXT_ERROR_DO_LOSETUP;
		}

		/* do mounting */
		ret = _app2sd_mount_app_content(application_path, pkgid,
			device_node, MOUNT_TYPE_RW, dir_list,
			APP2SD_PRE_UPGRADE, uid);
		if (ret) {
			_E("mount failed");
			if (device_node) {
				free(device_node);
				device_node = NULL;
			}
			return APP2EXT_ERROR_MOUNT_PATH;
		}
	} else {
		/* do re-mounting */
		ret = _app2sd_mount_app_content(application_path, pkgid,
			device_node, MOUNT_TYPE_RW_REMOUNT, NULL,
			APP2SD_PRE_UPGRADE, uid);
		if (ret) {
			_E("remount failed");
			if (device_node) {
				free(device_node);
				device_node = NULL;
			}
			return APP2EXT_ERROR_MOUNT_PATH;
		}
	}

	if (device_node) {
		free(device_node);
		device_node = NULL;
	}
	return ret;
}

int app2sd_usr_post_app_upgrade(const char *pkgid,
		app2ext_status install_status, uid_t uid)
{
	char *device_name = NULL;
	char loopback_device[FILENAME_MAX] = { 0, };
	char application_path[FILENAME_MAX] = { 0, };
	int ret = APP2EXT_SUCCESS;

	if (__app2sd_check_operation_permission() < 0) {
		_E("operation not permitted");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate the function parameter recieved */
	if (pkgid == NULL || install_status < APP2EXT_STATUS_FAILED
		|| install_status > APP2EXT_STATUS_SUCCESS) {
		_E("invalid func parameters");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		_E("MMC not preset OR Not ready (%d)", ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s/%s",
			APP2SD_PATH, tzplatform_getenv(TZ_USER_NAME), pkgid);
		tzplatform_reset_user();
	}
	_D("application_path = (%s)", application_path);
	_D("loopback_device = (%s)", loopback_device);

	/* get the associated device node for SD card applicationer */
	device_name = _app2sd_find_associated_device_node(loopback_device);
	if (NULL == device_name) {
		return APP2EXT_ERROR_FIND_ASSOCIATED_DEVICE_NODE;
	}

	ret = _app2sd_unmount_app_content(application_path);
	if (ret) {
		if (device_name) {
			free(device_name);
			device_name = NULL;
		}
		_E("unable to unmount the app content (%d)", ret);
		return APP2EXT_ERROR_UNMOUNT;
	}

	ret = _app2sd_remove_loopback_encryption_setup(loopback_device);
	if (ret) {
		if (device_name) {
			free(device_name);
			device_name = NULL;
		}
		_E("unable to detach the loopback encryption " \
			"setup for the application");
		return APP2EXT_ERROR_UNMOUNT;
	}

	if (device_name) {
		free(device_name);
		device_name = NULL;
	}

	return ret;
}

int app2sd_usr_force_clean(const char *pkgid, uid_t uid)
{
	char loopback_device[FILENAME_MAX] = { 0, };
	char application_path[FILENAME_MAX] = { 0, };
	int ret = APP2EXT_SUCCESS;

	if (__app2sd_check_operation_permission() < 0) {
		_E("operation not permitted");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	_D("start force_clean [%s]", pkgid);

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		_E("invalid func parameters");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	sync();

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s/%s",
			APP2SD_PATH, tzplatform_getenv(TZ_USER_NAME), pkgid);
		tzplatform_reset_user();
	}
	_D("application_path = (%s)", application_path);
	_D("loopback_device = (%s)", loopback_device);

	/* unmount the loopback encrypted pseudo device from the application installation path */
	ret = _app2sd_unmount_app_content(application_path);
	if (ret) {
		_E("unable to unmount the app content (%d)", ret);
	}

	/* detach the loopback encryption setup for the application */
	ret = _app2sd_remove_all_loopback_encryption_setups(pkgid);
	if (ret) {
		_E("unable to detach the loopback encryption setup for the application");
	}

	/* delete the loopback device from the SD card */
	ret = _app2sd_delete_loopback_device(loopback_device);
	if (ret) {
		_E("unable to detach the loopback encryption setup for the application");
	}

	/* delete symlink */
	_app2sd_delete_symlink(application_path);

	/* remove passwrd from DB */
	ret = _app2sd_initialize_db();
	if (ret) {
		_E("app2sd db initialize failed");
	}
	ret = _app2sd_remove_password_from_db(pkgid);
	if (ret) {
		_E("cannot remove password from db");
	}

	_D("finish force_clean");

	return 0;
}
