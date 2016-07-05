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

#include <pkgmgr-info.h>
#include <aul.h>

#include "app2sd_internals.h"

static int __app2sd_create_app2sd_directories(uid_t uid)
{
	int ret = 0;
	mode_t mode = DIR_PERMS;

	ret = mkdir(APP2SD_PATH, mode);
	if (ret) {
		if (errno != EEXIST) {
			_E("create directory failed," \
				" error no is (%d)", errno);
			return APP2EXT_ERROR_CREATE_DIRECTORY;
		}
	}

	return APP2EXT_SUCCESS;
}

int app2sd_usr_pre_app_install(const char *pkgid, GList *dir_list, int size, uid_t uid)
{
	int ret = 0;
	int free_mmc_mem = 0;
	char *device_node = NULL;
#if !defined(TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION)
	char *devi = NULL;
#endif
	char *result = NULL;
	char application_path[FILENAME_MAX] = { 0, };
	char loopback_device[FILENAME_MAX] = { 0, };
	char *encoded_id = NULL;
	int reqd_disk_size = size + ceil(size * 0.2);

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

	encoded_id = _app2sd_get_encoded_name(pkgid, uid);
	if (encoded_id == NULL)
		return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
		tzplatform_reset_user();
	}
	free(encoded_id);

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

#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	ret = _app2sd_dmcrypt_setup_device(pkgid, loopback_device, false, uid);
	if (ret) {
		_E("dmcrypt setup device error");
		return APP2EXT_ERROR_SETUP_DMCRYPT_DEVICE;
	}

	ret = _app2sd_dmcrypt_open_device(pkgid, loopback_device,
		false, uid, &device_node);
	if (ret) {
		_E("dmcrypt open device error");
		return APP2EXT_ERROR_OPEN_DMCRYPT_DEVICE;
	}
#else
	/* perform loopback encryption setup */
	device_node = _app2sd_do_loopback_encryption_setup(pkgid,
		loopback_device, uid);
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
#endif

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
	ret = _app2sd_mount_app_content(application_path, pkgid,
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
#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	ret = _app2sd_dmcrypt_close_device(pkgid, uid);
	if (ret)
		_E("close dmcrypt device error(%d)", ret);
	_app2sd_delete_loopback_device(loopback_device);
#else
		result = _app2sd_detach_loop_device(device_node);
		if (result) {
			free(result);
			result = NULL;
		}
		_app2sd_delete_loopback_device(loopback_device);
#endif
	}

END:
	if (device_node) {
		free(device_node);
		device_node = NULL;
	}

#if !defined(TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION)
	if (devi) {
		free(devi);
		devi = NULL;
	}
#endif

	return ret;
}

int app2sd_usr_post_app_install(const char *pkgid,
		app2ext_status install_status, uid_t uid)
{
	char *device_name = NULL;
	char application_path[FILENAME_MAX] = { 0, };
	char loopback_device[FILENAME_MAX] = { 0, };
	char *encoded_id = NULL;
	int ret = APP2EXT_SUCCESS;
	int pkgmgr_ret = 0;

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

	encoded_id = _app2sd_get_encoded_name(pkgid, uid);
	if (encoded_id == NULL)
		return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
		tzplatform_reset_user();
	}
	free(encoded_id);

	/* get the associated device node for SD card applicationer */
#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	device_name =
		_app2sd_find_associated_dmcrypt_device_node(pkgid, uid);
	if (!device_name)
		return APP2EXT_ERROR_FIND_ASSOCIATED_DMCRYPT_DEVICE_NODE;
#else
	device_name = _app2sd_find_associated_device_node(loopback_device);
	if (NULL == device_name)
		return APP2EXT_ERROR_FIND_ASSOCIATED_DEVICE_NODE;
#endif

	ret = _app2sd_unmount_app_content(application_path);
	if (ret) {
		if (device_name) {
			free(device_name);
			device_name = NULL;
		}
		_E("unable to unmount the app content (%d)", ret);
		return APP2EXT_ERROR_UNMOUNT;
	}

#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	ret = _app2sd_dmcrypt_close_device(pkgid, uid);
	if (ret) {
		if (device_name) {
			free(device_name);
			device_name = NULL;
		}
		_E("close dmcrypt device error(%d)", ret);
		return ret;
	}
#else
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
#endif

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
		ret = _app2sd_remove_info_from_db(pkgid, uid);
		if (ret)
			_E("unable to delete info");

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
	char *encoded_id = NULL;
	char *device_node = NULL;
#if !defined(TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION)
	char *result = NULL;
#endif
	FILE *fp = NULL;

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

	encoded_id = _app2sd_get_encoded_name(pkgid, uid);
	if (encoded_id == NULL)
		return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;

	/* check app entry is there in sd card or not. */
	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
		tzplatform_reset_user();
	}
	free(encoded_id);

	fp = fopen(loopback_device, "r+");
	if (fp == NULL) {
		_E("app entry is not present in SD Card");
		return APP2EXT_ERROR_INVALID_PACKAGE;
	}
	fclose(fp);

#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	device_node =
		_app2sd_find_associated_dmcrypt_device_node(pkgid, uid);
	if (device_node) {
		_E("device_node(%s_%d) already associated", pkgid, uid);
		return APP2EXT_ERROR_ALREADY_MOUNTED;
	}

	ret = _app2sd_dmcrypt_open_device(pkgid, loopback_device,
		false, uid, &device_node);
	if (ret) {
		_E("dmcrypt open device error(%d)", ret);
		return APP2EXT_ERROR_OPEN_DMCRYPT_DEVICE;
	}
#else
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
		loopback_device, uid);
	if (device_node == NULL) {
		_E("loopback encryption setup failed");
		return APP2EXT_ERROR_DO_LOSETUP;
	}
#endif

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

static int _app2sd_application_handler(const pkgmgrinfo_appinfo_h handle, void *data)
{
	int ret = 0;
	int pid = 0;
	char *appid = NULL;
	uid_t uid = *(uid_t *)data;

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret < 0) {
		_E("failed to get appid");
		return APP2EXT_ERROR_PKGMGR_ERROR;
	}

	_D("appid(%s), uid(%d)", appid, uid);

	ret = aul_app_is_running_for_uid(appid, uid);
	if (ret == 0)
		return APP2EXT_SUCCESS;

	pid = aul_app_get_pid_for_uid(appid, uid);
	if (pid < 0) {
		_E("failed to get pid");
		return APP2EXT_ERROR_KILLAPP_ERROR;
	}

	ret = aul_terminate_pid_sync_for_uid(pid, uid);
	if (ret != AUL_R_OK) {
		_E("failed to kill app");
		return APP2EXT_ERROR_KILLAPP_ERROR;
	}

	return APP2EXT_SUCCESS;
}

static int _app2sd_kill_running_app(const char *pkgid, uid_t uid)
{
	int ret = 0;
	pkgmgrinfo_pkginfo_h handle;

	ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &handle);
	if (ret < 0) {
		_E("failed to get pkginfo");
		return APP2EXT_ERROR_PKGMGR_ERROR;
	}

	ret = pkgmgrinfo_appinfo_get_usr_list(handle,
		PMINFO_ALL_APP, _app2sd_application_handler, &uid, uid);
	if (ret < 0) {
		_E("failed to get appinfo");
		return APP2EXT_ERROR_PKGMGR_ERROR;
	}

	ret = pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	if (ret < 0) {
		_E("failed to destroy pkginfo");
		return APP2EXT_ERROR_PKGMGR_ERROR;
	}

	return APP2EXT_SUCCESS;
}

int app2sd_usr_on_demand_setup_exit(const char *pkgid, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;
	char application_path[FILENAME_MAX] = { 0, };
	char loopback_device[FILENAME_MAX] = { 0, };
	char *encoded_id = NULL;
	FILE *fp = NULL;
	int mmc_present = 1;

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		_E("invalid function arguments to app launch setup");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	_app2sd_kill_running_app(pkgid, uid);

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		_W("MMC not preset OR Not ready (%d)", ret);
		mmc_present = 0;
	}

	encoded_id = _app2sd_get_encoded_name(pkgid, uid);
	if (encoded_id == NULL)
		return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;

	/* check app entry is there in sd card or not. */
	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
		tzplatform_reset_user();
	}
	free(encoded_id);

	if (mmc_present) {
		fp = fopen(loopback_device, "r+");
		if (fp == NULL) {
			_E("app entry is not present in SD Card");
			return APP2EXT_ERROR_INVALID_PACKAGE;
		}
		fclose(fp);
	}

	ret = _app2sd_unmount_app_content(application_path);
	if (ret) {
		_E("unable to unmount the SD application");
		return APP2EXT_ERROR_UNMOUNT;
	}

#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	ret = _app2sd_dmcrypt_close_device(pkgid, uid);
	if (ret)
		_E("close dmcrypt device error(%d)", ret);
#else
	ret = _app2sd_remove_loopback_encryption_setup(loopback_device);
	if (ret) {
		_E("unable to remove loopback setup");
		return APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
	}
#endif

	return ret;
}

int app2sd_usr_pre_app_uninstall(const char *pkgid, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;
	char application_path[FILENAME_MAX] = { 0, };
	char loopback_device[FILENAME_MAX] = { 0, };
	char *encoded_id = NULL;
	char *device_node = NULL;
	FILE *fp = NULL;

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

	encoded_id = _app2sd_get_encoded_name(pkgid, uid);
	if (encoded_id == NULL)
		return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
		tzplatform_reset_user();
	}
	free(encoded_id);

	/* check app entry is there in sd card or not. */
	fp = fopen(loopback_device, "r+");
	if (fp == NULL) {
		_E("app entry is not present in SD Card");
		ret = APP2EXT_ERROR_INVALID_PACKAGE;
		goto END;
	}
	fclose(fp);

	/* get the associated device node for SD card applicationer */
#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	device_node =
		_app2sd_find_associated_dmcrypt_device_node(pkgid, uid);
#else
	device_node = _app2sd_find_associated_device_node(loopback_device);
#endif
	if (NULL == device_node) {
		/* do loopback setup */
#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
		ret = _app2sd_dmcrypt_open_device(pkgid, loopback_device,
			false, uid, &device_node);
		if (ret) {
			_E("dmcrypt open device error(%d)", ret);
			return APP2EXT_ERROR_OPEN_DMCRYPT_DEVICE;
		}
#else
		device_node = _app2sd_do_loopback_encryption_setup(pkgid,
			loopback_device, uid);
		if (device_node == NULL) {
			_E("loopback encryption setup failed");
			ret = APP2EXT_ERROR_DO_LOSETUP;
			goto END;
		}
#endif
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
	char *encoded_id = NULL;
	int ret = APP2EXT_SUCCESS;

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

	encoded_id = _app2sd_get_encoded_name(pkgid, uid);
	if (encoded_id == NULL)
		return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
		tzplatform_reset_user();
	}
	free(encoded_id);

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
#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	ret = _app2sd_dmcrypt_close_device(pkgid, uid);
	if (ret) {
		_E("close dmcrypt device error(%d)", ret);
		goto END;
	}
#else
	ret = _app2sd_remove_loopback_encryption_setup(loopback_device);
	if (ret) {
		_E("unable to Detach the loopback encryption setup" \
			" for the application");
		ret = APP2EXT_ERROR_DETACH_LOOPBACK_DEVICE;
		goto END;
	}
#endif

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

	ret = _app2sd_remove_info_from_db(pkgid, uid);
	if (ret) {
		_E("cannot remove info from db");
		ret = APP2EXT_ERROR_SQLITE_REGISTRY;
		goto END;
	}

END:
	return ret;
}

int app2sd_usr_pre_move_installed_app(const char *pkgid,
		GList *dir_list, app2ext_move_type move_type, uid_t uid)
{
	int ret = 0;
	int pkgmgr_ret = 0;

	/* validate function arguments */
	if (pkgid == NULL || dir_list == NULL
		|| move_type < APP2EXT_MOVE_TO_EXT
		|| move_type > APP2EXT_MOVE_TO_PHONE) {
		_E("invalid function arguments");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	ret = __app2sd_create_app2sd_directories(uid);
	if (ret) {
		_E("failed to create app2sd dirs");
		return ret;
	}

	ret = _app2sd_usr_move_app(pkgid, move_type, dir_list, uid);
	if (ret) {
		_D("unable to move application");
		return ret;
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

	return APP2EXT_SUCCESS;
}

int app2sd_usr_post_move_installed_app(const char *pkgid,
		app2ext_move_type move_type, uid_t uid)
{
	int ret = 0;
	char application_path[FILENAME_MAX] = { 0, };
	char loopback_device[FILENAME_MAX] = { 0, };
	char *encoded_id = NULL;

	/* validate function arguments */
	if (pkgid == NULL || move_type < APP2EXT_MOVE_TO_EXT
		|| move_type > APP2EXT_MOVE_TO_PHONE) {
		_E("invalid function arguments");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	if (move_type == APP2EXT_MOVE_TO_PHONE)
		return APP2EXT_SUCCESS;

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		_E("MMC not preset OR Not ready(%d)", ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}

	encoded_id = _app2sd_get_encoded_name(pkgid, uid);
	if (encoded_id == NULL)
		return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;

	snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
	free(encoded_id);
	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		tzplatform_reset_user();
	}

	ret = _app2sd_unmount_app_content(application_path);
	if (ret)
		_E("unmount error (%d)", ret);

#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	ret = _app2sd_dmcrypt_close_device(pkgid, uid);
	if (ret)
		_E("close dmcrypt device error(%d)", ret);
#else
	ret = _app2sd_remove_loopback_encryption_setup(loopback_device);
	if (ret)
		_E("unable to detach loopback setup for (%s)",
			loopback_device);
#endif

	sync();
	return APP2EXT_SUCCESS;
}

int app2sd_usr_pre_app_upgrade(const char *pkgid, GList *dir_list,
		int size, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;
	char loopback_device[FILENAME_MAX] = { 0, };
	char application_path[FILENAME_MAX] = { 0, };
	char temp_uid[32] = { 0, };
	char *temp_pkgid = NULL;
	char *temp_loopback_device = NULL;
	char *temp_application_path = NULL;
	char *device_node = NULL;
	char *encoded_id = NULL;
	char *temp_encoded_id = NULL;
	int len = 0;
	unsigned long long curr_size = 0;
	FILE *fp = NULL;
	int reqd_disk_size = size + ceil(size * 0.2);

	/* validate function arguments*/
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

	encoded_id = _app2sd_get_encoded_name(pkgid, uid);
	if (encoded_id == NULL)
		return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
		tzplatform_reset_user();
	}
	free(encoded_id);

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
		len = strlen(pkgid) + strlen(".new");
		temp_pkgid = calloc(len + 1, sizeof(char));
		if (temp_pkgid == NULL) {
			_E("memory alloc failed");
			return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;
		}
		snprintf(temp_pkgid, len + 1, "%s.new", pkgid);

		if (_is_global(uid)) {
			len = strlen(tzplatform_getenv(TZ_SYS_RW_APP)) + strlen(temp_pkgid) + 1;
			temp_application_path = calloc(len + 1, sizeof(char));
			if (temp_application_path == NULL) {
				_E("memory alloc failed");
				free(temp_pkgid);
				return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;
			}
			snprintf(temp_application_path, len + 1, "%s/%s",
				tzplatform_getenv(TZ_SYS_RW_APP), temp_pkgid);

			temp_encoded_id = _app2sd_get_encoded_name((const char *)temp_pkgid, uid);
			if (temp_encoded_id == NULL) {
				free(temp_pkgid);
				free(temp_application_path);
				return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;
			}
			len = strlen(APP2SD_PATH) + strlen(temp_encoded_id) + 1;
			temp_loopback_device = calloc(len + 1, sizeof(char));
			if (temp_loopback_device == NULL) {
				_E("memory alloc failed");
				free(temp_pkgid);
				free(temp_application_path);
				free(temp_encoded_id);
				return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;
			}
			snprintf(temp_loopback_device, len + 1, "%s/%s",
				APP2SD_PATH, temp_encoded_id);
			free(temp_encoded_id);
		} else {
			tzplatform_set_user(uid);
			len = strlen(tzplatform_getenv(TZ_USER_APP)) + strlen(temp_pkgid) + 1;
			temp_application_path = calloc(len + 1, sizeof(char));
			if (temp_application_path == NULL) {
				_E("memory alloc failed");
				free(temp_pkgid);
				return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;
			}
			snprintf(temp_application_path, len + 1, "%s/%s",
				tzplatform_getenv(TZ_USER_APP), temp_pkgid);

			temp_encoded_id = _app2sd_get_encoded_name((const char *)temp_pkgid, uid);
			if (temp_encoded_id == NULL) {
				free(temp_pkgid);
				free(temp_application_path);
				return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;
			}
			snprintf(temp_uid, 32, "%d", uid);
			len = strlen(APP2SD_PATH) + strlen(temp_uid) + strlen(temp_encoded_id) + 2;
			temp_loopback_device = calloc(len + 1, sizeof(char));
			if (temp_loopback_device == NULL) {
				_E("memory alloc failed");
				free(temp_pkgid);
				free(temp_application_path);
				free(temp_encoded_id);
				return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;
			}
			snprintf(temp_loopback_device, len + 1, "%s/%s",
				APP2SD_PATH, temp_encoded_id);
			free(temp_encoded_id);
			tzplatform_reset_user();
		}
		ret = _app2sd_update_loopback_device_size(pkgid,
			loopback_device, application_path, temp_pkgid,
			temp_loopback_device, temp_application_path,
			reqd_disk_size, dir_list, uid);
		free(temp_pkgid);
		free(temp_application_path);
		free(temp_loopback_device);
		if (APP2EXT_SUCCESS != ret) {
			_E("failed to update loopback device size");
			return ret;
		}
	}

	/* get the associated device node for SD card applicationer */
#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	device_node =
		_app2sd_find_associated_dmcrypt_device_node(pkgid, uid);
#else
	device_node = _app2sd_find_associated_device_node(loopback_device);
#endif
	if (NULL == device_node) {
		/* do loopback setup */
#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
		ret = _app2sd_dmcrypt_open_device(pkgid, loopback_device,
			false, uid, &device_node);
		if (ret) {
			_E("dmcrypt open device error");
			return APP2EXT_ERROR_OPEN_DMCRYPT_DEVICE;
		}
#else
		device_node = _app2sd_do_loopback_encryption_setup(pkgid,
			loopback_device, uid);
		if (device_node == NULL) {
			_E("loopback encryption setup failed");
			return APP2EXT_ERROR_DO_LOSETUP;
		}
#endif

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
	char *encoded_id = NULL;
	int ret = APP2EXT_SUCCESS;

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

	encoded_id = _app2sd_get_encoded_name(pkgid, uid);
	if (encoded_id == NULL)
		return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
		tzplatform_reset_user();
	}
	free(encoded_id);

	/* get the associated device node for SD card applicationer */
#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	device_name =
		_app2sd_find_associated_dmcrypt_device_node(pkgid, uid);
	if (!device_name) {
		_E("could not find associated dmcrypt device node" \
			" (%s_%d)", pkgid, uid);
		return APP2EXT_ERROR_FIND_ASSOCIATED_DMCRYPT_DEVICE_NODE;
	}
#else
	device_name = _app2sd_find_associated_device_node(loopback_device);
	if (NULL == device_name)
		return APP2EXT_ERROR_FIND_ASSOCIATED_DEVICE_NODE;
#endif

	ret = _app2sd_unmount_app_content(application_path);
	if (ret) {
		if (device_name) {
			free(device_name);
			device_name = NULL;
		}
		_E("unable to unmount the app content (%d)", ret);
		return APP2EXT_ERROR_UNMOUNT;
	}

#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	ret = _app2sd_dmcrypt_close_device(pkgid, uid);
	if (ret) {
		if (device_name) {
			free(device_name);
			device_name = NULL;
		}
		_E("close dmcrypt device error(%d)", ret);
		return APP2EXT_ERROR_CLOSE_DMCRYPT_DEVICE;
	}
#else
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
#endif

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
	char *encoded_id = NULL;
	int ret = APP2EXT_SUCCESS;

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		_E("invalid func parameters");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	sync();

	encoded_id = _app2sd_get_encoded_name(pkgid, uid);
	if (encoded_id == NULL)
		return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, encoded_id);
		tzplatform_reset_user();
	}
	free(encoded_id);

	ret = _app2sd_force_clean(pkgid, application_path, loopback_device, uid);

	return ret;
}

int app2sd_enable_full_pkg(void)
{
	int ret = APP2EXT_SUCCESS;
	int rc = 0;
	char buf[FILENAME_MAX] = { 0, };
	char loopback_device[FILENAME_MAX] = { 0, };
	DIR *dir = NULL;
	struct dirent entry;
	struct dirent *result = NULL;
	char *pkgid = NULL;
	uid_t uid = 0;

	dir = opendir(APP2SD_PATH);
	if (!dir) {
		strerror_r(errno, buf, sizeof(buf));
		_E("failed to opendir (%s)", buf);
		return APP2EXT_ERROR_OPEN_DIR;
	}

	ret = _app2sd_initialize_db();
	if (ret) {
		_E("app2sd db initialize failed");
		closedir(dir);
		return APP2EXT_ERROR_SQLITE_REGISTRY;
	}

	for (rc = readdir_r(dir, &entry, &result);
		rc == 0 && result != NULL;
		rc = readdir_r(dir, &entry, &result)) {
		if (strcmp(entry.d_name, ".") == 0 ||
			strcmp(entry.d_name, "..") == 0)
			continue;
		snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s",
			APP2SD_PATH, entry.d_name);
		ret = _app2sd_get_info_from_db(loopback_device,
			&pkgid, &uid);
		if (ret) {
			_E("failed to get info from db");
			break;;
		}
		if (pkgid) {
			_D("pkgid(%s), uid(%d)", pkgid, uid);
			ret = app2sd_usr_on_demand_setup_init(pkgid, uid);
			if (ret) {
				_E("error(%d)", ret);
				break;
			}
			free(pkgid);
			pkgid = NULL;
		}
	}

	if (pkgid) {
		free(pkgid);
		pkgid = NULL;
	}
	closedir(dir);

	return ret;
}

static int _app2sd_info_cb_func(const char *pkgid, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;

	if (pkgid) {
		_D("pkgid(%s), uid(%d)", pkgid, uid);
		ret = app2sd_usr_on_demand_setup_exit(pkgid, uid);
		if (ret)
			_E("error(%d)", ret);
	}

	return ret;
}

int app2sd_disable_full_pkg(void)
{
	int ret = APP2EXT_SUCCESS;

	ret = _app2sd_initialize_db();
	if (ret) {
		_E("app2sd db initialize failed");
		return APP2EXT_ERROR_SQLITE_REGISTRY;
	}

	ret = _app2sd_get_foreach_info_from_db((app2sd_info_cb)_app2sd_info_cb_func);
	if (ret)
		_E("disable full pkg error(%d)", ret);

	return ret;
}
