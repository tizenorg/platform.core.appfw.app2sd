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
#include <vconf.h>

/* For multi-user support */
#include <tzplatform_config.h>

#define MAX_BUF_LEN	1024
#define APP2SD_TMP_PATH tzplatform_mkpath(TZ_USER_APP, "tmp")

int app2sd_pre_app_install(const char *pkgid, GList* dir_list,
				int size)
{
	int ret = 0;
	int free_mmc_mem = 0;
	char *device_node = NULL;
	char *devi = NULL;
	char *result = NULL;

	/*Validate the function parameter recieved */
	if (pkgid == NULL || dir_list == NULL || size <= 0) {
		app2ext_print("App2Sd Error : Invalid function arguments\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}
	/*Check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR Not ready %d\n",
			ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}
	/*Find available free memory in the MMC card */
	ret = _app2sd_get_available_free_memory(MMC_PATH,
						&free_mmc_mem);
	if (ret) {
		app2ext_print("App2Sd Error : Unable to get available free memory in MMC %d\n", ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}
	/*If avaialalbe free memory in MMC is less than required size + 5MB , return error */
	if ((size + PKG_BUF_SIZE + MEM_BUF_SIZE) > free_mmc_mem) {
		app2ext_print("Insufficient memory in MMC for application installation %d\n", ret);
		return APP2EXT_ERROR_MMC_INSUFFICIENT_MEMORY;
	}
	/*Create a loopback device */
	ret = _app2sd_create_loopback_device(pkgid, (size+PKG_BUF_SIZE));
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
	/*Perform Loopback encryption setup */
	device_node = _app2sd_do_loopback_encryption_setup(pkgid);
	if (!device_node) {
		app2ext_print("App2Sd Error : Loopback encryption setup failed\n");
		_app2sd_delete_loopback_device(pkgid);
		return APP2EXT_ERROR_DO_LOSETUP;
	}
	/*Check whether loopback device is associated with device node or not */
	devi = _app2sd_find_associated_device_node(pkgid);
	if (devi == NULL) {
		app2ext_print("App2Sd Error : finding associated device node failed\n");
		ret = APP2EXT_ERROR_DO_LOSETUP;
		goto FINISH_OFF;
	}

	/*Format the loopback file system */
	ret = _app2sd_create_file_system(device_node);
	if (ret) {
		app2ext_print("App2Sd Error : creating FS failed failed\n");
		ret = APP2EXT_ERROR_CREATE_FS;
		goto FINISH_OFF;
	}

	/*Mount the loopback encrypted pseudo device on application installation path as with Read Write permission */
	ret =_app2sd_mount_app_content(pkgid, device_node, MOUNT_TYPE_RW,
					dir_list, APP2SD_PRE_INSTALL);
	if (ret) {
		app2ext_print("App2Sd Error : mounting dev path to app install path failed\n");
		ret = APP2EXT_ERROR_MOUNT_PATH;
		goto FINISH_OFF;
	}

	/*Success */
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

int app2sd_post_app_install(const char *pkgid,
			app2ext_status install_status)
{
	char *device_name = NULL;
	char buf_dir[FILENAME_MAX] = { 0, };
	int ret = APP2EXT_SUCCESS;
	/*Validate the function parameter recieved */
	if (pkgid == NULL || install_status < APP2EXT_STATUS_FAILED
		|| install_status > APP2EXT_STATUS_SUCCESS) {
		app2ext_print("Invalid func parameters\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/*Check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR Not ready %d\n",
			     ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}
	sync();	//2
	/*Get the associated device node for SD card applicationer */
	device_name = _app2sd_find_associated_device_node(pkgid);
	if (NULL == device_name) {
		return APP2EXT_ERROR_FIND_ASSOCIATED_DEVICE_NODE;
	}
	ret = _app2sd_unmount_app_content(pkgid);
	if (ret) {
		if (device_name) {
			free(device_name);
			device_name = NULL;
		}
		app2ext_print("Unable to unmount the app content %d\n", ret);
		return APP2EXT_ERROR_UNMOUNT;
	}
	ret = _app2sd_remove_loopback_encryption_setup(pkgid);
	if (ret) {
		if (device_name) {
			free(device_name);
			device_name = NULL;
		}
		app2ext_print
		    ("Unable to Detach the loopback encryption setup for the application");
		return APP2EXT_ERROR_UNMOUNT;
	}
	if (device_name) {
		free(device_name);
		device_name = NULL;
	}

	/*Take appropriate action based on installation
	status of application package */
	if (install_status == APP2EXT_STATUS_FAILED) {
		/*Delete the loopback device from the SD card */
		ret = _app2sd_delete_loopback_device(pkgid);
		if (ret) {
			app2ext_print
			    ("App2Sd Error : Unable to delete the loopback device from the SD Card\n");
			return APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
		}
		ret = _app2sd_remove_password_from_db(pkgid);

		if (ret) {
			app2ext_print
			    ("App2Sd Error : Unable to delete the password\n");
		}

		snprintf(buf_dir, FILENAME_MAX, "%s%s", APP_INSTALLATION_PATH, pkgid);

		ret = _app2sd_delete_directory(buf_dir);

		if (ret) {
			app2ext_print
			    ("App2Sd Error : Unable to delete the directory %s\n",
			     buf_dir);
		}

	} else {
		/*If  the status is success, then update installed storage to pkgmgr_parser db*/
		int rt = 0;
		pkgmgrinfo_pkgdbinfo_h handle = NULL;
		rt = pkgmgrinfo_create_pkgdbinfo(pkgid, &handle);
		if (rt < 0) {
			app2ext_print("pkgmgrinfo_create_pkgdbinfo[%s] fail.. \n", pkgid);
		}
		rt = pkgmgrinfo_set_installed_storage_to_pkgdbinfo(handle, INSTALL_EXTERNAL);
		if (rt < 0) {
			app2ext_print("fail to update installed location to db[%s, %s]\n", pkgid, INSTALL_EXTERNAL);
		}
		rt =pkgmgrinfo_save_pkgdbinfo(handle);
		if (rt < 0) {
			app2ext_print("pkgmgrinfo_save_pkgdbinfo[%s] failed\n", pkgid);
		}
		rt =pkgmgrinfo_destroy_pkgdbinfo(handle);
		if (rt < 0) {
			app2ext_print("pkgmgrinfo_destroy_pkgdbinfo[%s] failed\n", pkgid);
		}
	}
	return ret;
}

int app2sd_on_demand_setup_init(const char *pkgid)
{
	int ret = APP2EXT_SUCCESS;
	char app_path[FILENAME_MAX] = { 0, };
	char *device_node = NULL;
	char *result = NULL;
	FILE *fp = NULL;

	/*Validate the function parameter recieved */
	if (pkgid == NULL) {
		app2ext_print
		    ("App2Sd Error : Invalid function arguments to app launch setup\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/*Check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR Not ready %d\n",
			     ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}

	/*check app entry is there in sd card or not. */
	snprintf(app_path, FILENAME_MAX, "%s%s", APP2SD_PATH,
		 pkgid);
	fp = fopen(app_path, "r+");
	if (fp == NULL) {
		app2ext_print
		    ("App2SD Error: App Entry is not present in SD Card\n");
		return APP2EXT_ERROR_INVALID_PACKAGE;
	}
	fclose(fp);
	result = (char *)_app2sd_find_associated_device(app_path);
	/*process the string */
	if ((result!=NULL) && strstr(result, "/dev") != NULL) {
		app2ext_print("App2SD Error! Already associated\n");
		free(result);
		result = NULL;
		return APP2EXT_ERROR_ALREADY_MOUNTED;
	}

	/*Do loopback setup */
	device_node = _app2sd_do_loopback_encryption_setup(pkgid);
	if (device_node == NULL) {
		app2ext_print
		    ("App2Sd Error : loopback encryption setup failed\n");
		return APP2EXT_ERROR_DO_LOSETUP;
	}

	/*Do  mounting */
	ret =
	    _app2sd_mount_app_content(pkgid, device_node, MOUNT_TYPE_RD,
				NULL, APP2SD_APP_LAUNCH);
	if (ret) {
		app2ext_print("App2Sd Error : Re-mount failed\n");
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

int app2sd_on_demand_setup_exit(const char *pkgid)
{
	int ret = APP2EXT_SUCCESS;
	char app_path[FILENAME_MAX] = { 0, };
	FILE *fp = NULL;

	/*Validate the function parameter recieved */
	if (pkgid == NULL) {
		app2ext_print
		    ("App2Sd Error : Invalid function arguments to app launch setup\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/*Check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR Not ready %d\n",
			     ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}
	/*check app entry is there in sd card or not. */
	snprintf(app_path, FILENAME_MAX, "%s%s", APP2SD_PATH,
		 pkgid);
	fp = fopen(app_path, "r+");
	if (fp == NULL) {
		app2ext_print
		    ("App2SD Error: App Entry is not present in SD Card\n");
		return APP2EXT_ERROR_INVALID_PACKAGE;
	}
	fclose(fp);
	ret = _app2sd_unmount_app_content(pkgid);
	if (ret) {
		app2ext_print
		    ("App2SD Error: Unable to unmount the SD application\n");
		return APP2EXT_ERROR_UNMOUNT;
	}
	ret = _app2sd_remove_loopback_encryption_setup(pkgid);
	if (ret) {
		app2ext_print("App2SD Error: Unable to remove loopback setup\n");
		return APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
	}
	return ret;
}

int app2sd_pre_app_uninstall(const char *pkgid)
{
	int ret = APP2EXT_SUCCESS;
	char app_path[FILENAME_MAX] = { 0, };
	char *device_node = NULL;
	FILE*fp = NULL;

	/*Validate the function parameter recieved */
	if (pkgid == NULL) {
		app2ext_print
		    ("App2Sd Error : Invalid function arguments to app launch setup\n");
		ret = APP2EXT_ERROR_INVALID_ARGUMENTS;
		goto END;
	}
	/*Check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR Not ready %d\n",
			     ret);
		ret = APP2EXT_ERROR_MMC_STATUS;
		goto END;
	}
	/*check app entry is there in sd card or not. */
	snprintf(app_path, FILENAME_MAX, "%s%s", APP2SD_PATH, pkgid);
	fp = fopen(app_path, "r+");
	if (fp == NULL) {
		app2ext_print
		    ("App2SD Error: App Entry is not present in SD Card\n");
		ret = APP2EXT_ERROR_INVALID_PACKAGE;
		goto END;
	}
	fclose(fp);

	/*Get the associated device node for SD card applicationer */
	device_node = _app2sd_find_associated_device_node(pkgid);
	if (NULL == device_node) {
		/*Do loopback setup */
		device_node = _app2sd_do_loopback_encryption_setup(pkgid);

		if (device_node == NULL) {
			app2ext_print
			    ("App2Sd Error : loopback encryption setup failed\n");
			ret = APP2EXT_ERROR_DO_LOSETUP;
			goto END;
		}
		/*Do  mounting */
		ret =
		    _app2sd_mount_app_content(pkgid, device_node,
					MOUNT_TYPE_RW, NULL,
					APP2SD_PRE_UNINSTALL);

		if (ret) {
			app2ext_print("App2Sd Error : RW-mount failed\n");
			if (device_node) {
				free(device_node);
				device_node = NULL;
			}
			ret = APP2EXT_ERROR_MOUNT_PATH;
			goto END;
		}
	} else {
		/*Do  re-mounting */
		ret =
		    _app2sd_mount_app_content(pkgid, device_node,
					MOUNT_TYPE_RW_REMOUNT, NULL,
					APP2SD_PRE_UNINSTALL);

		if (ret) {
			app2ext_print("App2Sd Error : Re-mount failed\n");
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
	if (ret != APP2EXT_SUCCESS)
		app2ext_print("App2Sd Error : app2sd has [%d]error, but return success for uninstallation\n", ret);
	return APP2EXT_SUCCESS;
}

/*
* app2sd_post_app_uninstall_setup
* Uninstall Application and free all the allocated resources
* Called after dpkg remove, It deallocates dev node and loopback
*/
int app2sd_post_app_uninstall(const char *pkgid)
{
	char buf_dir[FILENAME_MAX] = { 0, };
	int ret = APP2EXT_SUCCESS;
	int ret1 = APP2EXT_SUCCESS;
	/*Validate the function parameter recieved */
	if (pkgid == NULL) {
		app2ext_print
		    ("App2Sd Error : Invalid function arguments to Post Uninstall\n");
		ret = APP2EXT_ERROR_INVALID_ARGUMENTS;
		goto END;
	}
	/*Check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR Not ready %d\n",
			     ret);
		ret = APP2EXT_ERROR_MMC_STATUS;
		goto END;
	}
	/*Unmount the loopback encrypted pseudo device from the application installation path */
	ret = _app2sd_unmount_app_content(pkgid);
	if (ret) {
		app2ext_print("Unable to unmount the app content %d\n", ret);
		ret = APP2EXT_ERROR_UNMOUNT;
		goto END;
	}
	/*Detach the loopback encryption setup for the application */
	ret = _app2sd_remove_loopback_encryption_setup(pkgid);
	if (ret) {
		app2ext_print
		    ("Unable to Detach the loopback encryption setup for the application");
		ret = APP2EXT_ERROR_DETACH_LOOPBACK_DEVICE;
		goto END;
	}
	/*Delete the loopback device from the SD card */
	ret = _app2sd_delete_loopback_device(pkgid);
	if (ret) {
		app2ext_print
		    ("App2Sd Error : Unable to delete the loopback device from the SD Card\n");
		ret =  APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
		goto END;
	}
	memset((void *)&buf_dir, '\0', FILENAME_MAX);
	snprintf(buf_dir, FILENAME_MAX, "%s%s", APP_INSTALLATION_PATH, pkgid);
	ret1 = _app2sd_delete_directory(buf_dir);
	if (ret1) {
		app2ext_print
		    ("App2Sd Error : Unable to delete the directory %s\n",
		     buf_dir);
	}
	/*remove encryption password from DB */
	ret = _app2sd_initialize_db();
	if (ret) {
		app2ext_print("\n app2sd db initialize failed");
		ret = APP2EXT_ERROR_SQLITE_REGISTRY;
		goto END;
	}
	ret = _app2sd_remove_password_from_db(pkgid);
	if (ret) {
		app2ext_print("cannot remove password from db \n");
		ret = APP2EXT_ERROR_SQLITE_REGISTRY;
		goto END;
	}

END:
	if (ret != APP2EXT_SUCCESS)
		app2ext_print("App2Sd Error : app2sd has [%d]error, but return success for uninstallation\n", ret);
	return APP2EXT_SUCCESS;
}

int app2sd_move_installed_app(const char *pkgid, GList* dir_list,
			app2ext_move_type move_type)
{
	int ret = 0;
	int pkgmgrinfo_ret = 0;

	/*Validate function arguments*/
	if (pkgid == NULL || dir_list == NULL
		|| move_type < APP2EXT_MOVE_TO_EXT
		|| move_type > APP2EXT_MOVE_TO_PHONE) {
		app2ext_print("App2Sd Error : Invalid function arguments\n");
		ret = APP2EXT_ERROR_INVALID_ARGUMENTS;
		goto END;
	}

	/*If  move is completed, then update installed storage to pkgmgr_parser db*/
	pkgmgrinfo_pkginfo_h info_handle = NULL;
	pkgmgrinfo_installed_storage storage = PMINFO_INTERNAL_STORAGE;
	pkgmgrinfo_ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &info_handle);
	if (pkgmgrinfo_ret < 0) {
		app2ext_print("App2Sd Error : pkgmgrinfo_pkginfo_get_pkginfo[%s] fail.. \n", pkgid);
	}
	pkgmgrinfo_ret = pkgmgrinfo_pkginfo_get_installed_storage(info_handle, &storage);
	if (pkgmgrinfo_ret < 0) {
		app2ext_print("App2Sd Error : pkgmgrinfo_pkginfo_get_installed_storage[%s] fail.. \n", pkgid);
	}

	if ((move_type == APP2EXT_MOVE_TO_EXT && storage == PMINFO_EXTERNAL_STORAGE)
		|| (move_type == APP2EXT_MOVE_TO_PHONE && storage == PMINFO_INTERNAL_STORAGE)) {
			ret = APP2EXT_ERROR_PKG_EXISTS;
			app2ext_print("App2Sd Error : PKG_EXISTS in [%d]STORAGE\n", storage);
			pkgmgrinfo_pkginfo_destroy_pkginfo(info_handle);
			goto END;
	} else {
		app2ext_print("App2Sd info : STORAGE Move[%d] is success\n", storage);
	}
	pkgmgrinfo_pkginfo_destroy_pkginfo(info_handle);

	ret = _app2sd_move_app(pkgid, move_type, dir_list);
	if (ret) {
		app2ext_print("App2Sd Error : Unable to move application\n");
		goto END;
	}

	/*If  move is completed, then update installed storage to pkgmgr_parser db*/
	pkgmgrinfo_pkgdbinfo_h handle = NULL;
	pkgmgrinfo_ret = pkgmgrinfo_create_pkgdbinfo(pkgid, &handle);
	if (pkgmgrinfo_ret < 0) {
		app2ext_print("App2Sd Error : pkgmgrinfo_create_pkgdbinfo[%s] fail.. \n", pkgid);
	}

	if (move_type == APP2EXT_MOVE_TO_EXT) {
		pkgmgrinfo_ret = pkgmgrinfo_set_installed_storage_to_pkgdbinfo(handle, INSTALL_EXTERNAL);
		if (pkgmgrinfo_ret < 0) {
			app2ext_print("App2Sd Error : fail to update installed location to db[%s, %s]\n", pkgid, INSTALL_EXTERNAL);
		}
	} else {
		pkgmgrinfo_ret = pkgmgrinfo_set_installed_storage_to_pkgdbinfo(handle, INSTALL_INTERNAL);
		if (pkgmgrinfo_ret < 0) {
			app2ext_print("App2Sd Error : fail to update installed location to db[%s, %s]\n", pkgid, INSTALL_INTERNAL);
		}
	}
	pkgmgrinfo_ret =pkgmgrinfo_save_pkgdbinfo(handle);
	if (pkgmgrinfo_ret < 0) {
		app2ext_print("pkgmgrinfo_save_pkgdbinfo[%s] failed\n", pkgid);
	}
	pkgmgrinfo_ret =pkgmgrinfo_destroy_pkgdbinfo(handle);
	if (pkgmgrinfo_ret < 0) {
		app2ext_print("pkgmgrinfo_destroy_pkgdbinfo failed\n");
	}

END:

	vconf_set_int(VCONFKEY_PKGMGR_STATUS, ret);

	return ret;
}

int app2sd_pre_app_upgrade(const char *pkgid, GList* dir_list,
			int size)
{
	int ret = APP2EXT_SUCCESS;
	char app_path[FILENAME_MAX] = { 0, };
	char *device_node = NULL;
	unsigned long long curr_size = 0;
	FILE *fp = NULL;

	/*Validate function arguments*/
	if (pkgid == NULL || dir_list == NULL || size<=0) {
		app2ext_print
		    ("App2Sd Error : Invalid function arguments \n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}
	/*Check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR Not ready %d\n",
			     ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}
	/*check app entry is there in sd card or not. */
	snprintf(app_path, FILENAME_MAX, "%s%s", APP2SD_PATH,
		 pkgid);
	app2ext_print("App2Sd Log : Checking path %s\n", app_path);
	fp = fopen(app_path, "r+");
	if (fp == NULL) {
		app2ext_print
		    ("App2SD Error: App Entry is not present in SD Card\n");
		return APP2EXT_ERROR_INVALID_PACKAGE;
	}
	fclose(fp);
	/*Get installed app size*/
	curr_size = _app2sd_calculate_file_size(app_path);
	curr_size = (curr_size/1024)/1024;

	if (curr_size==0) {
		app2ext_print
		    ("App2SD Error: App Entry is not present in SD Card\n");
		return APP2EXT_ERROR_LOOPBACK_DEVICE_UNAVAILABLE;
	}
	if (curr_size<size) {
		ret = _app2sd_update_loopback_device_size(pkgid, size, dir_list);
		if(APP2EXT_SUCCESS !=ret) {
			app2ext_print
			    ("App2SD Error: _app2sd_update_loopback_device_size() failed\n");
			return ret;
		}
	}

	/*Get the associated device node for SD card applicationer */
	device_node = _app2sd_find_associated_device_node(pkgid);
	if (NULL == device_node) {
		/*Do loopback setup */
		device_node = _app2sd_do_loopback_encryption_setup(pkgid);
		if (device_node == NULL) {
			app2ext_print
			    ("App2Sd Error : loopback encryption setup failed\n");
			return APP2EXT_ERROR_DO_LOSETUP;
		}
		/*Do  mounting */
		ret =
		    _app2sd_mount_app_content(pkgid, device_node,
					MOUNT_TYPE_RW, NULL,
					APP2SD_PRE_UPGRADE);
		if (ret) {
			app2ext_print("App2Sd Error : Re-mount failed\n");
			if (device_node) {
				free(device_node);
				device_node = NULL;
			}
			return APP2EXT_ERROR_MOUNT_PATH;
		}
	} else {
		/*Do  re-mounting */
		ret =
		    _app2sd_mount_app_content(pkgid, device_node,
					      MOUNT_TYPE_RW_REMOUNT, NULL,
					      APP2SD_PRE_UPGRADE);
		if (ret) {
			app2ext_print("App2Sd Error : Re-mount failed\n");
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


int app2sd_post_app_upgrade(const char *pkgid,
			app2ext_status install_status)
{
	char *device_name = NULL;
	int ret = APP2EXT_SUCCESS;
	/*Validate the function parameter recieved */
	if (pkgid == NULL || install_status < APP2EXT_STATUS_FAILED
		|| install_status > APP2EXT_STATUS_SUCCESS) {
		app2ext_print("Invalid func parameters\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}
	/*Check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR Not ready %d\n",
			     ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}

	/*Get the associated device node for SD card applicationer */
	device_name = _app2sd_find_associated_device_node(pkgid);
	if (NULL == device_name) {
		return APP2EXT_ERROR_FIND_ASSOCIATED_DEVICE_NODE;
	}
	ret = _app2sd_unmount_app_content(pkgid);
	if (ret) {
		if (device_name) {
			free(device_name);
			device_name = NULL;
		}
		app2ext_print("Unable to unmount the app content %d\n", ret);
		return APP2EXT_ERROR_UNMOUNT;
	}
	ret = _app2sd_remove_loopback_encryption_setup(pkgid);
	if (ret) {
		if (device_name) {
			free(device_name);
			device_name = NULL;
		}
		app2ext_print
		    ("Unable to Detach the loopback encryption setup for the application");
		return APP2EXT_ERROR_UNMOUNT;
	}
	if (device_name) {
		free(device_name);
		device_name = NULL;
	}
	return ret;
}

#if 0
/**
 * Reserved API for forced cleanup
 *
 */
int app2sd_force_cleanup(const char *pkgid){
	char *device_name = NULL;
	char buf_dir[FILENAME_MAX] = { 0, };
	int ret = APP2EXT_SUCCESS;
	FILE *fp = NULL;

	/*Validate the function parameter recieved */
	if (pkgid == NULL) {
		app2ext_print("invalid func parameters\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}
	memset((void *)&buf_dir, '\0', FILENAME_MAX);
	snprintf(buf_dir, FILENAME_MAX, "%s%s", APP2SD_PATH, pkgid);
	fp = fopen(buf_dir, "r+");
	if (fp == NULL) {
		app2ext_print("\"%s\" not installed on SD Card\n", pkgid);
		return APP2EXT_ERROR_INVALID_PACKAGE;
	}
	fclose(fp);
	/*Check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR Not ready %d\n",
			     ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}

	/*Get the associated device node for SD card applicationer */
	device_name = _app2sd_find_associated_device_node(pkgid);
	if (NULL != device_name) {
		free(device_name);
		device_name = NULL;
		ret = _app2sd_unmount_app_content(pkgid);
		if (ret) {
			app2ext_print("Unable to unmount the app content %d\n", ret);
			return APP2EXT_ERROR_UNMOUNT;
		}
		ret = _app2sd_remove_loopback_encryption_setup(pkgid);
		if (ret) {
			app2ext_print
			    ("Unable to Detach the loopback encryption setup for the application");
			return APP2EXT_ERROR_UNMOUNT;
		}
	}

	memset((void *)&buf_dir, '\0', FILENAME_MAX);
	snprintf(buf_dir, FILENAME_MAX, "%s%s", APP_INSTALLATION_PATH, pkgid);
	ret = _app2sd_delete_directory(buf_dir);
	if (ret) {
		app2ext_print
		    ("App2Sd Error : Unable to delete the directory %s\n",
		     buf_dir);
	}

	/*remove passwrd from DB*/
	ret = _app2sd_initialize_db();
	if (ret) {
		app2ext_print("\n app2sd db initialize failed");
		return APP2EXT_ERROR_SQLITE_REGISTRY;
	}
	ret = _app2sd_remove_password_from_db(pkgid);
	if (ret) {
		app2ext_print("cannot remove password from db \n");
		return APP2EXT_ERROR_SQLITE_REGISTRY;
	}
	return ret;
}
#endif

/* This is the plug-in load function. The plugin has to bind its functions to function pointers of handle
	@param[in/out]		st_interface 	Specifies the storage interface.
*/
void
app2ext_on_load(app2ext_interface *st_interface)
{
	/*Plug-in Binding.*/
	st_interface->pre_install= app2sd_pre_app_install;
	st_interface->post_install= app2sd_post_app_install;
	st_interface->pre_uninstall= app2sd_pre_app_uninstall;
	st_interface->post_uninstall= app2sd_post_app_uninstall;
	st_interface->pre_upgrade= app2sd_pre_app_upgrade;
	st_interface->post_upgrade= app2sd_post_app_upgrade;
	st_interface->move= app2sd_move_installed_app;
	st_interface->enable= app2sd_on_demand_setup_init;
	st_interface->disable= app2sd_on_demand_setup_exit;
}

