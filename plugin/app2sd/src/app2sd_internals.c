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

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <time.h>
#include <dlog.h>

/*
########### Internal APIs ##################
 */
enum path_type {
	PATH_PRIVATE,
	PATH_GROUP_RW,
	PATH_PUBLIC_RO,
	PATH_SETTINGS_RW,
	PATH_ANY_LABEL
};

static int _app2sd_apply_app_smack(const char *pkgid, GList* dir_list, const char *groupid)
{
	int ret = APP2EXT_SUCCESS;
	GList *list = NULL;
	app2ext_dir_details* dir_detail = NULL;
	char path[FILENAME_MAX] = { 0, };

	list = g_list_first(dir_list);
	while (list) {
		dir_detail = (app2ext_dir_details *)list->data;
		if (dir_detail && dir_detail->name
			&& dir_detail->type == APP2EXT_DIR_RO) {
			snprintf(path, FILENAME_MAX, "%s%s/%s",APP_INSTALLATION_PATH, pkgid, dir_detail->name);
			ret = _app2sd_setup_path(pkgid, path, PATH_ANY_LABEL, groupid);
			if (ret) {
				app2ext_print ("App2Sd Error : unable to smack %s\n", path);
				return APP2EXT_ERROR_MOVE;
			}
		}
		list = g_list_next(list);
	}

	return APP2EXT_SUCCESS;
}

static int _app2sd_apply_mmc_smack(const char *pkgid, GList* dir_list, const char *groupid)
{
	int ret = APP2EXT_SUCCESS;
	GList *list = NULL;
	app2ext_dir_details* dir_detail = NULL;
	char path[FILENAME_MAX] = { 0, };

	list = g_list_first(dir_list);
	while (list) {
		dir_detail = (app2ext_dir_details *)list->data;
		if (dir_detail && dir_detail->name
			&& dir_detail->type == APP2EXT_DIR_RO) {
			snprintf(path, FILENAME_MAX, "%s%s/.mmc/%s",APP_INSTALLATION_PATH, pkgid, dir_detail->name);

			ret = _app2sd_setup_path(pkgid, path, PATH_ANY_LABEL, groupid);
			if (ret) {
				app2ext_print ("App2Sd Error : unable to smack %s\n", path);
				return APP2EXT_ERROR_MOVE;
			}
		}
		list = g_list_next(list);
	}

	return APP2EXT_SUCCESS;
}

char *_app2sd_find_associated_device_node(const char *pkgid)
{
	char *ret_result = NULL;
	char delims[] = ":";
	char *result = NULL;
	char app_path[FILENAME_MAX] = { '\0' };
	char dev[FILENAME_MAX] = {0,};
	char *devnode = NULL;
	snprintf(app_path, FILENAME_MAX, "%s%s", APP2SD_PATH,
		 pkgid);
	result = (char *)_app2sd_find_associated_device(app_path);
	if (result == NULL) {
		app2ext_print
		    ("App2SD Error! Unable to find the associated File\n");
		return NULL;
	}
	/*process the string*/
	snprintf(dev, FILENAME_MAX-1, "%s", result);
	if (strstr(dev, "/dev") == NULL) {
		app2ext_print
		    ("App2SD Error! Unable to find the associated File\n");

		free(result);
		return NULL;
	} else {
		ret_result = strtok(dev, delims);
		if (ret_result)
			devnode = strdup(ret_result);
	}
	free(result);
	return devnode;
}

char *_app2sd_create_loopdevice_node(void)
{
	char *ret_result = NULL;
	mode_t mode = DIR_PERMS;
	int count = 0;
	int ret = APP2EXT_SUCCESS;
	char *result = NULL;
	FILE *fp = NULL;

	result = (char *)_app2sd_find_free_device();
	/*validate the result */
	if (result == NULL || strstr(result, "/dev") == NULL) {
		app2ext_print("No device found, creating device node...\n");

		if (result) {
			free(result);
			result = NULL;
		}
		count = 0;
		char dev_path[BUF_SIZE] = { 0, };
		snprintf(dev_path, BUF_SIZE, "/dev/loop%d", count);
		while ((fp = fopen(dev_path, "r+")) != NULL) {
			count = count + 1;
			snprintf(dev_path, BUF_SIZE, "/dev/loop%d", count);
			app2ext_print("next dev path for checking is %s\n",
				     dev_path);
			fclose(fp);
		}
		app2ext_print("Device node candidate is %s \n", dev_path);
		dev_t dev_node;
		dev_node = makedev(DEV_MAJOR, count);
		ret = mknod(dev_path, S_IFBLK | mode, dev_node);
		if (ret < 0) {
			app2ext_print
			    ("Error while creating the device node: errno is %d\n",
			     errno);
			return NULL;
		}
		ret_result = (char *)malloc(strlen(dev_path) + 1);
		if (ret_result == NULL) {
			app2ext_print("Unable to allocate memory\n");
			return NULL;
		}
		memset(ret_result, '\0', strlen(dev_path) + 1);
		memcpy(ret_result, dev_path, strlen(dev_path));
	} else {
		ret_result = (char *)malloc(strlen(result) + 1);
		if (ret_result == NULL) {
			app2ext_print("Malloc failed!\n");
			free(result);
			result = NULL;
			return NULL;
		}
		memset(ret_result, '\0', strlen(result) + 1);
		if (strlen(result) > 0) {
			memcpy(ret_result, result, strlen(result) - 1);
		}
		free(result);
		result = NULL;

	}
	return ret_result;
}

char *_app2sd_do_loopback_encryption_setup(const char *pkgid)
{
	int ret = APP2EXT_SUCCESS;
	char *passwd = NULL;
	char app_path[FILENAME_MAX] = { '\0' };
	char *result = NULL;
	char *device_node = NULL;
	if (pkgid == NULL) {
		app2ext_print("App2Sd Error: Invalid argument\n");
		return NULL;
	}

	snprintf(app_path, FILENAME_MAX, "%s%s", APP2SD_PATH,
		 pkgid);
	/* Get password for loopback encryption */
	ret = _app2sd_initialize_db();
	if (ret) {
		app2ext_print("\n app2sd db initialize failed");
		return NULL;
	}
	if ((passwd = _app2sd_get_password_from_db(pkgid)) == NULL) {
		passwd = (char *)_app2sd_generate_password(pkgid);
		if (NULL == passwd) {
			app2ext_print
			    ("App2Sd Error: Unable to generate password\n");
			return NULL;
		} else {
			app2ext_print("Password is %s\n", passwd);
			if ((ret = _app2sd_set_password_in_db(pkgid,
					passwd)) < 0) {
				app2ext_print
				("App2Sd Error: Unable to save password\n");
				free(passwd);
				passwd = NULL;
				return NULL;
			}
		}
	}

	/*Get Free device node*/
	device_node = _app2sd_create_loopdevice_node();
	if (NULL == device_node) {
		free(passwd);
		passwd = NULL;
		app2ext_print
		    ("App2Sd Error: Unable to find free loopback node\n");
		return NULL;
	}
	result = (char *)_app2sd_encrypt_device(device_node, app_path, passwd);
	if (result == NULL) {
		app2ext_print("App2Sd Error: Encryption failed!\n\n");
		free(passwd);
		passwd = NULL;
		return NULL;
	} else {
		free(result);
		result = NULL;
		free(passwd);
		passwd = NULL;
		return device_node;
	}
}

char *_app2sd_do_loopback_duplicate_encryption_setup(const char *pkgid, const char * dup_appname)
{
	int ret = APP2EXT_SUCCESS;
	char *passwd = NULL;
	char app_path[FILENAME_MAX] = { '\0' };
	char *result = NULL;
	char *device_node = NULL;
	if (pkgid == NULL || dup_appname == NULL) {
		app2ext_print("App2Sd Error: Invalid argument\n");
		return NULL;
	}

	snprintf(app_path, FILENAME_MAX, "%s%s", APP2SD_PATH,
		 dup_appname);
	/* Get password for loopback encryption */
	ret = _app2sd_initialize_db();
	if (ret) {
		app2ext_print("\n app2sd db initialize failed");
		return NULL;
	}
	if ((passwd = _app2sd_get_password_from_db(pkgid)) == NULL) {
		passwd = (char *)_app2sd_generate_password(pkgid);
		if (NULL == passwd) {
			app2ext_print
			    ("App2Sd Error: Unable to generate password\n");
			return NULL;
		} else {
			app2ext_print("Password is %s\n", passwd);
			if ((ret = _app2sd_set_password_in_db(pkgid,
					passwd)) < 0) {
				app2ext_print
				("App2Sd Error: Unable to save password\n");
				free(passwd);
				passwd = NULL;
				return NULL;
			}
		}

	}
	/*Get Free device node*/
	device_node = _app2sd_create_loopdevice_node();
	if (NULL == device_node) {
		free(passwd);
		passwd = NULL;
		app2ext_print
		    ("App2Sd Error: Unable to find free loopback node\n");
		return NULL;
	}
	result = (char *)_app2sd_encrypt_device(device_node, app_path, passwd);
	if (result == NULL) {
		app2ext_print("App2Sd Error: Encryption failed!\n\n");
		free(passwd);
		passwd = NULL;
		return NULL;
	} else {
		if (strlen(result) == 0) {
			free(result);
			result = NULL;
			free(passwd);
			passwd = NULL;
			return device_node;
		} else {
			app2ext_print("App2Sd Error: Error is %s\n", result);
			free(result);
			result = NULL;
			free(passwd);
			passwd = NULL;
			return NULL;
		}
	}
	return device_node;
}

int _app2sd_remove_loopback_encryption_setup(const char *pkgid)
{
	int ret = APP2EXT_SUCCESS;
	char *result = NULL;
	char *dev_node = NULL;
	if ((dev_node = _app2sd_find_associated_device_node(pkgid)) == NULL) {
		app2ext_print("Unable to find the association\n");
		ret = APP2EXT_ERROR_FIND_ASSOCIATED_DEVICE_NODE;
	}
	result = (char *)_app2sd_detach_loop_device(dev_node);
	if (result == NULL) {
		app2ext_print("App2sd Error: Error in detaching\n");
		ret = APP2EXT_ERROR_DETACH_LOOPBACK_DEVICE;
	} else {
		free(result);
		result = NULL;
	}
	if (dev_node) {
		free(dev_node);
		dev_node = NULL;
	}
	return ret;
}

int _app2sd_create_loopback_device(const char *pkgid, int size)
{
	int ret = APP2EXT_SUCCESS;
	char command[FILENAME_MAX] = { 0, };
	mode_t mode = DIR_PERMS;
	char external_storage_path[FILENAME_MAX] = { 0, };
	char buff[BUF_SIZE] = { 0, };
	char app_path[FILENAME_MAX] = { 0, };
	FILE *fp = NULL;

	if (NULL == pkgid || size <= 0) {
		app2ext_print("App2Sd Error: Invalid argument\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}
	snprintf(command, FILENAME_MAX, "of=%s%s", APP2SD_PATH,
		 pkgid);
	snprintf(buff, BUF_SIZE, "count=%d", size);
	const char *argv1[] =
	    { "dd", "if=/dev/zero", command, "bs=1M", buff, NULL };
	snprintf(external_storage_path, FILENAME_MAX, "%s",
		 APP2SD_PATH);
	ret = mkdir(external_storage_path, mode);
	if (ret) {
		if (errno != EEXIST) {
			app2ext_print
			    ("App2sd Error : Create directory failed, error no is %d\n",
			     errno);
			return APP2EXT_ERROR_CREATE_DIRECTORY;
		}
	}
	snprintf(app_path, FILENAME_MAX, "%s%s", APP2SD_PATH,
		 pkgid);
	if ((fp = fopen(app_path, "r+")) != NULL) {
		app2ext_print("Application already exists %s\n", app_path);
		fclose(fp);
		return APP2EXT_ERROR_PKG_EXISTS;
	}

	ret = _xsystem(argv1);
	if (ret) {
		app2ext_print("App2Sd Error : command \"%s\" failed \n",
			     command);
		return ret;
	}
	return ret;
}

int _app2sd_delete_loopback_device(const char *pkgid)
{
	int ret = APP2EXT_SUCCESS;
	char loopback_device[FILENAME_MAX] = { 0, };

	snprintf(loopback_device, FILENAME_MAX, "%s%s", APP2SD_PATH,
		 pkgid);

	ret = unlink(loopback_device);
	if (ret) {
		if (errno == ENOENT) {
			app2ext_print("Unable to access file %s\n", loopback_device);
		} else {
			app2ext_print("Unable to delete %s\n", loopback_device);
			return APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
		}
	}
	return ret;
}

int _app2sd_create_file_system(const char *device_path)
{
	int ret = APP2EXT_SUCCESS;
	FILE *fp = NULL;
	if (NULL == device_path) {
		app2ext_print("App2Sd Error: invalid param [NULL]\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/*Format the filesystem [create a filesystem]*/
	const char *argv[] = { "/sbin/mkfs.ext4", device_path, NULL };
	fp = fopen(device_path, "r+");
	if (fp == NULL) {
		app2ext_print
		    ("App2sd Error: Unable to access %s [System errono is %d.....%s]\n",
		     device_path, errno, strerror(errno));
		return APP2EXT_ERROR_ACCESS_FILE;
	} else {
		fclose(fp);
	}
	ret = _xsystem(argv);
	if (ret) {
		app2ext_print
		    ("App2Sd Error : creating file system failed [System error is %s\n",
		     strerror(errno));
		return APP2EXT_ERROR_CREATE_FS;
	}
	return ret;
}

static int _app2sd_create_dir_with_link(const char *pkgid,
					 const char *dir_name)
{
	mode_t mode = DIR_PERMS;
	int ret = APP2EXT_SUCCESS;
	char app_dir_mmc_path[FILENAME_MAX] = { 0, };
	char app_dir_path[FILENAME_MAX] = { 0, };
	snprintf(app_dir_mmc_path, FILENAME_MAX, "%s%s/.mmc/%s",APP_INSTALLATION_PATH,
		 pkgid, dir_name);
	snprintf(app_dir_path, FILENAME_MAX, "%s%s/%s", APP_INSTALLATION_PATH, pkgid,
		 dir_name);

	ret = mkdir(app_dir_mmc_path, mode);
	if (ret) {
		if (errno != EEXIST) {
			app2ext_print
			    ("App2sd Error : Create directory failed, error no is %d\n",
			     errno);
			return APP2EXT_ERROR_CREATE_DIRECTORY;
		}
	}

	if ((ret = symlink(app_dir_mmc_path, app_dir_path)) < 0) {
		if (errno == EEXIST) {
			app2ext_print
			    ("App2sd : File with Symlink name present %s\n",
			     app_dir_path);
		} else {
			app2ext_print
			    ("A2Sd Error : Symbolic link creation failed, error no is %d\n",
			     errno);
			return APP2EXT_ERROR_CREATE_SYMLINK;
		}
	}

	ret = _app2sd_setup_path(pkgid, app_dir_path, PATH_ANY_LABEL, pkgid);
	if (ret) {
		app2ext_print ("App2Sd Error : unable to smack %s\n", app_dir_mmc_path);
		return APP2EXT_ERROR_MOVE;
	}

	return ret;
}

int _app2sd_create_directory_entry(const char *pkgid, GList* dir_list)
{
	int ret = APP2EXT_SUCCESS;
	char app_dir_path[FILENAME_MAX] = { 0, };
	GList *list = NULL;
	app2ext_dir_details* dir_detail = NULL;

	snprintf(app_dir_path, FILENAME_MAX, "%s%s", APP_INSTALLATION_PATH,
		 pkgid);

	list = g_list_first(dir_list);
	while (list) {
		dir_detail = (app2ext_dir_details *)list->data;
		if (dir_detail && dir_detail->name
			&& dir_detail->type == APP2EXT_DIR_RO) {
			ret = _app2sd_create_dir_with_link(pkgid, dir_detail->name);
			if (ret) {
				return ret;
			}
		}
		list = g_list_next(list);
	}
	return APP2EXT_SUCCESS;
}


/*
 *
 * _app2sd_mount_app_content
 This function is to create the path for mmc and mount the content
Example usage: _app2sd_mount_app_content("deb.com.samsung.helloworld","/dev/loop0",MOUNT_TYPE_RD)
*/
int _app2sd_mount_app_content(const char *pkgid, const char *dev,
			int mount_type, GList* dir_list, app2sd_cmd cmd)
{
	int ret = APP2EXT_SUCCESS;
	mode_t mode = DIR_PERMS;
	char app_dir_path[FILENAME_MAX] = { 0, };
	char app_dir_mmc_path[FILENAME_MAX] = { 0, };
	if (NULL == pkgid || NULL == dev) {
		app2ext_print("App2Sd Error : Input param is NULL %s %s \n",
			     pkgid, dev);
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}
	snprintf(app_dir_path, FILENAME_MAX, "%s%s", APP_INSTALLATION_PATH, pkgid);
	ret = mkdir(app_dir_path, mode);
	if (ret) {
		if (errno != EEXIST) {
			app2ext_print
			    ("App2Sd Error : Create directory failed, error no is %d\n",
			     errno);
			return APP2EXT_ERROR_CREATE_DIRECTORY;
		}
	}
	snprintf(app_dir_mmc_path, FILENAME_MAX, "%s%s/.mmc", APP_INSTALLATION_PATH, pkgid);
	ret = mkdir(app_dir_mmc_path, mode);
	if (ret) {
		if (errno != EEXIST) {
			app2ext_print
			    ("App2Sd Error : Create directory failed, error no is %d\n",
			     errno);
			return APP2EXT_ERROR_CREATE_DIRECTORY;
		}
	}

	switch (mount_type) {
	case MOUNT_TYPE_RD:
		{
			if ((ret =
			     mount(dev, app_dir_mmc_path, FS_TYPE,
				   MS_MGC_VAL | MS_RDONLY, NULL)) < 0) {
				app2ext_print
				    ("App2Sd Error : Read Only Mount failed [System Erro no is %d], dev is %s path is %s\n",
				     errno, dev, app_dir_mmc_path);
				ret = APP2EXT_ERROR_MOUNT;
			}
			break;
		}
	case MOUNT_TYPE_RW:
		{
			if ((ret =
			     mount(dev, app_dir_mmc_path, FS_TYPE, MS_MGC_VAL,
				   NULL)) < 0) {
				app2ext_print
				    ("App2Sd Error : Read Write Mount failed [System Erro no is %d]\n",
				     errno);
				ret = APP2EXT_ERROR_MOUNT;
			}
			break;
		}
	case MOUNT_TYPE_RW_NOEXEC:
		{
			if ((ret =
			     mount(dev, app_dir_mmc_path, FS_TYPE,
				   MS_MGC_VAL | MS_NOEXEC, NULL)) < 0) {
				app2ext_print
				    ("App2Sd Error : RWX Mount failed [System Erro no is %d]\n",
				     errno);
				ret = APP2EXT_ERROR_MOUNT;
			}
			break;
		}
	case MOUNT_TYPE_RD_REMOUNT:
		{
			if ((ret =
			     mount(dev, app_dir_mmc_path, FS_TYPE,
				   MS_MGC_VAL | MS_RDONLY | MS_REMOUNT,
				   NULL)) < 0) {
				app2ext_print
				    ("App2Sd Error : RWX Mount failed [System Erro no is %d]\n",
				     errno);
				ret = APP2EXT_ERROR_MOUNT;
			}
			break;
		}
	case MOUNT_TYPE_RW_REMOUNT:
		{
			if ((ret =
			     mount(dev, app_dir_mmc_path, FS_TYPE,
				   MS_MGC_VAL | MS_REMOUNT, NULL)) < 0) {
				app2ext_print
				    ("App2Sd Error : RWX Mount failed [System Erro no is %d]\n",
				     errno);
				ret = APP2EXT_ERROR_MOUNT;
			}
			break;
		}

	default:
		{
			app2ext_print("App2Sd Error: Invalid mount type\n");
			break;
		}
	}
	if (cmd == APP2SD_PRE_INSTALL || cmd == APP2SD_MOVE_APP_TO_MMC) {
		ret = _app2sd_create_directory_entry(pkgid, dir_list);
	}
	return ret;
}

int _app2sd_unmount_app_content(const char *pkgid)
{
	int ret = APP2EXT_SUCCESS;
	char app_dir_mmc_path[FILENAME_MAX] = { 0, };
	snprintf(app_dir_mmc_path, FILENAME_MAX, "%s%s/.mmc", APP_INSTALLATION_PATH, pkgid);
	if ((ret = umount(app_dir_mmc_path)) < 0) {
		app2ext_print("Unable to umount the dir %s\n", strerror(errno));
	}
	return ret;
}

static int _app2sd_move_to_archive(const char *src_path, const char *arch_path)
{
	int ret = APP2EXT_SUCCESS;

	ret = _app2sd_copy_dir(src_path, arch_path);
	if (ret) {
		if (ret != APP2EXT_ERROR_ACCESS_FILE) {
			app2ext_print
			    ("App2Sd Error : unable to copy from %s to %s .....err is %s\n",
			     src_path, arch_path, strerror(errno));
			return APP2EXT_ERROR_MOVE;
		}
	}
	ret = _app2sd_delete_directory((char *)src_path);
	if (ret) {
		if (ret != APP2EXT_ERROR_ACCESS_FILE) {
			app2ext_print("App2Sd Error : unable to delete %s \n", src_path);
			return APP2EXT_ERROR_DELETE_DIRECTORY;
		}
	}
	return ret;
}

int _app2sd_move_app_to_external(const char *pkgid, GList* dir_list)
{
	int ret = APP2EXT_SUCCESS;
	char app_path[FILENAME_MAX] = { 0, };
	char path[FILENAME_MAX] = { 0, };
	char app_mmc_path[FILENAME_MAX] = { 0, };
	char app_archive_path[FILENAME_MAX] = { 0, };
	char mmc_path[FILENAME_MAX] = { 0, };
	unsigned long long total_size = 0;
	int reqd_size = 0;
	char *device_node = NULL;
	char *devi = NULL;
	mode_t mode = DIR_PERMS;
	int free_mmc_mem = 0;
	FILE *fp = NULL;
	GList *list = NULL;
	app2ext_dir_details* dir_detail = NULL;

	/*Check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print
		    ("App2Sd Error : MMC not preset OR Not ready %d\n",
		     ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}

	snprintf(mmc_path, FILENAME_MAX,
		 "%s%s", APP2SD_PATH, pkgid);

	/*check whether application is in external memory or not */
	fp = fopen(mmc_path, "r+");
	if (fp != NULL) {
		app2ext_print
		    ("Already %s entry is present in the SD Card, delete entry and go on without return\n",
		     pkgid);
		fclose(fp);
//		return APP2EXT_ERROR_ALREADY_FILE_PRESENT;
	}

	snprintf(app_mmc_path, FILENAME_MAX,
		 "%s%s/.mmc", APP_INSTALLATION_PATH, pkgid);
	snprintf(app_archive_path, FILENAME_MAX,
		 "%s%s/.archive", APP_INSTALLATION_PATH, pkgid);

	ret = mkdir(app_archive_path, mode);
	if (ret) {
		if (errno != EEXIST) {
			app2ext_print
			    ("App2sd Error: Unable to create directory for archiving, error no is %d\n",
			     errno);
//			return APP2EXT_ERROR_CREATE_DIRECTORY;
		}
	}

	list = g_list_first(dir_list);
	while (list) {
		dir_detail = (app2ext_dir_details *)list->data;
		if (dir_detail && dir_detail->name
			&& dir_detail->type == APP2EXT_DIR_RO) {
			memset((void *)&app_path, '\0',
			       FILENAME_MAX);
			snprintf(app_path, FILENAME_MAX,
				 "%s%s/%s",APP_INSTALLATION_PATH,
				 pkgid,
				 dir_detail->name);
			total_size +=
			    _app2sd_calculate_dir_size
			    (app_path);
		}
		list = g_list_next(list);
	}

	reqd_size = ((total_size / 1024) / 1024) + 2;

	/*Find avialable free memory in the MMC card */
	ret =
	    _app2sd_get_available_free_memory
	    (MMC_PATH, &free_mmc_mem);
	if (ret) {
		app2ext_print
		    ("App2Sd Error : Unable to get available free memory in MMC %d\n",
		     ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}
	/*If avaialalbe free memory in MMC is less than required size + 5MB , return error */
	if (reqd_size > free_mmc_mem) {
		app2ext_print
		    ("App2Sd Error : Insufficient memory in MMC for application installation %d\n",
		     ret);
		return APP2EXT_ERROR_MMC_INSUFFICIENT_MEMORY;
	}
	/*Create a loopback device */
	ret =
	    _app2sd_create_loopback_device(pkgid, (reqd_size+PKG_BUF_SIZE));
	if (ret) {
		app2ext_print
		    ("App2Sd Error : loopback node creation failed\n");
//		return APP2EXT_ERROR_CREATE_DEVICE;
	}
	/*Perform Loopback encryption setup */
	device_node =
	    _app2sd_do_loopback_encryption_setup(pkgid);
	if (!device_node) {
		app2ext_print
		    ("App2Sd Error : losetup failed, device node is %s\n",
		     device_node);
		return APP2EXT_ERROR_DO_LOSETUP;
	}
	/*Check whether loopback device is associated with device node or not */
	devi = _app2sd_find_associated_device_node(pkgid);
	if (devi == NULL) {
		app2ext_print
		    ("App2Sd Error :  _app2sd_find_associated_device_node  losetup failed\n");
		return APP2EXT_ERROR_DO_LOSETUP;
	} else {
		free(devi);
		devi = NULL;
	}
	/*Format the loopback file system */
	ret = _app2sd_create_file_system(device_node);
	if (ret) {
		app2ext_print
		    ("App2Sd Error : create ext4 filesystem failed\n");
		return APP2EXT_ERROR_CREATE_FS;
	}
	/********Archiving code begin***********/
	list = g_list_first(dir_list);
	while (list) {
		dir_detail = (app2ext_dir_details *)list->data;
		if (dir_detail && dir_detail->name
			&& dir_detail->type == APP2EXT_DIR_RO) {
			snprintf(path, FILENAME_MAX,
				 "%s%s/%s",APP_INSTALLATION_PATH,
				 pkgid,
				 dir_detail->name);
			ret =
			    _app2sd_move_to_archive
			    (path,
			     app_archive_path);
			if (ret) {
				if (ret == APP2EXT_ERROR_ACCESS_FILE) {
					app2ext_print
					    ("App2Sd Error : unable to access %s\n",
					     path);
				} else {
					app2ext_print
					    ("App2Sd Error : unable to copy from %s to %s \n",
					     path,
					     app_archive_path);
//					return APP2EXT_ERROR_MOVE;
				}
			}
		}
		list = g_list_next(list);
	}
	/********Archiving code ends***********/

	/*mount the loopback encrypted pseudo device on application installation path as with Read Write permission */
	ret =
	    _app2sd_mount_app_content(pkgid, device_node,
				      MOUNT_TYPE_RW, dir_list,
				      APP2SD_MOVE_APP_TO_MMC);
	if (ret) {
		return ret;
	}
	/********restore Archive begin***********/
	list = g_list_first(dir_list);
	while (list) {
		dir_detail = (app2ext_dir_details *)list->data;
		if (dir_detail && dir_detail->name
			&& dir_detail->type == APP2EXT_DIR_RO) {
			memset((void *)&path, '\0',
			       FILENAME_MAX);
			snprintf(path, FILENAME_MAX,
				 "%s%s/.archive/%s",APP_INSTALLATION_PATH,
				 pkgid,
				 dir_detail->name);
			ret =
			    _app2sd_copy_dir
			    (path,
			     app_mmc_path);
			if (ret) {
				if (ret == APP2EXT_ERROR_ACCESS_FILE) {
					app2ext_print
					    ("App2Sd Error : unable to access %s\n",
					     path);
				} else {
					app2ext_print
					    ("App2Sd Error : unable to copy from %s to %s .....err is %s\n",
					     path,
					     app_mmc_path,
					     strerror
					     (errno));
//					return APP2EXT_ERROR_MOVE;
				}
			}
			ret =
			    _app2sd_delete_directory
			    (path);
			if (ret) {
				if (ret == APP2EXT_ERROR_ACCESS_FILE) {
					app2ext_print
					    ("App2Sd Error : unable to access %s\n",
					     path);
				} else {
					app2ext_print
					    ("App2Sd Error : unable to delete %s \n",
					     path);
					return
					    APP2EXT_ERROR_DELETE_DIRECTORY;
				}
			}
		}
		list = g_list_next(list);
	}

	ret = _app2sd_delete_directory(app_archive_path);
	if (ret) {
		app2ext_print
		    ("App2Sd Error : unable to delete %s \n",
		     app_archive_path);
//		return APP2EXT_ERROR_DELETE_DIRECTORY;
	}

	ret = _app2sd_apply_mmc_smack(pkgid, dir_list, pkgid);
	if (ret) {
		app2ext_print("App2Sd Error : unable to apply app smack\n");
		return APP2EXT_ERROR_MOVE;
	}

	/*Restore archive ends */
	/*Re-mount the loopback encrypted pseudo device on application installation path as with Read Only permission */
	ret = _app2sd_unmount_app_content(pkgid);
	if (ret) {
		return APP2EXT_ERROR_REMOUNT;
	}
	ret =
	    _app2sd_remove_loopback_encryption_setup(pkgid);
	if (ret) {
		app2ext_print
		    ("App2Sd Error : unable to detach loopback setup for %s\n",
		     pkgid);
		return APP2EXT_ERROR_DETACH_LOOPBACK_DEVICE;
	}
	return APP2EXT_SUCCESS;
}

int _app2sd_move_app_to_internal(const char *pkgid, GList* dir_list)
{
	int ret = APP2EXT_SUCCESS;
	mode_t mode = DIR_PERMS;
	char path[FILENAME_MAX] = { 0, };
	char app_mmc_path[FILENAME_MAX] = { 0, };
	char app_path[FILENAME_MAX] = { 0, };
	char mmc_path[FILENAME_MAX] = { 0, };
	char app_archive_path[FILENAME_MAX] = { 0, };
	char *device_node = NULL;
	FILE *fp = NULL;
	GList *list = NULL;
	app2ext_dir_details* dir_detail = NULL;

	snprintf(app_mmc_path, FILENAME_MAX,
		 "%s%s/.mmc", APP_INSTALLATION_PATH,  pkgid);
	snprintf(app_path, FILENAME_MAX, "%s%s/", APP_INSTALLATION_PATH,
		 pkgid);
	snprintf(app_archive_path, FILENAME_MAX,
		 "%s%s/.archive", APP_INSTALLATION_PATH, pkgid);
	snprintf(mmc_path, FILENAME_MAX,
		 "%s%s", APP2SD_PATH, pkgid);

	/*Check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print
		    ("App2Sd Error : MMC not preset OR Not ready %d\n",
		     ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}

	/*check whether application is in external memory or not */
	fp = fopen(mmc_path, "r+");
	if (fp == NULL) {
		app2ext_print
		    ("Application %s is not installed on SD Card\n",
		     pkgid);
		return APP2EXT_ERROR_FILE_ABSENT;
	} else {
		fclose(fp);
		fp = NULL;
	}

	/*Get the associated device node for SD card applicationer */
	device_node =
	    _app2sd_find_associated_device_node(pkgid);
	if (NULL == device_node) {
		/*Do loopback setup */
		device_node =
		    _app2sd_do_loopback_encryption_setup
		    (pkgid);
		if (device_node == NULL) {
			app2ext_print
			    ("App2Sd Error : loopback encryption setup failed\n");
			return APP2EXT_ERROR_DO_LOSETUP;
		}
		/*Do  mounting */
		ret =
		    _app2sd_mount_app_content(pkgid,
					      device_node,
					      MOUNT_TYPE_RW,
					      dir_list,
					      APP2SD_MOVE_APP_TO_PHONE);
		if (ret) {
			app2ext_print
			    ("App2Sd Error : Re-mount failed\n");
			return APP2EXT_ERROR_MOUNT_PATH;
		}
	} else {
		/*Do  re-mounting */
		ret =
		    _app2sd_mount_app_content(pkgid,
					      device_node,
					      MOUNT_TYPE_RW_REMOUNT,
					      dir_list,
					      APP2SD_MOVE_APP_TO_PHONE);
		if (ret) {
			app2ext_print
			    ("App2Sd Error : Re-mount failed\n");
			return APP2EXT_ERROR_MOUNT_PATH;
		}
	}
	ret = mkdir(app_archive_path, mode);
	if (ret) {
		app2ext_print
		    ("App2Sd Error : unable to create directory%s\n",
		     app_archive_path);
//		return APP2EXT_ERROR_CREATE_DIRECTORY;
	}


	list = g_list_first(dir_list);
	while (list) {
		dir_detail = (app2ext_dir_details *)list->data;
		if (dir_detail && dir_detail->name
			&& dir_detail->type == APP2EXT_DIR_RO) {
				/*Archiving code */
				memset((void *)&path, '\0',
				       FILENAME_MAX);
				snprintf(path, FILENAME_MAX,
					 "%s%s/.mmc/%s", APP_INSTALLATION_PATH,
					 pkgid,
					 dir_detail->name);
				ret =
				    _app2sd_copy_dir
				    (path,
				     app_archive_path);
				if (ret) {
					if (ret == APP2EXT_ERROR_ACCESS_FILE) {
						app2ext_print
						    ("App2Sd Error : unable to access %s\n",
						     path);
					} else {
						app2ext_print
						    ("App2Sd Error : unable to copy from %s to %s .....err is %s\n",
						     path,
						     app_archive_path,
						     strerror
						     (errno));
//						return APP2EXT_ERROR_MOVE;
					}
				}

				/*Delete the symbolic link files [bin, lib, res]*/
				memset((void *)&path, '\0',
				       FILENAME_MAX);
				snprintf(path, FILENAME_MAX,
					 "%s%s/%s", APP_INSTALLATION_PATH,
					 pkgid,
					 dir_detail->name);
				ret = unlink(path);
				if (ret) {
					if (errno == ENOENT) {
						app2ext_print
						    ("App2Sd Error : Directory %s does not exist\n",
						     path);
					} else {
						app2ext_print
						    ("App2Sd Error : unable to remove the symbolic link file %s, it is already unlinked!!!\n",
						     path);
//						return APP2EXT_ERROR_DELETE_LINK_FILE;
					}
				}

				/*Copy content to destination */
				memset((void *)&path, '\0',
				       FILENAME_MAX);
				snprintf(path, FILENAME_MAX,
					 "%s%s/.archive/%s", APP_INSTALLATION_PATH,
					 pkgid,
					 dir_detail->name);
				ret =
				    _app2sd_copy_dir
				    (path, app_path);
				if (ret) {
					if (ret == APP2EXT_ERROR_ACCESS_FILE) {
						app2ext_print
						    ("App2Sd Error : unable to access %s\n",
						     path);
					} else {
						app2ext_print
						    ("App2Sd Error : unable to copy from %s to %s .....err is %s\n",
						     path,
						     app_path,
						     strerror
						     (errno));
//						return APP2EXT_ERROR_MOVE;
					}
				}
		}
		list = g_list_next(list);
	}

	ret = _app2sd_unmount_app_content(pkgid);
	if (ret) {
		app2ext_print
		    ("App2Sd Error : unable to unmount SD directory for app %s\n",
		     pkgid);
		return APP2EXT_ERROR_UNMOUNT;
	}
	ret =
	    _app2sd_remove_loopback_encryption_setup(pkgid);
	if (ret) {
		app2ext_print
		    ("App2Sd Error : unable to detach loopback setup for %s\n",
		     pkgid);
		return APP2EXT_ERROR_DETACH_LOOPBACK_DEVICE;
	}
	ret = _app2sd_delete_loopback_device(pkgid);
	if (ret) {
		app2ext_print
		    ("App2Sd Error : unable to delete the loopback device for %s\n",
		     pkgid);
		return APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
	}
	ret = _app2sd_delete_directory(app_mmc_path);
	if (ret) {
		app2ext_print
		    ("App2Sd Error : unable to delete %s \n",
		     app_mmc_path);
//		return APP2EXT_ERROR_DELETE_DIRECTORY;
	}
	ret = _app2sd_delete_directory(app_archive_path);
	if (ret) {
		app2ext_print
		    ("App2Sd Error : unable to delete %s \n",
		     app_archive_path);
//		return APP2EXT_ERROR_DELETE_DIRECTORY;
	}

	ret = _app2sd_apply_app_smack(pkgid, dir_list, pkgid);
	if (ret) {
		app2ext_print("App2Sd Error : unable to apply app smack\n");
		return APP2EXT_ERROR_MOVE;
	}

	return APP2EXT_SUCCESS;
}

int _app2sd_move_app(const char *pkgid, app2ext_move_type move_cmd, GList* dir_list)
{
	int ret = APP2EXT_SUCCESS;

	/*Check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print
		    ("App2Sd Error : MMC not preset OR Not ready %d\n",
		     ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}

	switch (move_cmd) {
	case APP2EXT_MOVE_TO_EXT:
		{
			ret = _app2sd_move_app_to_external(pkgid, dir_list);
			if (ret) {
				app2ext_print
				    ("App2Sd Error : move app to external memory failed %d\n",
				     ret);
				return ret;
			}
			break;
		}
	case APP2EXT_MOVE_TO_PHONE:
		{
			ret = _app2sd_move_app_to_internal(pkgid, dir_list);
			if (ret) {
				app2ext_print
				    ("App2Sd Error : move app to internal memory failed %d\n",
				     ret);
				return ret;
			}
			break;
		}
	default:
		{
			app2ext_print("App2Sd Error : invalid argument\n");
			return APP2EXT_ERROR_INVALID_ARGUMENTS;
		}
	}

	return ret;

}

int _app2sd_copy_ro_content(const char *src, const char *dest, GList* dir_list)
{
	char path[FILENAME_MAX] = { 0, };
	int ret = 	APP2EXT_SUCCESS;
	GList *list = NULL;
	app2ext_dir_details* dir_detail = NULL;

	list = g_list_first(dir_list);
	while (list) {
		dir_detail = (app2ext_dir_details *)list->data;
		if (dir_detail && dir_detail->name
			&& dir_detail->type == APP2EXT_DIR_RO) {
			memset((void *)&path, '\0',
			       FILENAME_MAX);
			snprintf(path, FILENAME_MAX,
				 "%s/%s", src,
				 dir_detail->name);
			ret =
			    _app2sd_copy_dir
			    (path,
			     dest);
			if (ret) {
				if (ret == APP2EXT_ERROR_ACCESS_FILE) {
					app2ext_print
					    ("App2Sd Error : unable to access %s\n",
					     path);
				} else {
					app2ext_print
					    ("App2Sd Error : unable to copy from %s to %s .....errno is %d\n",
					     path,
					     dest,
					     errno);
					return
					    APP2EXT_ERROR_MOVE;
				}
			}
		}
		list = g_list_next(list);
	}

	return APP2EXT_SUCCESS;
}

int _app2sd_duplicate_device(const char *pkgid, GList* dir_list, char *dev_node, int size)
{
	int ret = 0;
	char temp_pkgid[FILENAME_MAX] = { 0, };
	char *devi = NULL;
	int err_res = 0;
	char *result = NULL;

	/*Create a new loopback device */
	snprintf(temp_pkgid, FILENAME_MAX,
		 "%s.new", pkgid);
	ret = _app2sd_create_loopback_device(temp_pkgid, (size+PKG_BUF_SIZE));
	if (ret) {
		app2ext_print("App2Sd Error : Package already present\n");
		return ret;
	}
	app2ext_print("App2Sd  : _app2sd_create_loopback_device SUCCESS\n");
	/*Perform Loopback encryption setup */
	dev_node = _app2sd_do_loopback_duplicate_encryption_setup(pkgid, temp_pkgid);
	if (!dev_node) {
		app2ext_print("App2Sd Error : losetup failed, device node is %s\n", dev_node);
		_app2sd_delete_loopback_device(pkgid);
		app2ext_print("App2Sd Error : create ext filesystem failed\n");
		return APP2EXT_ERROR_DO_LOSETUP;
	}
	app2ext_print("App2Sd  : _app2sd_do_loopback_duplicate_encryption_setup SUCCESS\n");
	/*Check whether loopback device is associated with device node or not */
	devi = _app2sd_find_associated_device_node(temp_pkgid);
	if (devi == NULL) {
		app2ext_print("App2Sd Error : finding associated device node failed\n");
		err_res = APP2EXT_ERROR_DO_LOSETUP;
		goto FINISH_OFF;
	}
	app2ext_print("App2Sd  : _app2sd_find_associated_device_node SUCCESS\n");
	/*Format the loopback file system */
	ret = _app2sd_create_file_system(dev_node);
	if (ret) {
		app2ext_print("App2Sd Error : creating FS failed failed\n");
		err_res = APP2EXT_ERROR_CREATE_FS;
		goto FINISH_OFF;
	}
	app2ext_print("App2Sd  : _app2sd_create_file_system SUCCESS\n");
	/*Do  mounting for new dev*/
	ret =
	    _app2sd_mount_app_content(temp_pkgid, dev_node, MOUNT_TYPE_RW,
				dir_list, APP2SD_PRE_UPGRADE);
	if (ret) {
		app2ext_print("App2Sd Error : Re-mount failed\n");
		err_res = APP2EXT_ERROR_MOUNT_PATH;
		goto FINISH_OFF;
	}
	if (devi) {
		free(devi);
		devi = NULL;
	}
	return APP2EXT_SUCCESS;

FINISH_OFF:
	if (dev_node) {
		result = _app2sd_detach_loop_device(dev_node);
		if (result) {
			free(result);
			result = NULL;
		}
		_app2sd_delete_loopback_device(pkgid);
		free(dev_node);
		dev_node = NULL;
	}

	if (devi) {
		free(devi);
		devi = NULL;
	}
	return err_res;
}

int _app2sd_update_loopback_device_size(const char *pkgid,
	int size, GList* dir_list)
{
	int ret = 0;
	char *device_node = NULL;
	char *old_device_node = NULL;
	int err_res = 0;
	char app_mmc_path[FILENAME_MAX] = { 0, };
	char app_archive_path[FILENAME_MAX] = { 0, };
	char temp_pkgid[FILENAME_MAX] = { 0, };
	char app_path[FILENAME_MAX] = { 0, };

	snprintf(temp_pkgid, FILENAME_MAX,
		 "%s.new", pkgid);

	ret = _app2sd_duplicate_device(pkgid, dir_list, device_node, size);
	if (ret) {
		app2ext_print("App2Sd Error : Creating duplicate device failed\n");
		return ret;
	}

	app2ext_print("App2Sd  : _app2sd_mount_app_content SUCCESS\n");
	/*check app entry is there in sd card or not. */
	snprintf(app_path, FILENAME_MAX, "%s%s", APP2SD_PATH,
		 pkgid);

	/*Get the associated device node for SD card applicatione */
	old_device_node = _app2sd_find_associated_device_node(pkgid);
	if (NULL == old_device_node) {
		/*Do loopback setup */
		old_device_node = _app2sd_do_loopback_encryption_setup(pkgid);
		if (old_device_node == NULL) {
			app2ext_print
			    ("App2Sd Error : loopback encryption setup failed\n");
			err_res = APP2EXT_ERROR_DO_LOSETUP;
			goto FINISH_OFF;
		}
		/*Do  mounting */
		ret =
		    _app2sd_mount_app_content(pkgid, old_device_node,
					      MOUNT_TYPE_RW, dir_list,
					      APP2SD_PRE_UPGRADE);
		if (ret) {
			app2ext_print("App2Sd Error : Re-mount failed\n");
			err_res = APP2EXT_ERROR_MOUNT_PATH;
			goto FINISH_OFF;
		}
	} else {
		/*Do  re-mounting */
		ret =
		    _app2sd_mount_app_content(pkgid, old_device_node,
					      MOUNT_TYPE_RW_REMOUNT, dir_list,
					      APP2SD_PRE_UPGRADE);
		if (ret) {
			app2ext_print("App2Sd Error : Re-mount failed\n");
			err_res = APP2EXT_ERROR_MOUNT_PATH;
			goto FINISH_OFF;
		}
	}

	snprintf(app_mmc_path, FILENAME_MAX,
		 "%s%s/.mmc", APP_INSTALLATION_PATH, pkgid);
	snprintf(app_archive_path, FILENAME_MAX,
		"%s%s/.mmc", APP_INSTALLATION_PATH, temp_pkgid);

	ret = _app2sd_copy_ro_content(app_mmc_path, app_archive_path, dir_list);
	if (ret) {
		app2ext_print("App2Sd Error : copy ro content  failed\n");
		err_res = ret;
		goto FINISH_OFF;
	}

	ret = _app2sd_unmount_app_content(pkgid);
	if (ret) {
		app2ext_print
		    ("App2SD Error: Unable to unmount the SD application\n");
		err_res = APP2EXT_ERROR_UNMOUNT;
		goto FINISH_OFF;
	}
	ret = _app2sd_remove_loopback_encryption_setup(pkgid);
	if (ret) {
		app2ext_print("App2SD Error: Unable to remove loopback setup\n");
		err_res = APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
		goto FINISH_OFF;
	}
	ret = _app2sd_unmount_app_content(temp_pkgid);
	if (ret) {
		app2ext_print
		    ("App2SD Error: Unable to unmount the SD application\n");
		err_res = APP2EXT_ERROR_UNMOUNT;
		goto FINISH_OFF;
	}
	ret = _app2sd_remove_loopback_encryption_setup(temp_pkgid);
	if (ret) {
		app2ext_print("App2SD Error: Unable to remove loopback setup\n");
		err_res = APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
		goto FINISH_OFF;
	}
	snprintf(app_archive_path, FILENAME_MAX,
		"%s%s", APP2SD_PATH, temp_pkgid);
	ret = _app2sd_delete_directory(app_path);
	if (ret) {
		app2ext_print
		    ("App2Sd Error : unable to delete %s \n",
		     app_path);
		err_res = APP2EXT_ERROR_DELETE_DIRECTORY;
		goto FINISH_OFF;
	}
	ret = _app2sd_rename_dir(app_archive_path, app_path);
	if (ret) {
		app2ext_print
		    ("App2Sd Error : unable to rename %s \n",
		     app_archive_path);
		err_res = APP2EXT_ERROR_MOVE;
		goto FINISH_OFF;
	}
	snprintf(app_path, FILENAME_MAX,
		"%s%s", APP_INSTALLATION_PATH, temp_pkgid);
	ret = _app2sd_delete_directory(app_path);
	if (ret) {
		app2ext_print
		    ("App2Sd Error : unable to delete %s \n",
		     app_path);
		err_res = APP2EXT_ERROR_DELETE_DIRECTORY;
		goto FINISH_OFF;
	}
	return APP2EXT_SUCCESS;

FINISH_OFF:
	if (old_device_node) {
		free(old_device_node);
		old_device_node = NULL;
	}

	ret = _app2sd_remove_loopback_encryption_setup(pkgid);
	if (ret) {
		app2ext_print("App2SD Error: Unable to remove loopback setup\n");
		err_res = APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
	}
	return err_res;
}
