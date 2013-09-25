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

#ifndef _APP2SD_INTERNAL_H
#define _APP2SD_INTERNAL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

/*Include Headers*/
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>
#include <unistd.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/mount.h>
#include <app2sd_interface.h>

#define DIR_PERMS (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)

#define BUF_SIZE 256
#define MEM_BUF_SIZE 	5	/*Memory buffer size in MB*/
#define PKG_BUF_SIZE 	2	/*Memory buffer size in MB*/

/*Device entry defines*/
#define DEV_MAJOR		7

#define FS_TYPE		"ext4"

typedef enum mount_type_t {
	MOUNT_TYPE_RD = 0,
	MOUNT_TYPE_RW,
	MOUNT_TYPE_RW_NOEXEC,
	MOUNT_TYPE_RD_REMOUNT,
	MOUNT_TYPE_RW_REMOUNT
} mount_type;

typedef enum app2sd_cmd_t {
	APP2SD_PRE_INSTALL = 1,
	APP2SD_POST_INSTALL,
	APP2SD_PRE_UNINSTALL,
	APP2SD_POST_UNINSTALL,
	APP2SD_PRE_UPGRADE,
	APP2SD_POST_UPGRADE,
	APP2SD_APP_LAUNCH,
	APP2SD_APP_TERMINATE,
	APP2SD_MOVE_APP_TO_MMC,
	APP2SD_MOVE_APP_TO_PHONE
} app2sd_cmd;

/*This will store password in DB*/
int _app2sd_set_passwod_in_db(const char *pkgid, const char *password);

/*This will remove password from db*/
int _app2sd_remove_password_from_db(const char *pkgid);

/*This will fetch password from db*/
char *_app2sd_get_passowrd_from_db(const char *pkgid);

/*Checks whether mmc is present or not*/
int _app2sd_check_mmc_status(void);

/*this function is similar to system()*/
int _xsystem(const char *argv[]);

/*this function will return the free available memory on the SD Card*/
int _app2sd_get_available_free_memory(const char *sd_path, int *free_mem);

/*Function to move the application from/to SD Card*/
int _app2sd_move_app(const char *pkgid, app2ext_move_type move_cmd, GList* dir_list);

/*utility to delete the directory*/
int _app2sd_delete_directory(char *dirname);

/*utility to calculate the size of a directory in MB*/
unsigned long long _app2sd_calculate_dir_size(char *dirname);

/*utility to calculate the size of a file in MB*/
unsigned long long _app2sd_calculate_file_size(const char *filename);

/*Utility to copy a directory*/
int _app2sd_copy_dir(const char *src, const char *dest);

/*Utility to rename a directory*/
int _app2sd_rename_dir(const char *old_name, const char *new_name);

/*Utility to create application directory structure entry as per package type*/
int _app2sd_create_directory_entry(const char *pkgid, GList* dir_list);

/* Utility to create symlinks */
int _app2sd_create_symlink(char *pkgid);

/*This function finds the associated device node for the app*/
char *_app2sd_find_associated_device_node(const char *pkgid);

/*This function does the loopback encryption for app*/
char *_app2sd_do_loopback_encryption_setup(const char *pkgid);

/*This function detaches the loopback device*/
char *_app2sd_detach_loop_device(const char *device);

/*This function finds loopback device associated with the app*/
char *_app2sd_find_associated_device(const char *mmc_app_path);

/*This function creates loopback device*/
int _app2sd_create_loopback_device(const char *pkgid, int size);

/*This function deletes loopback device associated with the app*/
int _app2sd_delete_loopback_device(const char *pkgid);

/*This function creates ext4 FS on the device path*/
int _app2sd_create_file_system(const char *device_path);

/*This function mounts the app content on the device node*/
int _app2sd_mount_app_content(const char *pkgid, const char *dev,
			int mount_type, GList* dir_list, app2sd_cmd cmd);

/*This function unmounts the app content */
int _app2sd_unmount_app_content(const char *pkgid);

/*This function removes the loopbck encryption setup for the app*/
int _app2sd_remove_loopback_encryption_setup(const char *pkgid);

/*This function updates loopback device size*/
int _app2sd_update_loopback_device_size(const char *pkgid,
	int size, GList* dir_list);

/* This generates password */
char *_app2sd_generate_password(const char *pkgid);

/*This function encrypts device*/
char *_app2sd_encrypt_device(const char *device, const char *pkgid,
                              char *passwd);

/*This function finds free device*/
char *_app2sd_find_free_device(void);

/*This function initializes app2sd DB*/
int _app2sd_initialize_db();

/*This function is used to get password from db*/
char *_app2sd_get_password_from_db(const char *pkgid);

/*This function removes password from db */
int _app2sd_remove_password_from_db(const char *pkgid);

/* This functions saved password in db */
int _app2sd_set_password_in_db(const char *pkgid,
				      const char *passwd);

/* This functions setup path for smack */
int _app2sd_setup_path(const char *pkgid, const char *dirpath,
						int apppathtype, const char *groupid);

#endif
