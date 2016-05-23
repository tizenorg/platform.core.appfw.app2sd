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

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

/*Include Headers*/
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <malloc.h>
#include <math.h>
#include <errno.h>
#include <stdbool.h>

#include "app2sd_interface.h"

#define BUF_SIZE 256
#define MEM_BUF_SIZE 5 /* Memory buffer size in MB */
#define PKG_BUF_SIZE 2 /* Memory buffer size in MB */

/*Device entry defines*/
#define DEV_MAJOR 7

#define FS_TYPE "ext4"
#define INTERNAL_STORAGE_PATH "/opt"

typedef enum mount_type_t {
	MOUNT_TYPE_RD = 0,
	MOUNT_TYPE_RW,
	MOUNT_TYPE_RW_NOEXEC,
	MOUNT_TYPE_RD_REMOUNT,
	MOUNT_TYPE_RW_REMOUNT
} mount_type;

/*Checks whether mmc is present or not*/
int _app2sd_check_mmc_status(void);

/*this function is similar to system()*/
int _xsystem(const char *argv[]);

/*this function will return the free available memory on the SD Card*/
int _app2sd_get_available_free_memory(const char *sd_path, int *free_mem);

/*Function to move the application from/to SD Card*/
int _app2sd_usr_move_app(const char *pkgid, app2ext_move_type move_cmd,
		GList *dir_list, uid_t uid);

/*utility to delete symbolic link*/
void _app2sd_delete_symlink(const char *dirname);

/*utility to calculate the size of a directory in MB*/
unsigned long long _app2sd_calculate_dir_size(char *dirname);

/*utility to calculate the size of a file in MB*/
unsigned long long _app2sd_calculate_file_size(const char *filename);

/*Utility to copy a directory*/
int _app2sd_copy_dir(const char *src, const char *dest);

/*Utility to rename a directory*/
int _app2sd_rename_dir(const char *old_name, const char *new_name);

/* Utility to create symlinks */
int _app2sd_create_symlink(char *pkgid);

/*This function finds the associated device node for the app*/
char *_app2sd_find_associated_device_node(const char *loopback_device);

/*This function does the loopback encryption for app*/
char *_app2sd_do_loopback_encryption_setup(const char *pkgid,
		const char *loopback_device, uid_t uid);

/*This function detaches the loopback device*/
char *_app2sd_detach_loop_device(const char *device);

/*This function finds loopback device associated with the app*/
char *_app2sd_find_associated_device(const char *loopback_device);

/*This function creates loopback device*/
int _app2sd_create_loopback_device(const char *pkgid,
		const char *loopback_device, int size);

/*This function deletes loopback device associated with the app*/
int _app2sd_delete_loopback_device(const char *loopback_device);

/*This function creates ext4 FS on the device path*/
int _app2sd_create_file_system(const char *device_path);

/*This function mounts the app content on the device node*/
int _app2sd_mount_app_content(const char *application_path, const char *pkgid,
		const char *dev, int mount_type, GList* dir_list,
		app2sd_cmd cmd, uid_t uid);

/*This function unmounts the app content */
int _app2sd_unmount_app_content(const char *application_path);

/*This function removes the loopbck encryption setup for the app*/
int _app2sd_remove_loopback_encryption_setup(const char *loopback_device);

/*This function removes all of loopbck encryption setup for the app*/
int _app2sd_remove_all_loopback_encryption_setups(const char *loopback_device);

/*This function updates loopback device size*/
int _app2sd_update_loopback_device_size(const char *pkgid,
		const char *loopback_device, const char *application_path,
		const char *temp_pkgid, const char *temp_loopback_device,
		const char *temp_application_path, int size, GList* dir_list,
		uid_t uid);

/* This generates password */
char *_app2sd_generate_password(const char *pkgid);

/*This function encrypts device*/
char *_app2sd_encrypt_device(const char *device, const char *loopback_device,
		char *passwd);

/*This function finds free device*/
char *_app2sd_find_free_device(void);

/*This function initializes app2sd DB*/
int _app2sd_initialize_db();

/*This function is used to get password from db*/
char *_app2sd_get_password_from_db(const char *pkgid, uid_t uid);

/*This function removes info from db */
int _app2sd_remove_info_from_db(const char *pkgid, uid_t uid);

/* This functions save info in db */
int _app2sd_set_info_in_db(const char *pkgid, const char *passwd,
		const char *loopback_device, uid_t uid);

int _app2sd_get_info_from_db(const char *filename, char **pkgid, uid_t *uid);

int _app2sd_force_clean(const char *pkgid, const char *application_path,
		const char *loopback_device, uid_t uid);

#ifdef _APPFW_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
/*This function setup dmcrypt header in the app2sd file */
int _app2sd_dmcrypt_setup_device(const char *pkgid,
		const char *loopback_device, bool is_dup, uid_t uid);

/*This function maps the app2sd file with a dmcrypt device node */
int _app2sd_dmcrypt_open_device(const char *pkgid, const char *loopback_device,
		uid_t uid, char **dev_node);

/*This function remove dmcrypt device node */
int _app2sd_dmcrypt_close_device(const char *loopback_device);

/*This function find associated dmcrypt device node */
char *_app2sd_find_associated_dmcrypt_device_node(const char *loopback_device);
#endif

#endif
