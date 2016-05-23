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

#ifndef __APP2EXT_INTERFACE_H__
#define __APP2EXT_INTERFACE_H__

/**
 * @file app2ext_interface.h
 * @version 0.5
 * @brief    This file declares API of app2ext library
 */
/**
 * @addtogroup APPLICATION_FRAMEWORK
 * @{
 *
 * @defgroup app2ext
 * @version    0.5
 *
 * @section    Header to use them:
 * @code
 * #include <app2ext_interface.h>
 * @endcode
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef API
#define API __attribute__ ((visibility("default")))
#endif

#include <dlog/dlog.h>
#include <glib.h>

/* for multi-user support */
#include <tzplatform_config.h>

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "APP2EXT"

#define _E(fmt, arg...) LOGE(fmt, ##arg)
#define _D(fmt, arg...) LOGD(fmt, ##arg)
#define _W(fmt, arg...) LOGW(fmt, ##arg)
#define _I(fmt, arg...) LOGI(fmt, ##arg)

#define APP2EXT_SUCCESS 0

#define OWNER_ROOT 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
#define MMC_PATH tzplatform_mkpath(TZ_SYS_MEDIA, "SDCardA1")
#define APP2SD_PATH tzplatform_mkpath(TZ_SYS_MEDIA, "SDCardA1/app2sd")

#define APP2SD_BUS_NAME "org.tizen.app2sd"
#define APP2SD_OBJECT_PATH "/org/tizen/app2sd"
#define APP2SD_INTERFACE_NAME "org.tizen.app2sd"

/**
 * Enum for application installation location
 */
typedef enum app2ext_install_location_t {
	APP2EXT_INTERNAL_MEM = 0,
	APP2EXT_SD_CARD,
	APP2EXT_MICRO_USB,
	APP2EXT_CLOUD,
	APP2EXT_NOT_INSTALLED
} app2ext_install_location;

/**
 * Enum for installation/upgrade status[success/failure]
 */
typedef enum app2ext_status_t {
	APP2EXT_STATUS_FAILED = 1,
	APP2EXT_STATUS_SUCCESS
} app2ext_status;

/**
 * Enum for directory type
 */
typedef enum app2ext_dir_type_t {
	APP2EXT_DIR_RO,
	APP2EXT_DIR_RW,
} app2ext_dir_type;

/**
 * Enum for move command
 * @see app2sd_move_installed_app()
 */
typedef enum app2ext_move_type_t {
	APP2EXT_MOVE_TO_EXT = 1,
	APP2EXT_MOVE_TO_PHONE
} app2ext_move_type;

/**
 * Enum for error codes
 */
typedef enum app2ext_error_t {
	APP2EXT_ERROR_INVALID_ARGUMENTS = 2,
	APP2EXT_ERROR_MOVE,
	APP2EXT_ERROR_PRE_UNINSTALL,
	APP2EXT_ERROR_MMC_STATUS,
	APP2EXT_ERROR_DB_INITIALIZE,
	APP2EXT_ERROR_SQLITE_REGISTRY,
	APP2EXT_ERROR_PASSWD_GENERATION,
	APP2EXT_ERROR_MMC_INFORMATION,
	APP2EXT_ERROR_MMC_INSUFFICIENT_MEMORY,
	APP2EXT_ERROR_DELETE_DIRECTORY,
	APP2EXT_ERROR_CREATE_SYMLINK,
	APP2EXT_ERROR_CREATE_DIRECTORY,
	APP2EXT_ERROR_DELETE_LINK_FILE,
	APP2EXT_ERROR_PKG_EXISTS,
	APP2EXT_ERROR_ACCESS_FILE,
	APP2EXT_ERROR_OPEN_DIR,
	APP2EXT_ERROR_ALREADY_FILE_PRESENT,
	APP2EXT_ERROR_FILE_ABSENT,
	APP2EXT_ERROR_STRCMP_FAILED,
	APP2EXT_ERROR_INVALID_PACKAGE,
	APP2EXT_ERROR_CREATE_DIR_ENTRY,
	APP2EXT_ERROR_PASSWORD_GENERATION,
	APP2EXT_ERROR_COPY_DIRECTORY,
	APP2EXT_ERROR_INVALID_CASE,
	APP2EXT_ERROR_SYMLINK_ALREADY_EXISTS,
	APP2EXT_ERROR_APPEND_HASH_TO_FILE,
	APP2EXT_ERROR_CREATE_DEVICE,
	APP2EXT_ERROR_DO_LOSETUP,
	APP2EXT_ERROR_CREATE_FS,
	APP2EXT_ERROR_MOUNT_PATH,
	APP2EXT_ERROR_CLEANUP,
	APP2EXT_ERROR_MOUNT,
	APP2EXT_ERROR_REMOUNT,
	APP2EXT_ERROR_PIPE_CREATION,
	APP2EXT_ERROR_LOOPBACK_DEVICE_UNAVAILABLE,
	APP2EXT_ERROR_VCONF_REGISTRY,
	APP2EXT_ERROR_FIND_ASSOCIATED_DEVICE_NODE,
	APP2EXT_ERROR_UNMOUNT,
	APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE,
	APP2EXT_ERROR_DETACH_LOOPBACK_DEVICE,
	APP2EXT_ERROR_ALREADY_MOUNTED,
	APP2EXT_ERROR_PLUGIN_INIT_FAILED,
	APP2EXT_ERROR_PLUGIN_DEINIT_FAILED,
	APP2EXT_ERROR_DBUS_FAILED,
	APP2EXT_ERROR_MEMORY_ALLOC_FAILED,
	APP2EXT_ERROR_OPERATION_NOT_PERMITTED,
	APP2EXT_ERROR_SAME_LOOPBACK_DEVICE_EXISTS,
	APP2EXT_ERROR_PKGMGR_ERROR,
	APP2EXT_ERROR_SETUP_DMCRYPT_DEVICE,
	APP2EXT_ERROR_OPEN_DMCRYPT_DEVICE,
	APP2EXT_ERROR_CLOSE_DMCRYPT_DEVICE,
	APP2EXT_ERROR_FIND_ASSOCIATED_DMCRYPT_DEVICE_NODE,
	APP2EXT_ERROR_DMCRYPT_DEVICE_UNAVAILABLE
} app2ext_error;

/**
 * @brief :This function type is for a function that is implemented by plugin
 * and called before application is to be installed.
 *
 * @param[in] 	appname		application package name which is to be installed
 * @param[in] 	dir_list	directory structure of the application
 *                              This should be polulated by the package manager
 *                              before calling pre_install and should be freed after
 *                              pre_install returns.
 *                              Each node of dir_list is of type app2ext_dir_details
 *                              which has members Name(dirname) and Type (RO/RW)
 *                              For eg for rpm the dir_list should be populated with
 *                              nodes like : (lib, APP2EXT_DIR_RO), (res, APP2EXT_DIR_RO),
                                (bin, APP2EXT_DIR_RO), (data, APP2EXT_DIR_RW)
 * @param[in]	size		Size of the application
 * @return 	0 if success,  error code(>0) if fail
 */
typedef int (*app2ext_client_usr_pre_install)(const char *appname, GList* dir_list,
		int size, uid_t uid);
typedef int (*app2ext_client_pre_install)(const char *appname, GList* dir_list,
		int size);

/**
 * @brief :This function type is for a function that is implemented by plugin
 * and called after application installation.
 *
 * @param[in] 	appname		application package name which is to be installed
 * @param[in]	install_status	Installation status (Success/Failure)
 *				[ Enum :APP2EXT_STATUS_SUCCESS,
 *					APP2EXT_STATUS_FAILED]
 * @return 	0 if success,  error code(>0) if fail
 */
typedef int (*app2ext_client_usr_post_install)(const char *appname,
		app2ext_status install_status, uid_t uid);
typedef int (*app2ext_client_post_install)(const char *appname,
		app2ext_status install_status);

/**
 * @brief :This function type is for a function that is implemented by plugin
 * and called before application upgrade.
 *
 * @param[in] 	appname		application package name which is to be upgraded
 * @param[in] 	dir_list	directory structure of the application
 *                              This should be polulated by the package manager
 *                              before calling pre_upgrade and should be freed after
 *                              pre_upgrade returns.
 *                              Each node of dir_list is of type app2ext_dir_details
 *                              which has members Name(dirname) and Type (RO/RW)
 *                              For eg for rpm the dir_list should be populated with
 *                              nodes like : (lib, APP2EXT_DIR_RO), (res, APP2EXT_DIR_RO),
                                (bin, APP2EXT_DIR_RO), (data, APP2EXT_DIR_RW)
 * @param[in]	size		Size of the application
 * @return 	0 if success,  error code(>0) if fail
 */
typedef int (*app2ext_client_usr_pre_upgrade)(const char *appname, GList* dir_list,
		int size, uid_t uid);
typedef int (*app2ext_client_pre_upgrade)(const char *appname, GList* dir_list,
		int size);

/**
 * @brief :This function type is for a function that is implemented by plugin
 * and called before application upgradation.
 *
 * @param[in] 	appname		application package name which is to be upgraded
 * @param[in]	upgrade_status	Upgrade status (Success/Failure)
 *				[ Enum :APP2EXT_STATUS_SUCCESS,
 *					APP2EXT_STATUS_FAILED]
 * @return 	0 if success,  error code(>0) if fail
 */
typedef int (*app2ext_client_usr_post_upgrade)(const char *appname,
		app2ext_status upgrade_status, uid_t uid);
typedef int (*app2ext_client_post_upgrade)(const char *appname,
		app2ext_status upgrade_status);

/**
 * @brief :This function type is for a function that is implemented by plugin
 * and called before application uninstallation.
 *
 * @param[in] 	appname		application package name which is to be uninstalled
 * @return 	0 if success,  error code(>0) if fail
 */
typedef int (*app2ext_client_usr_pre_uninstall)(const char *appname, uid_t uid);
typedef int (*app2ext_client_pre_uninstall)(const char *appname);

/**
 * @brief :This function type is for a function that is implemented by plugin
 * and called after application uninstallation.
 *
 * @param[in] 	appname		application package name which is to be uninstalled
 * @return 	0 if success,  error code(>0) if fail
 */
typedef int (*app2ext_client_usr_post_uninstall)(const char *appname, uid_t uid);
typedef int (*app2ext_client_post_uninstall)(const char *appname);

/**
 * @brief :This function type is for a function that is implemented by plugin
 * and called when application is to be moved from extrenal memory
 *to internal memory or vice versa.
 *
 * @param[in] 	appname		application package name which is to be moved
 * @param[in] 	dir_list	directory structure of the application
 *                              This should be polulated by the package manager
 *                              before calling move and should be freed after
 *                              move returns.
 *                              Each node of dir_list is of type app2ext_dir_details
 *                              which has members Name(dirname) and Type (RO/RW)
 *                              For eg for rpm the dir_list should be populated with
 *                              nodes like : (lib, APP2EXT_DIR_RO), (res, APP2EXT_DIR_RO),
                                (bin, APP2EXT_DIR_RO), (data, APP2EXT_DIR_RW)
 * @param[in]	move_type	move type
 *				[Enum: APP2EXT_MOVE_TO_EXT, APP2EXT_MOVE_TO_PHONE]
 * @return 	0 if success,  error code(>0) if fail
 */
typedef int (*app2ext_client_usr_move)(const char *appname, GList* dir_list,
		app2ext_move_type move_type, uid_t uid);
typedef int (*app2ext_client_move)(const char *appname, GList* dir_list,
		app2ext_move_type move_type);

/**
 * @brief :This function type is for a function that is implemented by plugin
 * and called to enable application before application launch.
 *
 * @param[in] 	appname		application package name which is to be enabled
 * @return 	0 if success,  error code(>0) if fail
 */
typedef int (*app2ext_client_usr_enable)(const char *appname, uid_t uid);
typedef int (*app2ext_client_enable)(const char *appname);

/**
 * @brief :This function type is for a function that is implemented by plugin
 * and called to disable application before application exit.
 *
 * @param[in] 	appname		application package name which is to be disabled
 * @return 	0 if success,  error code(>0) if fail
 */
typedef int (*app2ext_client_usr_disable)(const char *appname, uid_t uid);
typedef int (*app2ext_client_disable)(const char *appname);

/**
 * @brief :This function type is for a function that is implemented by plugin
 * and called after application uninstallation.
 *
 * @param[in] 	pkgid		application package name which is to be uninstalled
 * @return 	0 if success,  error code(>0) if fail
 */
typedef int (*app2ext_client_usr_force_clean)(const char *pkgid, uid_t uid);
typedef int (*app2ext_client_force_clean)(const char *pkgid);

/**
 * This structure defines the app2ext interfaces. Plugins have to implement these functions
 */
typedef struct app2ext_interface_t{
	/* for library function */
	app2ext_client_pre_install		client_pre_install;
	app2ext_client_post_install		client_post_install;
	app2ext_client_pre_upgrade		client_pre_upgrade;
	app2ext_client_post_upgrade		client_post_upgrade;
	app2ext_client_pre_uninstall		client_pre_uninstall;
	app2ext_client_post_uninstall		client_post_uninstall;
	app2ext_client_force_clean		client_force_clean;
	app2ext_client_enable			client_enable;
	app2ext_client_disable			client_disable;
	app2ext_client_move			client_move;

	app2ext_client_usr_pre_install		client_usr_pre_install;
	app2ext_client_usr_post_install		client_usr_post_install;
	app2ext_client_usr_pre_upgrade		client_usr_pre_upgrade;
	app2ext_client_usr_post_upgrade		client_usr_post_upgrade;
	app2ext_client_usr_pre_uninstall	client_usr_pre_uninstall;
	app2ext_client_usr_post_uninstall	client_usr_post_uninstall;
	app2ext_client_usr_force_clean		client_usr_force_clean;
	app2ext_client_usr_enable		client_usr_enable;
	app2ext_client_usr_disable		client_usr_disable;
	app2ext_client_usr_move			client_usr_move;
} app2ext_interface;

/**
 * This structure defines app2ext handle .Each storage type maps to a different plugin
 * type			: storage type,
 * plugin_handle	: plugin handle, need to close dlopen handle
 * interface		: inteface with plugin library
 */
typedef struct {
	app2ext_install_location 	type;
	void				*plugin_handle;
	app2ext_interface 		interface;
} app2ext_handle;

/**
 * This structure defines directory details
 * name			: directory name
 * type			: permission (rw/ro)
 */
typedef struct {
	char *		name;
	app2ext_dir_type 	type;
} app2ext_dir_details;

/**
 * @brief : This API initializes the appropriate plugin based on storage type.
 *	It should be called before installation/uninstallation/upgrade
 * @param[in] storage_type	Location where package should be installed
 *				[Ex: SD card, MicroUSB, Cloud]
 * @return	app2ext_handle pointer if success, NULL if fail
 *
 @code
 #include <app2ext_interface.h>
 app2ext_handle *handle = NULL;
 GLIst *dir_list = NULL;
 handle = app2ext_init(APP2EXT_SD_CARD); //Initializes SD card plug-in
 if(handle)
 {
	printf("\n SUCCESS");
	// Perform package install/uninstall/upgrade/move here
	// Packge install example
	// Package manager should polulate dir_list with directory structure information of the package
	ret = handle->interface.pre_install("com.samsung.calculator", dir_list, 20);
	if (ret) {
		printf("\n TC : pre app install API fail. Reason %s", error_list[ret]);
		return -1;
	}

	// Package manager installs the package

	ret = handle->interface.post_install("com.samsung.calculator", APP2EXT_STATUS_SUCCESS);
	if (ret) {
		printf("\n TC : post app install API fail Reason %s", error_list[ret]);

		return -1;
	}
	// Package manager should free dir_list
	return;
 } else
	 printf("\n FAILURE");
 @endcode
 */
API app2ext_handle *app2ext_init(int storage_type);

/**
 * @brief : This API deinitializes the plugin
 *	    This should be called when use of the plugin is completed
 * @param[in] handle	pointer to app2ext_handle which is to be deinitialized
 * @pre		Initialization is done for the storage handle
 * @return	0 if success,  error code(>0) if fail
 *
 @code
 #include <app2ext_interface.h>
 app2ext_handle *handle = NULL;
 handle = app2ext_init(APP2EXT_SD_CARD); //Initializes SD card plug-in
 int ret = -1;
 ret = app2ext_deinit(handle); // De-initializes the SD plugin
 if(!ret)
 {
	 printf("\n SUCCESS");
 }
 else
 printf("\n FAILURE");
 @endcode
 */
API int app2ext_deinit(app2ext_handle *handle);

/**
 * @brief : This API returns the application location by refering to package manager DB
 *	This should be called to know location of an application package
 * @param[in] pkgid	package id
 * @param[in] uid	target user id of this instruction
 * @return	APP2EXT_SD_CARD if pkg is in SD card,
 *		APP2EXT_INTERNAL_MEM if app is in internal memory
 *		error code(>0) if fail
 *@remarks see app2ext_install_location for more details
 */
API int app2ext_get_app_location(const char *pkgid);
API int app2ext_usr_get_app_location(const char *pkgid, uid_t uid);

/**
 * @brief : This API enable the package which is located in external memory
 * @param[in] pkgid	package id
 * @param[in] uid	target user id of this instruction
 * @return	error < 0  if pkg enable fail ,
 */
API int app2ext_enable_external_pkg(const char *pkgid);
API int app2ext_usr_enable_external_pkg(const char *pkgid, uid_t uid);

/**
 * @brief : This API disable the package which is located in external memory
 * @param[in] pkgid	package id
 * @param[in] uid	target user id of this instruction
 * @return	error < 0  if pkg enable fail ,
 */
API int app2ext_disable_external_pkg(const char *pkgid);
API int app2ext_usr_disable_external_pkg(const char *pkgid, uid_t uid);

/**
 * @brief : This API clean the directory and symbolic link which are made by app2ext
 * @param[in] pkgid	package id
 * @param[in] uid	target user id of this instruction
 * @return	error < 0  if pkg enable fail ,
 */
API int app2ext_force_clean_pkg(const char *pkgid);
API int app2ext_usr_force_clean_pkg(const char *pkgid, uid_t uid);

#ifdef __cplusplus
}
#endif
#endif
