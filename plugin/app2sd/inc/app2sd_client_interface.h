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

#ifndef __APPTOSD_INTERFACE_H__
#define __APPTOSD_INTERFACE_H__

/**
 * @file app2sd_client_interface.h
 * @version 0.2
 * @brief    This file declares API of app2sd library
 */
/**
 * @addtogroup APPLICATION_FRAMEWORK
 * @{
 *
 * @defgroup app2sd
 * @version    0.2
 *
 * @section    Header to use them:
 * @code
 * #include <app2sd_client_interface.h>
 * @endcode
 *
 * @addtogroup app2sd
 * @{
 */


#ifdef __cplusplus
extern "C" {
#endif

#include "app2ext_interface.h"

/**
 * @brief : This API prepares the setup for installation in SD card.
 *		It should be called before actual installation is done.
 * @pre		vfat type sd card must be present.
 * @post	Installation is done by package installer.
 *		Encryption password is saved in db TZ_SYS_DB/.app2sd.db
 * @param[in] appname		application package name
 *				[Ex: com.samsung.calculator]
 *This entry is parsed from application package control/manifest file.
 * @param[in] dir_list		directory structure of the application
 * @param[in] size	size of memory required by application(in MB).
 *This entry is parsed from application package control/manifest file.
 * @return	0 if success,  error code(>0) if fail
 * @remark	None.
 */
int app2sd_client_usr_pre_app_install(const char *pkgid,
		GList *dir_list, int size, uid_t uid);
int app2sd_client_pre_app_install(const char *pkgid,
		GList *dir_list, int size);

/**
 * @brief : This API does post installation operations after
 *		the installation in SD card
 * @param[in] appname		application package name
 *				[Ex: com.samsung.calculator]
 * @param[in] install_status	Status of installation of package
 *[ enum app2ext_status].If package installation failed then
 * install_status= APP2EXT_STATUS_FAILURE else if installation
 * was successful then install_status = APP2EXT_ISTATUS_SUCCESS.
 * @pre		Installation should be done by package installer.
 * @return	0 if success,  error code(>0) if fail
 * @remark	@see enum app2sd_install_status
 */
int app2sd_client_usr_post_app_install(const char *pkgid,
		app2ext_status install_status, uid_t uid);
int app2sd_client_post_app_install(const char *pkgid,
		app2ext_status install_status);

/**
 * @brief : This API prepares the setup for upgradation of
 *		 application package
 * @pre			vfat type sd card must be present.
 * @post		Upgradation is done by package installer.
 * @param[in] appname		application package name
 *				[Ex: com.samsung.calculator]
 * @param[in] dir_list		directory structure of the application
 * @param[in] size	size of memory required by application(in MB).
 *This entry is parsed from application package control/manifest file.
 * @return	0 if success,  error code(>0) if fail
 * @remark	None.
 */
int app2sd_client_usr_pre_app_upgrade(const char *pkgid,
		GList *dir_list, int size, uid_t uid);
int app2sd_client_pre_app_upgrade(const char *pkgid,
		GList *dir_list, int size);

/**
 * @brief : This API does post upgradation operations after
 *		the installation in SD card
 * @param[in] appname		application package name
 *				[Ex: com.samsung.calculator]
 * @param[in] install_status	Status of installation of package
 *[ enum app2extl_status].If package upgradation failed then
 * upgrade_status= APP2EXT_STATUS_FAILURE else if upgradation
 * was successful then upgrade_status = APP2EXT_STATUS_SUCCESS.
 * @pre		Upgradation should be done by package installer.
 * @return	0 if success,  error code(>0) if fail
 * @remark	@see enum app2ext_status
 */
int app2sd_client_usr_post_app_upgrade(const char *pkgid,
		app2ext_status upgrade_status, uid_t uid);
int app2sd_client_post_app_upgrade(const char *pkgid,
		app2ext_status upgrade_status);
/**
 * @brief: This API prepares the setup for uninstallation
 * @pre			Package must be installed in sdcard.
 * @post	Package is uninstalled by the package installer.
 * @param[in] appname		application package name
 *				[Ex: com.samsung.calculator]
 * @return	0 if success,  error code(>0) if fail
 * @remark	None.
 */
int app2sd_client_usr_pre_app_uninstall(const char *pkgid, uid_t uid);
int app2sd_client_pre_app_uninstall(const char *pkgid);

/**
 * @brief This API removes the resources created during
 app2sd setup.It is called after uninstallation.
 * @pre			Package must be uninstalled .
 * @post		Encryption password is removed from sqlite db.
 * @param[in] appname		application package name
 *				[Ex: com.samsung.calculator]
 * @return	0 if success,  error code(>0) if fail
 * @remark	None.
 */
int app2sd_client_usr_post_app_uninstall(const char *pkgid, uid_t uid);
int app2sd_client_post_app_uninstall(const char *pkgid);

/**
 * @brief : This API moves the package from sd card
 to internal memory and vice versa.
 * @param[in] pkgid		application package id
 *				[Ex: com.samsung.calculator]
 * @param[in] move_type		Move type[enum app2ext_move_type]
 *			[sd card to internal/internal to sd card]
 * @param[in] dir_list		directory structure of the application
 * @pre			Package must be installed and its installation
 * location should be known. Use dedicated API to get installation location.
 * @post	Package is moved to new location.
 * @return	0 if success,  error code(>0) if fail
 * @remark	None.
 */
int app2sd_client_usr_move_installed_app(const char *pkgid,
		GList *dir_list, app2ext_move_type move_type, uid_t uid);
int app2sd_client_move_installed_app(const char *pkgid,
		GList *dir_list, app2ext_move_type move_type);

/**
 * @brief : This API Enables the application in sd card
 for use. This API should be called by AUL.
 * @param[in] pkgid		application package id
*				[Ex: com.samsung.calculator]
 * @pre			Package must be installed
 * @post	application is enabled in SD card.
 * @return	0 if success,  error code(>0) if fail
 * @remark	None.
 */
int app2sd_client_usr_on_demand_setup_init(const char *pkgid, uid_t uid);
int app2sd_client_on_demand_setup_init(const char *pkgid);

/**
 * @brief : This API Disables the application in sd card
 . This API should be called by Launchpad callback which will be registered
  during app launch for exit action of the application
 * @param[in] pkgid		application package id
*				[Ex: com.samsung.calculator]
 * @pre			Package must be installed and enabled
 *			and application must be running in SD card
 * @post	application is disabked in SD card.
 * @return	0 if success,  error code(>0) if fail
 * @remark	None.
 */
int app2sd_client_usr_on_demand_setup_exit(const char *pkgid, uid_t uid);
int app2sd_client_on_demand_setup_exit(const char *pkgid);

int app2sd_client_usr_force_clean(const char *pkgid, uid_t uid);
int app2sd_client_force_clean(const char *pkgid);

/**
 * @brief : This is the plug-in load function.
 *	The plugin has to bind its functions to function pointers of storage handle
 * @param[in/out] st_interface		Specifies the storage interface.
 * @return	None
*/
API void app2ext_on_load(app2ext_interface *st_interface);

#ifdef __cplusplus
}
#endif
#endif