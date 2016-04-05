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
#include <glib.h>
#include <gio/gio.h>
#include <pkgmgr-info.h>

int _is_global(uid_t uid)
{
	if (uid == OWNER_ROOT || uid == GLOBAL_USER)
		return 1;
	else
		return 0;
}

static int __app2sd_create_app2sd_directories(uid_t uid)
{
	int ret = 0;
	char app2sd_user_path[FILENAME_MAX] = { 0, };
	mode_t mode = DIR_PERMS;

	ret = mkdir(APP2SD_PATH, mode);
	if (ret) {
		if (errno != EEXIST) {
			app2ext_print("App2sd Error : Create directory failed,"
				" error no is %d\n", errno);
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
				app2ext_print("App2sd Error : Create directory failed,"
					" error no is %d\n", errno);
				return APP2EXT_ERROR_CREATE_DIRECTORY;
			}
		}
	}

	return APP2EXT_SUCCESS;
}

static int app2sd_gdbus_shared_connection(GDBusConnection **connection)
{
	GError *error = NULL;

#if (GLIB_MAJOR_VERSION <= 2 && GLIB_MINOR_VERSION < 36)
	g_type_init();
#endif

	*connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (*connection == NULL) {
		if (error != NULL) {
			_E("app2sd error : failed to get "
				"system dbus [%s]\n", error->message);
			g_error_free(error);
		}
		return APP2EXT_ERROR_DBUS_FAILED;
	}

	return APP2EXT_SUCCESS;
}

static int __app2sd_call_server_method(const gchar *method_name,
		GVariant *param)
{
	int ret = APP2EXT_SUCCESS;
	int result = 0;
	GDBusConnection *conn = NULL;
	GDBusProxy *proxy = NULL;
	GError *error = NULL;
	GVariant *value = NULL;

	/* get gdbus connection */
	ret = app2sd_gdbus_shared_connection(&conn);
	if (ret) {
		_E("app2sd error : dbus connection error");
		return ret;
	}

	/* method call */
	proxy = g_dbus_proxy_new_sync(conn,
		G_DBUS_PROXY_FLAGS_NONE, NULL,
		APP2SD_BUS_NAME, APP2SD_OBJECT_PATH, APP2SD_INTERFACE_NAME,
		NULL, &error);
	if (proxy == NULL) {
		_E("failed to create new proxy, error(%s)", error->message);
		g_error_free(error);
		ret = APP2EXT_ERROR_DBUS_FAILED;
		goto out;
	}

	value = g_dbus_proxy_call_sync(proxy, method_name, param,
		G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (error != NULL) {
		_E("proxy call sync error(%s)", error->message);
		g_error_free(error);
		ret = APP2EXT_ERROR_DBUS_FAILED;
		goto out;
	}

	g_variant_get(value, "(i)", &result);
	g_variant_unref(value);

	_D("result(%d)", result);
	if (result)
		ret = result;

out:
	if (conn)
		g_object_unref(conn);

	return ret;
}

static void __app2sd_create_dir_list_builder(gpointer data, gpointer user_data)
{
	app2ext_dir_details *item = (app2ext_dir_details *)data;
	GVariantBuilder *builder = (GVariantBuilder *)user_data;

	g_variant_builder_add(builder, "(si)", item->name, item->type);
}

int app2sd_client_usr_pre_app_install(const char *pkgid, GList* dir_list,
		int size, uid_t uid)
{
	int ret = 0;
	GVariantBuilder *builder = NULL;
	GVariant *param = NULL;

	/* validate the function parameter recieved */
	if (pkgid == NULL || dir_list == NULL || size <= 0) {
		_E("invalid function arguments");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("a(si)"));
	g_list_foreach(dir_list, __app2sd_create_dir_list_builder, builder);

	param = g_variant_new("(sia(si))", pkgid, size, builder);
	ret = __app2sd_call_server_method("PreAppInstall", param);

	if (builder)
		g_variant_builder_unref(builder);

	return ret;
}

int app2sd_client_usr_post_app_install(const char *pkgid,
		app2ext_status install_status, uid_t uid)
{
	int ret = 0;
	GVariant *param = NULL;

	/* validate the function parameter recieved */
	if (pkgid == NULL || install_status < APP2EXT_STATUS_FAILED
		|| install_status > APP2EXT_STATUS_SUCCESS) {
		app2ext_print("Invalid func parameters\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	param = g_variant_new("(sii)", pkgid, install_status, uid);
	ret = __app2sd_call_server_method("PostAppInstall", param);

	return ret;
}

int app2sd_client_usr_pre_app_upgrade(const char *pkgid, GList* dir_list,
		int size, uid_t uid)
{
	int ret = 0;
	GVariantBuilder *builder = NULL;
	GVariant *param = NULL;

	/* validate the function parameter recieved */
	if (pkgid == NULL || dir_list == NULL || size <= 0) {
		_E("invalid function arguments");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("a(si)"));
	g_list_foreach(dir_list, __app2sd_create_dir_list_builder, builder);

	param = g_variant_new("(sia(si)i)", pkgid, size, builder, uid);
	ret = __app2sd_call_server_method("PreAppUpgrade", param);

	if (builder)
		g_variant_builder_unref(builder);

	return ret;
}

int app2sd_client_usr_post_app_upgrade(const char *pkgid,
		app2ext_status install_status, uid_t uid)
{
	int ret = 0;
	GVariant *param = NULL;

	/* validate the function parameter recieved */
	if (pkgid == NULL || install_status < APP2EXT_STATUS_FAILED
		|| install_status > APP2EXT_STATUS_SUCCESS) {
		app2ext_print("Invalid func parameters\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	param = g_variant_new("(sii)", pkgid, install_status, uid);
	ret = __app2sd_call_server_method("PostAppUpgrade", param);

	return ret;
}

int app2sd_client_usr_pre_app_uninstall(const char *pkgid, uid_t uid)
{
	int ret = 0;
	GVariant *param = NULL;

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		app2ext_print("Invalid func parameters\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	param = g_variant_new("(si)", pkgid, uid);
	ret = __app2sd_call_server_method("PreAppUninstall", param);

	return ret;
}

int app2sd_client_usr_post_app_uninstall(const char *pkgid, uid_t uid)
{
	int ret = 0;
	GVariant *param = NULL;

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		app2ext_print("Invalid func parameters\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	param = g_variant_new("(si)", pkgid, uid);
	ret = __app2sd_call_server_method("PostAppUninstall", param);

	return ret;
}

int app2sd_client_usr_force_clean(const char *pkgid, uid_t uid)
{
	int ret = 0;
	GVariant *param = NULL;

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		app2ext_print("Invalid func parameters\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	param = g_variant_new("(si)", pkgid, uid);
	ret = __app2sd_call_server_method("ForceClean", param);

	return ret;
}

int app2sd_client_usr_on_demand_setup_init(const char *pkgid, uid_t uid)
{
	int ret = 0;
	GVariant *param = NULL;

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		app2ext_print("Invalid func parameters\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	param = g_variant_new("(si)", pkgid, uid);
	ret = __app2sd_call_server_method("OndemanSetupInit", param);

	return ret;
}

int app2sd_client_usr_on_demand_setup_exit(const char *pkgid, uid_t uid)
{
	int ret = 0;
	GVariant *param = NULL;

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		app2ext_print("Invalid func parameters\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	param = g_variant_new("(si)", pkgid, uid);
	ret = __app2sd_call_server_method("OndemanSetupExit", param);

	return ret;
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
		app2ext_print("App2Sd Error : Operation not permitted\n");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate the function parameter recieved */
	if (pkgid == NULL || dir_list == NULL || size <= 0) {
		app2ext_print("App2Sd Error : Invalid function arguments\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR"
			" Not ready %d\n", ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}

	/* find available free memory in the MMC card */
	ret = _app2sd_get_available_free_memory(MMC_PATH, &free_mmc_mem);
	if (ret) {
		app2ext_print("App2Sd Error : Unable to get available"
			" free memory in MMC %d\n", ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}
	app2ext_print("Size details for application installation:"
		"size=%dMB, reqd_disk_size=%dMB, free_mmc_size=%dMB\n",
		 size, reqd_disk_size, free_mmc_mem);

	/* if avaialalbe free memory in MMC is less than required size + 5MB,
	 * return error
	 */
	if ((reqd_disk_size + PKG_BUF_SIZE + MEM_BUF_SIZE) > free_mmc_mem) {
		app2ext_print("Insufficient memory in MMC for"
			" application installation %d\n", ret);
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
		app2ext_print("App2Sd Error : failed to create app2sd dirs");
	}

	/* create a loopback device */
	ret = _app2sd_create_loopback_device(pkgid, loopback_device,
		(reqd_disk_size + PKG_BUF_SIZE));
	if (ret) {
		app2ext_print("App2Sd Error : Package already present\n");
		ret = _app2sd_delete_directory(application_path);
		if (ret)
			app2ext_print("App2Sd Error : Unable to delete"
				" the directory %s\n", application_path);
	}

	/* perform Loopback encryption setup */
	device_node = _app2sd_do_loopback_encryption_setup(pkgid,
		loopback_device);
	if (!device_node) {
		app2ext_print("App2Sd Error : "
			"Loopback encryption setup failed\n");
		_app2sd_delete_loopback_device(loopback_device);
		return APP2EXT_ERROR_DO_LOSETUP;
	}

	/* check whether loopback device is associated
	 * with device node or not
	 */
	devi = _app2sd_find_associated_device_node(loopback_device);
	if (devi == NULL) {
		app2ext_print("App2Sd Error : "
			"finding associated device node failed\n");
		ret = APP2EXT_ERROR_DO_LOSETUP;
		goto FINISH_OFF;
	}

	/* format the loopback file system */
	ret = _app2sd_create_file_system(device_node);
	if (ret) {
		app2ext_print("App2Sd Error : creating FS failed failed\n");
		ret = APP2EXT_ERROR_CREATE_FS;
		goto FINISH_OFF;
	}

	/* mount the loopback encrypted pseudo device on application
	 * installation path as with Read Write permission
	 */
	ret =_app2sd_mount_app_content(application_path, device_node, MOUNT_TYPE_RW,
		dir_list, APP2SD_PRE_INSTALL);
	if (ret) {
		app2ext_print("App2Sd Error : "
			"mounting dev path to app install path failed\n");
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

	if (__app2sd_check_operation_permission() < 0) {
		app2ext_print("App2Sd Error : Operation not permitted\n");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate the function parameter recieved */
	if (pkgid == NULL || install_status < APP2EXT_STATUS_FAILED
		|| install_status > APP2EXT_STATUS_SUCCESS) {
		app2ext_print("Invalid func parameters\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not present OR "
			"Not ready %d\n", ret);
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
		app2ext_print("Unable to unmount the app content %d\n", ret);
		return APP2EXT_ERROR_UNMOUNT;
	}

	ret = _app2sd_remove_loopback_encryption_setup(loopback_device);
	if (ret) {
		if (device_name) {
			free(device_name);
			device_name = NULL;
		}
		app2ext_print("Unable to Detach the loopback encryption setup"
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
			app2ext_print("App2Sd Error : Unable to delete "
				"the loopback device from the SD Card\n");
			return APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
		}
		ret = _app2sd_remove_password_from_db(pkgid);

		if (ret)
			app2ext_print("App2Sd Error : Unable to delete "
				"the password\n");

		ret = _app2sd_delete_directory(application_path);

		if (ret)
			app2ext_print("App2Sd Error : Unable to delete "
				"the directory (%s)\n", application_path);
	} else {
		/* if the status is success, then update installed storage
		 * to pkgmgr_parser db
		 */
		int rt = 0;
		rt = pkgmgrinfo_pkginfo_set_usr_installed_storage(pkgid,
			INSTALL_EXTERNAL, uid);
		if (rt < 0)
			app2ext_print("fail to update installed location "
				"to db[%s, %d, %d]\n",
				pkgid, INSTALL_EXTERNAL, uid);
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
		app2ext_print("App2Sd Error : Operation not permitted\n");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		app2ext_print
		    ("App2Sd Error : Invalid function arguments to app launch setup\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR Not ready %d\n",
			     ret);
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
		app2ext_print
		    ("App2SD Error: App Entry is not present in SD Card\n");
		return APP2EXT_ERROR_INVALID_PACKAGE;
	}
	fclose(fp);

	result = (char *)_app2sd_find_associated_device(loopback_device);
	/* process the string */
	if ((result != NULL) && strstr(result, "/dev") != NULL) {
		app2ext_print("App2SD Error! Already associated\n");
		free(result);
		result = NULL;
		return APP2EXT_ERROR_ALREADY_MOUNTED;
	}

	/* do loopback setup */
	device_node = _app2sd_do_loopback_encryption_setup(pkgid,
		loopback_device);
	if (device_node == NULL) {
		app2ext_print
		    ("App2Sd Error : loopback encryption setup failed\n");
		return APP2EXT_ERROR_DO_LOSETUP;
	}

	/* do mounting */
	ret =
	    _app2sd_mount_app_content(application_path, device_node, MOUNT_TYPE_RD,
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

int app2sd_usr_on_demand_setup_exit(const char *pkgid, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;
	char application_path[FILENAME_MAX] = { 0, };
	char loopback_device[FILENAME_MAX] = { 0, };
	FILE *fp = NULL;

	if (__app2sd_check_operation_permission() < 0) {
		app2ext_print("App2Sd Error : Operation not permitted\n");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		app2ext_print
		    ("App2Sd Error : Invalid function arguments to app launch setup\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR Not ready %d\n",
			     ret);
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
		app2ext_print
		    ("App2SD Error: App Entry is not present in SD Card\n");
		return APP2EXT_ERROR_INVALID_PACKAGE;
	}
	fclose(fp);

	ret = _app2sd_unmount_app_content(application_path);
	if (ret) {
		app2ext_print
		    ("App2SD Error: Unable to unmount the SD application\n");
		return APP2EXT_ERROR_UNMOUNT;
	}

	ret = _app2sd_remove_loopback_encryption_setup(loopback_device);
	if (ret) {
		app2ext_print("App2SD Error: Unable to remove loopback setup\n");
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
		app2ext_print("App2Sd Error : Operation not permitted\n");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		app2ext_print("App2Sd Error : Invalid function arguments"
			" to app launch setup\n");
		ret = APP2EXT_ERROR_INVALID_ARGUMENTS;
		goto END;
	}

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR"
			" Not ready %d\n", ret);
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
		app2ext_print("App2SD Error: "
			"App Entry is not present in SD Card\n");
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
			app2ext_print("App2Sd Error : "
				"loopback encryption setup failed\n");
			ret = APP2EXT_ERROR_DO_LOSETUP;
			goto END;
		}
		/* do mounting */
		ret = _app2sd_mount_app_content(application_path,
			device_node, MOUNT_TYPE_RW, NULL,
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
		/* do re-mounting */
		ret = _app2sd_mount_app_content(application_path,
			device_node, MOUNT_TYPE_RW_REMOUNT, NULL,
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
		app2ext_print("App2Sd Error : app2sd has [%d]error, "
			"but return success for uninstallation\n", ret);
	return ret;
}

/*
* app2sd_post_app_uninstall_setup
* uninstall Application and free all the allocated resources
* called after dpkg remove, It deallocates dev node and loopback
*/
int app2sd_usr_post_app_uninstall(const char *pkgid, uid_t uid)
{
	char application_path[FILENAME_MAX] = { 0, };
	char loopback_device[FILENAME_MAX] = { 0, };
	int ret = APP2EXT_SUCCESS;

	if (__app2sd_check_operation_permission() < 0) {
		app2ext_print("App2Sd Error : Operation not permitted\n");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		app2ext_print("App2Sd Error : Invalid function arguments "
			"to Post Uninstall\n");
		ret = APP2EXT_ERROR_INVALID_ARGUMENTS;
		goto END;
	}

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR "
			"Not ready %d\n", ret);
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
		app2ext_print("Unable to unmount the app content %d\n", ret);
		ret = APP2EXT_ERROR_UNMOUNT;
		goto END;
	}
	/* detach the loopback encryption setup for the application */
	ret = _app2sd_remove_loopback_encryption_setup(loopback_device);
	if (ret) {
		app2ext_print("Unable to Detach the loopback encryption setup"
			" for the application");
		ret = APP2EXT_ERROR_DETACH_LOOPBACK_DEVICE;
		goto END;
	}

	/* delete the loopback device from the SD card */
	ret = _app2sd_delete_loopback_device(loopback_device);
	if (ret) {
		app2ext_print("App2Sd Error : Unable to delete the "
			"loopback device from the SD Card\n");
		ret =  APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
		goto END;
	}

	ret = _app2sd_delete_directory(application_path);
	if (ret) {
		app2ext_print("App2Sd Error : Unable to delete "
			"the directory %s\n", application_path);
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
		app2ext_print("App2Sd Error : app2sd has [%d]error, "
			"but return success for uninstallation\n", ret);

	return ret;
}

#if 0
int app2sd_usr_move_installed_app(const char *pkgid, GList* dir_list,
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
		app2ext_print("App2Sd info : pkgid[%s] move to STORAGE[%d]\n", pkgid, storage);
	}
	pkgmgrinfo_pkginfo_destroy_pkginfo(info_handle);

	ret = _app2sd_move_app(pkgid, move_type, dir_list);
	if (ret) {
		app2ext_print("App2Sd Error : Unable to move application\n");
		goto END;
	}

	/* If move is completed, then update installed storage to pkgmgr_parser db */
	if (move_type == APP2EXT_MOVE_TO_EXT) {
		pkgmgrinfo_ret = pkgmgrinfo_pkginfo_set_installed_storage(pkgid, INSTALL_EXTERNAL);
		if (pkgmgrinfo_ret < 0) {
			app2ext_print("App2Sd Error : fail to update installed location to db[%s, %s]\n", pkgid, INSTALL_EXTERNAL);
		}
	} else {
		pkgmgrinfo_ret = pkgmgrinfo_pkginfo_set_installed_storage(pkgid, INSTALL_INTERNAL);
		if (pkgmgrinfo_ret < 0) {
			app2ext_print("App2Sd Error : fail to update installed location to db[%s, %s]\n", pkgid, INSTALL_INTERNAL);
		}
	}
END:

	_app2sd_make_result_info_file((char*)pkgid, ret);

	return ret;
}
#endif

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
		app2ext_print("App2Sd Error : Operation not permitted\n");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate function arguments*/
	if (pkgid == NULL || dir_list == NULL || size<=0) {
		app2ext_print("App2Sd Error : Invalid function arguments\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR "
			"Not ready %d\n", ret);
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
		app2ext_print("App2SD Error: App Entry is not "
			"present in SD Card\n");
		return APP2EXT_ERROR_INVALID_PACKAGE;
	}
	fclose(fp);

	/* get installed app size*/
	curr_size = _app2sd_calculate_file_size(loopback_device);
	curr_size = (curr_size) / (1024 * 1024);
	if (curr_size==0) {
		app2ext_print("App2SD Error: App Entry is not "
			"present in SD Card\n");
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
			reqd_disk_size, dir_list);
		if (APP2EXT_SUCCESS != ret) {
			app2ext_print("App2SD Error: failed to update"
				" loopback device size\n");
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
			app2ext_print("App2Sd Error : loopback encryption"
				" setup failed\n");
			return APP2EXT_ERROR_DO_LOSETUP;
		}

		/* do mounting */
		ret = _app2sd_mount_app_content(application_path, device_node,
			MOUNT_TYPE_RW, dir_list, APP2SD_PRE_UPGRADE);
		if (ret) {
			app2ext_print("App2Sd Error : Re-mount failed\n");
			if (device_node) {
				free(device_node);
				device_node = NULL;
			}
			return APP2EXT_ERROR_MOUNT_PATH;
		}
	} else {
		/* do re-mounting */
		ret = _app2sd_mount_app_content(application_path, device_node,
			MOUNT_TYPE_RW_REMOUNT, NULL, APP2SD_PRE_UPGRADE);
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

int app2sd_usr_post_app_upgrade(const char *pkgid,
		app2ext_status install_status, uid_t uid)
{
	char *device_name = NULL;
	char loopback_device[FILENAME_MAX] = { 0, };
	char application_path[FILENAME_MAX] = { 0, };
	int ret = APP2EXT_SUCCESS;

	if (__app2sd_check_operation_permission() < 0) {
		app2ext_print("App2Sd Error : Operation not permitted\n");
		return APP2EXT_ERROR_OPERATION_NOT_PERMITTED;
	}

	/* validate the function parameter recieved */
	if (pkgid == NULL || install_status < APP2EXT_STATUS_FAILED
		|| install_status > APP2EXT_STATUS_SUCCESS) {
		app2ext_print("Invalid func parameters\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR "
			"Not ready %d\n", ret);
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
		app2ext_print("Unable to unmount the app content %d\n", ret);
		return APP2EXT_ERROR_UNMOUNT;
	}

	ret = _app2sd_remove_loopback_encryption_setup(loopback_device);
	if (ret) {
		if (device_name) {
			free(device_name);
			device_name = NULL;
		}
		app2ext_print("Unable to Detach the loopback encryption "
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

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		app2ext_print("Invalid func parameters\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}
	app2ext_print("start force_clean [%s]", pkgid);

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
		app2ext_print("Unable to unmount the app content %d\n", ret);
	}

	/* detach the loopback encryption setup for the application */
	ret = _app2sd_remove_all_loopback_encryption_setups(pkgid);
	if (ret) {
		app2ext_print("Unable to Detach the loopback encryption setup for the application");
	}

	/* delete the loopback device from the SD card */
	ret = _app2sd_delete_loopback_device(loopback_device);
	if (ret) {
		app2ext_print("Unable to Detach the loopback encryption setup for the application");
	}

	/* delete symlink */
	_app2sd_delete_symlink(application_path);

	/* remove passwrd from DB */
	ret = _app2sd_initialize_db();
	if (ret) {
		app2ext_print("\n app2sd db initialize failed");
	}
	ret = _app2sd_remove_password_from_db(pkgid);
	if (ret) {
		app2ext_print("cannot remove password from db \n");
	}

	app2ext_print("finish force_clean");
	return 0;
}

/* This is the plug-in load function. The plugin has to bind its functions to function pointers of handle
 * @param[in/out] interface, Specifies the storage interface.
 */
void app2ext_on_load(app2ext_interface *interface)
{
	/* Plug-in Binding.*/
	interface->client_usr_pre_install = app2sd_client_usr_pre_app_install;
	interface->client_usr_post_install = app2sd_client_usr_post_app_install;
	interface->client_usr_pre_upgrade = app2sd_client_usr_pre_app_upgrade;
	interface->client_usr_post_upgrade = app2sd_client_usr_post_app_upgrade;
	interface->client_usr_pre_uninstall = app2sd_client_usr_pre_app_uninstall;
	interface->client_usr_post_uninstall = app2sd_client_usr_post_app_uninstall;
	interface->client_usr_force_clean = app2sd_client_usr_force_clean;
	interface->client_usr_enable = app2sd_client_usr_on_demand_setup_init;
	interface->client_usr_disable = app2sd_client_usr_on_demand_setup_exit;
	//interface->move = app2sd_move_installed_app;
}

