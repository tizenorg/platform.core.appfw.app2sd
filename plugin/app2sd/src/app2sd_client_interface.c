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

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <gio/gio.h>

#include "app2sd_client_interface.h"
#include "app2ext_utils.h"

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
				"system dbus [%s]", error->message);
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

static int __app2sd_create_default_directories(const char *pkgid,
		app2sd_cmd cmd, uid_t uid)
{
	int ret = 0;
	mode_t mode = DIR_PERMS;
	char application_path[FILENAME_MAX] = { 0, };
	char application_mmc_path[FILENAME_MAX] = { 0, };

	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		tzplatform_reset_user();
	}

	ret = mkdir(application_path, mode);
	if (ret) {
		if (errno != EEXIST) {
			_E("create directory failed," \
				" error no is (%d)", errno);
			return APP2EXT_ERROR_CREATE_DIRECTORY;
		}
	}

	snprintf(application_mmc_path, FILENAME_MAX - 1, "%s/.mmc",
		application_path);

	ret = mkdir(application_mmc_path, mode);
	if (ret) {
		if (errno != EEXIST) {
			_E("create directory failed," \
				" error no is (%d)", errno);
			return APP2EXT_ERROR_CREATE_DIRECTORY;
		}
	}

	if (cmd == APP2SD_PRE_UPGRADE) {
	}

	return APP2EXT_SUCCESS;
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

	ret = __app2sd_create_default_directories(pkgid,
		APP2SD_PRE_INSTALL, uid);
	if (ret)
		return ret;

	builder = g_variant_builder_new(G_VARIANT_TYPE("a(si)"));
	g_list_foreach(dir_list, __app2sd_create_dir_list_builder, builder);

	param = g_variant_new("(sia(si)i)", pkgid, size, builder, uid);
	ret = __app2sd_call_server_method("PreAppInstall", param);

	if (builder)
		g_variant_builder_unref(builder);

	return ret;
}
int app2sd_client_pre_app_install(const char *pkgid, GList* dir_list,
		int size)
{
	int ret = 0;

	ret = app2sd_client_usr_pre_app_install(pkgid,
		dir_list, size, getuid());

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
		_E("invalid func parameters");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	param = g_variant_new("(sii)", pkgid, install_status, uid);
	ret = __app2sd_call_server_method("PostAppInstall", param);

	return ret;
}
int app2sd_client_post_app_install(const char *pkgid,
		app2ext_status install_status)
{
	int ret = 0;

	ret = app2sd_client_usr_post_app_install(pkgid,
		install_status, getuid());

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

	ret = __app2sd_create_default_directories(pkgid,
		APP2SD_PRE_UPGRADE, uid);
	if (ret)
		return ret;

	builder = g_variant_builder_new(G_VARIANT_TYPE("a(si)"));
	g_list_foreach(dir_list, __app2sd_create_dir_list_builder, builder);

	param = g_variant_new("(sia(si)i)", pkgid, size, builder, uid);
	ret = __app2sd_call_server_method("PreAppUpgrade", param);

	if (builder)
		g_variant_builder_unref(builder);

	return ret;
}
int app2sd_client_pre_app_upgrade(const char *pkgid, GList* dir_list,
		int size)
{
	int ret = 0;

	ret = app2sd_client_usr_pre_app_upgrade(pkgid,
		dir_list, size, getuid());

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
		_E("invalid func parameters");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	param = g_variant_new("(sii)", pkgid, install_status, uid);
	ret = __app2sd_call_server_method("PostAppUpgrade", param);

	return ret;
}
int app2sd_client_post_app_upgrade(const char *pkgid,
		app2ext_status install_status)
{
	int ret = 0;

	ret = app2sd_client_usr_post_app_upgrade(pkgid,
		install_status, getuid());

	return ret;
}

int app2sd_client_usr_pre_app_uninstall(const char *pkgid, uid_t uid)
{
	int ret = 0;
	GVariant *param = NULL;

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		_E("invalid func parameters");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	param = g_variant_new("(si)", pkgid, uid);
	ret = __app2sd_call_server_method("PreAppUninstall", param);

	return ret;
}
int app2sd_client_pre_app_uninstall(const char *pkgid)
{
	int ret = 0;

	ret = app2sd_client_usr_pre_app_uninstall(pkgid,
		getuid());

	return ret;
}

int app2sd_client_usr_post_app_uninstall(const char *pkgid, uid_t uid)
{
	int ret = 0;
	GVariant *param = NULL;

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		_E("invalid func parameters");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	param = g_variant_new("(si)", pkgid, uid);
	ret = __app2sd_call_server_method("PostAppUninstall", param);

	return ret;
}
int app2sd_client_post_app_uninstall(const char *pkgid)
{
	int ret = 0;

	ret = app2sd_client_usr_post_app_uninstall(pkgid,
		getuid());

	return ret;
}

int app2sd_client_usr_force_clean(const char *pkgid, uid_t uid)
{
	int ret = 0;
	GVariant *param = NULL;

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		_E("invalid func parameters");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	param = g_variant_new("(si)", pkgid, uid);
	ret = __app2sd_call_server_method("ForceClean", param);

	return ret;
}
int app2sd_client_force_clean(const char *pkgid)
{
	int ret = 0;

	ret = app2sd_client_usr_force_clean(pkgid, getuid());

	return ret;
}

int app2sd_client_enable_full_pkg(void)
{
	int ret = 0;

	ret = __app2sd_call_server_method("EnableFullPkg", NULL);

	return ret;
}

int app2sd_client_disable_full_pkg(void)
{
	int ret = 0;

	ret = __app2sd_call_server_method("DisableFullPkg", NULL);

	return ret;
}

int app2sd_client_usr_on_demand_setup_init(const char *pkgid, uid_t uid)
{
	int ret = 0;
	GVariant *param = NULL;

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		_E("invalid func parameters");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	param = g_variant_new("(si)", pkgid, uid);
	ret = __app2sd_call_server_method("OndemandSetupInit", param);

	return ret;
}
int app2sd_client_on_demand_setup_init(const char *pkgid)
{
	int ret = 0;

	ret = app2sd_client_usr_on_demand_setup_init(pkgid,
		getuid());

	return ret;
}

int app2sd_client_usr_on_demand_setup_exit(const char *pkgid, uid_t uid)
{
	int ret = 0;
	GVariant *param = NULL;

	/* validate the function parameter recieved */
	if (pkgid == NULL) {
		_E("invalid func parameters");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	param = g_variant_new("(si)", pkgid, uid);
	ret = __app2sd_call_server_method("OndemandSetupExit", param);

	return ret;
}
int app2sd_client_on_demand_setup_exit(const char *pkgid)
{
	int ret = 0;

	ret = app2sd_client_usr_on_demand_setup_exit(pkgid,
		getuid());

	return ret;
}

int app2sd_client_usr_move_installed_app(const char *pkgid, GList* dir_list,
		app2ext_move_type move_type, uid_t uid)
{
	int ret = 0;
	GVariantBuilder *builder = NULL;
	GVariant *param = NULL;
	app2sd_cmd cmd = APP2SD_MOVE_APP_TO_PHONE;

	/* validate the function parameter recieved */
	if (pkgid == NULL || dir_list == NULL
		|| move_type < APP2EXT_MOVE_TO_EXT
		|| move_type > APP2EXT_MOVE_TO_PHONE) {
		_E("invalid function arguments");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	if (move_type == APP2EXT_MOVE_TO_EXT)
		cmd = APP2SD_MOVE_APP_TO_MMC;

	ret = __app2sd_create_default_directories(pkgid, cmd, uid);
	if (ret)
		return ret;

	builder = g_variant_builder_new(G_VARIANT_TYPE("a(si)"));
	g_list_foreach(dir_list, __app2sd_create_dir_list_builder, builder);

	param = g_variant_new("(sia(si)i)", pkgid, move_type, builder, uid);
	ret = __app2sd_call_server_method("MoveInstalledApp", param);

	if (builder)
		g_variant_builder_unref(builder);

	return ret;
}
int app2sd_client_move_installed_app(const char *pkgid, GList* dir_list,
		app2ext_move_type move_type)
{
	int ret = 0;

	ret = app2sd_client_usr_move_installed_app(pkgid,
		dir_list, move_type, getuid());

	return ret;
}

void app2ext_on_load(app2ext_interface *interface)
{
	/* Plug-in Binding.*/
	interface->client_pre_install = app2sd_client_pre_app_install;
	interface->client_post_install = app2sd_client_post_app_install;
	interface->client_pre_upgrade = app2sd_client_pre_app_upgrade;
	interface->client_post_upgrade = app2sd_client_post_app_upgrade;
	interface->client_pre_uninstall = app2sd_client_pre_app_uninstall;
	interface->client_post_uninstall = app2sd_client_post_app_uninstall;
	interface->client_force_clean = app2sd_client_force_clean;
	interface->client_enable = app2sd_client_on_demand_setup_init;
	interface->client_disable = app2sd_client_on_demand_setup_exit;
	interface->client_enable_full_pkg = app2sd_client_enable_full_pkg;
	interface->client_disable_full_pkg = app2sd_client_disable_full_pkg;
	interface->client_move = app2sd_client_move_installed_app;

	interface->client_usr_pre_install = app2sd_client_usr_pre_app_install;
	interface->client_usr_post_install = app2sd_client_usr_post_app_install;
	interface->client_usr_pre_upgrade = app2sd_client_usr_pre_app_upgrade;
	interface->client_usr_post_upgrade = app2sd_client_usr_post_app_upgrade;
	interface->client_usr_pre_uninstall = app2sd_client_usr_pre_app_uninstall;
	interface->client_usr_post_uninstall = app2sd_client_usr_post_app_uninstall;
	interface->client_usr_force_clean = app2sd_client_usr_force_clean;
	interface->client_usr_enable = app2sd_client_usr_on_demand_setup_init;
	interface->client_usr_disable = app2sd_client_usr_on_demand_setup_exit;
	interface->client_usr_move = app2sd_client_usr_move_installed_app;
}
