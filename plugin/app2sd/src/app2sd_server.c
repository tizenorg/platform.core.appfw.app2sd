/*
 * app2sd-server
 *
 * Copyright (c) 2016 Samsung Electronics Co., Ltd. All rights reserved.
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

#include <gio/gio.h>

#include "app2sd_internals.h"

GMainLoop *app2sd_mainloop = NULL;

gboolean __exit_app2sd_server(void *data)
{
	_D("exit app2sd_server");

	g_main_loop_quit(app2sd_mainloop);

	return FALSE;
}

static int __app2sd_get_sender_unixinfo(GDBusConnection *conn,
		const char *sender_name, const char *type)
{
	GDBusMessage *msg = NULL;
	GDBusMessage *reply = NULL;
	GError *err = NULL;
	GVariant *body;
	int ret = -1;
	unsigned int value;

	msg = g_dbus_message_new_method_call("org.freedesktop.DBus",
		"/org/freedesktop/DBus", "org.freedesktop.DBus", type);
	if (!msg) {
		_E("Can't allocate new method call");
		goto out;
	}

	g_dbus_message_set_body(msg, g_variant_new("(s)", sender_name));
	reply = g_dbus_connection_send_message_with_reply_sync(conn, msg,
		G_DBUS_SEND_MESSAGE_FLAGS_NONE, -1, NULL, NULL, &err);

	if (!reply) {
		if (err != NULL) {
			_E("Failed to get info [%s]", err->message);
			g_error_free(err);
		}
		goto out;
	}

	body = g_dbus_message_get_body(reply);
	g_variant_get(body, "(u)", &value);
	ret = (int)value;

out:
	if (msg)
		g_object_unref(msg);
	if (reply)
		g_object_unref(reply);

	return ret;
}

/*
static int __app2sd_get_sender_pid(GDBusConnection *conn,
		const char *sender_name)
{
	int pid = 0;

	pid = __app2sd_get_sender_unixinfo(conn, sender_name,
		"GetConnectionUnixProcessID");
	if (pid < 0) {
		_E("failed to get pid");
		pid = 0;
	}

	_D("sender_name(%s), pid(%d)", sender_name, pid);

	return pid;
}
*/

static int __app2sd_get_sender_uid(GDBusConnection *conn,
		const char *sender_name)
{
	int uid = -1;

	uid = __app2sd_get_sender_unixinfo(conn, sender_name,
		"GetConnectionUnixUser");
	if (uid < 0)
		_E("failed to get uid");

	_D("sender_name(%s), uid(%d)", sender_name, uid);

	return uid;
}

static GDBusNodeInfo *introspection_data;
static const gchar introspection_xml[] =
"<node>"
"	<interface name='org.tizen.app2sd'>"
"		<method name='PreAppInstall'>"
"			<arg type='s' name='pkgid' direction='in'/>"
"			<arg type='i' name='size' direction='in'/>"
"			<arg type='a(si)' name='dir_list' direction='in'/>"
"			<arg type='i' name='uid' direction='in'/>"
"			<arg type='i' name='result' direction='out'/>"
"		</method>"
"		<method name='PostAppInstall'>"
"			<arg type='s' name='pkgid' direction='in'/>"
"			<arg type='i' name='install_status' direction='in'/>"
"			<arg type='i' name='uid' direction='in'/>"
"			<arg type='i' name='result' direction='out'/>"
"		</method>"
"		<method name='PreAppUpgrade'>"
"			<arg type='s' name='pkgid' direction='in'/>"
"			<arg type='i' name='size' direction='in'/>"
"			<arg type='a(si)' name='dir_list' direction='in'/>"
"			<arg type='i' name='uid' direction='in'/>"
"			<arg type='i' name='result' direction='out'/>"
"		</method>"
"		<method name='PostAppUpgrade'>"
"			<arg type='s' name='pkgid' direction='in'/>"
"			<arg type='i' name='install_status' direction='in'/>"
"			<arg type='i' name='uid' direction='in'/>"
"			<arg type='i' name='result' direction='out'/>"
"		</method>"
"		<method name='PreAppUninstall'>"
"			<arg type='s' name='pkgid' direction='in'/>"
"			<arg type='i' name='uid' direction='in'/>"
"			<arg type='i' name='result' direction='out'/>"
"		</method>"
"		<method name='PostAppUninstall'>"
"			<arg type='s' name='pkgid' direction='in'/>"
"			<arg type='i' name='uid' direction='in'/>"
"			<arg type='i' name='result' direction='out'/>"
"		</method>"
"		<method name='OndemandSetupInit'>"
"			<arg type='s' name='pkgid' direction='in'/>"
"			<arg type='i' name='uid' direction='in'/>"
"			<arg type='i' name='result' direction='out'/>"
"		</method>"
"		<method name='OndemandSetupExit'>"
"			<arg type='s' name='pkgid' direction='in'/>"
"			<arg type='i' name='uid' direction='in'/>"
"			<arg type='i' name='result' direction='out'/>"
"		</method>"
"		<method name='MoveInstalledApp'>"
"			<arg type='s' name='pkgid' direction='in'/>"
"			<arg type='i' name='move_type' direction='in'/>"
"			<arg type='a(si)' name='dir_list' direction='in'/>"
"			<arg type='i' name='uid' direction='in'/>"
"			<arg type='i' name='result' direction='out'/>"
"		</method>"
"		<method name='ForceClean'>"
"			<arg type='s' name='pkgid' direction='in'/>"
"			<arg type='i' name='uid' direction='in'/>"
"			<arg type='i' name='result' direction='out'/>"
"		</method>"
"		<method name='EnableFullPkg'>"
"			<arg type='i' name='result' direction='out'/>"
"		</method>"
"		<method name='DisableFullPkg'>"
"			<arg type='i' name='result' direction='out'/>"
"		</method>"
"	</interface>"
"</node>";

static void _app2sd_server_return_method_error(GDBusMethodInvocation *invocation, int result)
{
	GVariant *param = NULL;

	param = g_variant_new("(i)", result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void _app2sd_server_pre_app_install(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation, uid_t sender_uid)
{
	GVariant *param = NULL;
	int result = APP2EXT_SUCCESS;
	int size;
	char *pkgid = NULL;
	GVariantIter *iter;
	gchar *str = NULL;
	int type;
	int ret = 0;
	uid_t target_uid = -1;
	GList *dir_list = NULL;
	GList *list = NULL;
	app2ext_dir_details *dir_detail = NULL;

	g_variant_get(parameters, "(&sia(si)i)", &pkgid, &size, &iter, &target_uid);

	_D("pkgid(%s), size(%d),sender_uid(%d), target_uid(%d)",
		pkgid, size, sender_uid, target_uid);

	if (sender_uid != 0 && sender_uid != target_uid) {
		_E("Not permitted user!");
		g_variant_iter_free(iter);
		_app2sd_server_return_method_error(invocation,
			APP2EXT_ERROR_OPERATION_NOT_PERMITTED);
		return;
	}

	while (g_variant_iter_loop(iter, "(si)", &str, &type)) {
		if (str) {
			_D("str(%s), type(%d)", str, type);

			/* generate dir_list */
			dir_detail = (app2ext_dir_details *)calloc(1, sizeof(app2ext_dir_details));
			if (dir_detail == NULL) {
				_E("memory allocation failed");
				result = APP2EXT_ERROR_MEMORY_ALLOC_FAILED;
				break;
			}

			dir_detail->name = strdup((char *)str);
			if (dir_detail->name == NULL) {
				_E("out of memory");
				free(dir_detail);
				result = APP2EXT_ERROR_MEMORY_ALLOC_FAILED;
				break;
			}

			dir_detail->type = type;
			list = g_list_append(list, dir_detail);
		}
	}
	g_variant_iter_free(iter);

	dir_list = g_list_first(list);
	ret = app2sd_usr_pre_app_install(pkgid, dir_list, size, target_uid);
	if (ret) {
		_E("error(%d)", ret);
		result = ret;
	}

	param = g_variant_new("(i)", result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void _app2sd_server_post_app_install(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation, uid_t sender_uid)
{
	GVariant *param = NULL;
	int result = APP2EXT_SUCCESS;
	char *pkgid = NULL;
	int install_status = 0;
	int target_uid = -1;
	int ret = 0;

	g_variant_get(parameters, "(&sii)", &pkgid, &install_status, &target_uid);

	_D("pkgid(%s), install_status(%d), sender_uid(%d), target_uid(%d)",
		pkgid, install_status, sender_uid, target_uid);

	if (sender_uid != 0 && sender_uid != target_uid) {
		_E("Not permitted user!");
		_app2sd_server_return_method_error(invocation,
			APP2EXT_ERROR_OPERATION_NOT_PERMITTED);
		return;
	}

	ret = app2sd_usr_post_app_install(pkgid, install_status, target_uid);
	if (ret) {
		_E("error(%d)", ret);
		result = ret;
	}

	param = g_variant_new("(i)", result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void _app2sd_server_pre_app_upgrade(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation, uid_t sender_uid)
{
	GVariant *param = NULL;
	int result = APP2EXT_SUCCESS;
	int size;
	char *pkgid = NULL;
	GVariantIter *iter;
	gchar *str = NULL;
	int type;
	uid_t target_uid = -1;
	int ret = 0;
	GList *dir_list = NULL;
	GList *list = NULL;
	app2ext_dir_details *dir_detail = NULL;

	g_variant_get(parameters, "(&sia(si)i)", &pkgid, &size, &iter, &target_uid);

	_D("pkgid(%s), size(%d), sender_uid(%d), target_uid(%d)",
		pkgid, size, sender_uid, target_uid);

	if (sender_uid != 0 && sender_uid != target_uid) {
		_E("Not permitted user!");
		g_variant_iter_free(iter);
		_app2sd_server_return_method_error(invocation,
			APP2EXT_ERROR_OPERATION_NOT_PERMITTED);
		return;
	}

	while (g_variant_iter_loop(iter, "(si)", &str, &type)) {
		if (str) {
			_D("str(%s), type(%d)", str, type);

			/* generate dir_list */
			dir_detail = (app2ext_dir_details *)calloc(1, sizeof(app2ext_dir_details));
			if (dir_detail == NULL) {
				_E("memory allocation failed");
				result = APP2EXT_ERROR_MEMORY_ALLOC_FAILED;
				break;
			}

			dir_detail->name = strdup((char *)str);
			if (dir_detail->name == NULL) {
				_E("out of memory");
				free(dir_detail);
				result = APP2EXT_ERROR_MEMORY_ALLOC_FAILED;
				break;
			}

			dir_detail->type = type;
			list = g_list_append(list, dir_detail);
		}
	}
	g_variant_iter_free(iter);

	dir_list = g_list_first(list);
	ret = app2sd_usr_pre_app_upgrade(pkgid, dir_list, size, target_uid);
	if (ret) {
		_E("error(%d)", ret);
		result = ret;
	}

	param = g_variant_new("(i)", result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void _app2sd_server_post_app_upgrade(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation, uid_t sender_uid)
{
	GVariant *param = NULL;
	int result = APP2EXT_SUCCESS;
	char *pkgid = NULL;
	int install_status = 0;
	uid_t target_uid = -1;
	int ret = 0;

	g_variant_get(parameters, "(&sii)", &pkgid, &install_status, &target_uid);

	_D("pkgid(%s), install_status(%d), sender_uid(%d), target_uid(%d)",
		pkgid, install_status, sender_uid, target_uid);

	if (sender_uid != 0 && sender_uid != target_uid) {
		_E("Not permitted user!");
		_app2sd_server_return_method_error(invocation,
			APP2EXT_ERROR_OPERATION_NOT_PERMITTED);
		return;
	}

	ret = app2sd_usr_post_app_upgrade(pkgid, install_status, target_uid);
	if (ret) {
		_E("error(%d)", ret);
		result = ret;
	}

	param = g_variant_new("(i)", result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void _app2sd_server_pre_app_uninstall(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation, uid_t sender_uid)
{
	GVariant *param = NULL;
	int result = APP2EXT_SUCCESS;
	char *pkgid = NULL;
	uid_t target_uid = -1;
	int ret = 0;

	g_variant_get(parameters, "(&si)", &pkgid, &target_uid);

	_D("pkgid(%s), sender_uid(%d), target_uid(%d)",
		pkgid, sender_uid, target_uid);

	if (sender_uid != 0 && sender_uid != target_uid) {
		_E("Not permitted user!");
		_app2sd_server_return_method_error(invocation,
			APP2EXT_ERROR_OPERATION_NOT_PERMITTED);
		return;
	}

	ret = app2sd_usr_pre_app_uninstall(pkgid, target_uid);
	if (ret) {
		_E("error(%d)", ret);
		result = ret;
	}

	param = g_variant_new("(i)", result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void _app2sd_server_post_app_uninstall(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation, uid_t sender_uid)
{
	GVariant *param = NULL;
	int result = APP2EXT_SUCCESS;
	char *pkgid = NULL;
	uid_t target_uid = -1;
	int ret = 0;

	g_variant_get(parameters, "(&si)", &pkgid, &target_uid);

	_D("pkgid(%s), sender_uid(%d), target_uid(%d)",
		pkgid, sender_uid, target_uid);

	if (sender_uid != 0 && sender_uid != target_uid) {
		_E("Not permitted user!");
		_app2sd_server_return_method_error(invocation,
			APP2EXT_ERROR_OPERATION_NOT_PERMITTED);
		return;
	}

	ret = app2sd_usr_post_app_uninstall(pkgid, target_uid);
	if (ret) {
		_E("error(%d)", ret);
		result = ret;
	}

	param = g_variant_new("(i)", result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void _app2sd_server_ondemand_setup_init(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation, uid_t sender_uid)
{
	GVariant *param = NULL;
	int result = APP2EXT_SUCCESS;
	char *pkgid = NULL;
	uid_t target_uid = -1;
	int ret = 0;

	g_variant_get(parameters, "(&si)", &pkgid, &target_uid);

	_D("pkgid(%s), sender_uid(%d), target_uid(%d)",
		pkgid, sender_uid, target_uid);

	if (sender_uid != 0 && sender_uid != target_uid) {
		_E("Not permitted user!");
		_app2sd_server_return_method_error(invocation,
			APP2EXT_ERROR_OPERATION_NOT_PERMITTED);
		return;
	}

	ret = app2sd_usr_on_demand_setup_init(pkgid, target_uid);
	if (ret) {
		_E("error(%d)", ret);
		result = ret;
	}

	param = g_variant_new("(i)", result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void _app2sd_server_ondemand_setup_exit(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation, uid_t sender_uid)
{
	GVariant *param = NULL;
	int result = APP2EXT_SUCCESS;
	char *pkgid = NULL;
	uid_t target_uid = -1;
	int ret = 0;

	g_variant_get(parameters, "(&si)", &pkgid, &target_uid);

	_D("pkgid(%s), sender_uid(%d), target_uid(%d)",
		pkgid, sender_uid, target_uid);

	if (sender_uid != 0 && sender_uid != target_uid) {
		_E("Not permitted user!");
		_app2sd_server_return_method_error(invocation,
			APP2EXT_ERROR_OPERATION_NOT_PERMITTED);
		return;
	}

	ret = app2sd_usr_on_demand_setup_exit(pkgid, target_uid);
	if (ret) {
		_E("error(%d)", ret);
		result = ret;
	}

	param = g_variant_new("(i)", result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void _app2sd_server_move_installed_app(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation, uid_t sender_uid)
{
	GVariant *param = NULL;
	int result = APP2EXT_SUCCESS;
	int move_type;
	char *pkgid = NULL;
	GVariantIter *iter;
	gchar *str = NULL;
	int type;
	int ret = 0;
	uid_t target_uid = -1;
	GList *dir_list = NULL;
	GList *list = NULL;
	app2ext_dir_details *dir_detail = NULL;

	g_variant_get(parameters, "(&sia(si)i)", &pkgid, &move_type, &iter, &target_uid);

	_D("pkgid(%s), move_type(%d),sender_uid(%d), target_uid(%d)",
		pkgid, move_type, sender_uid, target_uid);

	if (sender_uid != 0 && sender_uid != target_uid) {
		_E("Not permitted user!");
		g_variant_iter_free(iter);
		_app2sd_server_return_method_error(invocation,
			APP2EXT_ERROR_OPERATION_NOT_PERMITTED);
		return;
	}

	while (g_variant_iter_loop(iter, "(si)", &str, &type)) {
		if (str) {
			_D("str(%s), type(%d)", str, type);

			/* generate dir_list */
			dir_detail = (app2ext_dir_details *)calloc(1, sizeof(app2ext_dir_details));
			if (dir_detail == NULL) {
				_E("memory allocation failed");
				result = APP2EXT_ERROR_MEMORY_ALLOC_FAILED;
				break;
			}

			dir_detail->name = strdup((char *)str);
			if (dir_detail->name == NULL) {
				_E("out of memory");
				free(dir_detail);
				result = APP2EXT_ERROR_MEMORY_ALLOC_FAILED;
				break;
			}

			dir_detail->type = type;
			list = g_list_append(list, dir_detail);
		}
	}
	g_variant_iter_free(iter);

	dir_list = g_list_first(list);
	ret = app2sd_usr_move_installed_app(pkgid, dir_list, move_type, target_uid);
	if (ret) {
		_E("usr_move error(%d)", ret);
		result = ret;
	}

	param = g_variant_new("(i)", result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void _app2sd_server_force_clean(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation, uid_t sender_uid)
{
	GVariant *param = NULL;
	int result = APP2EXT_SUCCESS;
	char *pkgid = NULL;
	uid_t target_uid = -1;
	int ret = 0;

	g_variant_get(parameters, "(&si)", &pkgid, &target_uid);

	_D("pkgid(%s), sender_uid(%d), target_uid(%d)",
		pkgid, sender_uid, target_uid);

	if (sender_uid != 0 && sender_uid != target_uid) {
		_E("Not permitted user!");
		_app2sd_server_return_method_error(invocation,
			APP2EXT_ERROR_OPERATION_NOT_PERMITTED);
		return;
	}

	ret = app2sd_usr_force_clean(pkgid, target_uid);
	if (ret) {
		_E("error(%d)", ret);
		result = ret;
	}

	param = g_variant_new("(i)", result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void _app2sd_server_enable_full_pkg(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation, uid_t sender_uid)
{
	GVariant *param = NULL;
	int result = APP2EXT_SUCCESS;
	int ret = 0;

	_D("sender_uid(%d)", sender_uid);

	if (sender_uid >= REGULAR_USER) {
		_E("Not permitted user!");
		_app2sd_server_return_method_error(invocation,
			APP2EXT_ERROR_OPERATION_NOT_PERMITTED);
		return;
	}

	ret = app2sd_enable_full_pkg();
	if (ret) {
		_E("error(%d)", ret);
		result = ret;
	}

	param = g_variant_new("(i)", result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void _app2sd_server_disable_full_pkg(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation, uid_t sender_uid)
{
	GVariant *param = NULL;
	int result = APP2EXT_SUCCESS;
	int ret = 0;

	_D("sender_uid(%d)", sender_uid);

	if (sender_uid >= REGULAR_USER) {
		_E("Not permitted user!");
		_app2sd_server_return_method_error(invocation,
			APP2EXT_ERROR_OPERATION_NOT_PERMITTED);
		return;
	}

	ret = app2sd_disable_full_pkg();
	if (ret) {
		_E("error(%d)", ret);
		result = ret;
	}

	param = g_variant_new("(i)", result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void handle_method_call(GDBusConnection *connection,
	const gchar *sender, const gchar *object_path,
	const gchar *interface_name, const gchar *method_name,
	GVariant *parameters, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	uid_t sender_uid = -1;

	sender_uid = (uid_t)__app2sd_get_sender_uid(connection, sender);

	if (g_strcmp0(method_name, "PreAppInstall") == 0) {
		_app2sd_server_pre_app_install(connection, sender,
			parameters, invocation, sender_uid);
	} else if (g_strcmp0(method_name, "PostAppInstall") == 0) {
		_app2sd_server_post_app_install(connection, sender,
			parameters, invocation, sender_uid);
	} else if (g_strcmp0(method_name, "PreAppUpgrade") == 0) {
		_app2sd_server_pre_app_upgrade(connection, sender,
			parameters, invocation, sender_uid);
	} else if (g_strcmp0(method_name, "PostAppUpgrade") == 0) {
		_app2sd_server_post_app_upgrade(connection, sender,
			parameters, invocation, sender_uid);
	} else if (g_strcmp0(method_name, "PreAppUninstall") == 0) {
		_app2sd_server_pre_app_uninstall(connection, sender,
			parameters, invocation, sender_uid);
	} else if (g_strcmp0(method_name, "PostAppUninstall") == 0) {
		_app2sd_server_post_app_uninstall(connection, sender,
			parameters, invocation, sender_uid);
	} else if (g_strcmp0(method_name, "OndemandSetupInit") == 0) {
		_app2sd_server_ondemand_setup_init(connection, sender,
			parameters, invocation, sender_uid);
	} else if (g_strcmp0(method_name, "OndemandSetupExit") == 0) {
		_app2sd_server_ondemand_setup_exit(connection, sender,
			parameters, invocation, sender_uid);
	} else if (g_strcmp0(method_name, "MoveInstalledApp") == 0) {
		_app2sd_server_move_installed_app(connection, sender,
			parameters, invocation, sender_uid);
	} else if (g_strcmp0(method_name, "ForceClean") == 0) {
		_app2sd_server_force_clean(connection, sender,
			parameters, invocation, sender_uid);
	} else if (g_strcmp0(method_name, "EnableFullPkg") == 0) {
		_app2sd_server_enable_full_pkg(connection, sender,
			parameters, invocation, sender_uid);
	} else if (g_strcmp0(method_name, "DisableFullPkg") == 0) {
		_app2sd_server_disable_full_pkg(connection, sender,
			parameters, invocation, sender_uid);
	}

	g_timeout_add_seconds(5, __exit_app2sd_server, NULL);
}

static const GDBusInterfaceVTable interface_vtable = {
	handle_method_call,
	NULL,
	NULL
};

static void __app2sd_on_bus_acquired(GDBusConnection *connection,
		const gchar *name, gpointer user_data)
{
	_I("bus acquired(%s)", name);

	guint reg_id = 0;
	GError *error = NULL;

	reg_id = g_dbus_connection_register_object(connection,
		APP2SD_OBJECT_PATH,
		introspection_data->interfaces[0],
		&interface_vtable,
		NULL, NULL, &error);
	if (reg_id == 0) {
		_E("g_dbus_connection_register_object error(%s)", error->message);
		g_error_free(error);
	}
}

static void __app2sd_on_name_acquired(GDBusConnection *connection,
		const gchar *name, gpointer user_data)
{
	_I("name acquired(%s)", name);
}

static void __app2sd_on_name_lost(GDBusConnection *connection,
		const gchar *name, gpointer user_data)
{
	_E("name lost(%s)", name);
	g_main_loop_quit(app2sd_mainloop);
}

static int __app2sd_server_init()
{
	GError *error = NULL;
	guint owner_id = 0;

	/* gdbus setup for method call */
	introspection_data = g_dbus_node_info_new_for_xml(introspection_xml, &error);
	if (!introspection_data) {
		_E("g_dbus_node_info_new_for_xml error(%s)", error->message);
		g_error_free(error);
		return -1;
	}

	owner_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
		APP2SD_BUS_NAME,
		G_BUS_NAME_OWNER_FLAGS_NONE,
		__app2sd_on_bus_acquired,
		__app2sd_on_name_acquired,
		__app2sd_on_name_lost,
		NULL, NULL);
	if (!owner_id) {
		_E("g_bus_own_name error");
		g_dbus_node_info_unref(introspection_data);
		return -1;
	}

	/* add timer */

	return 0;
}

static void __app2sd_finalize(void)
{
	_D("app2sd finalize");

	if (introspection_data)
		g_dbus_node_info_unref(introspection_data);

	_D("app2sd finalize end");
}

int main(int argc, char *argv[])
{
	int ret = 0;

	_I("app2sd_server : start");

	ret = __app2sd_server_init();
	if (ret) {
		_E("app2sd_server init failed(%d)", ret);
		return -1;
	}

	app2sd_mainloop = g_main_loop_new(NULL, FALSE);
	if (!app2sd_mainloop) {
		_E("g_main_loop_new failed");
		return -1;
	}

	g_main_loop_run(app2sd_mainloop);

	__app2sd_finalize();

	_I("app2sd_server : end");

	return 0;
}
