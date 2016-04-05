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

#include <app2sd_internals.h>
#include <app2sd_interface.h>
#include <glib.h>
#include <gio/gio.h>

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

static int __app2sd_get_sender_uid(GDBusConnection *conn,
		const char *sender_name)
{
	int uid = -1;

	uid = __app2sd_get_sender_unixinfo(conn, sender_name,
		"GetConnectionUnixUser");
	if (uid < 0) {
		_E("failed to get uid");
	}

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
"			<arg type='i' name='result' direction='out'/>"
"		</method>"
"		<method name='PostAppInstall'>"
"			<arg type='s' name='pkgid' direction='in'/>"
"			<arg type='i' name='install_status' direction='in'/>"
"			<arg type='i' name='result' direction='out'/>"
"		</method>"
"	</interface>"
"</node>";

static void app2sd_server_pre_app_install(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation)
{
	GVariant *param = NULL;
	int result = 0;
	int size;
	char *pkgid = NULL;
	GVariantIter *iter;
	gchar *str;
	char *name;
	int type;
	int sender_pid = 0;
	uid_t sender_uid = 0;

	g_variant_get(parameters, "(&sia(si))", &pkgid, &size, &iter);

	sender_pid = __app2sd_get_sender_pid(connection, sender);
	sender_uid = (uid_t)__app2sd_get_sender_uid(connection, sender);

	_D("pkgid(%s), size(%d), sender_pid(%d), sender_uid(%d)",
		pkgid, size, sender_pid, sender_uid);

	while (g_variant_iter_loop(iter, "(si)", &str, &type)) {
		name = strdup((char *)str);
		if (name) {
			_D("name(%s), type(%d)", str, type);
			/* generate dir_list */
			free(name);
		} else {
			_E("out of memory");
			result = -1;
			break;
		}
	}
	g_variant_iter_free(iter);

	param = g_variant_new("(i)", result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void app2sd_server_post_app_install(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation)
{
	GVariant *param = NULL;
	int result = 0;
	int install_status = 0;
	char *pkgid = NULL;
	int sender_pid = 0;
	uid_t sender_uid = 0;

	g_variant_get(parameters, "(&si)", &pkgid, &install_status);

	sender_pid = __app2sd_get_sender_pid(connection, sender);
	sender_uid = (uid_t)__app2sd_get_sender_uid(connection, sender);

	_D("pkgid(%s), install_status(%d), sender_pid(%d), sender_uid(%d)",
		pkgid, install_status, sender_pid, sender_uid);

	param = g_variant_new("(i)", result);
	g_dbus_method_invocation_return_value(invocation, param);
}

static void handle_method_call(GDBusConnection *connection,
	const gchar *sender, const gchar *object_path,
	const gchar *interface_name, const gchar *method_name,
	GVariant *parameters, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	if (g_strcmp0(method_name, "PreAppInstall") == 0) {
		app2sd_server_pre_app_install(connection, sender, parameters, invocation);
	} else if (g_strcmp0(method_name, "PostAppInstall") == 0) {
		app2sd_server_post_app_install(connection, sender, parameters, invocation);
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
