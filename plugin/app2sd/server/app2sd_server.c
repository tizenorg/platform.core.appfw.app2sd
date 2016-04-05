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

#if 0
int app2sd_server_pre_app_install(const char *pkgid, GList* dir_list, int size)
{
	int ret = 0;
	int free_mmc_mem = 0;
	char *device_node = NULL;
	char *devi = NULL;
	char *result = NULL;
	int reqd_disk_size = size + ceil(size*0.2);

	/* debug path */
	app2ext_print("MMC_PATH = (%s)\n", MMC_PATH);
	app2ext_print("APP2SD_PATH = (%s)\n", APP2SD_PATH);
	app2ext_print("APP_INSTALLATION_PATH = (%s)\n", APP_INSTALLATION_PATH);
	app2ext_print("APP_INSTALLATION_USER_PATH = (%s)\n", APP_INSTALLATION_USER_PATH);

	/* Validate the function parameter recieved */
	if (pkgid == NULL || dir_list == NULL || size <= 0) {
		app2ext_print("App2Sd Error : Invalid function arguments\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}
	/* Check whether MMC is present or not */
	ret = _app2sd_check_mmc_status();
	if (ret) {
		app2ext_print("App2Sd Error : MMC not preset OR Not ready %d\n",
			ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}
	/* Find available free memory in the MMC card */
	ret = _app2sd_get_available_free_memory(MMC_PATH,
						&free_mmc_mem);
	if (ret) {
		app2ext_print("App2Sd Error : Unable to get available free memory in MMC %d\n", ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}
	app2ext_print("Size details for application installation:size=%dMB, reqd_disk_size=%dMB, free_mmc_size=%dMB\n",
			 size, reqd_disk_size, free_mmc_mem);
	/* If avaialalbe free memory in MMC is less than required size + 5MB , return error */
	if ((reqd_disk_size + PKG_BUF_SIZE + MEM_BUF_SIZE) > free_mmc_mem) {
		app2ext_print("Insufficient memory in MMC for application installation %d\n", ret);
		return APP2EXT_ERROR_MMC_INSUFFICIENT_MEMORY;
	}
	/* Create a loopback device */
	ret = _app2sd_create_loopback_device(pkgid, (reqd_disk_size+PKG_BUF_SIZE));
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
	/* Perform Loopback encryption setup */
	device_node = _app2sd_do_loopback_encryption_setup(pkgid);
	if (!device_node) {
		app2ext_print("App2Sd Error : Loopback encryption setup failed\n");
		_app2sd_delete_loopback_device(pkgid);
		return APP2EXT_ERROR_DO_LOSETUP;
	}
	/* Check whether loopback device is associated with device node or not */
	devi = _app2sd_find_associated_device_node(pkgid);
	if (devi == NULL) {
		app2ext_print("App2Sd Error : finding associated device node failed\n");
		ret = APP2EXT_ERROR_DO_LOSETUP;
		goto FINISH_OFF;
	}

	/* Format the loopback file system */
	ret = _app2sd_create_file_system(device_node);
	if (ret) {
		app2ext_print("App2Sd Error : creating FS failed failed\n");
		ret = APP2EXT_ERROR_CREATE_FS;
		goto FINISH_OFF;
	}

	/* Mount the loopback encrypted pseudo device on application installation path as with Read Write permission */
	ret =_app2sd_mount_app_content(pkgid, device_node, MOUNT_TYPE_RW,
					dir_list, APP2SD_PRE_INSTALL);
	if (ret) {
		app2ext_print("App2Sd Error : mounting dev path to app install path failed\n");
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
#endif

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
"	</interface>"
"</node>";

static void app2sd_server_pre_app_install(GDBusConnection *connection, const gchar *sender,
	GVariant *parameters, GDBusMethodInvocation *invocation)
{
	GVariant *param = NULL;
	int result = 1;
	int size;
	char *pkgid = NULL;
	GVariantIter *iter;
	gchar *str;
	char *name;
	int type;
	//int sender_pid = 0;
	//uid_t sender_uid = 0;

	g_variant_get(parameters, "(&sia(si))", &pkgid, &size, &iter);

	_D("pkgid(%s), size(%d)", pkgid, size);

	//sender_pid = __get_sender_pid(connection, sender);
	//sender_uid = (uid_t)__get_sender_uid(connection, sender);

	while (g_variant_iter_loop(iter, "si", &str, &type)) {
		name = strdup((char *)str);
		if (name) {
			_D("name(%s)", str);
			//*dest_list = g_list_append(*dest_list, dest_name);
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

static void handle_method_call(GDBusConnection *connection,
	const gchar *sender, const gchar *object_path,
	const gchar *interface_name, const gchar *method_name,
	GVariant *parameters, GDBusMethodInvocation *invocation,
	gpointer user_data)
{
	if (g_strcmp0(method_name, "PreAppInstall") == 0) {
		app2sd_server_pre_app_install(connection, sender, parameters, invocation);
	}
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

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	_I("app2sd_server : start");

	ret = __app2sd_server_init();
	if (ret)
		_E("app2sd_server init failed(%d)", ret);

	_I("app2sd_server : end");

	return 0;
}
