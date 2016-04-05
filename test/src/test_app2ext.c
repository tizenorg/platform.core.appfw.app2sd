/*
 * test_app2ext
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

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <getopt.h>
#include <unzip.h>
#include <aul.h>
#include <tzplatform_config.h>
#include <app2ext_interface.h>

#define SUCCESS 0
#define FAIL 1
#define CMD_LEN 256
#define TEST_PKGNAME "org.example.basicuiapplication"
#define TEST_PKGNAME_PATH "/tmp/org.example.basicuiapplication-1.0.0-arm.tpk"

app2ext_handle *handle = NULL;

char pkg_ro_content_rpm[3][5] = { "bin", "res", "lib" };

#define COUNT_OF_ERROR_LIST 50
char error_list[COUNT_OF_ERROR_LIST][100] = {
	"SUCCESS",
	"APP2EXT_ERROR_UNKNOWN",
	"APP2EXT_ERROR_INVALID_ARGUMENTS",
	"APP2EXT_ERROR_MOVE",
	"APP2EXT_ERROR_PRE_UNINSTALL",
	"APP2EXT_ERROR_MMC_STATUS",
	"APP2EXT_ERROR_DB_INITIALIZE",
	"APP2EXT_ERROR_SQLITE_REGISTRY",
	"APP2EXT_ERROR_PASSWD_GENERATION",
	"APP2EXT_ERROR_MMC_INFORMATION",
	"APP2EXT_ERROR_MMC_INSUFFICIENT_MEMORY",
	"APP2EXT_ERROR_DELETE_DIRECTORY",
	"APP2EXT_ERROR_CREATE_SYMLINK",
	"APP2EXT_ERROR_CREATE_DIRECTORY",
	"APP2EXT_ERROR_DELETE_LINK_FILE",
	"APP2EXT_ERROR_PKG_EXISTS",
	"APP2EXT_ERROR_ACCESS_FILE",
	"APP2EXT_ERROR_OPEN_DIR",
	"APP2EXT_ERROR_ALREADY_FILE_PRESENT",
	"APP2EXT_ERROR_FILE_ABSENT",
	"APP2EXT_ERROR_STRCMP_FAILED",
	"APP2EXT_ERROR_INVALID_PACKAGE",
	"APP2EXT_ERROR_CREATE_DIR_ENTRY",
	"APP2EXT_ERROR_PASSWORD_GENERATION",
	"APP2EXT_ERROR_COPY_DIRECTORY",
	"APP2EXT_ERROR_INVALID_CASE",
	"APP2EXT_ERROR_SYMLINK_ALREADY_EXISTS",
	"APP2EXT_ERROR_APPEND_HASH_TO_FILE",
	"APP2EXT_ERROR_CREATE_DEVICE",
	"APP2EXT_ERROR_DO_LOSETUP",
	"APP2EXT_ERROR_CREATE_FS",
	"APP2EXT_ERROR_MOUNT_PATH",
	"APP2EXT_ERROR_CLEANUP",
	"APP2EXT_ERROR_MOUNT",
	"APP2EXT_ERROR_REMOUNT",
	"APP2EXT_ERROR_PIPE_CREATION",
	"APP2EXT_ERROR_LOOPBACK_DEVICE_UNAVAILABLE",
	"APP2EXT_ERROR_VCONF_REGISTRY",
	"APP2EXT_ERROR_FIND_ASSOCIATED_DEVICE_NODE",
	"APP2EXT_ERROR_UNMOUNT",
	"APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE",
	"APP2EXT_ERROR_DETACH_LOOPBACK_DEVICE",
	"APP2EXT_ERROR_ALREADY_MOUNTED",
	"APP2EXT_ERROR_PLUGIN_INIT_FAILED",
	"APP2EXT_ERROR_PLUGIN_DEINIT_FAILED",
	"APP2EXT_ERROR_DBUS_FAILED",
	"APP2EXT_ERROR_MEMORY_ALLOC_FAILED",
	"APP2EXT_ERROR_OPERATION_NOT_PERMITTED",
	"APP2EXT_ERROR_SAME_LOOPBACK_DEVICE_EXISTS",
	"APP2EXT_ERROR_PKGMGR_ERROR"
};

static void usage(void)
{
	printf("\n");
	printf("*************************************************\n");
	printf("app2sd test usage:\n");
	printf("pre-condition: /tmp/org.example.basicuiapplication-1.0.0-arm.tpk\n");
	printf("\n");
	printf("<INSTALL>\n");
	printf("1.(at target_user)$test_app2ext --pre-install\n");
	printf("2.(at target_user)$pkgcmd -it tpk {pkg-path}\n");
	printf("3.(at target_user)$test_app2ext --post-install\n");
	printf("------------------------------------------------\n");
	printf("\n");
	printf("<UPGRADE>\n");
	printf("1.(at target_user)$test_app2ext --pre-upgrade\n");
	printf("2.(at target_user)$pkgcmd -it tpk {pkg-path}\n");
	printf("3.(at target_user)$test_app2ext --post-upgrade\n");
	printf("------------------------------------------------\n");
	printf("\n");
	printf("<INSTALL>\n");
	printf("1.(at target_user)$test_app2ext --pre-uninstall\n");
	printf("2.(at target_user)$pkgcmd -un {pkg-id}\n");
	printf("3.(at target_user)$test_app2ext --post-uninstall\n");
	printf("------------------------------------------------\n");
	printf("\n");
	printf("<MOVE PKG TEST>\n");
	printf("(at target_user)$test_app2ext --move\n");
	printf("------------------------------------------------\n");
	printf("\n");
	printf("<GET INSTALLED LOCATION (Ext/Internal)>\n");
	printf("(at target_user)$test_app2ext --getlocation\n");
	printf("------------------------------------------------\n");
	printf("\n");
	printf("<ENABLE(mount)/DISABLE(umount) TEST W/ Installed PKG>\n");
	printf("(at target_user)$test_app2ext --enable\n");
	printf("(at target_user)$test_app2ext --disable\n");
	printf("------------------------------------------------\n");
	printf("**************************************************\n");
	printf("\n");
}

#define OPTVAL_PRE_INSTALL		1000
#define OPTVAL_POST_INSTALL		1001
#define OPTVAL_PRE_UNINSTALL		1002
#define OPTVAL_POST_UNINSTALL		1003
#define OPTVAL_PRE_UPGRADE		1004
#define OPTVAL_POST_UPGRADE		1005
#define OPTVAL_MOVE			1006
#define OPTVAL_GET_LOCATION		1007
#define OPTVAL_ENABLE_APP		1008
#define OPTVAL_DISABLE_APP		1009
#define OPTVAL_USAGE			1010

/* Supported options */
const struct option long_opts[] = {
        { "pre-install", 0, NULL, OPTVAL_PRE_INSTALL },
        { "post-install", 0, NULL, OPTVAL_POST_INSTALL },
	{ "pre-uninstall", 0, NULL, OPTVAL_PRE_UNINSTALL },
	{ "post-uninstall", 0, NULL, OPTVAL_POST_UNINSTALL },
	{ "pre-upgrade", 0, NULL, OPTVAL_PRE_UPGRADE },
	{ "post-upgrade", 0, NULL, OPTVAL_POST_UPGRADE },
	{ "move", 0, NULL, OPTVAL_MOVE },
	{ "getlocation", 0, NULL, OPTVAL_GET_LOCATION },
	{ "enable", 0, NULL, OPTVAL_ENABLE_APP },
	{ "disable", 0, NULL, OPTVAL_DISABLE_APP },
	{ "help", 0, NULL, OPTVAL_USAGE },
	{ "usage", 0, NULL, OPTVAL_USAGE },
	{ 0, 0, 0, 0 }	/* sentinel */
};

void clear_dir_list(GList* dir_list)
{
	GList *list = NULL;
	app2ext_dir_details* dir_detail = NULL;

	if (dir_list) {
		list = g_list_first(dir_list);
		while (list) {
			dir_detail = (app2ext_dir_details *)list->data;
			if (dir_detail && dir_detail->name) {
				free(dir_detail->name);
			}
			list = g_list_next(list);
		}
		g_list_free(dir_list);
	}
}

GList * populate_dir_details()
{
	GList *dir_list = NULL;
	GList *list = NULL;
	app2ext_dir_details *dir_detail = NULL;
	int i;

	for (i = 0; i < 3; i++) {
		dir_detail = (app2ext_dir_details*)calloc(1, sizeof(app2ext_dir_details));
		if (dir_detail == NULL) {
			printf("memory allocation failed\n");
			goto FINISH_OFF;
		}

		dir_detail->name = (char*)calloc(1, sizeof(char) * (strlen(pkg_ro_content_rpm[i]) + 2));
		if (dir_detail->name == NULL) {
			printf("memory allocation failed\n");
			free(dir_detail);
			goto FINISH_OFF;
		}
		snprintf(dir_detail->name, (strlen(pkg_ro_content_rpm[i]) + 1), "%s", pkg_ro_content_rpm[i]);
		dir_detail->type = APP2EXT_DIR_RO;
		dir_list = g_list_append(dir_list, dir_detail);
	}

	if (dir_list) {
		list = g_list_first(dir_list);
		while (list) {
			dir_detail = (app2ext_dir_details *)list->data;
			list = g_list_next(list);
		}
	}

	return dir_list;

FINISH_OFF:

	clear_dir_list(dir_list);

	return NULL;
}

static int get_unzip_size(const char *item, unsigned long long *size)
{
	if (!item || !size) {
		printf("get size : invalid argument\n");
		return -1;
	}
	int ret = 0;
	unzFile uzf = unzOpen64(item);
	if (uzf == NULL) {
		printf("get size : failed to open item : [%s]\n", item);
		*size = 0;
		return -1;
	} else {
		ret = unzGoToFirstFile(uzf);
		if (ret != UNZ_OK) {
			printf("get size : error get first zip file\n");
			unzClose(uzf);
			*size = 0;
			return -1;
		} else {
			do {
				ret = unzOpenCurrentFile(uzf);
				if (ret != UNZ_OK) {
					printf("get size : error unzOpenCurrentFile\n");
					unzClose(uzf);
					*size = 0;
					return -1;
				}

				unz_file_info fileInfo = { 0 };
				char *filename = (char *)calloc(1, 4096);
				ret = unzGetCurrentFileInfo(uzf, &fileInfo, filename, (4096 - 1), NULL, 0, NULL, 0);
				*size = (unsigned long long)fileInfo.uncompressed_size + *size;
				if (ret != UNZ_OK) {
					printf("get size : error get current file info\n");
					unzCloseCurrentFile(uzf);
					*size = 0;
					break;
				}

				free(filename);
				filename = NULL;
			} while (unzGoToNextFile(uzf) == UNZ_OK);
		}
	}
	unzClose(uzf);

	return 0;
}

static void print_error_code(const char *func_name, int ret)
{
	if (ret < 0 || ret > COUNT_OF_ERROR_LIST - 1) {
		printf("%s failed : unknown error(%d)\n", func_name, ret);
	} else {
		printf("%s return(%s)\n", func_name, error_list[ret]);
	}
}

static int pre_app_install()
{
	GList *dir_list = NULL;
	int ret = -1;
	unsigned long long size_byte = 0;
	int size_mega = 0;

	printf("pre_app_install for [%s]\n", TEST_PKGNAME_PATH);

	dir_list = populate_dir_details();
	if (dir_list == NULL) {
		printf("error in populating the directory list\n");
		return -1;
	}

	/* size : in MB */
	ret = get_unzip_size(TEST_PKGNAME_PATH, &size_byte);
	if (ret < 0 || size_byte == 0) {
		printf("wrong pkg size, ret(%d), size_byte(%llu)\n", ret, size_byte);
	}
	size_mega = size_byte / (1024 * 1024) + 1;
	printf("get pkg size : (%d)MB\n", size_mega);

	ret = handle->interface.client_usr_pre_install(TEST_PKGNAME,
		dir_list, size_mega, getuid());
	print_error_code(__func__, ret);

	clear_dir_list(dir_list);

	return ret;
}

static int post_app_install()
{
	int ret = -1;

	ret = handle->interface.client_usr_post_install(TEST_PKGNAME,
		APP2EXT_STATUS_SUCCESS, getuid());
	print_error_code(__func__, ret);

	return ret;
}

static int app_enable()
{
	int ret = -1;

	ret = handle->interface.client_usr_enable(TEST_PKGNAME, getuid());
	print_error_code(__func__, ret);

	return ret;
}

static int app_disable()
{
	int ret = -1;

	ret = handle->interface.client_usr_disable(TEST_PKGNAME, getuid());
	print_error_code(__func__, ret);

	return ret;
}

static int pre_app_uninstall()
{
	int ret = -1;

	printf("pre_app_uninstall for [%s]\n", TEST_PKGNAME);

	ret = handle->interface.client_usr_pre_uninstall(TEST_PKGNAME, getuid());
	print_error_code(__func__, ret);

	return ret;
}

static int post_app_uninstall()
{
	int ret = -1;

	ret = handle->interface.client_usr_post_uninstall(TEST_PKGNAME, getuid());
	print_error_code(__func__, ret);

	return ret;
}

static int pre_app_upgrade()
{
	GList *dir_list = NULL;
	int ret = -1;
	unsigned long long size_byte = 0;
	int size_mega = 0;

	printf("pre_app_upgrade for [%s]\n", TEST_PKGNAME);

	dir_list = populate_dir_details();
	if (dir_list == NULL) {
		printf("Error in populating the directory list\n");
		return -1;
	}

	/* size : in MB */
	ret = get_unzip_size(TEST_PKGNAME_PATH, &size_byte);
	if (ret < 0 || size_byte == 0) {
		printf("wrong pkg size, ret(%d), size_byte(%llu)\n", ret, size_byte);
	}
	size_mega = size_byte / (1024 * 1024) + 1;
	printf("get pkg size : (%d)MB\n", size_mega);

	ret = handle->interface.client_usr_pre_upgrade(TEST_PKGNAME, dir_list,
		size_mega, getuid());
	print_error_code(__func__, ret);

	clear_dir_list(dir_list);

	return ret;
}

static int post_app_upgrade()
{
	int ret = -1;

	ret = handle->interface.client_usr_post_upgrade(TEST_PKGNAME,
		APP2EXT_STATUS_SUCCESS, getuid());
	print_error_code(__func__, ret);

	return ret;
}

static int app_move()
{
	GList *dir_list = NULL;
	int ret = -1;
	int ret_check = -1;

	printf("app_move  %s\n", TEST_PKGNAME);

	dir_list = populate_dir_details();
	if (dir_list == NULL) {
		printf("Error in populating the directory list\n");
		return -1;
	}

	ret = app2ext_usr_get_app_location(TEST_PKGNAME, getuid());
	printf("return value = (%d)\n", ret);
	if (ret == APP2EXT_SD_CARD) {
		printf("pkg %s is in sd card\n", TEST_PKGNAME);
		printf("pkg %s will be moved to internal memory\n", TEST_PKGNAME);
		ret = handle->interface.client_usr_move(TEST_PKGNAME,
			dir_list, APP2EXT_MOVE_TO_PHONE, getuid());
		print_error_code(__func__, ret);
		ret = app2ext_usr_get_app_location(TEST_PKGNAME, getuid());
		if (ret_check == APP2EXT_INTERNAL_MEM)
			printf("pkg %s is moved to internal memory\n", TEST_PKGNAME);
	} else if (ret == APP2EXT_INTERNAL_MEM) {
		printf("pkg %s is in internal memory\n", TEST_PKGNAME);
		printf("pkg %s will be moved to sd card\n", TEST_PKGNAME);
		ret = handle->interface.client_usr_move(TEST_PKGNAME,
			dir_list, APP2EXT_MOVE_TO_EXT, getuid());
		print_error_code(__func__, ret);
		ret = app2ext_usr_get_app_location(TEST_PKGNAME, getuid());
		if (ret_check == APP2EXT_SD_CARD)
			printf("pkg %s is moved to sd card\n", TEST_PKGNAME);
	}  else {
		ret = APP2EXT_ERROR_INVALID_PACKAGE;
		printf("app_move failed (%s)\n", error_list[ret]);
	}

	clear_dir_list(dir_list);

	return ret;
}

static void app_get_location()
{
	printf("app_get_location for pkg(%s)\n", TEST_PKGNAME);
	int ret = -1;

	ret = app2ext_usr_get_app_location(TEST_PKGNAME, getuid());
	if (ret == APP2EXT_SD_CARD) {
		printf("pkg is in sd card\n");
	} else if (ret == APP2EXT_INTERNAL_MEM) {
		printf("pkg is in internal memory\n");
	} else {
		printf("pkg is not installed\n");
	}
}

int main(int argc, char **argv)
{
	int ret = 0;
	int opt_idx = 0;
	int c;
	uid_t uid = getuid();

	/* check user */
	if (uid == GLOBAL_USER) {
		printf("test for global app\n");
	} else if (uid == OWNER_ROOT) {
		printf("for root user, a test isn't supproted yet\n");
		return 0;
	} else {
		printf("test for user(%d) app\n", uid);
	}

	handle = app2ext_init(APP2EXT_SD_CARD);
	if (handle == NULL) {
		ret = APP2EXT_ERROR_PLUGIN_INIT_FAILED;
		printf("app2ext_init failed (%s)\n", error_list[ret]);
		return -1;
	}

	/* Parse argv */
	optind = 1;  /* Initialize optind to clear prev. index */
	while (1) {
		c = getopt_long(argc, argv, "", long_opts, &opt_idx);
		if (-1 == c) {
			usage();
			break;  /* Parse is end */
		}
		switch (c) {
		case OPTVAL_PRE_INSTALL:
			pre_app_install();
			break;
		case OPTVAL_POST_INSTALL:
			post_app_install();
			break;
		case OPTVAL_PRE_UNINSTALL:
			pre_app_uninstall();
			break;
		case OPTVAL_POST_UNINSTALL:
			post_app_uninstall();
			break;
		case OPTVAL_PRE_UPGRADE:
			pre_app_upgrade();
			break;
		case OPTVAL_POST_UPGRADE:
			post_app_upgrade();
			break;
		case OPTVAL_MOVE:
			app_move();
			break;
		case OPTVAL_GET_LOCATION:
			app_get_location();
			break;
		case OPTVAL_ENABLE_APP:
			app_enable();
			break;
		case OPTVAL_DISABLE_APP:
			app_disable();
			break;
		case OPTVAL_USAGE:
		default:
			usage();
			break;
		}

		break;
	}

	app2ext_deinit(handle);

	return 0;
}
