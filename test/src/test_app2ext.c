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
#include <app2ext_interface.h>

#define SUCCESS 0
#define FAIL 1
#define CMD_LEN 256

app2ext_handle *handle = NULL;

#define TEST_PKGNAME "org.example.basicuiapplication"

char pkg_ro_content_rpm[3][5] = { "bin", "res", "lib" };

char error_list[45][100] = {
	"SUCCESS",
	"APP2EXT_ERROR_UNKNOW",
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
	"APP2EXT_ERROR_PLUGIN_DEINIT_FAILED"
};

static int __get_integer_input_data(void);

static int __get_integer_input_data(void)
{
	char input_str[32] = { 0, };
	int data = 0;

	if (fgets(input_str, 32, stdin) == NULL) {
		printf("Input buffer overflow....\n");
		return -1;
	}

	if (sscanf(input_str, "%4d", &data) != 1) {
		printf("Input only integer option....\n");
		return -1;
	}

	return data;
}

static void usage(void)
{
	printf("\n*********************************************\n");
	printf("app2sd test\n");
	printf("test_case\n");
	printf("<1> app_install (pre-install, install, post-install, enable, launch, disable)\n");
	printf("<2> app_uninstall (pre-uninstall, uninstall, post-uninstall)\n");
	printf("<3> app_upgrade (pre-upgrade, upgrade, post-Upgrade)\n");
	printf("<4> app_move\n");
	printf("<5> app_get_location\n");
        printf("<6> enable_external_dir\n");
        printf("<7> disable_external_dir\n");
	printf("<8> exit\n");
}

GList * populate_dir_details()
{
	GList *dir_list = NULL;
	GList *list = NULL;
	app2ext_dir_details* dir_detail = NULL;
	int i;


	for (i=0; i<3; i++) {
		dir_detail = (app2ext_dir_details*) calloc(1, sizeof(app2ext_dir_details));
		if (dir_detail == NULL) {
			printf("\nMemory allocation failed\n");
			goto FINISH_OFF;
		}
		dir_detail->name = (char*) calloc(1, sizeof(char)*(strlen(pkg_ro_content_rpm[i])+2));
		if (dir_detail->name == NULL) {
			printf("\nMemory allocation failed\n");
			free(dir_detail);
			goto FINISH_OFF;
		}
		snprintf(dir_detail->name, (strlen(pkg_ro_content_rpm[i])+1), "%s", pkg_ro_content_rpm[i]);
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
	return NULL;
}

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

int app_install()
{
	printf("app_install %s\n", TEST_PKGNAME);
	GList *dir_list = NULL;
	int ret = -1;

	//char cmd_install[CMD_LEN+1];
	//snprintf(cmd_install, CMD_LEN,"tpk-backend -y %s", TEST_PKGNAME);

	dir_list = populate_dir_details();
	if (dir_list == NULL) {
		printf("Error in populating the directory list\n");
		return -1;
	}
	ret = handle->interface.pre_install(TEST_PKGNAME, dir_list, 20);
	if (ret) {
		printf("pre_install failed(%s)\n", error_list[ret]);
		clear_dir_list(dir_list);
		return -1;
	}

	/*
	printf("\n cmd_install is %s ", cmd_install);
	ret = system(cmd_install);
	if (ret) {

		printf("tpk-backend  install command  fail %d ", ret);
		ret = handle->interface.post_install(TEST_PKGNAME, 1);
		if (ret) {
			printf("post_install failed(%s)\n", error_list[ret]);
		}
		clear_dir_list(dir_list);
		return -1;
	}
	*/

	ret = handle->interface.post_install(TEST_PKGNAME, 2);
	if (ret) {
		printf("post_install failed(%s)\n", error_list[ret]);
		clear_dir_list(dir_list);
		return -1;
	}

	ret = handle->interface.enable(TEST_PKGNAME);
	if (ret) {
		printf("enable failed(%s)\n", error_list[ret]);
		clear_dir_list(dir_list);
		return -1;
	}

	/*
	printf("\nLaunching application after install");
	ret = aul_open_app(TEST_PKGNAME);

	if (ret < 0)
		printf("\n launch fail");
	else
		printf("\n application launched");

	sleep(5);

	ret = system("killall -9 basicuiapplication");
	if (ret < 0)
		printf("\n app exit fail");
	else
		printf("\n application exited");

	sleep(5);
	*/

	ret = handle->interface.disable(TEST_PKGNAME);
	if (ret < 0 || ret > 44) {
		printf("disable failed : unknown error\n");
	} else {
		printf("disable return(%s)\n", error_list[ret]);
	}

	clear_dir_list(dir_list);

	return ret;
}

int app_uninstall()
{
	printf("app_uninstall  %s\n", TEST_PKGNAME);
	int ret = -1;
	//char cmd_uninstall[CMD_LEN+1];
	//snprintf(cmd_uninstall, CMD_LEN, "tpk-backend -y %s", TEST_PKGNAME);

	ret = handle->interface.pre_uninstall(TEST_PKGNAME);
	if (ret) {
		printf("pre_uninstall failed(%s)", error_list[ret]);
		return -1;
	}

	/*
	printf("\n cmd_uninstall is %s ", cmd_uninstall);
	ret = system(cmd_uninstall);
	if (ret) {
		printf("\nrpm  uninstall command  fail Reason %s", error_list[ret]);
		return -1;
	}
	*/

	ret = handle->interface.post_uninstall(TEST_PKGNAME);
	if (ret) {
		printf("post app uninstall API fail Reason %s\n", error_list[ret]);
		return -1;
	}

	return ret;
}

int app_upgrade()
{
	printf("app_upgrade  %s\n", TEST_PKGNAME);
	int ret = -1;
	//char cmd_uninstall[CMD_LEN+1];
	//snprintf(cmd_uninstall, CMD_LEN, "rpm -U %s", TEST_PKGNAME);

	GList *dir_list = populate_dir_details();
	if (dir_list == NULL) {
		printf("Error in populating the directory list\n");
		return -1;
	}

	ret = handle->interface.pre_upgrade(TEST_PKGNAME, dir_list, 40);
	if (ret) {
		printf("pre app upgrade API fail. Reason %s\n", error_list[ret]);
		clear_dir_list(dir_list);
		return -1;
	}

	/*
	printf("\n cmd_uninstall is %s ", cmd_uninstall);
	ret = system(cmd_uninstall);
	if (ret) {
		printf("\nrpm  upgrade command  fail Reason %s", error_list[ret]);
		ret = handle->interface.post_upgrade(TEST_PKGNAME_RPM, 1);
		if (ret) {
			printf("post app upgrade API fail Reason %s\n", error_list[ret]);
		}
		clear_dir_list(dir_list);
		return -1;
	}
	*/

	ret = handle->interface.post_upgrade(TEST_PKGNAME, 2);
	if (ret) {
		printf("\n TC : post app upgrade API fail Reason %s", error_list[ret]);
		clear_dir_list(dir_list);
		return -1;
	}
	clear_dir_list(dir_list);
	return ret;
}

int app_move()
{
	printf("app_move  %s\n", TEST_PKGNAME);
	int ret = -1;
	int ret_check = -1;
	GList *dir_list = populate_dir_details();
	if (dir_list == NULL) {
		printf("\nError in populating the directory list\n");
		return -1;
	}

	ret = app2ext_get_app_location(TEST_PKGNAME);
	printf("return value = (%d)", ret);
	if (ret == APP2EXT_SD_CARD) {
		printf("\n app %s is in sd card ", TEST_PKGNAME);
		printf("\n app  %s  will be moved to internal memory ",
		       TEST_PKGNAME);
		ret = handle->interface.move(TEST_PKGNAME, dir_list, APP2EXT_MOVE_TO_PHONE);
		if (ret) {
			printf("\n  TC: move API failed Reason %s", error_list[ret]);
			clear_dir_list(dir_list);
			return -1;
		}
		ret = app2ext_get_app_location(TEST_PKGNAME);
		if (ret_check == APP2EXT_INTERNAL_MEM)
			printf("\n app %s is moved to internal memory ",
			       TEST_PKGNAME);
	} else if (ret == APP2EXT_INTERNAL_MEM) {
		printf("\n app %s  is  in internal memory ", TEST_PKGNAME);
		printf("\n app %s will be moved to sd card", TEST_PKGNAME);

		ret = handle->interface.move(TEST_PKGNAME, dir_list, APP2EXT_MOVE_TO_EXT);
		if (ret) {
			printf("\n  TC: move API failed Reason %s", error_list[ret]);
			clear_dir_list(dir_list);
			return -1;
		}
		ret = app2ext_get_app_location(TEST_PKGNAME);
		if (ret_check == APP2EXT_SD_CARD)
			printf("\n app %s is moved to sd card ",
			       TEST_PKGNAME);
	}  else {
		ret = APP2EXT_ERROR_INVALID_PACKAGE;
		printf("\n errorReason %s", error_list[ret]);
		clear_dir_list(dir_list);
		return ret;
	}
	clear_dir_list(dir_list);
	return ret;
}

void app_get_location()
{
	printf("app_get_location  %s \n", TEST_PKGNAME);
	int ret = -1;

	ret = app2ext_get_app_location(TEST_PKGNAME);
	if (ret == APP2EXT_SD_CARD) {
		printf("\n app %s is in sd card ", TEST_PKGNAME);
	} else if (ret == APP2EXT_INTERNAL_MEM) {
		printf("\n app %s  is  in internal memory ", TEST_PKGNAME);
	} else {
		printf("\napp %s is not installed", TEST_PKGNAME);
	}
}

void enable_external_dir()
{
	printf("enable_external_dir\n");
	int ret = -1;

	ret = app2ext_enable_external_dir();
	if (ret == 0) {
		printf("\n app2ext_enable_external_dir() success");
	} else {
		printf("\n app2ext_enable_external_dir() failed");
	}
}

void disable_external_dir()
{
	printf("disable_external_dir\n");
	int ret = -1;

	ret = app2ext_disable_external_dir();
	if (ret == 0) {
		printf("\n app2ext_disable_external_dir() success");
	} else {
		printf("\n app2ext_disable_external_dir() failed");
	}
}

int main(int argc, char **argv)
{
	int ret = 0;

	/* check authorized user */

	handle = app2ext_init(APP2EXT_SD_CARD);
	if (handle == NULL) {
		ret = APP2EXT_ERROR_PLUGIN_INIT_FAILED;
		printf("app2ext_init failed (%s)\n", error_list[ret]);
		return -1;
	}

	do {
		usage();
		printf("enter testcase\n");
		int option = __get_integer_input_data();
		switch (option) {
		case 1:
			app_install();
			break;
		case 2:
			app_uninstall();
			break;
		case 3:
			app_upgrade();
			break;
		case 4:
			app_move();
			break;
		case 5:
			app_get_location();
			break;
		case 6:
			enable_external_dir();
			break;
		case 7:
			disable_external_dir();
			break;
		case 8:
			app2ext_deinit(handle);
			printf("Exit!\n");
			return 0;
		default:
			printf("\nInvalid test id\n");
			break;
		}
	} while(1);

	app2ext_deinit(handle);

	return 0;
}
