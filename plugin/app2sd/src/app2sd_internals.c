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

#include <dirent.h>
#include <openssl/sha.h>
#include <time.h>
#include <pwd.h>

#include "app2sd_internals.h"

#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
#define DMCRYPT_ITER_TIME	50
#define DMCRYPT_KEY_LEN		128
#endif

static int _app2sd_make_directory(const char *path, uid_t uid)
{
	int ret = 0;
	int fd = -1;
	mode_t mode = DIR_PERMS;
	struct passwd pwd;
	struct passwd *pwd_result;
	char buf[1024] = { 0, };

	ret = _app2sd_delete_directory(path);
	if (ret) {
		_E("unable to delete (%s)", path);
		return APP2EXT_ERROR_DELETE_DIRECTORY;
	}

	ret = getpwuid_r(uid, &pwd, buf, sizeof(buf), &pwd_result);
	if (ret != 0 || pwd_result == NULL) {
		_E("get uid failed(%d)", ret);
		return APP2EXT_ERROR_ACCESS_FILE;
	}
	_D("uid(%d), gid(%d)", uid, pwd.pw_gid);

	/* create directory */
	ret = mkdir(path, mode);
	if (ret) {
		if (errno != EEXIST) {
			_E("create directory failed," \
				" error no is (%d)", errno);
			return APP2EXT_ERROR_CREATE_DIRECTORY;
		}
	}

	fd = open(path, O_RDONLY|O_DIRECTORY);
	if (fd < 0) {
		_E("can't open path(%s)", path);
		return APP2EXT_ERROR_OPEN_DIR;
	}

	ret = fchmod(fd, 0755);
	if (ret < 0) {
		_E("change file permission error");
		close(fd);
		return APP2EXT_ERROR_ACCESS_FILE;
	}

	ret = fchown(fd, uid, pwd.pw_gid);
	if (ret < 0) {
		_E("change file owner error");
		close(fd);
		return APP2EXT_ERROR_ACCESS_FILE;
	}

	close(fd);

	return APP2EXT_SUCCESS;
}

char *_app2sd_find_associated_device_node(const char *loopback_device)
{
	char *ret_result = NULL;
	char delims[] = ":";
	char *result = NULL;
	char dev[FILENAME_MAX] = { 0, };
	char *devnode = NULL;

	result = (char *)_app2sd_find_associated_device(loopback_device);
	if (result == NULL) {
		_D("there is no the associated file (%s)", loopback_device);
		return NULL;
	}

	/* process the string*/
	snprintf(dev, FILENAME_MAX - 1, "%s", result);

	if (strstr(dev, "dev") == NULL) {
		_E("unable to find the associated file");
		free(result);
		return NULL;
	} else {
		char *saveptr = NULL;
		ret_result = strtok_r(dev, delims, &saveptr);
		if (ret_result)
			devnode = strdup(ret_result);
	}

	free(result);

	return devnode;
}

char *_app2sd_create_loopdevice_node(void)
{
	char *ret_result = NULL;
	mode_t mode = DIR_PERMS;
	int count = 0;
	int ret = APP2EXT_SUCCESS;
	char *result = NULL;
	FILE *fp = NULL;

	result = (char *)_app2sd_find_free_device();
	_D("find_free_device(%s)", result);

	/* validate the result */
	if (result == NULL || strstr(result, "/dev") == NULL) {
		_D("no device found, creating device node");

		if (result) {
			free(result);
			result = NULL;
		}
		count = 0;
		char dev_path[BUF_SIZE] = { 0, };
		snprintf(dev_path, BUF_SIZE, "/dev/loop%d", count);
		while ((fp = fopen(dev_path, "r+")) != NULL) {
			count = count + 1;
			snprintf(dev_path, BUF_SIZE, "/dev/loop%d", count);
			_D("next dev path for checking is (%s)",
				     dev_path);
			fclose(fp);
		}
		_D("device node candidate is (%s)", dev_path);
		dev_t dev_node;
		dev_node = makedev(DEV_MAJOR, count);
		ret = mknod(dev_path, S_IFBLK | mode, dev_node);
		if (ret < 0) {
			_E("error while creating the device node: errno is (%d)",
			     errno);
			return NULL;
		}
		ret_result = (char *)malloc(strlen(dev_path) + 1);
		if (ret_result == NULL) {
			_E("unable to allocate memory");
			return NULL;
		}
		memset(ret_result, '\0', strlen(dev_path) + 1);
		memcpy(ret_result, dev_path, strlen(dev_path));
	} else {
		ret_result = (char *)malloc(strlen(result) + 1);
		if (ret_result == NULL) {
			_E("malloc failed");
			free(result);
			result = NULL;
			return NULL;
		}
		memset(ret_result, '\0', strlen(result) + 1);
		if (strlen(result) > 0)
			memcpy(ret_result, result, strlen(result) - 1);

		free(result);
		result = NULL;

	}
	return ret_result;
}

char *_app2sd_do_loopback_encryption_setup(const char *pkgid,
	const char *loopback_device, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;
	char *passwd = NULL;
	char *result = NULL;
	char *device_node = NULL;

	if (pkgid == NULL) {
		_E("invalid argument");
		return NULL;
	}

	/* get password for loopback encryption */
	ret = _app2sd_initialize_db();
	if (ret) {
		_E("app2sd db initialize failed");
		return NULL;
	}

	if ((passwd = _app2sd_get_password_from_db(pkgid, uid)) == NULL) {
		passwd = (char *)_app2sd_generate_password(pkgid);
		if (NULL == passwd) {
			_E("unable to generate password");
			return NULL;
		} else {
			if ((ret = _app2sd_set_info_in_db(pkgid,
				passwd, loopback_device, uid)) < 0) {
				_E("unable to save info");
				free(passwd);
				passwd = NULL;
				return NULL;
			}
		}
	}

	/* get free device node*/
	device_node = _app2sd_create_loopdevice_node();
	if (NULL == device_node) {
		free(passwd);
		passwd = NULL;
		_E("unable to find free loopback node");
		return NULL;
	}

	_D("device_node (%s)", device_node);

	result = (char *)_app2sd_encrypt_device(device_node,
		loopback_device, passwd);
	if (result == NULL) {
		_E("encryption failed");
		free(passwd);
		passwd = NULL;
		return NULL;
	} else {
		_D("result (%s)", result);
		free(result);
		result = NULL;
		free(passwd);
		passwd = NULL;
		return device_node;
	}
}

char *_app2sd_do_loopback_duplicate_encryption_setup(const char *pkgid,
		const char *temp_pkgid, const char *temp_loopback_device,
		char *passwd, uid_t uid)
{
	char *result = NULL;
	char *device_node = NULL;

	if (pkgid == NULL || temp_pkgid == NULL ||
		temp_loopback_device == NULL || passwd == NULL) {
		_E("invalid argument");
		return NULL;
	}

	/* get free device node*/
	device_node = _app2sd_create_loopdevice_node();
	if (NULL == device_node) {
		_E("unable to find free loopback node");
		return NULL;
	}
	result = (char *)_app2sd_encrypt_device(device_node,
		temp_loopback_device, passwd);
	if (result == NULL) {
		_E("encryption failed");
		return NULL;
	} else {
		if (strlen(result) == 0) {
			free(result);
			result = NULL;
			return device_node;
		} else {
			_E("error is (%s)", result);
			free(result);
			result = NULL;
			return NULL;
		}
	}

	return device_node;
}

int _app2sd_remove_loopback_encryption_setup(const char *loopback_device)
{
	int ret = APP2EXT_SUCCESS;
	char *result = NULL;
	char *dev_node = NULL;

	if ((dev_node = _app2sd_find_associated_device_node(loopback_device))
		== NULL) {
		_E("Unable to find the association");
		ret = APP2EXT_ERROR_FIND_ASSOCIATED_DEVICE_NODE;
	}

	result = (char *)_app2sd_detach_loop_device(dev_node);
	if (result == NULL) {
		_E("error in detaching");
		ret = APP2EXT_ERROR_DETACH_LOOPBACK_DEVICE;
	} else {
		free(result);
		result = NULL;
	}

	if (dev_node) {
		free(dev_node);
		dev_node = NULL;
	}

	return ret;
}

int _app2sd_remove_all_loopback_encryption_setups(const char *loopback_device)
{
	int ret = APP2EXT_SUCCESS;
	char *result = NULL;
	char *dev_node = NULL;
	while (1) {
		if ((dev_node =
			_app2sd_find_associated_device_node(loopback_device))
			== NULL) {
			_E("finish to find the association");
			ret = APP2EXT_SUCCESS;
			break;
		}

		_D("find node (%s)", dev_node);

		result = (char *)_app2sd_detach_loop_device(dev_node);
		if (result == NULL) {
			_E("error in detaching");
			ret = APP2EXT_ERROR_DETACH_LOOPBACK_DEVICE;
			break;
		} else {
			free(result);
			result = NULL;
		}
		if (dev_node) {
			free(dev_node);
			dev_node = NULL;
		}
	}

	return ret;
}

#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
int _app2sd_dmcrypt_setup_device(const char *pkgid,
		const char *loopback_device, bool is_dup, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;
	char *passwd = NULL;
	char dmcrypt_setup_cmd[BUF_SIZE] = { 0, };
	char err_buf[BUF_SIZE] = { 0, };

	if (pkgid == NULL || loopback_device == NULL) {
		_E("invalid argument");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* get password for dmcrypt encryption */
	ret = _app2sd_initialize_db();
	if (ret) {
		_E("app2sd db initialize failed");
		return APP2EXT_ERROR_DB_INITIALIZE;
	}

	passwd = _app2sd_get_password_from_db(pkgid, uid);
	if (passwd == NULL) {
		if (is_dup) {
			_E("no password found for (%s)", pkgid);
			return APP2EXT_ERROR_SQLITE_REGISTRY;
		}
		passwd = (char *)_app2sd_generate_password(pkgid);
		if (NULL == passwd) {
			_E("unable to generate password\n");
			return APP2EXT_ERROR_PASSWD_GENERATION;
		} else {
			if ((ret = _app2sd_set_info_in_db(pkgid, passwd,
				loopback_device, uid)) < 0) {
				_E("unable to save password");
				free(passwd);
				passwd = NULL;
				return APP2EXT_ERROR_SQLITE_REGISTRY;
			}
		}
	}

	snprintf(dmcrypt_setup_cmd, BUF_SIZE, "/bin/echo '%s' | /sbin/cryptsetup -q -i %d " \
		"-c aes-cbc-lmk -s %d --align-payload=8 luksFormat %s",
		passwd, DMCRYPT_ITER_TIME, DMCRYPT_KEY_LEN, loopback_device);

	ret = system(dmcrypt_setup_cmd);
	if (ret) {
		strerror_r(errno, err_buf, sizeof(err_buf));
		_E("Error setting up dmcrypt on app2sd file, " \
			"error(%s), ret(%d)", err_buf, ret);
		if (passwd) {
			free(passwd);
			passwd = NULL;
		}
		return APP2EXT_ERROR_SETUP_DMCRYPT_DEVICE;
	}

	if (passwd) {
		free(passwd);
		passwd = NULL;
	}

	return ret;
}

int _app2sd_dmcrypt_open_device(const char *pkgid, const char *loopback_device,
		bool is_dup, uid_t uid, char **dev_node)
{
	int ret = APP2EXT_SUCCESS;
	char *passwd = NULL;
	char dmcrypt_open_cmd[BUF_SIZE] = { 0, };
	char dev_name[BUF_SIZE] = { 0, };
	char buf[BUF_SIZE] = { 0, };
	int len = 0;

	if (pkgid == NULL || loopback_device == NULL) {
		_E("invalid argument");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	if (is_dup)
		snprintf(dev_name, BUF_SIZE, "%s.new_%d", pkgid, uid);
	else
		snprintf(dev_name, BUF_SIZE, "%s_%d", pkgid, uid);

	/* get password for dmcrypt encryption */
	ret = _app2sd_initialize_db();
	if (ret) {
		_E("app2sd db initialize failed");
		return APP2EXT_ERROR_DB_INITIALIZE;
	}
	if ((passwd = _app2sd_get_password_from_db(pkgid, uid)) == NULL) {
		_E("no password found for [%s]", pkgid);
		return APP2EXT_ERROR_SQLITE_REGISTRY;
	}

	snprintf(dmcrypt_open_cmd, BUF_SIZE, "/bin/echo '%s' | /sbin/cryptsetup -q luksOpen %s %s",
		passwd, loopback_device, dev_name);

	ret = system(dmcrypt_open_cmd);
	if (ret) {
		strerror_r(errno, buf, sizeof(buf));
		_E("error opening dmcrypt device, error: [%s]", buf);
		return APP2EXT_ERROR_OPEN_DMCRYPT_DEVICE;
	}

	snprintf(buf, BUF_SIZE, "/dev/mapper/%s", dev_name);
	len = strlen(buf);
	*dev_node = (char *)calloc(len + 1, sizeof(char));
	if (*dev_node == NULL) {
		_E("memory alloc failed");
		return APP2EXT_ERROR_OPEN_DMCRYPT_DEVICE;
	}
	snprintf(*dev_node, len + 1, "%s", buf);

	return ret;
}

int _app2sd_dmcrypt_close_device(const char *pkgid, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;
	char dev_node[BUF_SIZE] = { '\0' };
	char dmcrypt_close_cmd[BUF_SIZE] = { '\0' };
	char err_buf[BUF_SIZE] = { '\0' };
	char *t_dev_node = NULL;

	if (pkgid == NULL) {
		_E("invalid argument\n");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	t_dev_node = _app2sd_find_associated_dmcrypt_device_node(pkgid, uid);
	if (!t_dev_node) {
		_E("no associated device node(%s_%d) found", pkgid, uid);
		return APP2EXT_ERROR_DMCRYPT_DEVICE_UNAVAILABLE;
	}

	free(t_dev_node);
	t_dev_node = NULL;

	snprintf(dev_node, BUF_SIZE, "/dev/mapper/%s_%d", pkgid, uid);
	snprintf(dmcrypt_close_cmd, BUF_SIZE, "/sbin/cryptsetup -q luksClose %s", dev_node);
	ret = system(dmcrypt_close_cmd);
	if (ret) {
		strerror_r(errno, err_buf, sizeof(err_buf));
		_E("error closing dmcrypt on app2sd file,"\
			" error: [%s]", err_buf);
		return APP2EXT_ERROR_CLOSE_DMCRYPT_DEVICE;
	}

	return ret;
}

char *_app2sd_find_associated_dmcrypt_device_node(const char *pkgid, uid_t uid)
{
	char *dev_node = NULL;
	char buf[BUF_SIZE] = { 0, };
	int len = 0;

	snprintf(buf, BUF_SIZE, "/dev/mapper/%s_%d", pkgid, uid);
	len = strlen(buf);
	dev_node = (char *)calloc(len + 1, sizeof(char));
	if (dev_node == NULL) {
		_E("memory alloc failed");
		return NULL;
	}
	snprintf(dev_node, len + 1, "%s", buf);

	if (access(dev_node, F_OK) == 0) {
		_D("device_node: (%s)", dev_node);
		return dev_node;
	}

	free(dev_node);
	dev_node = NULL;

	return NULL;
}

char *_app2sd_dmcrypt_duplicate_encryption_setup(const char *pkgid,
		const char *temp_loopback_device, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;
	char *device_node = NULL;

	if (pkgid == NULL || temp_loopback_device == NULL) {
		_E("invalid argument\n");
		return NULL;
	}

	ret = _app2sd_dmcrypt_setup_device(pkgid, temp_loopback_device, true, uid);
	if (ret) {
		_E("dmcrypt setup device error(%d)", ret);
		return NULL;
	}

	ret = _app2sd_dmcrypt_open_device(pkgid, temp_loopback_device, true,
		uid, &device_node);
	if (ret) {
		_E("dmcrypt open device error");
		return NULL;
	}

	return device_node;
}
#endif

int _app2sd_create_loopback_device(const char *pkgid,
		const char *loopback_device, int size)
{
	int ret = APP2EXT_SUCCESS;
	char command[FILENAME_MAX] = { 0, };
	char buff[BUF_SIZE] = { 0, };
	FILE *fp = NULL;

	if (NULL == pkgid || size <= 0) {
		_E("invalid argument");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}
	snprintf(command, FILENAME_MAX - 1, "of=%s", loopback_device);
	snprintf(buff, BUF_SIZE - 1, "count=%d", size);

	const char *argv1[] = { "/bin/dd", "if=/dev/zero",
		command, "bs=1M", buff, NULL };

	if ((fp = fopen(loopback_device, "r+")) != NULL) {
		_W("encrypted file already exists (%s)",
			loopback_device);
		fclose(fp);
		return APP2EXT_ERROR_PKG_EXISTS;
	}

	ret = _xsystem(argv1);
	if (ret)
		_E("command (%s) failed, ret(%d), errno(%d)", command, ret, errno);

	return ret;
}

int _app2sd_delete_loopback_device(const char *loopback_device)
{
	int ret = APP2EXT_SUCCESS;

	ret = unlink(loopback_device);
	if (ret) {
		if (errno == ENOENT) {
			_W("unable to access file (%s)", loopback_device);
		} else {
			_E("unable to delete (%s)", loopback_device);
			return APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
		}
	}

	return APP2EXT_SUCCESS;
}

int _app2sd_create_file_system(const char *device_path)
{
	int ret = APP2EXT_SUCCESS;
	FILE *fp = NULL;
	char err_buf[1024] = {0,};

	if (device_path == NULL) {
		_E("invalid param");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* Format the filesystem [create a filesystem]*/
	const char *argv[] = { "/sbin/mkfs.ext4", device_path, NULL };
	fp = fopen(device_path, "r+");
	if (fp == NULL) {
		strerror_r(errno, err_buf, sizeof(err_buf));
		_E("unable to access (%s) error is (%d, %s)",
		     device_path, errno, err_buf);
		return APP2EXT_ERROR_ACCESS_FILE;
	} else {
		fclose(fp);
	}
	ret = _xsystem(argv);
	if (ret) {
		strerror_r(errno, err_buf, sizeof(err_buf));
		_E("creating file system failed, error is (%s)",
		     err_buf);
		return APP2EXT_ERROR_CREATE_FS;
	}
	return ret;
}

static int _app2sd_create_dir_with_link(const char *application_path,
		const char *pkgid, const char *dir_name, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;
	char application_dir_mmc_path[FILENAME_MAX] = { 0, };
	char application_dir_path[FILENAME_MAX] = { 0, };

	snprintf(application_dir_mmc_path, FILENAME_MAX - 1, "%s/.mmc/%s",
		application_path, dir_name);
	snprintf(application_dir_path, FILENAME_MAX, "%s/%s",
		application_path, dir_name);

	ret = _app2sd_make_directory(application_dir_mmc_path, uid);
	if (ret) {
		_E("create directory failed");
		return APP2EXT_ERROR_CREATE_DIRECTORY;
	}

	if ((ret = symlink(application_dir_mmc_path,
		application_dir_path)) < 0) {
		if (errno == EEXIST) {
			_D("file with symlink name present (%s)",
				application_dir_path);
		} else {
			_E("symbolic link creation "
				"failed, error no is (%d)", errno);
			return APP2EXT_ERROR_CREATE_SYMLINK;
		}
	}

	return APP2EXT_SUCCESS;
}

static int _app2sd_create_directory_entry(const char *application_path,
		const char *pkgid, GList *dir_list, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;
	GList *list = NULL;
	app2ext_dir_details *dir_detail = NULL;

	list = g_list_first(dir_list);
	while (list) {
		dir_detail = (app2ext_dir_details *)list->data;
		if (dir_detail && dir_detail->name
			&& dir_detail->type == APP2EXT_DIR_RO) {
			ret = _app2sd_create_dir_with_link(application_path,
				pkgid, dir_detail->name, uid);
			if (ret)
				return ret;
		}
		list = g_list_next(list);
	}
	return APP2EXT_SUCCESS;
}

int _app2sd_mount_app_content(const char *application_path, const char *pkgid,
		const char *dev, int mount_type, GList *dir_list,
		app2sd_cmd cmd, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;
	int fd = -1;
	char application_mmc_path[FILENAME_MAX] = { 0, };
	char temp_path[FILENAME_MAX] = { 0, };
	char err_buf[1024] = {0,};
	struct timespec time = {
		.tv_sec = 0,
		.tv_nsec = 1000 * 1000 * 200
	};

	if (NULL == dev) {
		_E("input param is NULL (%s)",
			     dev);
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	/* check directory existence */
	fd = open(application_path, O_RDONLY|O_DIRECTORY);
	if (fd < 0) {
		_E("path(%s) error(%d)", application_path, errno);
		return APP2EXT_ERROR_OPEN_DIR;
	}
	close(fd);

	snprintf(application_mmc_path, FILENAME_MAX - 1, "%s/.mmc",
		application_path);
	fd = open(application_mmc_path, O_RDONLY|O_DIRECTORY);
	if (fd < 0) {
		_E("path(%s) error(%d)", application_mmc_path, errno);
		return APP2EXT_ERROR_OPEN_DIR;
	}
	close(fd);

	nanosleep(&time, NULL); /* 200ms sleep */
	_D("give a delay for mount");

	switch (mount_type) {
	case MOUNT_TYPE_RD:
		if ((ret = mount(dev, application_mmc_path, FS_TYPE,
			MS_MGC_VAL | MS_RDONLY | MS_NOSUID, NULL)) < 0) {
			_E("read only mount failed, " \
				"errono is (%d), " \
				"dev is (%s) path is (%s)",
				errno, dev, application_mmc_path);
			ret = APP2EXT_ERROR_MOUNT;
		}
		break;
	case MOUNT_TYPE_RW:
		if ((ret = mount(dev, application_mmc_path, FS_TYPE,
			MS_MGC_VAL | MS_NOSUID, NULL)) < 0) {
			_E("read write mount failed, " \
				"errono is (%d)", errno);
			ret = APP2EXT_ERROR_MOUNT;
		}
		break;
	case MOUNT_TYPE_RW_NOEXEC:
		if ((ret = mount(dev, application_mmc_path, FS_TYPE,
			MS_MGC_VAL | MS_NOEXEC | MS_NOSUID, NULL)) < 0) {
			_E("rwnx mount failed " \
				"errono is (%d)", errno);
			ret = APP2EXT_ERROR_MOUNT;
		}
		break;
	case MOUNT_TYPE_RD_REMOUNT:
		if ((ret = mount(dev, application_mmc_path, FS_TYPE,
			MS_MGC_VAL | MS_RDONLY | MS_REMOUNT | MS_NOSUID,
			NULL)) < 0) {
			_E("read remount failed "
				"errono is (%d)", errno);
			ret = APP2EXT_ERROR_MOUNT;
		}
		break;
	case MOUNT_TYPE_RW_REMOUNT:
		if ((ret = mount(dev, application_mmc_path, FS_TYPE,
			MS_MGC_VAL | MS_REMOUNT | MS_NOSUID, NULL)) < 0) {
			_E("read write remount failed "
				"errono(%d), errstr(%s)", errno,
				strerror_r(errno, err_buf, sizeof(err_buf)));
				ret = APP2EXT_ERROR_MOUNT;
		}
		break;
	default:
		_E("invalid mount type");
		break;
	}

	if (cmd == APP2SD_PRE_INSTALL || cmd == APP2SD_MOVE_APP_TO_MMC ||
		cmd == APP2SD_PRE_UPGRADE) {
		ret = _app2sd_create_directory_entry(application_path,
			pkgid, dir_list, uid);
	}

	/* change lost+found permission */
	snprintf(temp_path, FILENAME_MAX - 1, "%s/lost+found",
			application_mmc_path);
	ret = _app2sd_make_directory(temp_path, uid);
	if (ret) {
		_E("create directory(%s) failed", temp_path);
		return APP2EXT_ERROR_CREATE_DIRECTORY;
	}

	return ret;
}

int _app2sd_unmount_app_content(const char *application_path)
{
	int ret = APP2EXT_SUCCESS;
	char application_dir_mmc_path[FILENAME_MAX] = { 0, };
	char err_buf[1024] = {0,};

	snprintf(application_dir_mmc_path, FILENAME_MAX - 1, "%s/.mmc",
		application_path);
	if ((ret = umount(application_dir_mmc_path)) < 0) {
		strerror_r(errno, err_buf, sizeof(err_buf));
		_E("unable to umount the dir, ret(%d) error(%d, %s)",
			ret, errno, err_buf);
	}

	return ret;
}

static int _app2sd_move_to_archive(const char *src_path, const char *arch_path)
{
	int ret = APP2EXT_SUCCESS;

	ret = _app2sd_copy_dir(src_path, arch_path);
	if (ret && ret != APP2EXT_ERROR_ACCESS_FILE) {
		char err_buf[1024] = {0,};
		strerror_r(errno, err_buf, sizeof(err_buf));
		_E("unable to copy from (%s) to (%s), err is (%s)",
			src_path, arch_path, err_buf);
		return APP2EXT_ERROR_MOVE;
	}

	ret = _app2sd_delete_directory((char *)src_path);
	if (ret) {
		_E("unable to delete (%s)", src_path);
		return APP2EXT_ERROR_DELETE_DIRECTORY;
	}

	return ret;
}

static int _app2sd_move_app_to_external(const char *pkgid, GList *dir_list,
		uid_t uid, char *mmc_path)
{
	int ret = APP2EXT_SUCCESS;
	mode_t mode = DIR_PERMS;
	char temp_dir_path[FILENAME_MAX] = { 0, };
	char application_mmc_path[FILENAME_MAX] = { 0, };
	char application_archive_path[FILENAME_MAX] = { 0, };
	char application_path[FILENAME_MAX] = { 0, };
	char loopback_device[FILENAME_MAX] = { 0, };
	unsigned long long total_size = 0;
	int reqd_size = 0;
	int reqd_disk_size = 0;
	char *device_node = NULL;
#if !defined(TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION)
	char *devi = NULL;
#endif
	int free_mmc_mem = 0;
	FILE *fp = NULL;
	GList *list = NULL;
	app2ext_dir_details *dir_detail = NULL;
	char err_buf[1024] = { 0,};
	char *encoded_id = NULL;

	encoded_id = _app2sd_get_encoded_name(pkgid, uid);
	if (encoded_id == NULL)
		return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;

	snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s/%s",
			mmc_path, EXTIMG_DIR, encoded_id);
	free(encoded_id);
	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		tzplatform_reset_user();
	}

	/* check whether application is in external memory or not */
	fp = fopen(loopback_device, "r+");
	if (fp != NULL) {
		_W("Already %s entry is present in the SD Card, " \
			"delete entry and go on without return", pkgid);
		fclose(fp);
		_app2sd_force_clean(pkgid, application_path, loopback_device, uid);
	}

	snprintf(application_mmc_path, FILENAME_MAX - 1, "%s/.mmc",
		application_path);
	snprintf(application_archive_path, FILENAME_MAX - 1, "%s/.archive",
		application_path);

	ret = mkdir(application_mmc_path, mode);
	if (ret) {
		if (errno != EEXIST) {
			_E("unable to create directory for archiving," \
				" error(%d)", errno);
			return APP2EXT_ERROR_CREATE_DIRECTORY;
		}
	}

	ret = mkdir(application_archive_path, mode);
	if (ret) {
		if (errno != EEXIST) {
			_E("unable to create directory for archiving," \
				" error(%d)", errno);
			return APP2EXT_ERROR_CREATE_DIRECTORY;
		}
	}

	list = g_list_first(dir_list);
	while (list) {
		dir_detail = (app2ext_dir_details *)list->data;
		if (dir_detail && dir_detail->name
			&& dir_detail->type == APP2EXT_DIR_RO) {
			memset(temp_dir_path, '\0', FILENAME_MAX);
			snprintf(temp_dir_path, FILENAME_MAX,
				 "%s/%s", application_path,
				 dir_detail->name);
			_D("cal size of app dirs, temp_dir_path(%s)",
				temp_dir_path);
			total_size +=
			    _app2sd_calculate_dir_size(temp_dir_path);
		}
		list = g_list_next(list);
	}

	reqd_size = ((total_size) / (1024 * 1024)) + 2;
	reqd_disk_size = reqd_size + ceil(reqd_size * 0.2);

	/* find avialable free memory in the MMC card */
	ret = _app2sd_get_available_free_memory(mmc_path, &free_mmc_mem);
	if (ret) {
		_E("unable to get available free memory in MMC (%d)", ret);
		return APP2EXT_ERROR_MMC_STATUS;
	}
	/* if avaialalbe free memory in MMC is less than
	 * required size + 5MB, return error
	 */
	if (reqd_disk_size > free_mmc_mem) {
		_E("insufficient memory in MMC for application installation (%d)",
			ret);
		return APP2EXT_ERROR_MMC_INSUFFICIENT_MEMORY;
	}
	/* create a loopback device */
	ret = _app2sd_create_loopback_device(pkgid, loopback_device,
		(reqd_disk_size + PKG_BUF_SIZE));
	if (ret) {
		_E("loopback node creation failed");
		return ret;
	}

#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	ret = _app2sd_dmcrypt_setup_device(pkgid, loopback_device, false, uid);
	if (ret) {
		_E("dmcrypt setup device error(%d)", ret);
		return APP2EXT_ERROR_SETUP_DMCRYPT_DEVICE;
	}

	ret = _app2sd_dmcrypt_open_device(pkgid, loopback_device, false,
		uid, &device_node);
	if (ret) {
		_E("dmcrypt open device error");
		return APP2EXT_ERROR_OPEN_DMCRYPT_DEVICE;
	}
#else
	/* perform loopback encryption setup */
	device_node = _app2sd_do_loopback_encryption_setup(pkgid,
		loopback_device, uid);
	if (!device_node) {
		_E("loopback encryption setup failed");
		return APP2EXT_ERROR_DO_LOSETUP;
	}
	_D("device_node (%s)", device_node);
	/* check whether loopback device is associated with device node or not */
	devi = _app2sd_find_associated_device_node(loopback_device);
	if (devi == NULL) {
		_E("finding associated device node failed");
		ret = APP2EXT_ERROR_DO_LOSETUP;
		goto ERR;
	} else {
		free(devi);
		devi = NULL;
	}
#endif
	/* format the loopback file system */
	ret = _app2sd_create_file_system(device_node);
	if (ret) {
		_E("create ext4 filesystem failed");
		ret = APP2EXT_ERROR_CREATE_FS;
		goto ERR;
	}

	list = g_list_first(dir_list);
	while (list) {
		dir_detail = (app2ext_dir_details *)list->data;
		if (dir_detail && dir_detail->name
			&& dir_detail->type == APP2EXT_DIR_RO) {
			memset(temp_dir_path, '\0', FILENAME_MAX);
			snprintf(temp_dir_path, FILENAME_MAX,
				 "%s/%s", application_path,
				dir_detail->name);
			_D("app2archive, temp_dir_path(%s)",
				temp_dir_path);
			ret = _app2sd_move_to_archive(temp_dir_path,
				application_archive_path);
			if (ret) {
				if (ret == APP2EXT_ERROR_ACCESS_FILE) {
					_E("unable to access (%s)",
						temp_dir_path);
				} else {
					_E("unable to copy from (%s) to (%s)",
					     temp_dir_path,
					     application_archive_path);
				}
				goto ERR;
			}
		}
		list = g_list_next(list);
	}

	/* mount the loopback encrypted pseudo device on application installation path
	 * as with Read Write permission
	 */
	ret = _app2sd_mount_app_content(application_path, pkgid, device_node,
		MOUNT_TYPE_RW, dir_list, APP2SD_MOVE_APP_TO_MMC, uid);
	if (ret) {
		_E("mount failed");
		goto ERR;
	}

	list = g_list_first(dir_list);
	while (list) {
		dir_detail = (app2ext_dir_details *)list->data;
		if (dir_detail && dir_detail->name
			&& dir_detail->type == APP2EXT_DIR_RO) {
			memset(temp_dir_path, '\0', FILENAME_MAX);
			snprintf(temp_dir_path, FILENAME_MAX,
				"%s/%s", application_archive_path,
				dir_detail->name);
			_D("archive2mmc, temp_dir_path(%s)",
				temp_dir_path);
			ret = _app2sd_copy_dir(temp_dir_path,
				application_mmc_path);
			if (ret) {
				if (ret == APP2EXT_ERROR_ACCESS_FILE) {
					_E("unable to access (%s)",
						temp_dir_path);
				} else {
					strerror_r(errno,
						err_buf, sizeof(err_buf));
					_E("unable to copy from (%s) to (%s)," \
						" error is (%s)",
						temp_dir_path,
						application_mmc_path, err_buf);
				}
				goto ERR;
			}
			ret = _app2sd_delete_directory(temp_dir_path);
			if (ret) {
				_E("unable to delete (%s)", temp_dir_path);
				goto ERR;
			}
		}
		list = g_list_next(list);
	}

	ret = _app2sd_delete_directory(application_archive_path);
	if (ret) {
		_E("unable to delete (%s)", application_archive_path);
		ret = APP2EXT_ERROR_DELETE_DIRECTORY;
		goto ERR;
	}

	return APP2EXT_SUCCESS;

ERR:
	if (device_node) {
		free(device_node);
		device_node = NULL;
	}

	return ret;
}

static int _app2sd_move_app_to_internal(const char *pkgid, GList *dir_list,
		uid_t uid, char *mmc_path)
{
	int ret = APP2EXT_SUCCESS;
	mode_t mode = DIR_PERMS;
	char temp_dir_path[FILENAME_MAX] = { 0, };
	char application_mmc_path[FILENAME_MAX] = { 0, };
	char application_archive_path[FILENAME_MAX] = { 0, };
	char application_path[FILENAME_MAX] = { 0, };
	char loopback_device[FILENAME_MAX] = { 0, };
	char *device_node = NULL;
	FILE *fp = NULL;
	GList *list = NULL;
	app2ext_dir_details *dir_detail = NULL;
	int reqd_size = 0;
	int free_internal_mem = 0;
	struct statvfs buf = {0,};
	unsigned long long temp = 0;
	char err_buf[1024] = {0,};
	char *encoded_id = NULL;

	encoded_id = _app2sd_get_encoded_name(pkgid, uid);
	if (encoded_id == NULL)
		return APP2EXT_ERROR_MEMORY_ALLOC_FAILED;

	snprintf(loopback_device, FILENAME_MAX - 1, "%s/%s/%s",
			mmc_path, EXTIMG_DIR, encoded_id);
	free(encoded_id);
	if (_is_global(uid)) {
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_SYS_RW_APP), pkgid);
	} else {
		tzplatform_set_user(uid);
		snprintf(application_path, FILENAME_MAX - 1, "%s/%s",
			tzplatform_getenv(TZ_USER_APP), pkgid);
		tzplatform_reset_user();
	}

	/* check whether application is in external memory or not */
	fp = fopen(loopback_device, "r+");
	if (fp == NULL) {
		_E("application (%s) is not installed on SD Card",
		     pkgid);
		return APP2EXT_ERROR_FILE_ABSENT;
	} else {
		fclose(fp);
		fp = NULL;
	}

	memset((void *)&buf, '\0', sizeof(struct statvfs));
	ret = statvfs(INTERNAL_STORAGE_PATH, &buf);
	if (0 == ret) {
		temp = (buf.f_bsize * buf.f_bavail) / (1024 * 1024);
		free_internal_mem = (int)temp;
	} else {
		_E("unable to get internal storage size");
		return APP2EXT_ERROR_MMC_INSUFFICIENT_MEMORY;
	}

	fp = fopen(loopback_device, "r+");
	if (fp == NULL) {
		_E("app entry is not present in SD card");
		return APP2EXT_ERROR_INVALID_PACKAGE;
	}
	fclose(fp);

	/* get installed app size*/
	temp = _app2sd_calculate_file_size(loopback_device);
	reqd_size = (int)((temp) / (1024 * 1024));
	_D("reqd size is (%d)", reqd_size);

	if (reqd_size == 0) {
		_E("app entry is not present in SD Card");
		return APP2EXT_ERROR_LOOPBACK_DEVICE_UNAVAILABLE;
	}

	_D("reqd size: (%d)MB, free internal mem: (%d)MB",
		reqd_size, free_internal_mem);

	/* if avaialalbe free memory in internal storage is
	 * less than required size, return error
	 */
	if (reqd_size > free_internal_mem) {
		_E("innsufficient memory in internal storage" \
			" for application installation (%d)", ret);
		return APP2EXT_ERROR_MMC_INSUFFICIENT_MEMORY;
	}

#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	device_node =
		_app2sd_find_associated_dmcrypt_device_node(pkgid, uid);
#else
	device_node = _app2sd_find_associated_device_node(loopback_device);
#endif
	if (NULL == device_node) {
		/* do loopback setup */
#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
		ret = _app2sd_dmcrypt_open_device(pkgid, loopback_device,
			false, uid, &device_node);
		if (ret) {
			_E("dmcrypt open device error(%d)", ret);
			return APP2EXT_ERROR_OPEN_DMCRYPT_DEVICE;
		}
#else
		device_node = _app2sd_do_loopback_encryption_setup(pkgid,
			loopback_device, uid);
		if (device_node == NULL) {
			_E("loopback encryption setup failed");
			return APP2EXT_ERROR_DO_LOSETUP;
		}
#endif
		/* do mounting */
		ret = _app2sd_mount_app_content(application_path,
			pkgid, device_node, MOUNT_TYPE_RW,
			dir_list, APP2SD_MOVE_APP_TO_PHONE, uid);
		if (ret) {
			_E("mount failed");
			ret = APP2EXT_ERROR_MOUNT_PATH;
			goto ERR;
		}
	} else {
		/* do re-mounting */
		ret = _app2sd_mount_app_content(application_path,
			pkgid, device_node, MOUNT_TYPE_RW_REMOUNT,
			dir_list, APP2SD_MOVE_APP_TO_PHONE, uid);
		if (ret) {
			_E("re-mount failed");
			ret = APP2EXT_ERROR_MOUNT_PATH;
			goto ERR;
		}
	}

	snprintf(application_mmc_path, FILENAME_MAX - 1, "%s/.mmc",
		application_path);
	snprintf(application_archive_path, FILENAME_MAX - 1, "%s/.archive",
		application_path);

	ret = mkdir(application_archive_path, mode);
	if (ret) {
		if (errno != EEXIST) {
			_E("unable to create directory for archiving," \
				" error(%d)", errno);
			ret = APP2EXT_ERROR_CREATE_DIRECTORY;
			goto ERR;
		}
	}

	list = g_list_first(dir_list);
	while (list) {
		dir_detail = (app2ext_dir_details *)list->data;
		if (dir_detail && dir_detail->name
			&& dir_detail->type == APP2EXT_DIR_RO) {
			/* archiving code */
			memset(temp_dir_path, '\0', FILENAME_MAX);
			snprintf(temp_dir_path, FILENAME_MAX,
				 "%s/%s", application_mmc_path,
				 dir_detail->name);
			_D("mmc2archive, temp_dir_path(%s)", temp_dir_path);
			ret = _app2sd_copy_dir(temp_dir_path,
				     application_archive_path);
			if (ret) {
				if (ret == APP2EXT_ERROR_ACCESS_FILE) {
					_E("unable to access (%s)",
						temp_dir_path);
				} else {
					strerror_r(errno,
						err_buf, sizeof(err_buf));
					_E("unable to copy from (%s) to (%s),"
						" error is (%s)",
						temp_dir_path,
						application_archive_path, err_buf);
				}
				goto ERR;
			}

			/* delete the symbolic link files [bin, lib, res]*/
			memset(temp_dir_path, '\0', FILENAME_MAX);
			snprintf(temp_dir_path, FILENAME_MAX,
				 "%s/%s", application_path,
				 dir_detail->name);
			_D("unlink, temp_dir_path(%s)", temp_dir_path);
			ret = unlink(temp_dir_path);
			if (ret) {
				if (errno == ENOENT) {
					_W("directory (%s) does not exist",
						temp_dir_path);
				} else {
					_E("unable to remove the symbolic link file (%s)," \
						" it is already unlinked",
						temp_dir_path);
					goto ERR;
				}
			}

			/* Copy content to destination */
			memset(temp_dir_path, '\0', FILENAME_MAX);
			snprintf(temp_dir_path, FILENAME_MAX,
				"%s/%s", application_archive_path,
				dir_detail->name);
			_D("archive2app, temp_dir_path(%s)", temp_dir_path);
			ret = _app2sd_copy_dir(temp_dir_path, application_path);
			if (ret) {
				if (ret == APP2EXT_ERROR_ACCESS_FILE) {
					_E("unable to access (%s)",
						temp_dir_path);
				} else {
					strerror_r(errno,
						err_buf, sizeof(err_buf));
					_E("unable to copy from (%s) to (%s) " \
						", error is (%s)",
						temp_dir_path,
						application_path, err_buf);
				}
				goto ERR;
			}
		}
		list = g_list_next(list);
	}

	_D("copying file completed");
	ret = _app2sd_unmount_app_content(application_path);
	if (ret)
		_E("unable to unmount SD directory for app (%s)",
		     pkgid);

#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	ret = _app2sd_dmcrypt_close_device(pkgid, uid);
	if (ret)
		_E("close dmcrypt device error(%d)", ret);
#else
	ret = _app2sd_remove_loopback_encryption_setup(loopback_device);
	if (ret)
		_E("unable to detach loopback setup for (%s)",
		     pkgid);
#endif

	ret = _app2sd_delete_loopback_device(loopback_device);
	if (ret)
		_E("unable to delete the loopback device for (%s)",
		     pkgid);

	ret = _app2sd_delete_directory(application_mmc_path);
	if (ret)
		_E("unable to delete (%s)", application_mmc_path);

	ret = _app2sd_delete_directory(application_archive_path);
	if (ret)
		_E("unable to delete (%s)", application_archive_path);

	/* remove passwrd from DB */
	ret = _app2sd_initialize_db();
	if (ret)
		_E("app2sd db initialize failed");

	ret = _app2sd_remove_info_from_db(pkgid, uid);
	if (ret)
		_E("cannot remove info from db");

	return APP2EXT_SUCCESS;

ERR:
	if (device_node) {
		free(device_node);
		device_node = NULL;
	}

	return ret;
}

int _app2sd_usr_move_app(const char *pkgid, app2ext_move_type move_type,
		GList *dir_list, uid_t uid, char *mmc_path)
{
	int ret = APP2EXT_SUCCESS;

	switch (move_type) {
	case APP2EXT_MOVE_TO_EXT:
		ret = _app2sd_move_app_to_external(pkgid, dir_list,
			uid, mmc_path);
		if (ret) {
			_E("move app to external memory failed(%d)", ret);
			return ret;
		}
		break;
	case APP2EXT_MOVE_TO_PHONE:
		ret = _app2sd_move_app_to_internal(pkgid, dir_list,
			uid, mmc_path);
		if (ret) {
			_E("move app to internal memory failed(%d)", ret);
			return ret;
		}
		break;
	default:
		_E("invalid argument");
		return APP2EXT_ERROR_INVALID_ARGUMENTS;
	}

	return ret;
}

int _app2sd_copy_ro_content(const char *src, const char *dest, GList *dir_list)
{
	char path[FILENAME_MAX] = { 0, };
	int ret = APP2EXT_SUCCESS;
	GList *list = NULL;
	app2ext_dir_details *dir_detail = NULL;

	list = g_list_first(dir_list);
	while (list) {
		dir_detail = (app2ext_dir_details *)list->data;
		if (dir_detail && dir_detail->name
			&& dir_detail->type == APP2EXT_DIR_RO) {
			memset((void *)&path, '\0', FILENAME_MAX);
			snprintf(path, FILENAME_MAX - 1, "%s/%s", src,
				 dir_detail->name);
			ret = _app2sd_copy_dir(path, dest);
			if (ret) {
				if (ret == APP2EXT_ERROR_ACCESS_FILE) {
					_E("unable to access (%s)", path);
				} else {
					_E("unable to copy from (%s) " \
						"to (%s), errno is (%d)",
						path, dest, errno);
					return APP2EXT_ERROR_MOVE;
				}
			}
		}
		list = g_list_next(list);
	}

	return APP2EXT_SUCCESS;
}

int _app2sd_duplicate_device(const char *pkgid,
		const char *loopback_device,
		const char *temp_pkgid,
		const char *temp_application_path,
		const char *temp_loopback_device,
		GList *dir_list, char *dev_node, int size,
		uid_t uid)
{
	int ret = 0;
	int err_res = 0;
#if !defined(TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION)
	char *devi = NULL;
	char *result = NULL;
	char *passwd = NULL;
#endif

	/* create a new loopback device */
	ret = _app2sd_create_loopback_device(temp_pkgid,
		temp_loopback_device, (size + PKG_BUF_SIZE));
	if (ret) {
		_E("package already present");
		return ret;
	}

	/* perform loopback encryption setup */
#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	dev_node = _app2sd_dmcrypt_duplicate_encryption_setup(pkgid,
		temp_loopback_device, uid);
	if (!dev_node) {
		_E("dmcrypt duplicate encryption setup failed");
		_app2sd_delete_loopback_device(temp_loopback_device);
		return APP2EXT_ERROR_SETUP_DMCRYPT_DEVICE;
	}
#else
	/* get password for loopback encryption */
	ret = _app2sd_initialize_db();
	if (ret) {
		_E("app2sd db initialize failed");
		return APP2EXT_ERROR_DB_INITIALIZE;
	}

	if ((passwd = _app2sd_get_password_from_db(pkgid, uid)) == NULL) {
		passwd = (char *)_app2sd_generate_password(pkgid);
		if (NULL == passwd) {
			_E("unable to generate password");
			return APP2EXT_ERROR_PASSWD_GENERATION;
		} else {
			if ((ret = _app2sd_set_info_in_db(pkgid,
				passwd, loopback_device, uid)) < 0) {
				_E("unable to save info");
				free(passwd);
				passwd = NULL;
				return APP2EXT_ERROR_SQLITE_REGISTRY;
			}
		}
	}

	dev_node = _app2sd_do_loopback_duplicate_encryption_setup(pkgid,
		temp_pkgid, temp_loopback_device, passwd, uid);
	if (!dev_node) {
		_E("losetup failed, device node is (%s)", dev_node);
		_app2sd_delete_loopback_device(temp_loopback_device);
		free(passwd);
		passwd = NULL;
		return APP2EXT_ERROR_DO_LOSETUP;
	}
	free(passwd);
	passwd = NULL;
	_D("duplicate setup SUCCESS");

	/* check whether loopback device is associated with
	 * device node or not
	 */
	devi = _app2sd_find_associated_device_node(temp_loopback_device);
	if (devi == NULL) {
		_E("finding associated device node failed");
		err_res = APP2EXT_ERROR_DO_LOSETUP;
		goto FINISH_OFF;
	}
	_D("losetup SUCCESS");
#endif

	/* format the loopback file system */
	ret = _app2sd_create_file_system(dev_node);
	if (ret) {
		_E("creating fs failed");
		err_res = APP2EXT_ERROR_CREATE_FS;
		goto FINISH_OFF;
	}
	_D("create filesystem SUCCESS");

	/* do mounting for new dev*/
	ret = _app2sd_mount_app_content(temp_application_path, pkgid,
		dev_node, MOUNT_TYPE_RW, dir_list,
		APP2SD_PRE_UPGRADE, uid);
	if (ret) {
		_E("remount failed");
		err_res = APP2EXT_ERROR_MOUNT_PATH;
		goto FINISH_OFF;
	}

#if !defined(TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION)
	if (devi) {
		free(devi);
		devi = NULL;
	}
#endif

	return APP2EXT_SUCCESS;

FINISH_OFF:
	if (dev_node) {
#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
		ret = _app2sd_dmcrypt_close_device(temp_pkgid, uid);
		if (ret)
			_E("close dmcrypt device error(%d)", ret);
#else
		result = _app2sd_detach_loop_device(dev_node);
		if (result) {
			free(result);
			result = NULL;
		}
#endif
		_app2sd_delete_loopback_device(temp_loopback_device);
		free(dev_node);
		dev_node = NULL;
	}

	return err_res;
}

int _app2sd_update_loopback_device_size(const char *pkgid,
		const char *loopback_device,
		const char *application_path,
		const char *temp_pkgid,
		const char *temp_loopback_device,
		const char *temp_application_path,
		int size, GList *dir_list,
		uid_t uid)
{
	int ret = 0;
	char *device_node = NULL;
	char *old_device_node = NULL;
	int err_res = 0;
	char application_mmc_path[FILENAME_MAX] = { 0, };
	char temp_application_mmc_path[FILENAME_MAX] = { 0, };

	ret = _app2sd_duplicate_device(pkgid, loopback_device,
		temp_pkgid, temp_application_path, temp_loopback_device,
		dir_list, device_node, size, uid);
	if (ret) {
		_E("creating duplicate device failed");
		return ret;
	}

	/* get the associated device node for SD card applicatione */
#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	old_device_node =
		_app2sd_find_associated_dmcrypt_device_node(pkgid, uid);
#else
	old_device_node = _app2sd_find_associated_device_node(loopback_device);
#endif
	if (NULL == old_device_node) {
		/* do loopback setup */
#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
		ret = _app2sd_dmcrypt_open_device(pkgid, loopback_device,
			false, uid, &old_device_node);
		if (ret) {
			_E("dmcrypt open device error");
			err_res = APP2EXT_ERROR_OPEN_DMCRYPT_DEVICE;
			goto FINISH_OFF;
		}
#else
		old_device_node = _app2sd_do_loopback_encryption_setup(pkgid,
			loopback_device, uid);
		if (old_device_node == NULL) {
			_E("loopback encryption setup failed");
			err_res = APP2EXT_ERROR_DO_LOSETUP;
			goto FINISH_OFF;
		}
#endif
		/* do mounting */
		ret = _app2sd_mount_app_content(application_path, pkgid,
			old_device_node, MOUNT_TYPE_RW, dir_list,
			APP2SD_PRE_UPGRADE, uid);
		if (ret) {
			_E("remount failed");
			err_res = APP2EXT_ERROR_MOUNT_PATH;
		}
	} else {
		/* do re-mounting */
		ret = _app2sd_mount_app_content(application_path, pkgid,
			old_device_node, MOUNT_TYPE_RW_REMOUNT, dir_list,
			APP2SD_PRE_UPGRADE, uid);
		if (ret) {
			_E("remount failed");
			err_res = APP2EXT_ERROR_MOUNT_PATH;
		}
	}

	snprintf(application_mmc_path, FILENAME_MAX - 1,
		 "%s/.mmc", application_path);
	snprintf(temp_application_mmc_path, FILENAME_MAX - 1,
		"%s/.mmc", temp_application_path);

	ret = _app2sd_copy_ro_content(application_mmc_path,
		temp_application_mmc_path, dir_list);
	if (ret) {
		_E("copy ro content failed");
		err_res = ret;
	}

	ret = _app2sd_unmount_app_content(application_path);
	if (ret) {
		_E("unable to unmount the SD application");
		err_res = APP2EXT_ERROR_UNMOUNT;
	}

	ret = _app2sd_unmount_app_content(temp_application_path);
	if (ret) {
		_E("unable to unmount the SD application");
		err_res = APP2EXT_ERROR_UNMOUNT;
		goto FINISH_OFF;
	}

#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	ret = _app2sd_dmcrypt_close_device(pkgid, uid);
	if (ret) {
		_E("close dmcrypt device error(%d)", ret);
		err_res = APP2EXT_ERROR_CLOSE_DMCRYPT_DEVICE;
		goto FINISH_OFF;
	}

	ret = _app2sd_dmcrypt_close_device(temp_pkgid, uid);
	if (ret) {
		_E("close dmcrypt device error(%d)", ret);
		err_res = APP2EXT_ERROR_CLOSE_DMCRYPT_DEVICE;
		goto FINISH_OFF;
	}
#else
	ret = _app2sd_remove_loopback_encryption_setup(loopback_device);
	if (ret) {
		_E("unable to remove loopback setup");
		err_res = APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
	}

	ret = _app2sd_remove_loopback_encryption_setup(temp_loopback_device);
	if (ret) {
		_E("unable to remove loopback setup");
		err_res = APP2EXT_ERROR_DELETE_LOOPBACK_DEVICE;
		goto FINISH_OFF;
	}
#endif

	ret = _app2sd_delete_directory(loopback_device);
	if (ret) {
		_E("unable to delete (%s)", loopback_device);
		err_res = APP2EXT_ERROR_DELETE_DIRECTORY;
		goto FINISH_OFF;
	}

	ret = _app2sd_rename_dir(temp_loopback_device, loopback_device);
	if (ret) {
		_E("unable to rename (%s)", temp_loopback_device);
		err_res = APP2EXT_ERROR_MOVE;
		goto FINISH_OFF;
	}

	ret = _app2sd_delete_directory(temp_application_path);
	if (ret) {
		_E("unable to delete (%s)", temp_application_path);
		err_res = APP2EXT_ERROR_DELETE_DIRECTORY;
		goto FINISH_OFF;
	}

	return APP2EXT_SUCCESS;

FINISH_OFF:
	if (old_device_node) {
		free(old_device_node);
		old_device_node = NULL;
	}

#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	ret = _app2sd_dmcrypt_close_device(pkgid, uid);
	if (ret)
		_E("close dmcrypt device error(%d)", ret);

	ret = _app2sd_dmcrypt_close_device(temp_pkgid, uid);

	if (ret)
		_E("close dmcrypt device error(%d)", ret);
#else
	ret = _app2sd_remove_loopback_encryption_setup(loopback_device);
	if (ret)
		_E("unable to remove loopback setup");

	ret = _app2sd_remove_loopback_encryption_setup(temp_loopback_device);
	if (ret)
		_E("unable to remove loopback setup");
#endif

	_app2sd_delete_loopback_device(temp_loopback_device);

	ret = _app2sd_delete_directory(temp_application_path);
	if (ret)
		_E("unable to delete (%s)", temp_application_path);

	return err_res;
}

int _app2sd_force_clean(const char *pkgid, const char *application_path,
		const char *loopback_device, uid_t uid)
{
	int ret = APP2EXT_SUCCESS;

	/* unmount the loopback encrypted pseudo device from the application installation path */
	ret = _app2sd_unmount_app_content(application_path);
	if (ret)
		_E("unable to unmount the app content (%d)", ret);

	/* detach the loopback encryption setup for the application */
#ifdef TIZEN_FEATURE_APP2SD_DMCRYPT_ENCRYPTION
	ret = _app2sd_dmcrypt_close_device(pkgid, uid);
	if (ret)
		_E("close dmcrypt device error (%d)", ret);
#else
	ret = _app2sd_remove_all_loopback_encryption_setups(loopback_device);
	if (ret)
		_E("unable to detach the loopback encryption setup for the application");
#endif

	/* delete the loopback device from the SD card */
	ret = _app2sd_delete_loopback_device(loopback_device);
	if (ret)
		_E("unable to detach the loopback encryption setup for the application");

	/* delete symlink */
	_app2sd_delete_symlink(application_path);

	/* remove passwrd from DB */
	ret = _app2sd_initialize_db();
	if (ret)
		_E("app2sd db initialize failed");

	ret = _app2sd_remove_info_from_db(pkgid, uid);
	if (ret)
		_E("cannot remove info from db");


	return ret;
}
