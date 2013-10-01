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

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <dlog.h>
#include <sys/statvfs.h>
#include <errno.h>
#include <dlfcn.h>

#define	PASSWD_LEN		8
#define	ASCII_PASSWD_CHAR	93
#define LIB_PRIVILEGE_CONTROL		"libprivilege-control.so.0"

/*
########### Internal APIs ##################
 */

/*Note: Don't use any printf statement inside this function*/
/*This function is similar to Linux's "system()"  for executing a process.*/
int _xsystem(const char *argv[])
{
	int status = 0;
	pid_t pid;
	pid = fork();
	switch (pid) {
	case -1:
		perror("fork failed");
		return -1;
	case 0:
		/* child */
		execvp(argv[0], (char *const *)argv);
		_exit(-1);
	default:
		/* parent */
		break;
	}
	if (waitpid(pid, &status, 0) == -1) {
		perror("waitpid failed");
		return -1;
	}
	if (WIFSIGNALED(status)) {
		perror("signal");
		return -1;
	}
	if (!WIFEXITED(status)) {
		/* shouldn't happen */
		perror("should not happen");
		return -1;
	}
	return WEXITSTATUS(status);
}


/*
* @_app2sd_check_mmc_status
* This function checks and returns MMC status
*/
int _app2sd_check_mmc_status(void)
{
	FILE *fp1 = NULL;
	char line[512];
	fp1 = fopen("/etc/mtab", "r");
	if (fp1 == NULL) {
		fprintf(stderr, "failed to open file\n");
		app2ext_print("failed to open file /etc/mtab\n");
		return APP2EXT_ERROR_MMC_STATUS;
	}
	while (fgets(line, 512, fp1) != NULL) {
		if (strstr(line, MMC_PATH) != NULL) {
			fclose(fp1);
			return APP2EXT_SUCCESS;
		}
	}
	fclose(fp1);
	return APP2EXT_ERROR_MMC_STATUS;
}

/*
 * @_app2sd_get_available_free_memory
 * This function returns the available free memory in the SD Card.
 * param [in]: sd_path: This is sd card access path.
 * param [out]: free_mem: Result will be available in this.
 * User has to pass valid memory address.
 * return: On success, it will return 0.
 * Else, appropriate error no will be returned.
 */
int _app2sd_get_available_free_memory(const char *sd_path, int *free_mem)
{
	struct statvfs buf;
	int ret = 0;
	if (sd_path == NULL || free_mem == NULL) {
		app2ext_print("App2Sd Error : Invalid input parameter\n");
		return -1;
	}
	memset((void *)&buf, '\0', sizeof(struct statvfs));
	ret = statvfs(sd_path, &buf);
	if (ret) {
		app2ext_print
		    ("App2SD Error: Unable to get SD Card memory information\n");
		return APP2EXT_ERROR_MMC_INFORMATION;
	}
	*free_mem = ((buf.f_bfree * buf.f_bsize) / 1024) / 1024;
	return 0;
}

int _app2sd_delete_directory(char *dirname)
{
	DIR *dp = NULL;
	struct dirent *ep = NULL;
	char abs_filename[FILENAME_MAX] = { 0, };
	int ret = 0;
	dp = opendir(dirname);
	if (dp != NULL) {
		while ((ep = readdir(dp)) != NULL) {
			struct stat stFileInfo;

			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname,
				ep->d_name);

			if (lstat(abs_filename, &stFileInfo) < 0) {
				perror(abs_filename);
				return -1;
			}

			if (S_ISDIR(stFileInfo.st_mode)) {
				if (strcmp(ep->d_name, ".")
				    && strcmp(ep->d_name, "..")) {
					ret = _app2sd_delete_directory(abs_filename);
					if (ret <0)
						return -1;
				}
			} else {
				ret = remove(abs_filename);
				if (ret <0)
					return -1;
			}
		}
		(void)closedir(dp);
		ret = remove(dirname);
		if (ret <0)
			return -1;
	} else {
		app2ext_print("Couldn't open the directory[%s]\n", dirname);
	}
	return 0;
}

int _app2sd_copy_dir(const char *src, const char *dest)
{
	int ret = APP2EXT_SUCCESS;
	const char *argv_bin[] = { "/bin/cp", "-raf", src, dest, NULL };
	ret = _xsystem(argv_bin);
	if (ret) {
		app2ext_print("copy fail\n");
		return APP2EXT_ERROR_MOVE;
	}
	return ret;
}

int _app2sd_rename_dir(const char *old_name, const char *new_name)
{
	int ret = APP2EXT_SUCCESS;
	const char *argv_bin[] = { "/bin/mv", old_name, new_name, NULL };
	ret = _xsystem(argv_bin);
	if (ret) {
		app2ext_print("mv/rename fail\n");
		return APP2EXT_ERROR_MOVE;
	}
	return ret;
}

unsigned long long _app2sd_calculate_dir_size(char *dirname)
{
	static unsigned long long total = 0;
	DIR *dp = NULL;
	struct dirent *ep = NULL;
	char abs_filename[FILENAME_MAX] = { 0, };;
	dp = opendir(dirname);
	if (dp != NULL) {
		while ((ep = readdir(dp)) != NULL) {
			struct stat stFileInfo;

			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname,
				 ep->d_name);

			if (stat(abs_filename, &stFileInfo) < 0)
				perror(abs_filename);
			else {
				total += stFileInfo.st_size;

				if (S_ISDIR(stFileInfo.st_mode)) {
					if (strcmp(ep->d_name, ".")
					    && strcmp(ep->d_name, "..")) {
						_app2sd_calculate_dir_size
						    (abs_filename);
					}
				} else {
					/*Do Nothing */
				}
			}
		}
		(void)closedir(dp);
	} else {
		app2ext_print("\n error in opening directory ");
	}
	return total;
}

unsigned long long _app2sd_calculate_file_size(const char *filename)
{
	struct stat stFileInfo;
	app2ext_print("\n Calculating file size for %s\n", filename);

	if (stat(filename, &stFileInfo) < 0) {
		perror(filename);
		return 0;
	} else
		return stFileInfo.st_size;
}

/*Note: Don't use any printf statement inside this function*/
char *_app2sd_encrypt_device(const char *device, const char *pkgid,
			      char *passwd)
{
	const char *argv[] =
	    { "/sbin/losetup", "-e", "aes", device, pkgid, "-k", passwd, NULL };
	pid_t pid = 0;
	int my_pipe[2] = { 0, };
	char buf[FILENAME_MAX] = { 0, };
	char *ret_result = NULL;
	int result = 0;
	if (pipe(my_pipe) < 0) {
		fprintf(stderr, "Unable to create pipe\n");
		return NULL;
	}
	pid = fork();
	switch (pid) {
	case -1:
		perror("fork failed");
		return NULL;
	case 0:
		/* child */
		close(1);
		close(2);
		result = dup(my_pipe[1]);
		if (result < 0) {
			fprintf(stderr, "dup failed %d....%s\n", errno, strerror(errno));
			_exit(-1);
		}
		result = dup(my_pipe[1]);
		if (result < 0) {
			fprintf(stderr, "dup failed %d....%s\n", errno, strerror(errno));
			_exit(-1);
		}
		if (execvp(argv[0], (char *const *)argv) < 0) {
			fprintf(stderr, "execvp failed %d....%s\n", errno, strerror(errno));	/*Don't use d_msg_app2sd */
		}
		_exit(-1);
	default:
		/* parent */
		close(my_pipe[1]);
		result = read(my_pipe[0], buf, FILENAME_MAX);
		if (result < 0)
			fprintf(stderr, "read failed %d....%s\n", errno, strerror(errno));
		break;
	}

	ret_result = (char *)malloc(strlen(buf) + 1);
	if (ret_result == NULL) {
		app2ext_print("Malloc failed!\n");
		return NULL;
	}
	memset(ret_result, '\0', strlen(buf) + 1);
	memcpy(ret_result, buf, strlen(buf));
	return ret_result;
}

/*Note: Don't use any printf statement inside this function*/
char *_app2sd_detach_loop_device(const char *device)
{
	const char *argv[] = { "/sbin/losetup", "-d", device, NULL };
	pid_t pid;
	int my_pipe[2] = { 0, };
	char buf[FILENAME_MAX] = { 0, };
	char *ret_result = NULL;
	int result = 0;
	if (pipe(my_pipe) < 0) {
		fprintf(stderr, "Unable to create pipe\n");
		return NULL;
	}
	pid = fork();
	switch (pid) {
	case -1:
		perror("fork failed");
		return NULL;
	case 0:
		/* child */
		close(1);
		close(2);
		result = dup(my_pipe[1]);
		if (result < 0) {
			fprintf(stderr, "dup failed %d....%s\n", errno, strerror(errno));
			_exit(-1);
		}
		result = dup(my_pipe[1]);
		if (result < 0) {
			fprintf(stderr, "dup failed %d....%s\n", errno, strerror(errno));
			_exit(-1);
		}
		if (execvp(argv[0], (char *const *)argv) < 0) {
			fprintf(stderr, "execvp failed\n");	/*Don't use d_msg_app2sd */
		}
		_exit(-1);
	default:
		/* parent */
		close(my_pipe[1]);
		result = read(my_pipe[0], buf, FILENAME_MAX);
		if (result < 0)
			fprintf(stderr, "read failed %d....%s\n", errno, strerror(errno));
		break;
	}

	ret_result = (char *)malloc(strlen(buf) + 1);
	if (ret_result == NULL) {
		app2ext_print("Malloc failed!\n");
		return NULL;
	}
	memset(ret_result, '\0', strlen(buf) + 1);
	memcpy(ret_result, buf, strlen(buf));

	return ret_result;
}

/*Note: Don't use any printf statement inside this function*/
char *_app2sd_find_associated_device(const char *mmc_app_path)
{
	const char *argv[] = { "/sbin/losetup", "-j", mmc_app_path, NULL };
	pid_t pid;
	int my_pipe[2] = { 0, };
	char buf[FILENAME_MAX] = { 0, };
	char *ret_result = NULL;
	int result = 0;
	if (pipe(my_pipe) < 0) {
		fprintf(stderr, "Unable to create pipe\n");
		return NULL;
	}
	pid = fork();
	switch (pid) {
	case -1:
		perror("fork failed");
		return NULL;
	case 0:
		/* child */
		close(1);
		close(2);
		result = dup(my_pipe[1]);
		if (result < 0) {
			fprintf(stderr, "dup failed %d....%s\n", errno, strerror(errno));
			_exit(-1);
		}
		result = dup(my_pipe[1]);
		if (result < 0) {
			fprintf(stderr, "dup failed %d....%s\n", errno, strerror(errno));
			_exit(-1);
		}
		if (execvp(argv[0], (char *const *)argv) < 0) {
			fprintf(stderr, "execvp failed\n");	/*Don't use d_msg_app2sd */
		}
		_exit(-1);
	default:
		/* parent */
		close(my_pipe[1]);
		result = read(my_pipe[0], buf, FILENAME_MAX);
		if (result < 0)
			fprintf(stderr, "read failed %d....%s\n", errno, strerror(errno));
		break;
	}

	ret_result = (char *)malloc(strlen(buf) + 1);
	if (ret_result == NULL) {
		app2ext_print("Malloc failed!\n");
		return NULL;
	}
	memset(ret_result, '\0', strlen(buf) + 1);
	memcpy(ret_result, buf, strlen(buf));

	return ret_result;
}

/*Note: Don't use any printf statement inside this function*/
char *_app2sd_find_free_device(void)
{
	const char *argv[] = { "/sbin/losetup", "-f", NULL };
	pid_t pid;
	int my_pipe[2] = { 0, };
	char buf[FILENAME_MAX+1] = { 0, };
	char *ret_result = NULL;
	int result = 0;
	if (pipe(my_pipe) < 0) {
		fprintf(stderr, "Unable to create pipe\n");
		return NULL;
	}
	pid = fork();
	switch (pid) {
	case -1:
		perror("fork failed");
		return NULL;
	case 0:
		/* child */
		close(1);
		close(2);
		result = dup(my_pipe[1]);
		if (result < 0) {
			fprintf(stderr, "dup failed %d....%s\n", errno, strerror(errno));
			_exit(-1);
		}
		result = dup(my_pipe[1]);
		if (result < 0) {
			fprintf(stderr, "dup failed %d....%s\n", errno, strerror(errno));
			_exit(-1);
		}
		if (execvp(argv[0], (char *const *)argv) < 0) {
			fprintf(stderr, "execvp failed\n");	/*Don't use d_msg_app2sd */
		}
		_exit(-1);
	default:
		/* parent */
		close(my_pipe[1]);
		result = read(my_pipe[0], buf, FILENAME_MAX);
		if (result < 0)
			fprintf(stderr, "read failed %d....%s\n", errno, strerror(errno));
		break;
	}

	ret_result = (char *)malloc(strlen(buf) + 1);
	if (ret_result == NULL) {
		app2ext_print("Malloc failed!\n");
		return NULL;
	}
	memset(ret_result, '\0', strlen(buf) + 1);
	memcpy(ret_result, buf, strlen(buf));

	return ret_result;
}

/*@_app2sd_generate_password
* This is a simple password generator
* return: On success, it will return the password, else NULL.
*/
char *_app2sd_generate_password(const char *pkgid)
{
	char passwd[PASSWD_LEN+1] = { 0, };
	char *ret_result = NULL;
	char set[ASCII_PASSWD_CHAR+1] = "!\"#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
	unsigned char char_1;
	unsigned char char_2;
	int i = 0;
	int appname_len = strlen(pkgid);
	int j = appname_len;

	/* Length of the password */
	ret_result = (char*)malloc(PASSWD_LEN+1);
	if (NULL == ret_result) {
		app2ext_print("Unable to Allocate memory\n");
		return NULL;
	}
	memset((void *)ret_result, '\0', PASSWD_LEN+1);

	while(i < PASSWD_LEN) {
		char_1 = (rand()+pkgid[j--])%ASCII_PASSWD_CHAR;
		char_2 = rand()%ASCII_PASSWD_CHAR;
		passwd[i] = set[char_1];
		passwd[i+1] = set[(pkgid[j--])*2];
		if (i<PASSWD_LEN-3)
			passwd[i+2] = set[char_2];
		i++;
	}

	app2ext_print("Password is %s\n", passwd);
	memcpy(ret_result, passwd, PASSWD_LEN+1);
	return ret_result;
}

/*@_app2sd_setup_path
* change smack label given groupid
* return: On success, it will return the password, else NULL.
*/
int _app2sd_setup_path(const char *pkgid, const char *dirpath,
						int apppathtype, const char *groupid)
{
	int ret = 0;
	void *handle = NULL;
	char *errmsg = NULL;
	int (*app_setup_path)(const char*, const char*, int, ...) = NULL;

	if (pkgid == NULL || dirpath == NULL)
		return -1;

	handle = dlopen(LIB_PRIVILEGE_CONTROL, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		app2ext_print( "setup path: dlopen() failed. [%s]", dlerror());
		return -1;
	}

	app_setup_path = dlsym(handle, "app_setup_path");
	errmsg = dlerror();
	if ((errmsg != NULL) || (app_setup_path == NULL)) {
		app2ext_print( "setup path: dlsym() failed. [%s]", errmsg);
		dlclose(handle);
		return -1;
	}

	if (groupid == NULL) {
		app2ext_print( "[smack] app_setup_path(%s, %s, %d)", pkgid, dirpath, apppathtype);
		ret = app_setup_path(pkgid, dirpath, apppathtype);
		app2ext_print( "[smack] app_setup_path(), result = [%d]", ret);
	} else {
		app2ext_print( "[smack] app_setup_path(%s, %s, %d, %s)", pkgid, dirpath, apppathtype, groupid);
		ret = app_setup_path(pkgid, dirpath, apppathtype, groupid);
		app2ext_print( "[smack] app_setup_path(), result = [%d]", ret);
	}

	dlclose(handle);
	return ret;
}

