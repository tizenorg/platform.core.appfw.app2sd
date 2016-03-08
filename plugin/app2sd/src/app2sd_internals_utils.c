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
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <dlog.h>
#include <sys/statvfs.h>
#include <errno.h>

#define	PASSWD_LEN		8
#define	ASCII_PASSWD_CHAR	93

/*
########### Internal APIs ##################
 */

/*Note: Don't use any printf statement inside this function*/
/*This function is similar to Linux's "system()"  for executing a process.*/
int _xsystem(const char *argv[])
{
	int status = 0;
	pid_t pid;
	char err_buf[1024] = {0,};

	pid = fork();
	switch (pid) {
	case -1:
		perror("fork failed");
		return -1;
	case 0:
		/* child */
		strerror_r(errno, err_buf, sizeof(err_buf));
		if (execvp(argv[0], (char *const *)argv) < 0) {
			fprintf(stderr, "execvp failed %d....%s\n", errno, err_buf);	/*Don't use d_msg_app2sd */
		}
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
	unsigned long long temp = 0;
	if (sd_path == NULL || free_mem == NULL) {
		app2ext_print("App2Sd Error : Invalid input parameter\n");
		return -1;
	}
	memset((void *)&buf, '\0', sizeof(struct statvfs));
	ret = statvfs(sd_path, &buf);
	if (ret) {
		app2ext_print("App2SD Error: Unable to get SD Card memory information\n");
		return APP2EXT_ERROR_MMC_INFORMATION;
	}
	temp = (unsigned long long)buf.f_bsize*buf.f_bavail;
	*free_mem = (int)(temp/(1024*1024));
	return 0;
}

int _app2sd_delete_directory(char *dirname)
{
	DIR *dp = NULL;
	struct dirent ep;
	struct dirent *er = NULL;
	char abs_filename[FILENAME_MAX] = { 0, };
	int ret = 0;

	dp = opendir(dirname);
	if (dp != NULL) {
		while (readdir_r(dp, &ep, &er) == 0 && er != NULL) {
			struct stat stFileInfo;

			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname,
				ep.d_name);

			if (lstat(abs_filename, &stFileInfo) < 0) {
				perror(abs_filename);
				(void)closedir(dp);
				return -1;
			}

			if (S_ISDIR(stFileInfo.st_mode)) {
				if (strcmp(ep.d_name, ".")
				    && strcmp(ep.d_name, "..")) {
					ret = _app2sd_delete_directory(abs_filename);
					if (ret <0) {
						(void)closedir(dp);
						return -1;
					}
				}
			} else {
				ret = remove(abs_filename);
				if (ret <0) {
					(void)closedir(dp);
					return -1;
				}
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

void _app2sd_delete_symlink(const char *dirname)
{
	int ret = 0;
	DIR *dp = NULL;
	struct dirent ep;
	struct dirent *er = NULL;
	char abs_filename[FILENAME_MAX] = { 0, };

	app2ext_print("star clean_symlink [%s]", dirname);

	dp = opendir(dirname);
	if (dp != NULL) {
		while (readdir_r(dp, &ep, &er) == 0 && er != NULL) {
			char mmc_path[PATH_MAX] = {0};

			if (!strcmp(ep.d_name, ".") || !strcmp(ep.d_name, ".."))
				continue;

			/*get realpath find symlink to ".mmc" and unlink it*/
			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname, ep.d_name);
			char *path = realpath(abs_filename, mmc_path);
			if(!path){
				app2ext_print("realpath failed\n");
			}

			if (strstr(mmc_path,".mmc")) {
				app2ext_print("force unlink [%s]", abs_filename);
				if (unlink(abs_filename)) {
					if (errno == ENOENT) {
						app2ext_print("Unable to access file %s\n", abs_filename);
					} else {
						app2ext_print("Unable to delete %s\n", abs_filename);
					}
				}
			}

		}
		(void)closedir(dp);

		/*delete ".mmc" folder*/
		snprintf(abs_filename, FILENAME_MAX, "%s/.mmc", dirname);
		ret = remove(abs_filename);
		if (ret == -1) {
			return;
		}
	} else {
		app2ext_print("Couldn't open the directory[%s]\n", dirname);
	}

	app2ext_print("finish clean_symlink");
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
	struct dirent ep;
	struct dirent *er = NULL;
	char abs_filename[FILENAME_MAX] = { 0, };;

	dp = opendir(dirname);
	if (dp != NULL) {
		while (readdir_r(dp, &ep, &er) == 0 && er != NULL) {
			struct stat stFileInfo;

			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname,
				 ep.d_name);

			if (stat(abs_filename, &stFileInfo) < 0)
				perror(abs_filename);
			else {
				total += stFileInfo.st_size;

				if (S_ISDIR(stFileInfo.st_mode)) {
					if (strcmp(ep.d_name, ".")
					    && strcmp(ep.d_name, "..")) {
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
	char err_buf[1024] = {0,};

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
			strerror_r(errno, err_buf, sizeof(err_buf));
			fprintf(stderr, "dup failed %d....%s\n", errno, err_buf);
			_exit(-1);
		}
		result = dup(my_pipe[1]);
		if (result < 0) {
			strerror_r(errno, err_buf, sizeof(err_buf));
			fprintf(stderr, "dup failed %d....%s\n", errno, err_buf);
			_exit(-1);
		}
		if (execvp(argv[0], (char *const *)argv) < 0) {
			strerror_r(errno, err_buf, sizeof(err_buf));
			fprintf(stderr, "execvp failed %d....%s\n", errno, err_buf);	/*Don't use d_msg_app2sd */
		}
		_exit(-1);
	default:
		/* parent */
		close(my_pipe[1]);
		result = read(my_pipe[0], buf, FILENAME_MAX);
		if (result < 0) {
			strerror_r(errno, err_buf, sizeof(err_buf));
			fprintf(stderr, "read failed %d....%s\n", errno, err_buf);
		}
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
	char err_buf[1024] = {0,};

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
			strerror_r(errno, err_buf, sizeof(err_buf));
			fprintf(stderr, "dup failed %d....%s\n", errno, err_buf);
			_exit(-1);
		}
		result = dup(my_pipe[1]);
		if (result < 0) {
			strerror_r(errno, err_buf, sizeof(err_buf));
			fprintf(stderr, "dup failed %d....%s\n", errno, err_buf);
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
		if (result < 0) {
			strerror_r(errno, err_buf, sizeof(err_buf));
			fprintf(stderr, "read failed %d....%s\n", errno, err_buf);
		}
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

/* Note: Don't use any printf statement inside this function*/
char *_app2sd_find_associated_device(const char *mmc_app_path)
{
	const char *argv[] = { "/sbin/losetup", "-j", mmc_app_path, NULL };
	pid_t pid;
	int my_pipe[2] = { 0, };
	char buf[FILENAME_MAX] = { 0, };
	char *ret_result = NULL;
	int result = 0;
	char err_buf[1024] = {0,};

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
			strerror_r(errno, err_buf, sizeof(err_buf));
			fprintf(stderr, "dup failed %d....%s\n", errno, err_buf);
			_exit(-1);
		}
		result = dup(my_pipe[1]);
		if (result < 0) {
			strerror_r(errno, err_buf, sizeof(err_buf));
			fprintf(stderr, "dup failed %d....%s\n", errno, err_buf);
			_exit(-1);
		}
		if (execvp(argv[0], (char *const *)argv) < 0) {
			fprintf(stderr, "execvp failed\n");	/* Don't use d_msg_app2sd */
		}
		_exit(-1);
	default:
		/* parent */
		close(my_pipe[1]);
		result = read(my_pipe[0], buf, FILENAME_MAX);
		if (result < 0) {
			strerror_r(errno, err_buf, sizeof(err_buf));
			fprintf(stderr, "read failed %d....%s\n", errno, err_buf);
		}
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
	char buf[FILENAME_MAX + 1] = { 0, };
	char *ret_result = NULL;
	int result = 0;
	char err_buf[1024] = {0,};

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
			strerror_r(errno, err_buf, sizeof(err_buf));
			fprintf(stderr, "dup failed %d....%s\n", errno, err_buf);
			_exit(-1);
		}
		result = dup(my_pipe[1]);
		if (result < 0) {
			strerror_r(errno, err_buf, sizeof(err_buf));
			fprintf(stderr, "dup failed %d....%s\n", errno, err_buf);
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
		if (result < 0) {
			strerror_r(errno, err_buf, sizeof(err_buf));
			fprintf(stderr, "read failed %d....%s\n", errno, err_buf);
		}
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
	unsigned int seed;

	/* Length of the password */
	ret_result = (char*)malloc(PASSWD_LEN+1);
	if (NULL == ret_result) {
		app2ext_print("Unable to Allocate memory\n");
		return NULL;
	}
	memset((void *)ret_result, '\0', PASSWD_LEN+1);

	while(i < PASSWD_LEN) {
		seed = time(NULL);
		char_1 = (rand_r(&seed)+pkgid[j--])%ASCII_PASSWD_CHAR;
		char_2 = rand_r(&seed)%ASCII_PASSWD_CHAR;
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
