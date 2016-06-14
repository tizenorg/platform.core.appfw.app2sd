/*
 * app2ext
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
#include <stdlib.h>

#include "app2ext_utils.h"

int _is_global(uid_t uid)
{
	if (uid == OWNER_ROOT || uid == GLOBAL_USER)
		return 1;
	else
		return 0;
}

char *_app2sd_get_encoded_name(const char *pkgid, uid_t uid)
{
	char *new_name = NULL;
	char *temp_string = NULL;
	char source_name[FILENAME_MAX] = { 0, };
	GChecksum *checksum;

	snprintf(source_name, FILENAME_MAX - 1, "%s_%d", pkgid, uid);
	checksum = g_checksum_new(G_CHECKSUM_MD5);
	g_checksum_update(checksum, (const guchar *)source_name, strlen(source_name));
	temp_string = (char *)g_checksum_get_string(checksum);
	_D("temp_string(%s)", temp_string);
	new_name = strdup(temp_string);
	g_checksum_free(checksum);

	_D("new_name(%s)", new_name);

	return new_name;
}

int _app2sd_delete_directory(const char *dirname)
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
					if (ret < 0) {
						(void)closedir(dp);
						return -1;
					}
				}
			} else {
				ret = remove(abs_filename);
				if (ret < 0) {
					(void)closedir(dp);
					return -1;
				}
			}
		}
		(void)closedir(dp);
		ret = remove(dirname);
		if (ret < 0)
			return -1;
	} else {
		_W("couldn't open the directory[%s]", dirname);
	}
	return 0;
}
