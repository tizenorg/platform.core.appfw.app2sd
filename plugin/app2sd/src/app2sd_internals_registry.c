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
#include <time.h>
#include <db-util.h>

#include "app2sd_internals.h"

#define MAX_QUERY_LEN 4096
#define PASSWORD_LENGTH 64
/*
########### Internal APIs ##################
 */

/*sqlite  db code*/
#define APP2SD_DB_FILE tzplatform_mkpath(TZ_SYS_DB, ".app2sd.db")
sqlite3 *app2sd_db;
#define QUERY_CREATE_TABLE_APP2SD "CREATE TABLE IF NOT EXISTS app2sd_info " \
	"(pkgid TEXT NOT NULL, password TEXT NOT NULL, " \
	"filename TEXT NOT NULL, uid INTEGER, PRIMARY KEY(pkgid, uid))"

int _app2sd_initialize_db()
{
	char *error_message = NULL;
	int ret;
	FILE *fp = NULL;

	fp = fopen(APP2SD_DB_FILE, "r");
	if (fp != NULL) {
		fclose(fp);
		ret = db_util_open(APP2SD_DB_FILE, &app2sd_db,
			DB_UTIL_REGISTER_HOOK_METHOD);

		if (ret != SQLITE_OK) {
			_E("connect menu_db [%s] failed",
				APP2SD_DB_FILE);
			return -1;
		}
		return 0;
	}

	ret = db_util_open(APP2SD_DB_FILE, &app2sd_db,
		 DB_UTIL_REGISTER_HOOK_METHOD);

	if (ret != SQLITE_OK) {
		_E("connect menu_db [%s] failed",
			APP2SD_DB_FILE);
		return -1;
	}

	if (SQLITE_OK != sqlite3_exec(app2sd_db,
		QUERY_CREATE_TABLE_APP2SD, NULL, NULL,
		&error_message)) {
		_E("don't execute query = (%s), " \
			"error message = (%s)",
			QUERY_CREATE_TABLE_APP2SD, error_message);
		return -1;
	}

	return 0;
}

static int _app2sd_check_existing_info(const char *pkgid, uid_t uid)
{
	char *query = NULL;
	const char *val = NULL;
	sqlite3_stmt *stmt = NULL;
	int ret = 0;

	query = sqlite3_mprintf("select count(*) from app2sd_info " \
		"where pkgid=%Q and uid=%d", pkgid, uid);
	if (query == NULL) {
		_E("failed to make a query");
		return -1;
	}

	ret = sqlite3_prepare_v2(app2sd_db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_E("prepare failed (%s)", sqlite3_errmsg(app2sd_db));
		sqlite3_free(query);
		return -1;
	}

	if (sqlite3_step(stmt) != SQLITE_ROW) {
		_E("failed to step");
		sqlite3_finalize(stmt);
		return -1;
	}

	val = (const char *)sqlite3_column_text(stmt, 0);
	ret = atoi(val);
	sqlite3_finalize(stmt);

	return ret;
}

int _app2sd_set_info_in_db(const char *pkgid, const char *passwd,
		const char *loopback_device, uid_t uid)
{
	char *error_message = NULL;
	char *query = NULL;
	int ret = 0;

	ret = _app2sd_check_existing_info(pkgid, uid);
	if (ret < 0) {
		_E("failed to get existing info");
		return APP2EXT_ERROR_SQLITE_REGISTRY;
	}

	if (ret == 0)
		query = sqlite3_mprintf("insert into app2sd_info " \
			"(pkgid, password, filename, uid) values (%Q, %Q, %Q, %d)",
			pkgid, passwd, loopback_device, uid);
	else
		query = sqlite3_mprintf("update app2sd_info " \
			"set password=%Q, filename=%Q where pkgid=%Q and uid=%d",
			passwd, loopback_device, pkgid, uid);

	ret = sqlite3_exec(app2sd_db, query, NULL, NULL, &error_message);
	if (ret != SQLITE_OK) {
		_E("failed to execute query(%s), error message(%s)",
			query, error_message);
		sqlite3_free(query);
		return APP2EXT_ERROR_SQLITE_REGISTRY;
	}
	sqlite3_free(query);

	return APP2EXT_SUCCESS;
}

int _app2sd_remove_info_from_db(const char *pkgid, uid_t uid)
{
	char *error_message = NULL;
	char *query = NULL;
	int ret = 0;

	query = sqlite3_mprintf("delete from app2sd_info " \
		"where pkgid=%Q and uid=%d", pkgid, uid);

	ret = sqlite3_exec(app2sd_db, query, NULL, NULL, &error_message);
	if (ret != SQLITE_OK) {
		_E("failed to execute query(%s), error message(%s)",
			query, error_message);
		sqlite3_free(query);
		return APP2EXT_ERROR_SQLITE_REGISTRY;
	}
	sqlite3_free(query);

	return APP2EXT_SUCCESS;
}

int _app2sd_get_info_from_db(const char *filename, char **pkgid, uid_t *uid)
{
	char *query = NULL;
	sqlite3_stmt *stmt = NULL;
	int ret = APP2EXT_SUCCESS;

	_D("filename(%s)", filename);
	query = sqlite3_mprintf("select * from app2sd_info " \
		"where filename=%Q", filename);
	if (query == NULL) {
		_E("failed to make a query");
		return APP2EXT_ERROR_SQLITE_REGISTRY;
	}

	ret = sqlite3_prepare_v2(app2sd_db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_E("prepare failed (%s)", sqlite3_errmsg(app2sd_db));
		sqlite3_free(query);
		*pkgid = NULL;
		*uid = 0;
		return APP2EXT_ERROR_SQLITE_REGISTRY;
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW || ret == SQLITE_DONE) {
		_W("no records found");
		ret = APP2EXT_SUCCESS;
		goto FINISH_OFF;
	}

	*pkgid = strdup((const char *)sqlite3_column_text(stmt, 0));
	if (*pkgid == NULL) {
		_E("out of memory");
		ret = APP2EXT_ERROR_SQLITE_REGISTRY;
		goto FINISH_OFF;
	}

	*uid = sqlite3_column_int(stmt, 3);
	if (*uid != GLOBAL_USER && *uid < REGULAR_USER) {
		_E("invalid uid");
		ret = APP2EXT_ERROR_SQLITE_REGISTRY;
		goto FINISH_OFF;
	}

	if (SQLITE_OK != sqlite3_finalize(stmt)) {
		_E("error : sqlite3_finalize");
		ret = APP2EXT_ERROR_SQLITE_REGISTRY;
		goto FINISH_OFF;
	}
	sqlite3_free(query);

	return APP2EXT_SUCCESS;

FINISH_OFF:
	if (*pkgid) {
		free(*pkgid);
		*pkgid = NULL;
	}
	*uid = 0;

	sqlite3_finalize(stmt);
	sqlite3_free(query);

	return ret;
}

int _app2sd_get_foreach_info_from_db(app2sd_info_cb cb_func)
{
	char *query = NULL;
	sqlite3_stmt *stmt = NULL;
	const char *pkgid = NULL;
	int uid = 0;
	int ret = 0;

	query = sqlite3_mprintf("select * from app2sd_info");
	if (query == NULL) {
		_E("failed to make a query");
		return APP2EXT_ERROR_SQLITE_REGISTRY;
	}

	ret = sqlite3_prepare_v2(app2sd_db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_E("prepare failed (%s)", sqlite3_errmsg(app2sd_db));
		sqlite3_free(query);
		return APP2EXT_ERROR_SQLITE_REGISTRY;
	}

	ret = APP2EXT_SUCCESS;
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		pkgid = (const char *)sqlite3_column_text(stmt, 0);
		uid = sqlite3_column_int(stmt, 3);

		ret = cb_func(pkgid, (uid_t)uid);
		if (ret) {
			_E("app2sd info callback error");
			/* continue */
		}
	}

	if (SQLITE_OK != sqlite3_finalize(stmt)) {
		_E("error : sqlite3_finalize");
		ret = APP2EXT_ERROR_SQLITE_REGISTRY;
	}
	sqlite3_free(query);

	return ret;
}

char *_app2sd_get_password_from_db(const char *pkgid, uid_t uid)
{
	char *query = NULL;
	char *passwd = NULL;
	sqlite3_stmt *stmt = NULL;
	int ret = 0;

	query = sqlite3_mprintf("select * from app2sd_info " \
		"where pkgid=%Q and uid=%d", pkgid, uid);
	if (query == NULL) {
		_E("failed to make a query");
		return NULL;
	}

	ret = sqlite3_prepare_v2(app2sd_db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_E("prepare failed (%s)", sqlite3_errmsg(app2sd_db));
		sqlite3_free(query);
		return NULL;
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW || ret == SQLITE_DONE) {
		_W("no records found");
		goto FINISH_OFF;
	}
	passwd = malloc(PASSWORD_LENGTH + 1);
	if (passwd == NULL) {
		_E("memory allocation failed");
		goto FINISH_OFF;
	}

	strncpy(passwd, (const char *)sqlite3_column_text(stmt, 1),
		PASSWORD_LENGTH);
	if (passwd == NULL) {
		_E("data is NULL");
		goto FINISH_OFF;
	}
	if (SQLITE_OK != sqlite3_finalize(stmt)) {
		_E("error : sqlite3_finalize");
		goto FINISH_OFF;
	}
	sqlite3_free(query);

	return passwd;

FINISH_OFF:
	if (passwd)
		free(passwd);

	sqlite3_finalize(stmt);
	sqlite3_free(query);

	return NULL;
}
