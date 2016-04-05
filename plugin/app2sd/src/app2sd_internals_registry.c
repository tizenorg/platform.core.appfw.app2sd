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
#include <dlog.h>
#include <time.h>
#include <db-util.h>
#include <tzplatform_config.h>

#define MAX_QUERY_LEN 4096
#define PASSWORD_LENGTH 64
/*
########### Internal APIs ##################
 */

/*sqlite  db code*/
#define APP2SD_DB_FILE tzplatform_mkpath(TZ_SYS_DB, ".app2sd.db")
sqlite3 *app2sd_db;
#define QUERY_CREATE_TABLE_APP2SD "create table app2sd \
	(pkgid text primary key,\
	 password text\
	)"

/*
 *@_app2sd_initialize_db
 *This function is to initialize sqlite db.
 * return: On success, it will return zero else  if fail then return val<0.
 */
int _app2sd_initialize_db()
{
	char *error_message = NULL;
	int ret;
	FILE * fp = NULL;
	fp = fopen(APP2SD_DB_FILE, "r");
	if (fp != NULL) {
		fclose(fp);
		ret =
		    db_util_open(APP2SD_DB_FILE, &app2sd_db,
				 DB_UTIL_REGISTER_HOOK_METHOD);

		if (ret != SQLITE_OK) {
			app2ext_print("====>>>> connect menu_db [%s] failed!\n",
				     APP2SD_DB_FILE);
			return -1;
		}
		return 0;
	}

	ret =
	    db_util_open(APP2SD_DB_FILE, &app2sd_db,
			 DB_UTIL_REGISTER_HOOK_METHOD);

	if (ret != SQLITE_OK) {
		app2ext_print("====>>>> connect menu_db [%s] failed!\n",
			     APP2SD_DB_FILE);
		return -1;
	}

	if (SQLITE_OK !=
	    sqlite3_exec(app2sd_db, QUERY_CREATE_TABLE_APP2SD,
			 NULL, NULL, &error_message)) {
		app2ext_print("Don't execute query = %s, "
			     "error message = %s\n",
			     QUERY_CREATE_TABLE_APP2SD, error_message);
		return -1;
	}

	app2ext_print("\n db_initialize_done ");
	return 0;
}

/*
 *@_app2sd_set_password_in_db
 *This function is to store password into  db.
 * param[in]: pkgid: package id
 * param[in]: password: password string
 * return: On success, it will return 0.
 * Else appropriate error will be returned.
 */
int _app2sd_set_password_in_db(const char *pkgid,
				      const char *passwd)
{
	char *error_message = NULL;

	char *query = sqlite3_mprintf("insert into app2sd(pkgid,password) values (%Q, %Q)", pkgid, passwd);

	if (SQLITE_OK != sqlite3_exec(app2sd_db, query, NULL, NULL,
				      &error_message)) {
		app2ext_print("Don't execute query = %s, error message = %s\n",
			     query, error_message);

		sqlite3_free(query);
		return APP2EXT_ERROR_SQLITE_REGISTRY;
	}
	sqlite3_free(query);
	app2ext_print("\n sqlite insertion done ");
	return APP2EXT_SUCCESS;
}

/*
 * @_app2sd_remove_password_from_db
 * This function is to remove passwod from  db.
 * param[in]: pkgid: package id
 * return: On success, it will return 0.
 * Else appropriate error will be returned.
 */
int _app2sd_remove_password_from_db(const char *pkgid)
{
	char *error_message = NULL;
	char *query = sqlite3_mprintf("delete from app2sd"
		" where pkgid LIKE %Q", pkgid);
	app2ext_print("\n deletion querys is %s ", query);

	if (SQLITE_OK != sqlite3_exec(app2sd_db, query, NULL,
		NULL, &error_message)) {
		app2ext_print("Don't execute query = %s, "
			"error message = %s\n", query, error_message);
		sqlite3_free(query);
		return APP2EXT_ERROR_SQLITE_REGISTRY;
	}

	sqlite3_free(query);
	app2ext_print("\n app2sd password deletion done ");
	return APP2EXT_SUCCESS;
}

/*
 * @_app2sd_get_password_from_db
 * This function is to retrive password from DB
 * param[in]: pkgid: package id
 * return: On success, it will return the password, else NULL.
 */
char *_app2sd_get_password_from_db(const char *pkgid)
{
	char query[MAX_QUERY_LEN] = { 0 };
	sqlite3_stmt *stmt = NULL;
	const char *tail = NULL;
	int rc = 0;
	char *passwd = NULL;

	sqlite3_snprintf(MAX_QUERY_LEN, query,
		"select * from app2sd where pkgid LIKE '%s'", pkgid);
	app2ext_print("access querys is %s ", query);

	if (SQLITE_OK != sqlite3_prepare(app2sd_db, query,
		strlen(query), &stmt, &tail)) {
		app2ext_print("sqlite3_prepare error\n");
		return NULL;
	}

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW || rc == SQLITE_DONE) {
		app2ext_print("No records found");
		goto FINISH_OFF;
	}
	passwd = malloc(PASSWORD_LENGTH + 1);
	if (passwd == NULL) {
		app2ext_print("memory allocation failed\n");
		goto FINISH_OFF;
	}

	app2ext_print("entry available in sqlite");
	strncpy(passwd, (const char*)sqlite3_column_text(stmt, 1),
		PASSWORD_LENGTH);
	if (passwd == NULL) {
		app2ext_print("\n password is NULL ");
		goto FINISH_OFF;
	}
	app2ext_print("passwd is %s ", passwd);
	if (SQLITE_OK != sqlite3_finalize(stmt)) {
		app2ext_print("error : sqlite3_finalize\n");
		goto FINISH_OFF;
	}

	return passwd;

FINISH_OFF:
	rc = sqlite3_finalize(stmt);
	if (rc != SQLITE_OK) {
		app2ext_print("sqlite3_finalize failed - %d", rc);
	}

	if (passwd)
		free(passwd);

	return NULL;
}
