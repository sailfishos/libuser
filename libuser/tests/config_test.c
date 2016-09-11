/* Copyright (C) 2000-2002, 2005, 2008 Red Hat, Inc.
 *
 * This is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <config.h>
#include <glib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/user.h"
#undef NDEBUG
#include <assert.h>

static struct lu_context *
start(const char *base, const char *file)
{
	char *path;
	struct lu_context *ctx;
	struct lu_error *error;

	path = g_strconcat(base, "/", file, NULL);
	setenv("LIBUSER_CONF", path, 1);
	g_free(path);

	error = NULL;
	ctx = lu_start(NULL, 0, NULL, NULL, lu_prompt_console_quiet, NULL,
		       &error);
	if (ctx == NULL) {
		fprintf(stderr, "Error initializing %s: %s.\n", PACKAGE,
			lu_strerror(error));
		exit(1);
	}
	return ctx;
}

static void
verify_var(struct lu_context *ctx, const char *key, ...)
{
	GList *list, *it;
	va_list ap;
	const char *val;

	list = lu_cfg_read(ctx, key, NULL);

	it = list;
	va_start(ap, key);
	while ((val = va_arg(ap, const char *)) != NULL) {
		assert(it != NULL && strcmp(it->data, val) == 0);
		it = it->next;
	}
	va_end(ap);
	assert(it == NULL);

	g_list_free(list);
}

int
main(int argc, char *argv[])
{
	struct lu_context *ctx;
	GList *list;

	assert(argc == 2);

	ctx = start(argv[1], "libuser.conf");

	verify_var(ctx, "test/name", "value1", "value2", (const char *)NULL);

	list = lu_cfg_read(ctx, "test/nonexistent", "default");
	assert(g_list_length(list) == 1);
	assert(strcmp(list->data, "default") == 0);
	g_list_free(list);

	verify_var(ctx, "test/nonexistent", (const char *)NULL);

	assert(strcmp(lu_cfg_read_single(ctx, "test/name", NULL), "value1")
	       == 0);
	assert(strcmp(lu_cfg_read_single(ctx, "test/nonexistent", "default"),
		      "default") == 0);
	assert(lu_cfg_read_single(ctx, "test/nonexistent", NULL) == NULL);

	list = lu_cfg_read_keys(ctx, "test");
	assert(g_list_length(list) == 2);
	assert(strcmp(list->data, "name") == 0);
	assert(strcmp(list->next->data, "name2") == 0);
	g_list_free(list);

	list = lu_cfg_read_keys(ctx, "invalid");
	assert(g_list_length(list) == 0);
	g_list_free(list);

	lu_end(ctx);

	ctx = start(argv[1], "libuser_import.conf");
	verify_var(ctx, "groupdefaults/" LU_GIDNUMBER, "1234",
		   (const char *)NULL);
	verify_var(ctx, "defaults/mailspooldir", "/mail/dir/value",
		   (const char *)NULL);
	verify_var(ctx, "defaults/crypt_style", "md5", (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_SHADOWMAX, "1235",
		   (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_SHADOWMIN, "1236",
		   (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_SHADOWWARNING, "1237",
		   (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_UIDNUMBER, "1239",
		   (const char *)NULL);
	verify_var(ctx, "defaults/hash_rounds_min", "1240", (const char *)NULL);
	verify_var(ctx, "defaults/hash_rounds_max", "1241", (const char *)NULL);
	/* From (echo $(($(date -d 'may 1 1980 0:0' +%s) / 24 / 3600))) */
	verify_var(ctx, "userdefaults/" LU_SHADOWEXPIRE, "3773",
		   (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_GIDNUMBER, "4322",
		   (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_HOMEDIRECTORY, "/custom/homes/%n",
		   (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_SHADOWINACTIVE, "4323",
		   (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_LOGINSHELL, "/login/shell",
		   (const char *)NULL);
	verify_var(ctx, "defaults/skeleton", "/skeleton/path",
		   (const char *)NULL);
	lu_end(ctx);

	ctx = start(argv[1], "libuser_import2.conf");
	verify_var(ctx, "defaults/crypt_style", "SHA256", (const char *)NULL);
	lu_end(ctx);

	ctx = start(argv[1], "libuser_override.conf");
	verify_var(ctx, "groupdefaults/LU_GIDNUMBER", "4242",
		   (const char *)NULL);
	verify_var(ctx, "groupdefaults/" LU_GIDNUMBER, (const char *)NULL);
	verify_var(ctx, "defaults/mailspooldir", "/overridden/mailspooldir",
		   (const char *)NULL);
	verify_var(ctx, "defaults/crypt_style", "des", (const char *)NULL);
	verify_var(ctx, "userdefaults/LU_SHADOWMAX", "4243",
		   (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_SHADOWMAX, (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_SHADOWMIN, "4244",
		   (const char *)NULL);
	verify_var(ctx, "userdefaults/LU_SHADOWWARNING", "4245",
		   (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_SHADOWWARNING, (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_UIDNUMBER, "4246",
		   (const char *)NULL);
	verify_var(ctx, "defaults/hash_rounds_min", "4250", (const char *)NULL);
	verify_var(ctx, "defaults/hash_rounds_max", "4251", (const char *)NULL);
	verify_var(ctx, "userdefaults/LU_SHADOWEXPIRE", "4247",
		   (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_SHADOWEXPIRE, (const char *)NULL);
	verify_var(ctx, "userdefaults/LU_GIDNUMBER", "4248",
		   (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_GIDNUMBER, (const char *)NULL);
	verify_var(ctx, "userdefaults/LU_HOMEDIRECTORY", "/overridden/home-%n",
		   (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_HOMEDIRECTORY, (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_SHADOWINACTIVE, "4249",
		   (const char *)NULL);
	verify_var(ctx, "userdefaults/LU_LOGINSHELL", "/overridden/shell",
		   (const char *)NULL);
	verify_var(ctx, "userdefaults/" LU_LOGINSHELL, (const char *)NULL);
	verify_var(ctx, "defaults/skeleton", "/overridden/skeleton",
		   (const char *)NULL);
	lu_end(ctx);

	return 0;
}
