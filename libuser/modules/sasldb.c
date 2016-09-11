/*
 * Copyright (C) 2000-2002, 2004 Red Hat, Inc.
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
#include <sasl/sasl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/user_private.h"

static gboolean
lu_sasldb_valid_module_combination(struct lu_module *module, GValueArray *names,
				   struct lu_error **error)
{
	(void)module;
	(void)names;
	(void)error;
	/* We never access LU_*PASSWORD, so no formatting conflicts are
	   possible. */
	return TRUE;
}

static gboolean
lu_sasldb_uses_elevated_privileges(struct lu_module *module)
{
	(void)module;
	/* FIXME: actually check the permissions on the sasldb. */
	return TRUE;
}

static gboolean
lu_sasldb_user_lookup_name(struct lu_module *module, const char *name,
			   struct lu_ent *ent, struct lu_error **error)
{
	int i;

	(void)ent;
	(void)error;
#ifdef HAVE_SASL_USER_EXISTS
	i = sasl_user_exists(module->module_context, NULL, NULL, name);
#else
	i = sasl_checkpass((sasl_conn_t *) module->module_context, name,
			   strlen(name), "", 0);
#endif

	return i != SASL_NOUSER;
}

static gboolean
lu_sasldb_user_lookup_id(struct lu_module *module, uid_t uid,
			 struct lu_ent *ent, struct lu_error **error)
{
	(void)module;
	(void)uid;
	(void)ent;
	(void)error;
	return FALSE;
}

static gboolean
lu_sasldb_group_lookup_name(struct lu_module *module, const char *name,
			    struct lu_ent *ent, struct lu_error **error)
{
	(void)module;
	(void)name;
	(void)ent;
	(void)error;
	return FALSE;
}

static gboolean
lu_sasldb_group_lookup_id(struct lu_module *module, gid_t gid,
			  struct lu_ent *ent, struct lu_error **error)
{
	(void)module;
	(void)gid;
	(void)ent;
	(void)error;
	return FALSE;
}

static gboolean
lu_sasldb_user_munge(struct lu_module *module, struct lu_ent *ent,
		     int flags, const char *password,
		     struct lu_error **error)
{
	size_t i;
	sasl_conn_t *connection;
	GValueArray *values;

	g_assert(module != NULL);
	LU_ERROR_CHECK(error);

	connection = module->module_context;

	values = lu_ent_get(ent, LU_USERNAME);
	for (i = 0; (values != NULL) && (i < values->n_values); i++) {
		GValue *value;
		char *tmp;
		int ret;

		value = g_value_array_get_nth(values, i);
		tmp = lu_value_strdup(value);
		ret = sasl_setpass(connection, tmp, password,
				   password != NULL ? strlen (password) : 0,
				   NULL, 0, flags);
		g_free(tmp);

		if (ret == SASL_OK) {
			return TRUE;
		} else {
			const char *err;

			err = sasl_errdetail(connection);
			if (password)
				lu_error_new(error, lu_error_generic,
					     _("Cyrus SASL error creating "
					       "user: %s"), err);
			else
				lu_error_new(error, lu_error_generic,
					     _("Cyrus SASL error removing "
					       "user: %s"), err);
			return FALSE;
		}
	}

	fprintf(stderr, "Error reading user name in %s at %d.\n", __FILE__,
		__LINE__);
	return FALSE;
}

static gboolean
lu_sasldb_user_default(struct lu_module *module,
		       const char *name, gboolean is_system,
		       struct lu_ent *ent,
		       struct lu_error **error)
{
	(void)module;
	(void)name;
	(void)ent;
	(void)error;
	return !is_system;
}

static gboolean
lu_sasldb_user_add_prep(struct lu_module *module, struct lu_ent *ent,
			struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return TRUE;
}

static gboolean
lu_sasldb_user_add(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	if (lu_sasldb_user_munge
	    (module, ent, SASL_SET_CREATE, PACKAGE, error)) {
		/* account created */
		if (lu_sasldb_user_munge(module, ent, SASL_SET_DISABLE,
					 PACKAGE, error) == TRUE) {
			/* account created and locked */
			return TRUE;
		} else {
			/* account created and couldn't be locked -- delete it */
			lu_sasldb_user_munge(module, ent, 0, NULL, error);
			return FALSE;
		}
	} else {
		/* account not created */
		return FALSE;
	}
	return FALSE;
}

static gboolean
lu_sasldb_user_mod(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	/* Nod our heads and smile. */
	return TRUE;
}

static gboolean
lu_sasldb_user_del(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	/* setting a NULL password removes the user */
	return lu_sasldb_user_munge(module, ent, 0, NULL, error);
}

static gboolean
lu_sasldb_user_lock(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	/* setting the disable flag locks the account, and setting a password unlocks it */
	return lu_sasldb_user_munge(module, ent, SASL_SET_DISABLE, "",
				    error);
}

static gboolean
lu_sasldb_user_unlock(struct lu_module *module, struct lu_ent *ent,
		      struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return FALSE;
}

static gboolean
lu_sasldb_user_unlock_nonempty(struct lu_module *module, struct lu_ent *ent,
			       struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return FALSE;
}

static gboolean
lu_sasldb_user_is_locked(struct lu_module *module, struct lu_ent *ent,
			struct lu_error **error)
{
	int i;
	char *name;

	(void)error;
	name = lu_ent_get_first_value_strdup(ent, LU_USERNAME);
#ifdef HAVE_SASL_USER_EXISTS
	i = sasl_user_exists(module->module_context, NULL, NULL, name);
#else
	i = sasl_checkpass((sasl_conn_t *) module->module_context, name,
			   strlen(name), "", 0);
#endif

	g_free(name);

	return (i == SASL_DISABLED);
}

static gboolean
lu_sasldb_user_setpass(struct lu_module *module, struct lu_ent *ent,
		       const char *password, struct lu_error **error)
{
	return lu_sasldb_user_munge(module, ent, 0, password, error);
}

static gboolean
lu_sasldb_user_removepass(struct lu_module *module, struct lu_ent *ent,
			  struct lu_error **error)
{
	/* SASL doesn't allow empty passwords */
	(void)module;
	(void)ent;
	(void)error;
	return FALSE;
}

static gboolean
lu_sasldb_group_default(struct lu_module *module,
			const char *name, gboolean is_system,
			struct lu_ent *ent,
			struct lu_error **error)
{
	(void)module;
	(void)name;
	(void)is_system;
	(void)ent;
	(void)error;
	return FALSE;
}

static gboolean
lu_sasldb_group_add_prep(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return TRUE;
}

static gboolean
lu_sasldb_group_add(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return FALSE;
}

static gboolean
lu_sasldb_group_mod(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return FALSE;
}

static gboolean
lu_sasldb_group_del(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return FALSE;
}

static gboolean
lu_sasldb_group_lock(struct lu_module *module, struct lu_ent *ent,
		     struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return FALSE;
}

static gboolean
lu_sasldb_group_unlock(struct lu_module *module, struct lu_ent *ent,
		       struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return FALSE;
}

static gboolean
lu_sasldb_group_unlock_nonempty(struct lu_module *module, struct lu_ent *ent,
				struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return FALSE;
}

static gboolean
lu_sasldb_group_is_locked(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return FALSE;
}

static gboolean
lu_sasldb_group_setpass(struct lu_module *module, struct lu_ent *ent,
			const char *password, struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)password;
	(void)error;
	return FALSE;
}

static gboolean
lu_sasldb_group_removepass(struct lu_module *module, struct lu_ent *ent,
			   struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return FALSE;
}


static GValueArray *
lu_sasldb_users_enumerate(struct lu_module *module, const char *pattern,
			  struct lu_error **error)
{
	(void)module;
	(void)pattern;
	(void)error;
	return NULL;
}

static GPtrArray *
lu_sasldb_users_enumerate_full(struct lu_module *module, const char *pattern,
			       struct lu_error **error)
{
	(void)module;
	(void)pattern;
	(void)error;
	return NULL;
}

static GValueArray *
lu_sasldb_groups_enumerate(struct lu_module *module, const char *pattern,
			   struct lu_error **error)
{
	(void)module;
	(void)pattern;
	(void)error;
	return NULL;
}

static GPtrArray *
lu_sasldb_groups_enumerate_full(struct lu_module *module, const char *pattern,
				struct lu_error **error)
{
	(void)module;
	(void)pattern;
	(void)error;
	return NULL;
}

static GValueArray *
lu_sasldb_users_enumerate_by_group(struct lu_module *module,
				   const char *group,
				   gid_t gid,
				   struct lu_error **error)
{
	(void)module;
	(void)group;
	(void)gid;
	(void)error;
	return NULL;
}

static GValueArray *
lu_sasldb_groups_enumerate_by_user(struct lu_module *module,
				   const char *user,
				   uid_t uid,
				   struct lu_error **error)
{
	(void)module;
	(void)user;
	(void)uid;
	(void)error;
	return NULL;
}

static gboolean
lu_sasldb_close_module(struct lu_module *module)
{
	sasl_conn_t *connection;

	connection = module->module_context;
	sasl_dispose(&connection);
	sasl_done();
	g_free(module);
	return TRUE;
}

struct lu_module *
libuser_sasldb_init(struct lu_context *context, struct lu_error **error)
{
	static const struct sasl_callback cb = {
		SASL_CB_LIST_END,
		NULL,
		NULL,
	};

	struct lu_module *ret;
	const char *appname;
	const char *domain;
	sasl_conn_t *connection;
	int i;

	g_assert(context != NULL);
	LU_ERROR_CHECK(error);

	/* Read in configuration variables. */
	appname = lu_cfg_read_single(context, "sasl/appname", "");
	domain = lu_cfg_read_single(context, "sasl/domain", "");

	/* Initialize SASL. */
	i = sasl_server_init(&cb, appname);
	if (i != SASL_OK) {
		lu_error_new(error, lu_error_generic,
			     _("error initializing Cyrus SASL: %s"),
			     sasl_errstring(i, NULL, NULL));
		return NULL;
	}
	i = sasl_server_new(PACKAGE, NULL, domain, NULL, NULL, &cb,
			    SASL_SEC_NOANONYMOUS, &connection);
	if (i != SASL_OK) {
		lu_error_new(error, lu_error_generic,
			     _("error initializing Cyrus SASL: %s"),
			     sasl_errstring(i, NULL, NULL));
		return NULL;
	}

	/* Allocate the method structure. */
	ret = g_malloc0(sizeof(struct lu_module));
	ret->version = LU_MODULE_VERSION;
	ret->scache = lu_string_cache_new(TRUE);
	ret->name = ret->scache->cache(ret->scache, "sasldb");
	ret->module_context = connection;

	/* Set the method pointers. */
	ret->valid_module_combination = lu_sasldb_valid_module_combination;
	ret->uses_elevated_privileges = lu_sasldb_uses_elevated_privileges;

	ret->user_lookup_name = lu_sasldb_user_lookup_name;
	ret->user_lookup_id = lu_sasldb_user_lookup_id;

	ret->user_default = lu_sasldb_user_default;
	ret->user_add_prep = lu_sasldb_user_add_prep;
	ret->user_add = lu_sasldb_user_add;
	ret->user_mod = lu_sasldb_user_mod;
	ret->user_del = lu_sasldb_user_del;
	ret->user_lock = lu_sasldb_user_lock;
	ret->user_unlock = lu_sasldb_user_unlock;
	ret->user_unlock_nonempty = lu_sasldb_user_unlock_nonempty;
	ret->user_is_locked = lu_sasldb_user_is_locked;
	ret->user_setpass = lu_sasldb_user_setpass;
	ret->user_removepass = lu_sasldb_user_removepass;
	ret->users_enumerate = lu_sasldb_users_enumerate;
	ret->users_enumerate_by_group = lu_sasldb_users_enumerate_by_group;
	ret->users_enumerate_full = lu_sasldb_users_enumerate_full;

	ret->group_lookup_name = lu_sasldb_group_lookup_name;
	ret->group_lookup_id = lu_sasldb_group_lookup_id;

	ret->group_default = lu_sasldb_group_default;
	ret->group_add_prep = lu_sasldb_group_add_prep;
	ret->group_add = lu_sasldb_group_add;
	ret->group_mod = lu_sasldb_group_mod;
	ret->group_del = lu_sasldb_group_del;
	ret->group_lock = lu_sasldb_group_lock;
	ret->group_unlock = lu_sasldb_group_unlock;
	ret->group_unlock_nonempty = lu_sasldb_group_unlock_nonempty;
	ret->group_is_locked = lu_sasldb_group_is_locked;
	ret->group_setpass = lu_sasldb_group_setpass;
	ret->group_removepass = lu_sasldb_group_removepass;
	ret->groups_enumerate = lu_sasldb_groups_enumerate;
	ret->groups_enumerate_by_user = lu_sasldb_groups_enumerate_by_user;
	ret->groups_enumerate_full = lu_sasldb_groups_enumerate_full;

	ret->close = lu_sasldb_close_module;

	/* Done. */
	return ret;
}
