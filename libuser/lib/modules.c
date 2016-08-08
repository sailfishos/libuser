/* Copyright (C) 2000-2002, 2005 Red Hat, Inc.
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "user_private.h"
#include "internal.h"

#define SEPARATORS "\t ,"

static gboolean
load_one_module(struct lu_context *ctx, const char *module_dir,
		char *module_name, struct lu_error **error)
{
	char *tmp, *symbol, *module_file;
	GModule *handle;
	lu_module_init_t module_init;
	struct lu_module *module;

	LU_ERROR_CHECK(error);

	/* Generate the file name. */
	tmp = g_strconcat(PACKAGE "_", module_name, NULL);
	module_file = g_module_build_path(module_dir, tmp);
	g_free(tmp);

	/* Open the module. */
	handle = g_module_open(module_file, G_MODULE_BIND_LOCAL);
	if (handle == NULL) {
		/* If the open failed, we return an error. */
		lu_error_new(error, lu_error_module_load, "%s",
			     g_module_error());
		goto err_module_file;
	}

	/* Determine the name of the module's initialization function and try
	 * to find it. */
	symbol = g_strconcat(PACKAGE "_", module_name, "_init", NULL);
	g_module_symbol(handle, symbol, (gpointer)&module_init);

	/* If we couldn't find the entry point, error out. */
	if (module_init == NULL) {
		lu_error_new(error, lu_error_module_sym,
			     _("no initialization function %s in `%s'"),
			     symbol, module_file);
		g_free(symbol);
		goto err_handle;
	}
	g_free(symbol);

	/* Ask the module to allocate the a module structure and hand it back
	 * to us. */
	module = module_init(ctx, error);

	if (module == NULL) {
		g_assert(*error != NULL);
		goto err_handle;
	}
	/* Check that the module interface version is right, too. */
	if (module->version != LU_MODULE_VERSION) {
		lu_error_new(error, lu_error_module_version,
			     _("module version mismatch in `%s'"),
			     module_file);
		/* Don't call module->close, the pointer might not be there */
		goto err_handle;
	}

	/* For safety's sake, make sure that all functions provided by the
	 * module exist.  This can often mean a useless round trip, but it
	 * simplifies the logic of the library greatly. */
#define M(MEMBER)							\
	do {								\
		if (module->MEMBER == NULL) {				\
			lu_error_new(error, lu_error_module_sym,	\
				     _("module `%s' does not define `%s'"), \
				     module_file, #MEMBER);		\
			goto err_module;				\
		}							\
	} while (0)
	M(valid_module_combination);
	M(uses_elevated_privileges);
	M(user_lookup_name);
	M(user_lookup_id);
	M(user_default);
	M(user_add_prep);
	M(user_add);
	M(user_mod);
	M(user_del);
	M(user_lock);
	M(user_unlock);
	M(user_unlock_nonempty);
	M(user_is_locked);
	M(user_setpass);
	M(user_removepass);
	M(users_enumerate);
	M(users_enumerate_by_group);
	M(users_enumerate_full);

	M(group_lookup_name);
	M(group_lookup_id);
	M(group_default);
	M(group_add_prep);
	M(group_add);
	M(group_mod);
	M(group_del);
	M(group_lock);
	M(group_unlock);
	M(group_unlock_nonempty);
	M(group_is_locked);
	M(group_setpass);
	M(group_removepass);
	M(groups_enumerate);
	M(groups_enumerate_by_user);
	M(groups_enumerate_full);

	M(close);
#undef M

	g_free(module_file);

	/* Initialize the last two fields in the module structure and add it to
	   the module tree. */
	module->lu_context = ctx;
	module->module_handle = handle;
	module_name = ctx->scache->cache(ctx->scache, module_name);
	g_tree_insert(ctx->modules, module_name, module);

	return TRUE;

err_module:
	if (module->close != NULL)
		module->close(module);
err_handle:
	g_module_close(handle);
err_module_file:
	g_free(module_file);
	return FALSE;
}

gboolean
lu_modules_load(struct lu_context *ctx, const char *module_list,
	       	GValueArray **names, struct lu_error **error)
{
	char *q, *modlist;
	const char *module_dir;
	char *module_name;
	GValueArray *our_names;
	size_t i;

	LU_ERROR_CHECK(error);

	g_assert(ctx != NULL);
	g_assert(module_list != NULL);
	g_assert(names != NULL);

	/* Build a GValueArray for the module names. */
	our_names = g_value_array_new(0);

	/* Figure out where the modules would be. */
	module_dir = lu_cfg_read_single(ctx, "defaults/moduledir", MODULEDIR);

	/* Load the modules. */
	modlist = g_strdup(module_list);
	for (module_name = strtok_r(modlist, SEPARATORS, &q);
	     module_name != NULL;
	     module_name = strtok_r(NULL, SEPARATORS, &q)) {
		GValue value;

		/* Only load the module if it's not already loaded. */
		if (g_tree_lookup(ctx->modules, module_name) == NULL) {
			if (load_one_module(ctx, module_dir, module_name,
					    error) == FALSE) {
				/* The module initializer may report a warning,
				   which is not fatal. */
				if (!lu_error_is_warning((*error)->code))
					goto error;
				lu_error_free(error);
				continue;
			}
		}

		/* Record that we loaded the module. */
		memset(&value, 0, sizeof(value));
		g_value_init(&value, G_TYPE_STRING);
		g_value_set_string(&value, module_name);
		g_value_array_append(our_names, &value);
		g_value_unset(&value);
	}

	for (i = 0; i < our_names->n_values; i++) {
		GValue *value;
		struct lu_module *module;

		value = g_value_array_get_nth(our_names, i);
		module = g_tree_lookup(ctx->modules, g_value_get_string(value));
		g_assert(module != NULL);
		if (module->valid_module_combination(module, our_names, error)
		    == FALSE)
			goto error;
	}

	g_free(modlist);
	if (*names != NULL)
		g_value_array_free(*names);
	*names = our_names;
	return TRUE;

error:
	/* Modules loaded before the failure are kept loaded, but the list of
	   used modules does not change. */
	g_value_array_free(our_names);
	g_free(modlist);
	return FALSE;
}

/* Unload a given module, implemented as a callback for a GTree where the
 * module's name is a key, and the module structure is the value. */
int
lu_module_unload(gpointer key, gpointer value, gpointer data)
{
	(void)key;
	(void)data;
	/* Give the module a chance to clean itself up. */
	if (value != NULL) {
		struct lu_module *module;
		GModule *handle;

		module = (struct lu_module *) value;
		handle = module->module_handle;
		module->close(module);
		/* Unload the module. */
		if (handle != NULL)
			g_module_close(handle);
	}
	return 0;
}
