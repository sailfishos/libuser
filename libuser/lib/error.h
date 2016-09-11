/*
 * Copyright (C) 2000-2002 Red Hat, Inc.
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

#ifndef libuser_error_h
#define libuser_error_h

#include <sys/types.h>
#include <errno.h>
#include <glib.h>

G_BEGIN_DECLS

/**
 * lu_status:
 * @lu_success: Success.
 * @lu_warning_config_disabled: Module disabled by configuration.
 * @lu_error_generic: Generic error.
 * @lu_error_privilege: Not enough privileges.
 * @lu_error_access_denied: Access denied.
 * @lu_error_name_bad: Bad user/group name.
 * @lu_error_id_bad: Bad user/group id.
 * @lu_error_name_used: User/group name in use.
 * @lu_error_id_used: User/group id in use.
 * @lu_error_terminal: Error manipulating terminal attributes.
 * @lu_error_open: Error opening file.
 * @lu_error_lock: Error locking file.
 * @lu_error_stat: Error statting file.
 * @lu_error_read: Error reading file.
 * @lu_error_write: Error writing to file.
 * @lu_error_search: Data not found in file.
 * @lu_error_init: Internal initialization error.
 * @lu_error_module_load: Error loading module.
 * @lu_error_module_sym: Error resolving symbol in module.
 * @lu_error_module_version: Library/module version mismatch.
 * @lu_error_unlock_empty: Unlocking would make the password field empty.
 *  Since: 0.53
 * @lu_error_invalid_attribute_value: Invalid attribute value.
 *  Since: 0.56
 * @lu_error_invalid_module_combination: Invalid module combination.
 *  Since: 0.57
 * @lu_error_homedir_not_owned: User's home directory not owned by them.
 *  Since: 0.60
 *
 * Program-readable error/status codes. Note that new ones may be added in the
 * future, even for existing operations.
 */
enum lu_status {
	/* Non-fatal. */
	lu_success = 0,
	lu_warning_config_disabled,

	/* Fatal. */
	lu_error_generic,
	lu_error_privilege,
	lu_error_access_denied,

	/* Data validation errors. */
	lu_error_name_bad,
	lu_error_id_bad,
	lu_error_name_used,
	lu_error_id_used,

	/* Terminal manipulation errors. */
	lu_error_terminal,

	/* File I/O errors. */
	lu_error_open,
	lu_error_lock,
	lu_error_stat,
	lu_error_read,
	lu_error_write,
	lu_error_search,

	/* Initialization or module-loading errors. */
	lu_error_init,
	lu_error_module_load,
	lu_error_module_sym,
	lu_error_module_version,

	/* Since 0.53 */
	lu_error_unlock_empty,

	/* Since 0.56 */
	lu_error_invalid_attribute_value,

	/* Since 0.57 */
	lu_error_invalid_module_combination,

	/* Since 0.60 */
	lu_error_homedir_not_owned,
};
#ifndef __GTK_DOC_IGNORE__
#ifndef LU_DISABLE_DEPRECATED
typedef enum lu_status lu_status_t;
#endif
#endif

/**
 * lu_error:
 * @code: A program-readable error code.
 * @string: A human-readable, possibly translated error string.  The error
 *  string uses the encoding specified by the %LC_CTYPE locale category.
 *
 * Error and status information.
 */
struct lu_error {
	enum lu_status code;
	char *string;
};
#ifndef LU_DISABLE_DEPRECATED
/**
 * lu_error_t:
 *
 * An alias for struct #lu_error.
 * Deprecated: 0.57.3: Use struct #lu_error directly.
 */
typedef struct lu_error lu_error_t;
#endif

/**
 * LU_ERROR_CHECK:
 * @err_p_p: A pointer to a struct #lu_error * which will be checked.
 *
 * Checks that the given pointer to a pointer to a struct does not already
 * point to a valid #lu_error structure, and calls abort() on failure.  This
 * macro is used by many internal functions to check that an error has not
 * already occurred when they are invoked.
 */
#define LU_ERROR_CHECK(err_p_p) \
do { \
	struct lu_error **__err = (err_p_p); \
	if ((__err == NULL) || (*__err != NULL)) { \
		if(__err == NULL) { \
			fprintf(stderr, "libuser fatal error: %s() called with NULL " #err_p_p "\n", __FUNCTION__); \
		} else \
		if(*__err != NULL) { \
			fprintf(stderr, "libuser fatal error: %s() called with non-NULL *" #err_p_p "\n", __FUNCTION__); \
		} \
		abort(); \
	} \
} while(0)

void lu_error_new(struct lu_error **error, enum lu_status code,
		  const char *fmt, ...) G_GNUC_PRINTF(3, 4);
const char *lu_strerror(struct lu_error *error);
gboolean lu_error_is_success(enum lu_status status);
gboolean lu_error_is_warning(enum lu_status status);
gboolean lu_error_is_error(enum lu_status status);
void lu_error_free(struct lu_error **error);

G_END_DECLS

#endif
