/* Copyright (C) 2000-2002 Red Hat, Inc.
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
#include <sys/types.h>
#include <errno.h>
#include <execinfo.h>
#include <libintl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "user.h"
#include "user_private.h"

/**
 * SECTION:error
 * @short_description: Functions for allocating and manipulating #lu_error
 * structures.
 * @include: libuser/error.h
 *
 * <filename>error.h</filename> includes declarations for allocating and
 * manipulating #lu_error structures.  These structures hold error and status
 * information passed between libuser, its modules, and applications.
 *
 * A struct #lu_error contains an error code and a human-readable, possibly
 * translated error string.  The error string uses the encoding specified by
 * the %LC_CTYPE locale category.
 */

/**
 * lu_strerror:
 * @error: An error
 *
 * Converts an #lu_error structure to a string describing the error.  If the
 * @error->string is %NULL, returns a text representation of @error->code.
 *
 * Returns: An error string valid at least until @error is freed.
 */
const char *
lu_strerror(struct lu_error *error)
{
	if (error != NULL) {
		if (error->string != NULL) {
			return error->string;
		}
		switch (error->code) {
			case lu_success:
				return _("success");
			case lu_warning_config_disabled:
				return _("module disabled by configuration");
			case lu_error_generic:
				return _("generic error");
			case lu_error_privilege:
				return _("not enough privileges");
			case lu_error_access_denied:
				return _("access denied");
			case lu_error_name_bad:
				return _("bad user/group name");
			case lu_error_id_bad:
				return _("bad user/group id");
			case lu_error_name_used:
				return _("user/group name in use");
			case lu_error_id_used:
				return _("user/group id in use");
			case lu_error_terminal:
				return _("error manipulating terminal attributes");
			case lu_error_open:
				return _("error opening file");
			case lu_error_lock:
				return _("error locking file");
			case lu_error_stat:
				return _("error statting file");
			case lu_error_read:
				return _("error reading file");
			case lu_error_write:
				return _("error writing to file");
			case lu_error_search:
				return _("data not found in file");
			case lu_error_init:
				return _("internal initialization error");
			case lu_error_module_load:
				return _("error loading module");
			case lu_error_module_sym:
				return _("error resolving symbol in module");
			case lu_error_module_version:
				return _("library/module version mismatch");
			case lu_error_unlock_empty:
				return _("unlocking would make the password "
					 "field empty");
			case lu_error_invalid_attribute_value:
				return _("invalid attribute value");
			case lu_error_invalid_module_combination:
				return _("invalid module combination");
			case lu_error_homedir_not_owned:
				return _("user's home directory not owned by "
					 "them");
			default:
				break;
		}
	}
	return _("unknown error");
}

/**
 * lu_error_is_success:
 * @status: An error code
 *
 * Check if the error code held by an error structure is a success code.
 *
 * Returns: a #gboolean indicating whether or not the error is a success code.
 */
gboolean
lu_error_is_success(enum lu_status status)
{
	switch (status) {
		case lu_success:
			return TRUE;
		default:
			return FALSE;
	}
}

/**
 * lu_error_is_warning:
 * @status: An error code
 *
 * Check if the error code held by an error structure is a warning code.
 *
 * Returns: a #gboolean indicating whether or not the error is a warning code.
 */
gboolean
lu_error_is_warning(enum lu_status status)
{
	switch (status) {
		case lu_warning_config_disabled:
			return TRUE;
		default:
			return FALSE;
	}
}

/**
 * lu_error_is_error:
 * @status: An error code
 *
 * Check if the error code held by an error structure is an error code.
 *
 * Returns: a #gboolean indicating whether or not the error is an error code.
 */
gboolean
lu_error_is_error(enum lu_status status)
{
	switch (status) {
		case lu_error_generic:
		case lu_error_privilege:
		case lu_error_access_denied:
		case lu_error_name_bad:
		case lu_error_id_bad:
		case lu_error_name_used:
		case lu_error_id_used:
		case lu_error_terminal:
		case lu_error_open:
		case lu_error_lock:
		case lu_error_stat:
		case lu_error_read:
		case lu_error_write:
		case lu_error_search:
		case lu_error_init:
		case lu_error_module_load:
		case lu_error_module_sym:
		case lu_error_module_version:
		case lu_error_unlock_empty:
		case lu_error_invalid_attribute_value:
		case lu_error_invalid_module_combination:
		case lu_error_homedir_not_owned:
			return TRUE;
		default:
			return FALSE;
	}
}

/**
 * lu_error_new:
 * @error: A pointer to a struct #lu_error * which will hold the newly-created
 * error structure. It must point to #NULL before calling this function.
 * @code: An error code
 * @fmt: Format string describing the error. If #NULL, a default string is used.
 * @...: Arguments for @fmt, if necessary
 *
 * Creates a new #lu_error structure.
 */
void
lu_error_new(struct lu_error **error, enum lu_status code,
	     const char *fmt, ...)
{
	if (error != NULL) {
		struct lu_error *ret;

		g_assert(*error == NULL);
		ret = g_malloc0(sizeof(struct lu_error));
		ret->code = code;
		if (fmt != NULL) {
			va_list args;

			va_start(args, fmt);
			ret->string = g_strdup_vprintf(fmt, args);
			va_end(args);
		} else
			ret->string = g_strdup(lu_strerror(ret));
		*error = ret;
	}
}

/**
 * lu_error_free:
 * @error: A pointer to a pointer to the structure to be freed.  The pointer is
 * set to %NULL after the error is freed.
 *
 * Frees an #lu_error structure.
 */
void
lu_error_free(struct lu_error **error)
{
	if (error != NULL) {
		g_free((*error)->string);
		memset(*error, 0, sizeof(**error));
		g_free(*error);
		*error = NULL;
	}
}
