/* Copyright (C) 2000-2002, 2004 Red Hat, Inc.
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
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "user_private.h"
#include "internal.h"

/**
 * SECTION:value
 * @short_description: Simplified interface to GValue types used in libuser
 * entities.
 * @include: libuser/user.h
 *
 * Libuser entities store attribute values as #GValue, which allows representing
 * any possible data type.  Only a few types are needed in practice; the only
 * types applications should hard-code are %G_TYPE_LONG and %G_TYPE_STRING
 * (%G_TYPE_STRING can usually be used as a fallback for other number types).
 *
 * The only currently used data types that are not conveniently supported using
 * the above types are #uid_t and #gid_t (which can be together represented in
 * #id_t), because they can support values outside of the range of #glong.
 * Helper functions are provided to convert values between #id_t and #GValue,
 * even if the value is stored using %G_TYPE_STRING.  The #GValue types used
 * for storing #id_t values are an internal implementation detail of libuser
 * and applications should not rely on them.
 *
 * Values of each attribute are expected to have a specific type, documented in
 * the documentation of the specific attribute name.  Using other types (e.g.
 * using %G_TYPE_STRING for %LU_UIDNUMBER) is not allowed and results in
 * undefined behavior.  You can use lu_value_strdup() and
 * lu_value_init_set_attr_from_string() for conversion between strings and
 * values appropriate for a specific attribute.
 */

/**
 * lu_value_strdup:
 * @value: #GValue
 *
 * Converts @value, of any type used by libuser, to a string.  Preferable to
 * hard-coding checks for expected value types.
 *
 * Returns: string, should be freed by g_free()
 */
char *
lu_value_strdup(const GValue *value)
{
	char *ret;

	if (G_VALUE_HOLDS_STRING(value))
		ret = g_value_dup_string(value);
	else if (G_VALUE_HOLDS_LONG(value))
		ret = g_strdup_printf("%ld", g_value_get_long(value));
	else if (G_VALUE_HOLDS_INT64(value))
		ret = g_strdup_printf("%lld",
				      (long long)g_value_get_int64(value));
	else {
		g_assert_not_reached();
		ret = NULL;
	}
	return ret;
}

/**
 * lu_values_equal:
 * @a: #GValue
 * @b: #GValue
 *
 * Check whether @a and @b have the same type and value.
 *
 * Returns: #TRUE if @a and @b have the same type and value
 */
int
lu_values_equal(const GValue *a, const GValue *b)
{
	g_return_val_if_fail(G_VALUE_TYPE(a) == G_VALUE_TYPE(b), FALSE);
	if (G_VALUE_HOLDS_STRING(a))
		return strcmp(g_value_get_string(a), g_value_get_string(b))
			== 0;
	else if (G_VALUE_HOLDS_LONG(a))
		return g_value_get_long(a) == g_value_get_long(b);
	else if (G_VALUE_HOLDS_INT64(a))
		return g_value_get_int64(a) == g_value_get_int64(b);
	else {
		g_assert_not_reached();
		return FALSE;
	}
}

/**
 * lu_value_init_set_id:
 * @value: #GValue
 * @id: User or group ID.
 *
 * Initializes a zero-filled (uninitialized) @value with an unspecified type and
 * sets it to @id.
 */
void
lu_value_init_set_id(GValue *value, id_t id)
{
	/* Don't unnecessarily change behavior when long is enough. Only when
	   long isn't enough, we fail in more interesting ways instead of
	   silently corrupting data.

	   The (intmax_t) casts are needed to handle the (Linux) case when id_t
	   is "unsigned long', otherwise the comparison would be
	   (unsigned long)(long)id == id, which is always true. */
	if ((intmax_t)(long)id == (intmax_t)id) {
		g_value_init(value, G_TYPE_LONG);
		g_value_set_long(value, id);
	} else {
		/* FIXME: check that int64 is enough */
		g_value_init(value, G_TYPE_INT64);
		g_value_set_int64(value, id);
	}
}

/**
 * lu_value_get_id:
 * @value: #GValue
 *
 * Get the contents of @value. @value should be initialized by
 * lu_value_init_set_id() or use %G_TYPE_LONG or %G_TYPE_STRING.
 *
 * If @value does not contain a valid #id_t value, %LU_VALUE_INVALID_ID
 * is returned.
 *
 * Returns: ID value or %LU_VALUE_INVALID_ID
 */
id_t
lu_value_get_id(const GValue *value)
{
	long long val;

	if (G_VALUE_HOLDS_LONG(value))
		val = g_value_get_long(value);
	else if (G_VALUE_HOLDS_INT64(value))
		val = g_value_get_int64(value);
	else if (G_VALUE_HOLDS_STRING(value)) {
		const char *src;
		char *end;

		src = g_value_get_string(value);
		errno = 0;
		val = strtoll(src, &end, 10);
		if (errno != 0 || *end != 0 || end == src)
			g_return_val_if_reached(LU_VALUE_INVALID_ID);
	} else
		g_return_val_if_reached(LU_VALUE_INVALID_ID);
	g_return_val_if_fail((id_t)val == val, LU_VALUE_INVALID_ID);
	g_return_val_if_fail(val != LU_VALUE_INVALID_ID, LU_VALUE_INVALID_ID);
	return val;
}

/* Check whether NAME is within LIST, which is a NUL-separated sequence of
   strings, terminated by double NUL. */
static gboolean
attr_in_list(const char *attr, const char *list)
{
	size_t attr_len;

	attr_len = strlen(attr);
	while (*list != '\0') {
		size_t s_len;

		s_len = strlen(list);
		if (attr_len == s_len && strcmp(attr, list) == 0)
			return TRUE;
		list += s_len + 1;
	}
	return FALSE;
}

/**
 * lu_value_init_set_attr_from_string:
 * @value: #GValue
 * @attr: Attribute name
 * @string: The string to convert
 * @error: Filled with a #lu_error if an error occurs, or %NULL if @attr is
 * unknown
 *
 * Initializes a zero-filled (uninitialized) @value for storing a value of
 * attribute @attr and sets it to the contents of @string.  To see whether a
 * specific type is used for an attribute, see the documentation of that
 * attribute.
 *
 * The error messages returned from this function don't contain the input
 * string, to allow the caller to output at least partially usable error
 * message without disclosing the invalid string in
 * e.g. <filename>/etc/shadow</filename>, which might be somebody's misplaced
 * password.
 *
 * Returns: %TRUE on success, %FALSE on error or if @attr is unknown
 */
gboolean
lu_value_init_set_attr_from_string(GValue *value, const char *attr,
				   const char *string, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
#define A(NAME) NAME "\0"
	if (attr_in_list(attr, A(LU_USERNAME) A(LU_USERPASSWORD) A(LU_GECOS)
			 A(LU_HOMEDIRECTORY) A(LU_LOGINSHELL) A(LU_GROUPNAME)
			 A(LU_GROUPPASSWORD) A(LU_MEMBERNAME)
			 A(LU_ADMINISTRATORNAME) A(LU_SHADOWNAME)
			 A(LU_SHADOWPASSWORD) A(LU_COMMONNAME) A(LU_GIVENNAME)
			 A(LU_SN) A(LU_ROOMNUMBER) A(LU_TELEPHONENUMBER)
			 A(LU_HOMEPHONE) A(LU_EMAIL))) {
		g_value_init(value, G_TYPE_STRING);
		g_value_set_string(value, string);
	} else if (attr_in_list(attr, A(LU_SHADOWLASTCHANGE) A(LU_SHADOWMIN)
				A(LU_SHADOWMAX) A(LU_SHADOWWARNING)
				A(LU_SHADOWINACTIVE) A(LU_SHADOWEXPIRE)
				A(LU_SHADOWFLAG))) {
		long l;
		char *p;

		errno = 0;
		l = strtol(string, &p, 10);
		if (errno != 0 || *p != 0 || p == string) {
			lu_error_new(error, lu_error_invalid_attribute_value,
				     _("invalid number"));
			return FALSE;
		}
		g_value_init(value, G_TYPE_LONG);
		g_value_set_long(value, l);
	} else if (attr_in_list(attr, A(LU_UIDNUMBER) A(LU_GIDNUMBER))) {
		intmax_t imax;
		char *p;

		errno = 0;
		imax = strtoimax(string, &p, 10);
		if (errno != 0 || *p != 0 || p == string
		    || (id_t)imax != imax || imax == LU_VALUE_INVALID_ID) {
			lu_error_new(error, lu_error_invalid_attribute_value,
				     _("invalid ID"));
			return FALSE;
		}
		lu_value_init_set_id(value, imax);
	} else {
		*error = NULL;
		return FALSE;
	}
#undef A
	return TRUE;
}

/**
 * lu_set_prompter:
 * @context: A context
 * @prompter: A new function to user for getting information from the user
 * @callback_data: Data for @prompter
 *
 * Changes the prompter function in a context
 */
void
lu_set_prompter(struct lu_context *context, lu_prompt_fn * prompter,
		gpointer prompter_data)
{
	g_assert(prompter != NULL);
	context->prompter = prompter;
	context->prompter_data = prompter_data;
}

/**
 * lu_get_prompter:
 * @context: A context
 * @prompter: If not %NULL, points to a place where the current prompter
 * function will be stored
 * @callback_data: If not %NULL, points to a place where the current prompter
 * function data will be stored
 *
 * Gets current prompter function from a context.
 */
void
lu_get_prompter(struct lu_context *context, lu_prompt_fn **prompter,
		gpointer *prompter_data)
{
	if (prompter != NULL) {
		*prompter = context->prompter;
	}
	if (prompter_data != NULL) {
		*prompter_data = context->prompter_data;
	}
}

/**
 * lu_set_modules:
 * @context: A context
 * @list: A list of modules (separated by whitespace or commas)
 * @error: Filled with a #lu_error if an error occurs
 *
 * Replaces the current set of modules for queries in @context to @list.
 *
 * Returns: %TRUE on success, %FALSE on failure
 */
gboolean
lu_set_modules(struct lu_context * context, const char *list,
	       struct lu_error ** error)
{
	return lu_modules_load(context, list, &context->module_names, error);
}

/**
 * lu_get_modules:
 * @context: A context
 *
 * Returns a list of modules for queries in @context.
 *
 * Returns: A list of modules separated by spaces, or %NULL if the list of
 * modules is empty.  The list should not be freed by the caller.
 */
const char *
lu_get_modules(struct lu_context *context)
{
	char *tmp = NULL, *ret = NULL;
	size_t i;

	for (i = 0; i < context->module_names->n_values; i++) {
		GValue *value;

		value = g_value_array_get_nth(context->module_names, i);
		if (tmp) {
			char *p;
			p = g_strconcat(tmp, " ",
					g_value_get_string(value), NULL);
			g_free(tmp);
			tmp = p;
		} else {
			tmp = g_value_dup_string(value);
		}
	}

	if (tmp) {
		ret = context->scache->cache(context->scache, tmp);
		g_free(tmp);
	}

	return ret;
}
