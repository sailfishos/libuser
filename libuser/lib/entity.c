/*
 * Copyright (C) 2000-2002, 2004, 2005 Red Hat, Inc.
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
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "user_private.h"
#include "internal.h"

/**
 * SECTION:entity
 * @short_description: Functions for manipulating #lu_ent structures.
 * @include: libuser/error.h
 *
 * <filename>entity.h</filename> declares functions for manipulating #lu_ent
 * structures, which are used by libuser, its modules, and applications to hold
 * data about a particular user or group account.
 */


/**
 * lu_ent_new:
 *
 * Creates a new, empty struct #lu_ent.
 *
 * Returns: The created entity, which should be deallocated by lu_ent_free()
 */
struct lu_ent *
lu_ent_new()
{
	struct lu_ent *ent;

	ent = g_malloc0(sizeof(struct lu_ent));
	ent->magic = LU_ENT_MAGIC;
	ent->cache = lu_string_cache_new(TRUE);
	ent->current = g_array_new(FALSE, TRUE, sizeof(struct lu_attribute));
	ent->pending = g_array_new(FALSE, TRUE, sizeof(struct lu_attribute));
	ent->modules = g_value_array_new(1);
	return ent;
}

struct lu_ent *
lu_ent_new_typed(enum lu_entity_type entity_type)
{
	struct lu_ent *ret;
	ret = lu_ent_new();
	ret->type = entity_type;
	return ret;
}

/**
 * lu_ent_free:
 * @ent: The entity to free
 *
 * Frees an struct #lu_ent, including all strings it owns.
 */
void
lu_ent_free(struct lu_ent *ent)
{
	size_t i;
	struct lu_attribute *attr;
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	/* Free the cache. */
	ent->cache->free(ent->cache);
	/* Free each current attribute. */
	for (i = 0; i < ent->current->len; i++) {
		attr = &g_array_index(ent->current, struct lu_attribute, i);
		/* Free the values array in this attribute; the array free
		 * will get the rest. */
		g_value_array_free(attr->values);
		attr->name = 0;
		attr->values = NULL;
	}
	g_array_free(ent->current, TRUE);
	/* Free each pending attribute. */
	for (i = 0; i < ent->pending->len; i++) {
		attr = &g_array_index(ent->pending, struct lu_attribute, i);
		/* Free the values array in this attribute; the array free
		 * will get the rest. */
		g_value_array_free(attr->values);
		attr->name = 0;
		attr->values = NULL;
	}
	g_array_free(ent->pending, TRUE);
	/* Free the module list. */
	g_value_array_free(ent->modules);
	memset(ent, 0, sizeof(struct lu_ent));
	g_free(ent);
}

/* Dump a set of attributes */
static void
lu_ent_dump_attributes(GArray *attrs, FILE *fp)
{
	size_t i;

	for (i = 0; i < attrs->len; i++) {
		struct lu_attribute *attribute;
		size_t j;

		attribute = &g_array_index(attrs, struct lu_attribute, i);
		for (j = 0; j < attribute->values->n_values; j++) {
			GValue *value;

			value = g_value_array_get_nth(attribute->values, j);
			fprintf(fp, " %s = ",
				g_quark_to_string(attribute->name));
			if (G_VALUE_HOLDS_STRING(value))
				fprintf(fp, "`%s'\n",
					g_value_get_string(value));
			else if (G_VALUE_HOLDS_LONG(value))
				fprintf(fp, "%ld\n", g_value_get_long(value));
			else if (G_VALUE_HOLDS_INT64(value))
				fprintf(fp, "%lld\n",
					(long long)g_value_get_int64(value));
			else
				fprintf(fp, "???\n");
		}
	}
}

/**
 * lu_ent_dump:
 * @ent: The entity to dump
 * @fp: Destination file
 *
 * Dumps a struct #lu_ent to a file in text form, for debugging.
 */
void
lu_ent_dump(struct lu_ent *ent, FILE *fp)
{
	size_t i;

	g_return_if_fail(ent != NULL);
	fprintf(fp, "dump of struct lu_ent at %p:\n", ent);
	fprintf(fp, " magic = %08x\n", ent->magic);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail((ent->type == lu_user) || (ent->type == lu_group));
	switch (ent->type) {
		case lu_invalid:
			fprintf(fp, " type = invalid\n");
			break;
		case lu_user:
			fprintf(fp, " type = user\n");
			break;
		case lu_group:
			fprintf(fp, " type = group\n");
			break;
		default:
			fprintf(fp, " type = UNKNOWN\n");
			break;
	}
	/* Print the module list. */
	fprintf(fp, " modules = (");
	for (i = 0; i < ent->modules->n_values; i++) {
		GValue *value;

		value = g_value_array_get_nth(ent->modules, i);
		if (i > 0)
			fprintf(fp, ", ");
		if (G_VALUE_HOLDS_STRING(value))
			fprintf(fp, "`%s'", g_value_get_string(value));
		else
			fprintf(fp, "?");
	}
	fprintf(fp, ")\n");
	/* Print the current data values. */
	lu_ent_dump_attributes(ent->current, fp);
	fprintf(fp, "\n");
	lu_ent_dump_attributes(ent->pending, fp);
}

/* Add a module to the list of modules kept for this entity. */
void
lu_ent_add_module(struct lu_ent *ent, const char *source)
{
	size_t i;

	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(ent->modules != NULL);
	for (i = 0; i < ent->modules->n_values; i++) {
		GValue *val;

		val = g_value_array_get_nth(ent->modules, i);
		/* We only add strings, so there had better be only strings
		 * in this list, otherwise someone is messing with us. */
		g_assert(G_VALUE_HOLDS_STRING(val));
		if (strcmp(g_value_get_string(val), source) == 0)
			break;
	}
	/* If we fell of the end of the array, then the new value is not
	 * in there, so we should add it. */
	if (i >= ent->modules->n_values) {
		GValue value;

		/* Initialize a value with the string. */
		memset(&value, 0, sizeof(value));
		g_value_init(&value, G_TYPE_STRING);
		g_value_set_string(&value, source);
		g_value_array_append(ent->modules, &value);
		g_value_unset(&value);
	}
}

/* Clear the list of modules which affect this module, by freeing the array
 * we use to keep track of them and allocating a new one. */
void
lu_ent_clear_modules(struct lu_ent *ent)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_value_array_free(ent->modules);
	ent->modules = g_value_array_new(1);
}

/* Remove all attributes from an object.  This function takes the address
 * of whichever list we want cleared. */
static void
clear_attribute_list(GArray *dest)
{
	int i;

	for (i = dest->len - 1; i >= 0; i--) {
		struct lu_attribute *attr;

		attr = &g_array_index(dest, struct lu_attribute, i);
		g_value_array_free(attr->values);
		attr->values = NULL;
		g_array_remove_index_fast(dest, i);
	}
}

/* Copy all attributes from source to dest, wiping out whatever was already
 * in the destination array. */
static void
copy_attributes(GArray *source, GArray *dest)
{
	size_t i;

	/* First, clear the destination list of all attributes. */
	clear_attribute_list(dest);
	/* Now copy all of the attributes and their values. */
	for (i = 0; i < source->len; i++) {
		struct lu_attribute *attr, newattr;

		attr = &g_array_index(source, struct lu_attribute, i);
		/* Copy the attribute name, then its values, into the holding
		 * area. */
		memset(&newattr, 0, sizeof(newattr));
		newattr.name = attr->name;
		newattr.values = g_value_array_copy(attr->values);
		/* Now append the attribute to the array. */
		g_array_append_val(dest, newattr);
	}
}

/**
 * lu_ent_revert:
 * @ent: an entity
 *
 * Replaces all attributes with changes pending by their current values,
 * forgetting the pending changes.
 */
void
lu_ent_revert(struct lu_ent *entity)
{
	copy_attributes(entity->current, entity->pending);
}

/**
 * lu_ent_commit:
 * @ent: An entity
 *
 * Sets pending attribute changes as current values of the entity.
 */
void
lu_ent_commit(struct lu_ent *entity)
{
	copy_attributes(entity->pending, entity->current);
}

/**
 * lu_ent_copy:
 * @source: The entity to copy
 * @dest: The destination space, must be already allocated by lu_ent_new()
 *
 * Copies one struct #lu_ent over another.
 */
void
lu_ent_copy(struct lu_ent *source, struct lu_ent *dest)
{
	g_return_if_fail(source != NULL);
	g_return_if_fail(dest != NULL);
	g_return_if_fail(source->magic == LU_ENT_MAGIC);
	g_return_if_fail(dest->magic == LU_ENT_MAGIC);
	dest->type = source->type;
	copy_attributes(source->current, dest->current);
	copy_attributes(source->pending, dest->pending);
	g_value_array_free(dest->modules);
	dest->modules = g_value_array_copy(source->modules);
}

/* Return a GQark for lower-cased attribute */
static GQuark
quark_from_attribute(const char *attribute)
{
	GQuark quark;
	char *lower;

	lower = g_ascii_strdown(attribute, -1);
	quark = g_quark_from_string(lower);
	g_free(lower);
	return quark;
}

static GValueArray *
lu_ent_get_int(GArray *list, const char *attribute)
{
	GQuark aquark;
	size_t i;

	g_return_val_if_fail(list != NULL, NULL);
	g_return_val_if_fail(attribute != NULL, NULL);
	g_return_val_if_fail(strlen(attribute) > 0, NULL);
	aquark = quark_from_attribute(attribute);
	for (i = 0; i < list->len; i++) {
		struct lu_attribute *attr;

		attr = &g_array_index(list, struct lu_attribute, i);
		if (attr != NULL) {
			if (attr->name == aquark) {
				g_assert(attr->values != NULL);
				g_assert(attr->values->n_values > 0);
				return attr->values;
			}
		}
	}
	return NULL;
}

/* Return a read-only pointer to the first string value of ATTRIBUTE in LIST
   if any, or NULL if ATTRIBUTE doesn't exist or on error. */
static const char *
lu_ent_get_first_string_int(GArray *list, const char *attribute)
{
	GValueArray *vals;
	GValue *v;

	vals = lu_ent_get_int(list, attribute);
	if (vals == NULL)
		return NULL;
	v = g_value_array_get_nth(vals, 0);
	if (!G_VALUE_HOLDS_STRING(v))
		return NULL;
	return g_value_get_string(v);
}

/* Return a string representation of the first value of ATTRIBUTE in LIST if
   any, or NULL if ATTRIBUTE doesn't exist or on error.

   The caller should call g_free() on the result. */
static char *
lu_ent_get_first_value_strdup_int(GArray *list, const char *attribute)
{
	GValueArray *vals;

	vals = lu_ent_get_int(list, attribute);
	if (vals == NULL)
		return NULL;
	return lu_value_strdup(g_value_array_get_nth(vals, 0));
}

/* Return an id_t contents of the first value of ATTRIBUTE in LIST if any,
   or LU_VALUE_INVALID_ID if ATTRIBUTE doesn't exist or on error. */
static id_t
lu_ent_get_first_id_int(GArray *list, const char *attribute)
{
	GValueArray *vals;

	vals = lu_ent_get_int(list, attribute);
	if (vals == NULL)
		return LU_VALUE_INVALID_ID;
	return lu_value_get_id(g_value_array_get_nth(vals, 0));
}

static gboolean
lu_ent_has_int(GArray *list, const char *attribute)
{
	g_return_val_if_fail(list != NULL, FALSE);
	g_return_val_if_fail(attribute != NULL, FALSE);
	g_return_val_if_fail(strlen(attribute) > 0, FALSE);
	return (lu_ent_get_int(list, attribute) != NULL) ? TRUE : FALSE;
}

static void
lu_ent_clear_int(GArray *list, const char *attribute)
{
	int i;
	struct lu_attribute *attr = NULL;
	GQuark aquark;

	g_return_if_fail(list != NULL);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	aquark = quark_from_attribute(attribute);
	for (i = list->len - 1; i >= 0; i--) {
		attr = &g_array_index(list, struct lu_attribute, i);
		if (attr->name == aquark)
			break;
	}
	if (i >= 0) {
		g_value_array_free(attr->values);
		attr->values = NULL;
		g_array_remove_index(list, i);
	}
}

/* Delete all existing values of ATTR in LIST and return a GValueArray to which
   new values should be appended. */
static GValueArray *
lu_ent_set_prepare(GArray *list, const char *attr)
{
	GValueArray *dest;

	dest = lu_ent_get_int(list, attr);
	if (dest == NULL) {
		struct lu_attribute newattr;

		memset(&newattr, 0, sizeof(newattr));
		newattr.name = quark_from_attribute(attr);
		newattr.values = g_value_array_new(0);
		dest = newattr.values;
		g_array_append_val(list, newattr);
	}
	while (dest->n_values > 0)
		g_value_array_remove(dest, dest->n_values - 1);
	return dest;
}

static void
lu_ent_set_int(GArray *list, const char *attr, const GValueArray *values)
{
	GValueArray *dest, *copy;

	g_return_if_fail(list != NULL);
	g_return_if_fail(attr != NULL);
	g_return_if_fail(strlen(attr) > 0);
	if (values->n_values == 0) {
		lu_ent_clear_int(list, attr);
		return;
	}
	dest = lu_ent_set_prepare(list, attr);
	copy = g_value_array_copy(values);
	lu_util_append_values(dest, copy);
	g_value_array_free(copy);
}

/* Replace current value of ATTR in LIST with a single string VALUE */
static void
lu_ent_set_string_int(GArray *list, const char *attr, const char *value)
{
	GValueArray *dest;
	GValue v;

	g_return_if_fail(list != NULL);
	g_return_if_fail(attr != NULL);
	g_return_if_fail(strlen(attr) > 0);
	g_return_if_fail(value != NULL);
	dest = lu_ent_set_prepare(list, attr);

	memset(&v, 0, sizeof(v));
	g_value_init(&v, G_TYPE_STRING);
	g_value_set_string(&v, value);
	g_value_array_append(dest, &v);
	g_value_unset(&v);
}

/* Replace current value of ATTR in LIST with a single id_t VALUE */
static void
lu_ent_set_id_int(GArray *list, const char *attr, id_t value)
{
	GValueArray *dest;
	GValue v;

	g_return_if_fail(list != NULL);
	g_return_if_fail(attr != NULL);
	g_return_if_fail(strlen(attr) > 0);
	g_return_if_fail(value != LU_VALUE_INVALID_ID);
	dest = lu_ent_set_prepare(list, attr);

	memset(&v, 0, sizeof(v));
	lu_value_init_set_id(&v, value);
	g_value_array_append(dest, &v);
	g_value_unset(&v);
}

/* Replace current value of ATTR in LIST with a single long VALUE */
static void
lu_ent_set_long_int(GArray *list, const char *attr, long value)
{
	GValueArray *dest;
	GValue v;

	g_return_if_fail(list != NULL);
	g_return_if_fail(attr != NULL);
	g_return_if_fail(strlen(attr) > 0);
	dest = lu_ent_set_prepare(list, attr);

	memset(&v, 0, sizeof(v));
	g_value_init(&v, G_TYPE_LONG);
	g_value_set_long(&v, value);
	g_value_array_append(dest, &v);
	g_value_unset(&v);
}

static void
lu_ent_add_int(GArray *list, const char *attr, const GValue *value)
{
	GValueArray *dest;
	size_t i;

	g_return_if_fail(list != NULL);
	g_return_if_fail(value != NULL);
	g_return_if_fail(attr != NULL);
	g_return_if_fail(strlen(attr) > 0);
	dest = lu_ent_get_int(list, attr);
	if (dest == NULL) {
		struct lu_attribute newattr;

		memset(&newattr, 0, sizeof(newattr));
		newattr.name = quark_from_attribute(attr);
		newattr.values = g_value_array_new(1);
		dest = newattr.values;
		g_array_append_val(list, newattr);
	}
	for (i = 0; i < dest->n_values; i++) {
		GValue *current;

		current = g_value_array_get_nth(dest, i);
		if (G_VALUE_TYPE(value) == G_VALUE_TYPE(current)
		    && lu_values_equal(value, current))
			break;
	}
	if (i >= dest->n_values)
		g_value_array_append(dest, value);
}

static void
lu_ent_clear_all_int(GArray *list)
{
	clear_attribute_list(list);
}

static void
lu_ent_del_int(GArray *list, const char *attr, const GValue *value)
{
	GValueArray *dest;
	size_t i;
	g_return_if_fail(list != NULL);
	g_return_if_fail(value != NULL);
	g_return_if_fail(attr != NULL);
	g_return_if_fail(strlen(attr) > 0);
	dest = lu_ent_get_int(list, attr);
	if (dest != NULL) {
		for (i = 0; i < dest->n_values; i++) {
			GValue *tvalue;

			tvalue = g_value_array_get_nth(dest, i);
			if (G_VALUE_TYPE(value) == G_VALUE_TYPE(tvalue)
			    && lu_values_equal(value, tvalue))
				break;
		}
		if (i < dest->n_values) {
			g_value_array_remove(dest, i);
			if (dest->n_values == 0)
				lu_ent_clear_int(list, attr);
		}
	}
}

static GList *
lu_ent_get_attributes_int(GArray *list)
{
	size_t i;
	GList *ret = NULL;
	g_return_val_if_fail(list != NULL, NULL);
	for (i = 0; i < list->len; i++) {
		struct lu_attribute *attr;

		attr = &g_array_index(list, struct lu_attribute, i);
		ret = g_list_prepend(ret, (char*)g_quark_to_string(attr->name));
	}
	return g_list_reverse(ret);
}

/**
 * lu_ent_get:
 * @ent: An entity
 * @attribute: Attribute name
 *
 * Returns values associated with a pending attribute in a struct #lu_ent.
 *
 * Returns: a #GValueArray of values, valid at least until they are modified or
 * deleted. The array is never empty and it should not be freed by the caller.
 * Returns %NULL if the attribute is not present at all or on error.
 */
GValueArray *
lu_ent_get(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	g_return_val_if_fail(attribute != NULL, NULL);
	g_return_val_if_fail(strlen(attribute) > 0, NULL);
	return lu_ent_get_int(ent->pending, attribute);
}
/**
 * lu_ent_get_current:
 * @ent: An entity
 * @attribute: Attribute name
 *
 * Returns values associated with a current attribute in a struct #lu_ent.
 *
 * Returns: a #GValueArray of values, valid at least until they are modified or
 * deleted. The array is never empty and it should not be freed by the caller.
 * Returns %NULL if the attribute is not present at all or on error.
 */
GValueArray *
lu_ent_get_current(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	g_return_val_if_fail(attribute != NULL, NULL);
	g_return_val_if_fail(strlen(attribute) > 0, NULL);
	return lu_ent_get_int(ent->current, attribute);
}

/**
 * lu_ent_get_first_string:
 * @ent: An entity
 * @attribute: Attribute name
 *
 * Returns the first string associated with a pending attribute in a struct
 * #lu_ent.
 *
 * Returns: a string pointer valid at least the value is modified or deleted if
 * the attribute is present and the first value is a string.  Returns %NULL if
 * the attribute is not present, the first value is not a string, or on error.
 */
const char *
lu_ent_get_first_string(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	g_return_val_if_fail(attribute != NULL, NULL);
	g_return_val_if_fail(strlen(attribute) > 0, NULL);
	return lu_ent_get_first_string_int(ent->pending, attribute);
}
/**
 * lu_ent_get_first_string_current:
 * @ent: An entity
 * @attribute: Attribute name
 *
 * Returns the first string associated with a current attribute in a struct
 * #lu_ent.
 *
 * Returns: a string pointer valid at least the value is modified or deleted if
 * the attribute is present and the first value is a string.  Returns %NULL if
 * the attribute is not present, the first value is not a string, or on error.
 */
const char *
lu_ent_get_first_string_current(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	g_return_val_if_fail(attribute != NULL, NULL);
	g_return_val_if_fail(strlen(attribute) > 0, NULL);
	return lu_ent_get_first_string_int(ent->current, attribute);
}

/**
 * lu_ent_get_first_value_strdup:
 * @ent: An entity
 * @attribute: Attribute name
 *
 * Returns a string representation (as if by lu_value_strdup()) of the first
 * value associated with a pending attribute in a struct #lu_ent.
 *
 * Returns: a string, should be freed by g_free() if the attribute is present.
 * Returns %NULL if the attribute is not present or on error.
 */
char *
lu_ent_get_first_value_strdup(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	g_return_val_if_fail(attribute != NULL, NULL);
	g_return_val_if_fail(strlen(attribute) > 0, NULL);
	return lu_ent_get_first_value_strdup_int(ent->pending, attribute);
}
/**
 * lu_ent_get_first_value_strdup_current:
 * @ent: An entity
 * @attribute: Attribute name
 *
 * Returns a string representation (as if by lu_value_strdup()) of the first
 * value associated with a current attribute in a struct #lu_ent.
 *
 * Returns: a string, should be freed by g_free() if the attribute is present.
 * Returns %NULL if the attribute is not present or on error.
 */
char *
lu_ent_get_first_value_strdup_current(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	g_return_val_if_fail(attribute != NULL, NULL);
	g_return_val_if_fail(strlen(attribute) > 0, NULL);
	return lu_ent_get_first_value_strdup_int(ent->current, attribute);
}

/**
 * lu_ent_get_first_id:
 * @ent: An entity
 * @attribute: Attribute name
 *
 * Returns the first #id_t value associated with a pending attribute in a struct
 * #lu_ent.
 *
 * Returns: ID value the attribute is present and can be converted into #id_t.
 * Returns %LU_VALUE_INVALID_ID if the attribute is not present, the first
 * value cannot be converted, or on error.
 */
id_t
lu_ent_get_first_id(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, LU_VALUE_INVALID_ID);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, LU_VALUE_INVALID_ID);
	g_return_val_if_fail(attribute != NULL, LU_VALUE_INVALID_ID);
	g_return_val_if_fail(strlen(attribute) > 0, LU_VALUE_INVALID_ID);
	return lu_ent_get_first_id_int(ent->pending, attribute);
}
/**
 * lu_ent_get_first_id_current:
 * @ent: An entity
 * @attribute: Attribute name
 *
 * Returns the first #id_t value associated with a current attribute in a struct
 * #lu_ent.
 *
 * Returns: ID value the attribute is present and can be converted into #id_t.
 * Returns %LU_VALUE_INVALID_ID if the attribute is not present, the first
 * value cannot be converted, or on error.
 */
id_t
lu_ent_get_first_id_current(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, LU_VALUE_INVALID_ID);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, LU_VALUE_INVALID_ID);
	g_return_val_if_fail(attribute != NULL, LU_VALUE_INVALID_ID);
	g_return_val_if_fail(strlen(attribute) > 0, LU_VALUE_INVALID_ID);
	return lu_ent_get_first_id_int(ent->current, attribute);
}

/**
 * lu_ent_has:
 * @ent: An entity
 * @attribute: Attribute name
 *
 * Checks if a struct #lu_ent has at least one pending attribute @attribute.
 *
 * Returns: %TRUE if @attribute has a value in @ent.
 */
gboolean
lu_ent_has(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	g_return_val_if_fail(attribute != NULL, FALSE);
	g_return_val_if_fail(strlen(attribute) > 0, FALSE);
	return lu_ent_has_int(ent->pending, attribute);
}
/**
 * lu_ent_has_current:
 * @ent: An entity
 * @attribute: Attribute name
 *
 * Checks if a struct #lu_ent has at least one current attribute @attribute.
 *
 * Returns: %TRUE if @attribute has a value in @ent.
 */
gboolean
lu_ent_has_current(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	g_return_val_if_fail(attribute != NULL, FALSE);
	g_return_val_if_fail(strlen(attribute) > 0, FALSE);
	return lu_ent_has_int(ent->current, attribute);
}

/**
 * lu_ent_set:
 * @ent: An entity
 * @attr: Attribute name
 * @values: An array of values
 *
 * Replaces all pending attributes @attr in a struct #lu_ent by a copy of
 * @values.  If @values is empty, it removes the pending attribute completely.
 */
void
lu_ent_set(struct lu_ent *ent, const char *attribute, const GValueArray *values)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	lu_ent_set_int(ent->pending, attribute, values);
}
/**
 * lu_ent_set_current:
 * @ent: An entity
 * @attr: Attribute name
 * @values: An array of values
 *
 * Replaces all current attributes @attr in a struct #lu_ent by a copy of
 * @values.  If @values is empty, it removes the pending attribute completely.
 */
void
lu_ent_set_current(struct lu_ent *ent, const char *attribute,
		   const GValueArray *values)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	lu_ent_set_int(ent->current, attribute, values);
}

/**
 * lu_ent_set_string:
 * @ent: An entity
 * @attr: Attribute name
 * @value: A string
 *
 * Replaces all pending attributes @attr in a struct #lu_ent by a copy of
 * string @value.
 */
void
lu_ent_set_string(struct lu_ent *ent, const char *attribute, const char *value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	g_return_if_fail(value != NULL);
	lu_ent_set_string_int(ent->pending, attribute, value);
}
/**
 * lu_ent_set_string_current:
 * @ent: An entity
 * @attr: Attribute name
 * @value: A string
 *
 * Replaces all current attributes @attr in a struct #lu_ent by a copy of
 * string @value.
 */
void
lu_ent_set_string_current(struct lu_ent *ent, const char *attribute,
			  const char *value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	g_return_if_fail(value != NULL);
	lu_ent_set_string_int(ent->current, attribute, value);
}

/**
 * lu_ent_set_id:
 * @ent: An entity
 * @attr: Attribute name
 * @value: An #id_t value
 *
 * Replaces all pending attributes @attr in a struct #lu_ent by an id_t @value.
 */
void
lu_ent_set_id(struct lu_ent *ent, const char *attribute, id_t value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	g_return_if_fail(value != LU_VALUE_INVALID_ID);
	lu_ent_set_id_int(ent->pending, attribute, value);
}
/**
 * lu_ent_set_id_current:
 * @ent: An entity
 * @attr: Attribute name
 * @value: An #id_t value
 *
 * Replaces all current attributes @attr in a struct #lu_ent by an id_t @value.
 */
void
lu_ent_set_id_current(struct lu_ent *ent, const char *attribute, id_t value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	g_return_if_fail(value != LU_VALUE_INVALID_ID);
	lu_ent_set_id_int(ent->current, attribute, value);
}

/**
 * lu_ent_set_long:
 * @ent: An entity
 * @attr: Attribute name
 * @value: A value
 *
 * Replaces all pending attributes @attr in a struct #lu_ent by a long @value.
 */
void
lu_ent_set_long(struct lu_ent *ent, const char *attribute, long value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	lu_ent_set_long_int(ent->pending, attribute, value);
}
/**
 * lu_ent_set_long_current:
 * @ent: An entity
 * @attr: Attribute name
 * @value: A value
 *
 * Replaces all current attributes @attr in a struct #lu_ent by a long @value.
 */
void
lu_ent_set_long_current(struct lu_ent *ent, const char *attribute, long value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	lu_ent_set_long_int(ent->current, attribute, value);
}

/**
 * lu_ent_add:
 * @ent: An entity
 * @attr: Attribute name
 * @value: New attribute value
 *
 * Appends @value to pending attribute @attr in a struct #lu_ent if @value is
 * not yet in the list of @attr values.
 */
void
lu_ent_add(struct lu_ent *ent, const char *attribute, const GValue *value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	lu_ent_add_int(ent->pending, attribute, value);
}
/**
 * lu_ent_add_current:
 * @ent: An entity
 * @attr: Attribute name
 * @value: New attribute value
 *
 * Appends @value to current attribute @attr in a struct #lu_ent if @value is
 * not yet in the list of @attr values.
 */
void
lu_ent_add_current(struct lu_ent *ent, const char *attribute,
		   const GValue *value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	lu_ent_add_int(ent->current, attribute, value);
}

/**
 * lu_ent_clear:
 * @ent: An entity
 * @attr: Attribute name
 *
 * Removes all values of pending attribute @attribute from a struct #lu_ent.
 */
void
lu_ent_clear(struct lu_ent *ent, const char *attribute)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	lu_ent_clear_int(ent->pending, attribute);
}
/**
 * lu_ent_clear_current:
 * @ent: An entity
 * @attr: Attribute name
 *
 * Removes all values of current attribute @attribute from a struct #lu_ent.
 */
void
lu_ent_clear_current(struct lu_ent *ent, const char *attribute)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	lu_ent_clear_int(ent->current, attribute);
}

/**
 * lu_ent_clear_all:
 * @ent: an entity
 *
 * Removes all pending attributes from a struct #lu_ent.
 */
void
lu_ent_clear_all(struct lu_ent *ent)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	lu_ent_clear_all_int(ent->pending);
}
/**
 * lu_ent_clear_all_current:
 * @ent: an entity
 *
 * Removes all current attributes from a struct #lu_ent.
 */
void
lu_ent_clear_all_current(struct lu_ent *ent)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	lu_ent_clear_all_int(ent->current);
}

/**
 * lu_ent_del:
 * @ent: An entity
 * @attr: Attribute name
 * @value: Attribute value
 *
 * Removes a pending attribute @attr value @value from a struct #lu_ent, if
 * present.
 */
void
lu_ent_del(struct lu_ent *ent, const char *attribute, const GValue *value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	g_return_if_fail(value != NULL);
	lu_ent_del_int(ent->pending, attribute, value);
}
/**
 * lu_ent_del_current:
 * @ent: An entity
 * @attr: Attribute name
 * @value: Attribute value
 *
 * Removes a current attribute @attr value @value from a struct #lu_ent, if
 * present.
 */
void
lu_ent_del_current(struct lu_ent *ent, const char *attribute,
		   const GValue *value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	g_return_if_fail(value != NULL);
	lu_ent_del_int(ent->current, attribute, value);
}

/**
 * lu_ent_get_attributes:
 * @ent: An entity
 *
 * Returns a list of all pending attributes in a struct #lu_ent.
 *
 * Returns: a #GList of attribute names.  The list (but not the strings in the
 * list) should be freed by the caller.
 */
GList *
lu_ent_get_attributes(struct lu_ent *ent)
{
	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	return lu_ent_get_attributes_int(ent->pending);
}
/**
 * lu_ent_get_attributes_current:
 * @ent: An entity
 *
 * Returns a list of all current attributes in a struct #lu_ent.
 *
 * Returns: a #GList of attribute names.  The list (but not the strings in the
 * list) should be freed by the caller.
 */
GList *
lu_ent_get_attributes_current(struct lu_ent *ent)
{
	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	return lu_ent_get_attributes_int(ent->current);
}
