/*
 * Copyright (C) 2000-2002, 2005, 2007 Red Hat, Inc.
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

/* gtkdoc: private_header */

#ifndef internal_h
#define internal_h

#include <glib.h>
#include <glib-object.h>

struct lu_ent;
struct lu_error;
struct lu_context;

/* An internal attribute checked (and removed) only in lu_user_add(), contains
   a default LU_HOMEDIRECTORY value that we refuse to use.  In that case,
   LU_HOMEDIRECTORY is not set by default, and exists only if the user has
   explicitly defined it. */
#define LU_DUBIOUS_HOMEDIRECTORY "__pw_dir_invalid!*/\\:"

/* Configuration initialization and shutdown. */
gboolean lu_cfg_init(struct lu_context *context, struct lu_error **error)
	G_GNUC_INTERNAL;
void lu_cfg_done(struct lu_context *context) G_GNUC_INTERNAL;

/* Set the sources of record for a given entity structure. */
void lu_ent_add_module(struct lu_ent *ent, const char *source) G_GNUC_INTERNAL;
void lu_ent_clear_modules(struct lu_ent *ent) G_GNUC_INTERNAL;

gboolean lu_modules_load(struct lu_context *ctx, const char *module_list,
			 GValueArray **names, struct lu_error **error)
	G_GNUC_INTERNAL;
int lu_module_unload(gpointer key, gpointer value, gpointer data)
	G_GNUC_INTERNAL;

gint lu_strcasecmp(gconstpointer v1, gconstpointer v2) G_GNUC_INTERNAL;
gint lu_strcmp(gconstpointer v1, gconstpointer v2) G_GNUC_INTERNAL;

long lu_util_shadow_current_date_or_minus_1(void) G_GNUC_INTERNAL;

/* Only for compatibility with shadow. */
time_t lu_get_date(const char *, const time_t *) G_GNUC_INTERNAL;

#endif
