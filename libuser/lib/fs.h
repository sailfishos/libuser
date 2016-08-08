/*
 * Copyright (C) 2000-2002, 2012 Red Hat, Inc.
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

#ifndef libuser_fs_h
#define libuser_fs_h

#include <sys/types.h>
#include <glib.h>

G_BEGIN_DECLS

struct lu_context;
struct lu_ent;
struct lu_error;

gboolean lu_homedir_populate(struct lu_context *ctx, const char *skeleton,
			     const char *directory, uid_t owner, gid_t group,
			     mode_t mode, struct lu_error **error);
gboolean lu_homedir_move(const char *oldhome, const char *newhome,
			 struct lu_error **error);
gboolean lu_homedir_remove(const char *directory, struct lu_error **error);
gboolean lu_homedir_remove_for_user(struct lu_ent *ent, struct lu_error **error);
gboolean lu_homedir_remove_for_user_if_owned(struct lu_ent *ent,
					     struct lu_error **error);

/**
 * LU_NSCD_CACHE_PASSWD:
 *
 * Name of the NSCD cache containing user data.
 */
#define LU_NSCD_CACHE_PASSWD "passwd"
/**
 * LU_NSCD_CACHE_GROUP:
 *
 * Name of the NSCD cache containing group data.
 */
#define LU_NSCD_CACHE_GROUP "group"

void lu_nscd_flush_cache(const char *table);

gboolean lu_mail_spool_create(struct lu_context *ctx, struct lu_ent *ent,
			      struct lu_error **error);
gboolean lu_mail_spool_remove(struct lu_context *ctx, struct lu_ent *ent,
			      struct lu_error **error);

G_END_DECLS

#endif
