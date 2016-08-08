/*
 * Copyright (C) 2000-2002, 2007 Red Hat, Inc.
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

/*
 * The interfaces defined in this file are in even more flux than the others,
 * because this is where the module interface is defined.  If you include it
 * in your code, bad things can happen.
 */

#ifndef libuser_user_private_h
#define libuser_user_private_h

#include <config.h>
#include <sys/types.h>
#include <glib.h>
#include <gmodule.h>
#include <libintl.h>
#include <locale.h>
#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#endif
#include "user.h"

G_BEGIN_DECLS

#define LU_ENT_MAGIC		0x00000006
#define LU_MODULE_VERSION	0x000e0000
#define _(String)		dgettext(PACKAGE_NAME, String)
#define N_(String)		String
/* A crypt hash is at least 64 bits of data, encoded 6 bits per printable
 * character, and we assume that all crypt algorithms generate strings at
 * least this long. */
#define LU_CRYPTED		"{CRYPT}"
#define LU_CRYPT_SIZE		howmany(64,6)
#define LU_CRYPT_INVALID(String) \
				((strlen(String) > 0) && \
				 (String[0] != '!') && \
				 (strlen(String) < LU_CRYPT_SIZE))

#define LU_COMMON_DEFAULT_PASSWORD		"!!"
#define LU_COMMON_DEFAULT_SHADOW_PASSWORD	"x"
#define LU_COMMON_DEFAULT_SHELL			"/bin/bash"

/* Well-known module names */
#define LU_MODULE_NAME_FILES "files"
#define LU_MODULE_NAME_LDAP "ldap"
#define LU_MODULE_NAME_SHADOW "shadow"

/* A string cache structure.  Useful for side-stepping most issues with
 * whether or not returned strings should be freed. */
struct lu_string_cache {
	GTree *tree;
	char *(*cache) (struct lu_string_cache *, const char *);
	void (*free) (struct lu_string_cache *);
};

/* A function to create a new cache. */
struct lu_string_cache *lu_string_cache_new(gboolean case_sensitive);

struct lu_attribute {
	GQuark name;
	GValueArray *values;
};

/* An entity structure. */
struct lu_ent {
	u_int32_t magic;
	enum lu_entity_type type;	/* User or group? */
	struct lu_string_cache *cache;	/* String cache for attribute values,
					   typically case-sensitive. */
	GArray *current, *pending;	/* Current and pending attribute names
					   and values, stored as a GArray of
					   lu_attribute structures. */
	GValueArray *modules;		/* Names of modules this user's info
					   was looked up in or initialized
					   using. */
};

/* A context structure. */
struct lu_context {
	struct lu_string_cache *scache;	/* A string cache. */
	char *auth_name;		/* Suggested client name to use when
					   connecting to servers, for
					   convenience purposes only. */
	enum lu_entity_type auth_type;	/* Whether auth_name is a user or
					   group. */
	void *config;			/* Opaque config structure used by
					   the lu_cfg family of functions. */
	lu_prompt_fn *prompter;		/* Pointer to the prompter function. */
	gpointer prompter_data;		/* Application-specific data to be
					   passed to the prompter function. */
	GValueArray *module_names;		/* Names of loaded modules. */
	GValueArray *create_module_names;	/* Names of modules to use to
						   create accounts -- usually
						   a subset of all modules. */
	GTree *modules;			/* A tree, keyed by module name,
					   of module structures. */
};

/* A module structure. */
struct lu_module {
	u_int32_t version;		/* Should be LU_MODULE_VERSION. */
	GModule *module_handle;		/* Pointer to the module data kept by
					   GModule. */
	struct lu_string_cache *scache;	/* A string cache. */
	const char *name;		/* Name of the module. */
	struct lu_context *lu_context;	/* Context the module was opened in. */
	void *module_context;		/* Module-private data. */

	/* Check if the current list of module combinations (array of module
	   names) is valid.  Note that this can be called several times during
	   the lifetime of the module (probably at least twice, for "modules"
	   and "create_modules"). */
	gboolean(*valid_module_combination) (struct lu_module *module,
					     GValueArray *names,
					     struct lu_error **error);

	/* A function for telling if the module makes use of elevated
	 * privileges (i.e., modifying files which normal users can't. */
	gboolean(*uses_elevated_privileges) (struct lu_module * module);

	/* Functions for looking up users by name or ID. */
	gboolean(*user_lookup_name) (struct lu_module * module,
				     const char *name,
				     struct lu_ent * ent,
				     struct lu_error ** error);
	gboolean(*user_lookup_id) (struct lu_module * module,
				   uid_t uid,
				   struct lu_ent * ent,
				   struct lu_error ** error);

	/* Populate a user entry with default information. */
	gboolean(*user_default) (struct lu_module * module,
				 const char *name,
				 gboolean is_system,
				 struct lu_ent * ent,
				 struct lu_error ** error);
	/* Make last-minute preparations for adding an account (default
	 * part two, as it might have been called). */
	gboolean(*user_add_prep) (struct lu_module * module,
				  struct lu_ent * ent,
				  struct lu_error ** error);
	/* Create the account. */
	gboolean(*user_add) (struct lu_module * module,
			     struct lu_ent * ent,
			     struct lu_error ** error);
	/* Modify the account, making the data store reflect any pending
	 * data changes. */
	gboolean(*user_mod) (struct lu_module * module,
			     struct lu_ent * ent,
			     struct lu_error ** error);
	/* Remove the account. */
	gboolean(*user_del) (struct lu_module * module,
			     struct lu_ent * ent,
			     struct lu_error ** error);

	/* Lock, unlock, check the status, or set the password on the account
	 * of the user. */
	gboolean(*user_lock) (struct lu_module * module,
			      struct lu_ent * ent,
			      struct lu_error ** error);
	gboolean(*user_unlock) (struct lu_module * module,
				struct lu_ent * ent,
				struct lu_error ** error);
	gboolean(*user_unlock_nonempty) (struct lu_module * module,
					 struct lu_ent * ent,
					 struct lu_error ** error);
	gboolean(*user_is_locked) (struct lu_module * module,
				   struct lu_ent * ent,
				   struct lu_error ** error);
	gboolean(*user_setpass) (struct lu_module * module,
				 struct lu_ent * ent,
				 const char *newpass,
				 struct lu_error ** error);
	gboolean(*user_removepass) (struct lu_module * module,
				    struct lu_ent * ent,
				    struct lu_error ** error);

	/* Search for users, returning the names of all users, just the names
	 * of users in a given group, or all users with their data. */
	GValueArray* (*users_enumerate) (struct lu_module * module,
					 const char *pattern,
					 struct lu_error ** error);
	GValueArray* (*users_enumerate_by_group) (struct lu_module * module,
						  const char *group,
						  gid_t gid,
						  struct lu_error ** error);
	GPtrArray* (*users_enumerate_full) (struct lu_module * module,
					    const char *pattern,
					    struct lu_error ** error);
	/* Search for a group by name or ID. */
	gboolean(*group_lookup_name) (struct lu_module * module,
				      const char *name,
				      struct lu_ent * ent,
				      struct lu_error ** error);
	gboolean(*group_lookup_id) (struct lu_module * module,
				    gid_t gid,
				    struct lu_ent * ent,
				    struct lu_error ** error);
	/* Populate a group with sensible defaults. */
	gboolean(*group_default) (struct lu_module * module,
				  const char *name,
				  gboolean is_system,
				  struct lu_ent * ent,
				  struct lu_error ** error);
	/* Prepare to add a group (default part two, possibly). */
	gboolean(*group_add_prep) (struct lu_module * module,
				   struct lu_ent * ent,
				   struct lu_error ** error);
	/* Add the group to the data stores. */
	gboolean(*group_add) (struct lu_module * module,
			      struct lu_ent * ent,
			      struct lu_error ** error);
	/* Modify the group entry, committing any pending changes. */
	gboolean(*group_mod) (struct lu_module * module,
			      struct lu_ent * ent,
			      struct lu_error ** error);
	/* Delete the group. */
	gboolean(*group_del) (struct lu_module * module,
			      struct lu_ent * ent,
			      struct lu_error ** error);

	/* Lock, unlock, check if locked, or set the password for a group. */
	gboolean(*group_lock) (struct lu_module * module,
			       struct lu_ent * ent,
			       struct lu_error ** error);
	gboolean(*group_unlock) (struct lu_module * module,
				 struct lu_ent * ent,
				 struct lu_error ** error);
	gboolean(*group_unlock_nonempty) (struct lu_module * module,
					  struct lu_ent * ent,
					  struct lu_error ** error);
	gboolean(*group_is_locked) (struct lu_module * module,
				    struct lu_ent * ent,
				    struct lu_error ** error);
	gboolean(*group_setpass) (struct lu_module * module,
				  struct lu_ent * ent,
				  const char *newpass,
				  struct lu_error ** error);
	gboolean(*group_removepass) (struct lu_module * module,
				     struct lu_ent * ent,
				     struct lu_error ** error);

	/* Look up all group names, just the groups a particular user is in,
	 * or all groups, with full information. */
	GValueArray* (*groups_enumerate) (struct lu_module * module,
					  const char *pattern,
					  struct lu_error ** error);
	GValueArray* (*groups_enumerate_by_user) (struct lu_module * module,
						  const char *user,
						  uid_t uid,
						  struct lu_error ** error);
	GPtrArray* (*groups_enumerate_full) (struct lu_module * module,
					     const char *pattern,
					     struct lu_error ** error);

	/* Clean up any data this module has, and unload it. */
	gboolean(*close) (struct lu_module * module);
};

/* The type of the initialization function a module exports for the library
 * to use when initializing it.  Should fit "lu_%s_init", where the string
 * is the name of the module being loaded (and this should match the "name"
 * attribute of the module structure). */
#define LU_MODULE_INIT(_fn) extern struct lu_module *\
_fn (struct lu_context * context, struct lu_error ** error);
typedef struct lu_module *(*lu_module_init_t) (struct lu_context * context,
					       struct lu_error ** error);

struct lu_ent *lu_ent_new_typed(enum lu_entity_type entity_type);

/* Common code expected to be used by some modules. */
gboolean lu_common_user_default(struct lu_module *module, const char *name,
				gboolean is_system, struct lu_ent *ent,
				struct lu_error **error);
gboolean lu_common_group_default(struct lu_module *module, const char *name,
				 gboolean is_system, struct lu_ent *ent,
				 struct lu_error **error);
gboolean lu_common_suser_default(struct lu_module *module, const char *name,
				 gboolean is_system, struct lu_ent *ent,
				 struct lu_error **error);
gboolean lu_common_sgroup_default(struct lu_module *module, const char *name,
				  gboolean is_system, struct lu_ent *ent,
				  struct lu_error **error);

/* Generate a crypted password. */
const char *lu_make_crypted(const char *plain, const char *previous);
char *lu_util_default_salt_specifier(struct lu_context *context);

/* Handle SELinux fscreate context.  Note that modules built WITH_SELINUX are
   intentionally not compatible with libuser built !WITH_SELINUX. */
#ifdef WITH_SELINUX
typedef security_context_t lu_security_context_t;
gboolean lu_util_fscreate_save(security_context_t *ctx,
				      struct lu_error **error);
void lu_util_fscreate_restore(security_context_t ctx);
gboolean lu_util_fscreate_from_fd(int fd, const char *path,
				  struct lu_error **error);
gboolean lu_util_fscreate_from_file(const char *file, struct lu_error **error);
gboolean lu_util_fscreate_from_lfile(const char *file, struct lu_error **error);
gboolean lu_util_fscreate_for_path(const char *path, mode_t mode,
				   struct lu_error **error);

#else
typedef char lu_security_context_t; /* "Something" */
#define lu_util_fscreate_save(CTX, ERROR) ((void)(CTX), (void)(ERROR), TRUE)
#define lu_util_fscreate_restore(CTX) ((void)(CTX))
#define lu_util_fscreate_from_fd(FD, PATH, ERROR) \
  ((void)(FD), (void)(PATH), (void)(ERROR), TRUE)
#define lu_util_fscreate_from_file(FILE, ERROR) \
  ((void)(FILE), (void)(ERROR), TRUE)
#define lu_util_fscreate_from_lfile(FILE, ERROR) \
  ((void)(FILE), (void)(ERROR), TRUE)
#define lu_util_fscreate_for_path(PATH, MODE, ERROR) \
  ((void)(PATH), (void)(MODE), (void)(ERROR), TRUE)
#endif

#ifndef LU_DISABLE_DEPRECATED
/* Lock a file. Deprecated. */
gpointer lu_util_lock_obtain(int fd, struct lu_error **error);
void lu_util_lock_free(gpointer lock);
#endif

/* Manipulate a colon-delimited flat text file. */
char *lu_util_line_get_matching1(int fd, const char *firstpart,
				 struct lu_error **error);
char *lu_util_line_get_matching3(int fd, const char *thirdpart,
				 struct lu_error **error);
char *lu_util_line_get_matchingx(int fd, const char *part, int field,
				 struct lu_error **error);
char *lu_util_field_read(int fd, const char *first, unsigned int field,
			 struct lu_error **error);
gboolean lu_util_field_write(int fd, const char *first, unsigned int field,
			     const char *value, struct lu_error **error);

void lu_util_update_shadow_last_change(struct lu_ent *ent);

/* Find the first unused ID of the given type, searching starting at "id". */
id_t lu_get_first_unused_id(struct lu_context *ctx, enum lu_entity_type type,
			    id_t id);

/* Append a copy of VALUES to DEST */
void lu_util_append_values(GValueArray *dest, GValueArray *values);

G_END_DECLS

#endif
