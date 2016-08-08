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

#ifndef libuser_entity_h
#define libuser_entity_h

#include <sys/types.h>
#include <stdio.h>
#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

/**
 * lu_ent:
 *
 * An opaque structure used to hold data about a particular user or group
 * account.
 *
 * Each struct lu_ent contains two sets of attributes: pending and current.
 * The pending attributes are modified by default, the current attributes are
 * modified by functions ending with _current.
 *
 * Each attribute contains a list of values.  The list is never empty; removing
 * the last entry from the list removes the list completely.
 */
struct lu_ent;
#ifndef LU_DISABLE_DEPRECATED
/**
 * lu_ent_t:
 *
 * An alias for struct #lu_ent.
 * Deprecated: 0.57.3: Use struct #lu_ent directly.
 */
typedef struct lu_ent lu_ent_t;
#endif

/* Attributes carried by all user structures. */
/**
 * LU_USERNAME:
 *
 * User name, a %G_TYPE_STRING.
 */
#define LU_USERNAME		"pw_name"
/**
 * LU_USERPASSWORD:
 *
 * User password, a %G_TYPE_STRING.  If shadow passwords are used, this is the
 * placeholder password.
 *
 * Don't modify passwords by changing this attribute directly, use one of the
 * specialized functions.
 */
#define LU_USERPASSWORD		"pw_passwd"
/**
 * LU_UIDNUMBER:
 *
 * User ID, an #id_t.
 */
#define LU_UIDNUMBER		"pw_uid"
/**
 * LU_GIDNUMBER:
 *
 * Group ID, an #id_t.
 */
#define LU_GIDNUMBER		"pw_gid"
/**
 * LU_GECOS:
 *
 * Usually user's real name, a %G_TYPE_STRING.  Often contains user's real name,
 * office name, office phone, home phone, separated by commas.
 */
#define LU_GECOS		"pw_gecos"
/**
 * LU_HOMEDIRECTORY:
 *
 * User's home directory, a %G_TYPE_STRING.
 */
#define LU_HOMEDIRECTORY	"pw_dir"
/**
 * LU_LOGINSHELL:
 *
 * User's login shell, a %G_TYPE_STRING.
 */
#define LU_LOGINSHELL		"pw_shell"

/* Attributes carried by group structures. */
/**
 * LU_GROUPNAME:
 *
 * Group name, a %G_TYPE_STRING.
 */
#define LU_GROUPNAME		"gr_name"
/**
 * LU_GROUPPASSWORD:
 *
 * Group password, a %G_TYPE_STRING.
 *
 * Don't modify passwords by changing this attribute directly, use one of the
 * specialized functions.
 */
#define LU_GROUPPASSWORD	"gr_passwd"
/* #define LU_GIDNUMBER		"gr_gid" */
/**
 * LU_MEMBERNAME:
 *
 * Group member names; each member is represented by a separate %G_TYPE_STRING
 * value.
 */
#define LU_MEMBERNAME		"gr_mem"
/**
 * LU_ADMINISTRATORNAME:
 *
 * Group administrator names; each administrator is represented by a separate
 * %G_TYPE_STRING value.
 */
#define LU_ADMINISTRATORNAME	"gr_adm"

/* Attributes carried by shadow user structures. */
/**
 * LU_SHADOWNAME:
 *
 * User name, a %G_TYPE_STRING.  Note that %LU_SHADOWNAME is not distinct from
 * %LU_USERNAME.
 */
#define LU_SHADOWNAME		LU_USERNAME
/**
 * LU_SHADOWPASSWORD:
 *
 * User password in the shadow file, a %G_TYPE_STRING.
 *
 * Don't modify passwords by changing this attribute directly, use one of the
 * specialized functions.
 */
#define LU_SHADOWPASSWORD	"sp_pwdp"
/**
 * LU_SHADOWLASTCHANGE:
 *
 * The number of days since the epoch to the day when the password was last
 * changed, a %G_TYPE_LONG.
 *
 * May be -1 to indicate that the field exists without a value.  This should be
 * handled the same as if the attribute was missing altogether, and consistently
 * with shadow(5).
 */
#define LU_SHADOWLASTCHANGE	"sp_lstchg"
/**
 * LU_SHADOWMIN:
 *
 * Minimum password lifetime in days before it can be changed, a %G_TYPE_LONG.
 *
 * May be -1 to indicate that the field exists without a value.  This should be
 * handled the same as if the attribute was missing altogether, and consistently
 * with shadow(5).
 */
#define LU_SHADOWMIN		"sp_min"
/**
 * LU_SHADOWMAX:
 *
 * Maximum password lifetime in days before it must be changed, a %G_TYPE_LONG.
 *
 * May be -1 to indicate that the field exists without a value.  This should be
 * handled the same as if the attribute was missing altogether, and consistently
 * with shadow(5).
 */
#define LU_SHADOWMAX		"sp_max"
/**
 * LU_SHADOWWARNING:
 *
 * Days before the password lifetime expires when the user should start to be
 * warned, a %G_TYPE_LONG.
 *
 * May be -1 to indicate that the field exists without a value.  This should be
 * handled the same as if the attribute was missing altogether, and consistently
 * with shadow(5).
 */
#define LU_SHADOWWARNING	"sp_warn"
/**
 * LU_SHADOWINACTIVE:
 *
 * Days after the password lifetime expires when the user account is disabled
 * (because it is considered inactive), a %G_TYPE_LONG.  -1 to disable inactive
 * account disabling.
 */
#define LU_SHADOWINACTIVE	"sp_inact"
/**
 * LU_SHADOWEXPIRE:
 *
 * The number of days since the epoch to the day when the account expires and
 * is disabled, a %G_TYPE_LONG.  -1 to disable account expiration.
 */
#define LU_SHADOWEXPIRE		"sp_expire"
/**
 * LU_SHADOWFLAG:
 *
 * A reserved value "for future use", a %G_TYPE_LONG.  In most cases the value
 * is -1.
 */
#define LU_SHADOWFLAG		"sp_flag"

/* Additional fields carried by some structures.  If they have them,
 * it's safe to change them. */
/**
 * LU_COMMONNAME:
 *
 * User's real name, a %G_TYPE_STRING.
 */
#define LU_COMMONNAME		"cn"
/**
 * LU_GIVENNAME:
 *
 * User's given name, a %G_TYPE_STRING.
 */
#define LU_GIVENNAME		"givenName"
/**
 * LU_SN:
 *
 * User's surname, a %G_TYPE_STRING.
 */
#define LU_SN			"sn"
/**
 * LU_ROOMNUMBER:
 *
 * User's room number, a %G_TYPE_STRING.
 */
#define LU_ROOMNUMBER		"roomNumber"
/**
 * LU_TELEPHONENUMBER:
 *
 * User's telephone number, a %G_TYPE_STRING.
 */
#define LU_TELEPHONENUMBER	"telephoneNumber"
/**
 * LU_HOMEPHONE:
 *
 * User's home telephone number, a %G_TYPE_STRING.
 */
#define LU_HOMEPHONE		"homePhone"
/**
 * LU_EMAIL:
 *
 * User's email address, a %G_TYPE_STRING.
 */
#define LU_EMAIL		"mail"

struct lu_ent *lu_ent_new(void);
void lu_ent_free(struct lu_ent *ent);

void lu_ent_copy(struct lu_ent *source, struct lu_ent *dest);

void lu_ent_revert(struct lu_ent *ent);
void lu_ent_commit(struct lu_ent *ent);

GValueArray *lu_ent_get_current(struct lu_ent *ent, const char *attribute);
const char *lu_ent_get_first_string_current(struct lu_ent *ent,
					    const char *attribute);
char *lu_ent_get_first_value_strdup_current(struct lu_ent *ent,
					    const char *attribute);
id_t lu_ent_get_first_id_current(struct lu_ent *ent, const char *attribute);
gboolean lu_ent_has_current(struct lu_ent *ent, const char *attribute);
void lu_ent_set_current(struct lu_ent *ent, const char *attr,
			const GValueArray *values);
void lu_ent_set_string_current(struct lu_ent *ent, const char *attr,
			       const char *value);
void lu_ent_set_id_current(struct lu_ent *ent, const char *attr, id_t value);
void lu_ent_set_long_current(struct lu_ent *ent, const char *attr,
			     long int value);
void lu_ent_add_current(struct lu_ent *ent, const char *attr,
			const GValue *value);
void lu_ent_clear_current(struct lu_ent *ent, const char *attr);
void lu_ent_clear_all_current(struct lu_ent *ent);
void lu_ent_del_current(struct lu_ent *ent, const char *attr,
			const GValue *value);
GList *lu_ent_get_attributes_current(struct lu_ent *ent);

GValueArray *lu_ent_get(struct lu_ent *ent, const char *attribute);
const char *lu_ent_get_first_string(struct lu_ent *ent, const char *attribute);
char *lu_ent_get_first_value_strdup(struct lu_ent *ent, const char *attribute);
id_t lu_ent_get_first_id(struct lu_ent *ent, const char *attribute);
gboolean lu_ent_has(struct lu_ent *ent, const char *attribute);
void lu_ent_set(struct lu_ent *ent, const char *attr,
		const GValueArray *values);
void lu_ent_set_string(struct lu_ent *ent, const char *attr, const char *value);
void lu_ent_set_id(struct lu_ent *ent, const char *attr, id_t value);
void lu_ent_set_long(struct lu_ent *ent, const char *attr, long int value);
void lu_ent_add(struct lu_ent *ent, const char *attr,
		const GValue *value);
void lu_ent_clear(struct lu_ent *ent, const char *attr);
void lu_ent_clear_all(struct lu_ent *ent);
void lu_ent_del(struct lu_ent *ent, const char *attr, const GValue *value);
GList *lu_ent_get_attributes(struct lu_ent *ent);

void lu_ent_dump(struct lu_ent *ent, FILE *fp);

G_END_DECLS

#endif
