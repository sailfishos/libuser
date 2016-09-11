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
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <popt.h>
#include <string.h>
#include "../lib/user_private.h"
#include "apputil.h"

int
main(int argc, const char **argv)
{
	const char *userPassword = NULL, *cryptedUserPassword = NULL,
		   *gid = NULL, *addAdmins = NULL, *remAdmins = NULL,
		   *addMembers = NULL, *remMembers = NULL, *group,
		   *gid_number_str = NULL;
	char **admins, **members;
	gid_t gidNumber = LU_VALUE_INVALID_ID;
	gid_t oldGidNumber = LU_VALUE_INVALID_ID;
	struct lu_context *ctx;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	GPtrArray *users = NULL;
	GValue val;
	int change = FALSE, lock = FALSE, unlock = FALSE;
	int interactive = FALSE;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 N_("prompt for all information"), NULL},
		{"gid", 'g', POPT_ARG_STRING, &gid_number_str, 0,
		 N_("set GID for group"), N_("NUM")},
		{"name", 'n', POPT_ARG_STRING, &gid, 0,
		 N_("change group to have given name"), N_("NAME")},
		{"plainpassword", 'P', POPT_ARG_STRING, &userPassword, 0,
		 N_("plaintext password for use with group"), N_("STRING")},
		{"password", 'p', POPT_ARG_STRING, &cryptedUserPassword, 0,
		 N_("pre-hashed password for use with group"), N_("STRING")},
		{"admin-add", 'A', POPT_ARG_STRING, &addAdmins, 0,
		 N_("list of administrators to add"), N_("STRING")},
		{"admin-remove", 'a', POPT_ARG_STRING, &remAdmins, 0,
		 N_("list of administrators to remove"), N_("STRING")},
		{"member-add", 'M', POPT_ARG_STRING, &addMembers, 0,
		 N_("list of group members to add"), N_("STRING")},
		{"member-remove", 'm', POPT_ARG_STRING, &remMembers, 0,
		 N_("list of group members to remove"), N_("STRING")},
		{"lock", 'L', POPT_ARG_NONE, &lock, 0, N_("lock group"), NULL},
		{"unlock", 'U', POPT_ARG_NONE, &unlock, 0, N_("unlock group"),
		 NULL},
		POPT_AUTOHELP POPT_TABLEEND
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("lgroupmod", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] group"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}
	group = poptGetArg(popt);

	if (group == NULL) {
		fprintf(stderr, _("No group name specified.\n"));
		poptPrintUsage(popt, stderr, 0);
		return 1;
	}
	if (gid_number_str != NULL) {
		intmax_t val;
		char *p;

		errno = 0;
		val = strtoimax(gid_number_str, &p, 10);
		if (errno != 0 || *p != 0 || p == gid_number_str
		    || (gid_t)val != val || (gid_t)val == LU_VALUE_INVALID_ID) {
			fprintf(stderr, _("Invalid group ID %s\n"),
				gid_number_str);
			poptPrintUsage(popt, stderr, 0);
			return 1;
		}
		gidNumber = val;
	}

	poptFreeContext(popt);

	ctx = lu_start(NULL, 0, NULL, NULL,
		       interactive ? lu_prompt_console :
		       lu_prompt_console_quiet, NULL, &error);
	if (ctx == NULL) {
		fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE,
			lu_strerror(error));
		return 1;
	}

	if (lock && unlock) {
		fprintf(stderr, _("Both -L and -U specified.\n"));
		return 2;
	}

	ent = lu_ent_new();

	if (lu_group_lookup_name(ctx, group, ent, &error) == FALSE) {
		fprintf(stderr, _("Group %s does not exist.\n"), group);
		return 3;
	}

	if (userPassword) {
		if (lu_group_setpass(ctx, ent, userPassword, FALSE, &error)
		    == FALSE) {
			fprintf(stderr, _("Failed to set password for group "
				"%s: %s\n"), group, lu_strerror(error));
			return 4;
		}
	}

	if (cryptedUserPassword) {
		if (lu_group_setpass(ctx, ent, cryptedUserPassword, TRUE,
				     &error) == FALSE) {
			fprintf(stderr, _("Failed to set password for group "
				"%s: %s\n"), group, lu_strerror(error));
			return 5;
		}
	}

	if (lock) {
		if (lu_group_lock(ctx, ent, &error) == FALSE) {
			fprintf(stderr,
				_("Group %s could not be locked: %s\n"), group,
				lu_strerror(error));
			return 6;
		}
	}

	if (unlock) {
		if (lu_group_unlock(ctx, ent, &error) == FALSE) {
			fprintf(stderr,
				_("Group %s could not be unlocked: %s\n"),
				group, lu_strerror(error));
			return 7;
		}
	}

	change = gid || addAdmins || remAdmins || addMembers || remMembers;

	if (gid != NULL) {
		if (lu_ent_get(ent, LU_GROUPNAME) != NULL)
			lu_ent_set_string(ent, LU_GROUPNAME, gid);
		else {
			lu_ent_clear(ent, LU_GROUPNAME);
			gid = group;
		}
	} else
		gid = group;
	if (addAdmins) {
		memset(&val, 0, sizeof(val));
		g_value_init(&val, G_TYPE_STRING);
		admins = g_strsplit(addAdmins, ",", 0);
		if (admins) {
			for (c = 0; admins && admins[c]; c++) {
				g_value_set_string(&val, admins[c]);
				lu_ent_add(ent, LU_ADMINISTRATORNAME, &val);
				g_value_reset(&val);
			}
			g_strfreev(admins);
		}
		g_value_unset(&val);
	}
	if (remAdmins) {
		memset(&val, 0, sizeof(val));
		g_value_init(&val, G_TYPE_STRING);
		admins = g_strsplit(remAdmins, ",", 0);
		if (admins) {
			for (c = 0; admins && admins[c]; c++) {
				g_value_set_string(&val, admins[c]);
				lu_ent_del(ent, LU_ADMINISTRATORNAME, &val);
				g_value_reset(&val);
			}
			g_strfreev(admins);
		}
		g_value_unset(&val);
	}

	if (addMembers) {
		memset(&val, 0, sizeof(val));
		g_value_init(&val, G_TYPE_STRING);
		members = g_strsplit(addMembers, ",", 0);
		if (members) {
			for (c = 0; members && members[c]; c++) {
				g_value_set_string(&val, members[c]);
				lu_ent_add(ent, LU_MEMBERNAME, &val);
				g_value_reset(&val);
			}
			g_strfreev(members);
		}
		g_value_unset(&val);
	}
	if (remMembers) {
		memset(&val, 0, sizeof(val));
		g_value_init(&val, G_TYPE_STRING);
		members = g_strsplit(remMembers, ",", 0);
		if (members) {
			for (c = 0; members && members[c]; c++) {
				g_value_set_string(&val, members[c]);
				lu_ent_del(ent, LU_MEMBERNAME, &val);
				g_value_reset(&val);
			}
			g_strfreev(members);
		}
		g_value_unset(&val);
	}

	if (change && lu_group_modify(ctx, ent, &error) == FALSE) {
		fprintf(stderr, _("Group %s could not be modified: %s\n"),
			group, lu_strerror(error));
		return 8;
	}
	if (gidNumber != LU_VALUE_INVALID_ID) {
		users = lu_users_enumerate_by_group_full(ctx, gid, &error);

		oldGidNumber = lu_ent_get_first_id(ent, LU_GIDNUMBER);

		lu_ent_set_id(ent, LU_GIDNUMBER, gidNumber);

		if (error != NULL)
			lu_error_free(&error);
		if (lu_group_modify(ctx, ent, &error) == FALSE) {
			fprintf(stderr,
				_("Group %s could not be modified: %s\n"),
				group, lu_strerror(error));
			return 8;
		}
	}

	lu_ent_free(ent);

	lu_nscd_flush_cache(LU_NSCD_CACHE_GROUP);

	if (oldGidNumber != LU_VALUE_INVALID_ID &&
	    gidNumber != LU_VALUE_INVALID_ID && users != NULL) {
		size_t i;

		for (i = 0; i < users->len; i++) {
			ent = g_ptr_array_index(users, i);
			if (lu_ent_get_first_id(ent, LU_GIDNUMBER)
			    == oldGidNumber) {
				lu_ent_set_id(ent, LU_GIDNUMBER, gidNumber);
				lu_user_modify(ctx, ent, &error);
				if (error != NULL)
					lu_error_free(&error);
			}
			lu_ent_free(ent);
		}
		g_ptr_array_free(users, TRUE);

		lu_nscd_flush_cache(LU_NSCD_CACHE_PASSWD);
	}

	lu_end(ctx);

	return 0;
}
