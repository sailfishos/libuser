/*
 * Copyright (C) 2000-2002, 2004, 2006, 2009 Red Hat, Inc.
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
		   *gecos = NULL, *homeDirectory = NULL, *loginShell = NULL,
		   *skeleton = NULL, *name, *gid = NULL,
		   *uid_number_str = NULL, *commonName = NULL,
		   *givenName = NULL, *surname = NULL, *roomNumber = NULL,
		   *telephoneNumber = NULL, *homePhone = NULL;
	struct lu_context *ctx;
	struct lu_ent *ent, *groupEnt;
	struct lu_error *error = NULL;
	uid_t uidNumber = LU_VALUE_INVALID_ID;
	gid_t gidNumber;
	int dont_create_group = FALSE, dont_create_home = FALSE,
	    system_account = FALSE, interactive = FALSE, create_group;
	int c;
	intmax_t imax;
	char *p;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 N_("prompt for all information"), NULL},
		{"reserved", 'r', POPT_ARG_NONE, &system_account, 0,
		 N_("create a system user"), NULL},
		{"gecos", 'c', POPT_ARG_STRING, &gecos, 0,
		 N_("GECOS information for new user"), N_("STRING")},
		{"directory", 'd', POPT_ARG_STRING, &homeDirectory, 0,
		 N_("home directory for new user"), N_("STRING")},
		{"skeleton", 'k', POPT_ARG_STRING, &skeleton, 0,
		 N_("directory with files for the new user"), N_("STRING")},
		{"shell", 's', POPT_ARG_STRING, &loginShell, 0,
		 N_("shell for new user"), N_("STRING")},
		{"uid", 'u', POPT_ARG_STRING, &uid_number_str, 0,
		 N_("uid for new user"), N_("NUM")},
		{"gid", 'g', POPT_ARG_STRING, &gid, 0,
		 N_("group for new user"), N_("STRING")},
		{"nocreatehome", 'M', POPT_ARG_NONE, &dont_create_home, 0,
		 N_("don't create home directory for user"), NULL},
		{"nocreategroup", 'n', POPT_ARG_NONE, &dont_create_group, 0,
		 N_("don't create group with same name as user"), NULL},
		{"plainpassword", 'P', POPT_ARG_STRING, &userPassword, 0,
		 N_("plaintext password for use with group"), N_("STRING")},
		{"password", 'p', POPT_ARG_STRING, &cryptedUserPassword, 0,
		 N_("pre-hashed password for use with group"), N_("STRING")},
		{"commonname", 0, POPT_ARG_STRING, &commonName, 0,
		 N_("common name for new user"), N_("STRING")},
		{"givenname", 0, POPT_ARG_STRING, &givenName, 0,
		 N_("given name for new user"), N_("STRING")},
		{"surname", 0, POPT_ARG_STRING, &surname, 0,
		 N_("surname for new user"), N_("STRING")},
		{"roomnumber", 0, POPT_ARG_STRING, &roomNumber, 0,
		 N_("room number for new user"), N_("STRING")},
		{"telephonenumber", 0, POPT_ARG_STRING, &telephoneNumber, 0,
		 N_("telephone number for new user"), N_("STRING")},
		{"homephone", 0, POPT_ARG_STRING, &homePhone, 0,
		 N_("home telephone number for new user"), N_("STRING")},
		POPT_AUTOHELP POPT_TABLEEND
	};

	/* Initialize i18n. */
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	/* Parse command-line arguments. */
	popt = poptGetContext("luseradd", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] user"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}

	/* Force certain flags one way or another. */
	if (system_account) {
		dont_create_home = TRUE;
	}

	/* We require at least the user's name (I suppose we could just
	 * make one up, but that could get weird). */
	name = poptGetArg(popt);
	if (name == NULL) {
		fprintf(stderr, _("No user name specified.\n"));
		poptPrintUsage(popt, stderr, 0);
		return 1;
	}
	if (uid_number_str != NULL) {
		errno = 0;
		imax = strtoimax(uid_number_str, &p, 10);
		if (errno != 0 || *p != 0 || p == uid_number_str
		    || (uid_t)imax != imax
		    || (uid_t)imax == LU_VALUE_INVALID_ID) {
			fprintf(stderr, _("Invalid user ID %s\n"),
				uid_number_str);
			poptPrintUsage(popt, stderr, 0);
			return 1;
		}
		uidNumber = imax;
	}

	poptFreeContext(popt);

	/* Initialize the library. */
	ctx = lu_start(NULL, 0, NULL, NULL,
		       interactive ? lu_prompt_console :
		       lu_prompt_console_quiet, NULL, &error);
	if (ctx == NULL) {
		fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE,
			lu_strerror(error));
		return 1;
	}

	/* Select a group name for the user to be in. */
	if (gid == NULL) {
		if (dont_create_group)
			gid = "users";
		else
			gid = name;
		/* Consider "gid" a group name even if it is composed of
		   digits. */
		gidNumber = LU_VALUE_INVALID_ID;
	} else {
		/* Try to convert the given GID to a number. */
		errno = 0;
		imax = strtoimax(gid, &p, 10);
		if (errno == 0 && *p == 0 && p != gid && (gid_t)imax == imax) {
			gidNumber = imax;
			if (gidNumber == LU_VALUE_INVALID_ID) {
				fprintf(stderr, _("Invalid group ID %s\n"),
					gid);
				return 1;
			}
		} else
			/* It's not a number, so it's a group name. */
			gidNumber = LU_VALUE_INVALID_ID;
	}

	/* Check if the group exists. */
	groupEnt = lu_ent_new();
	if (gidNumber == LU_VALUE_INVALID_ID) {
		if (lu_group_lookup_name(ctx, gid, groupEnt, &error)) {
			/* Retrieve the group's GID. */
			gidNumber = lu_ent_get_first_id(groupEnt, LU_GIDNUMBER);
			g_assert(gidNumber != LU_VALUE_INVALID_ID);
			create_group = FALSE;
		} else {
			/* No such group, we need to create one. */
			create_group = TRUE;
		}
	} else {
		if (lu_group_lookup_id(ctx, gidNumber, groupEnt, &error)) {
			create_group = FALSE;
		} else {
			fprintf(stderr, _("Group %jd does not exist\n"),
				(intmax_t)gidNumber);
			return 1;
		}
	}

	if (create_group) {
		g_assert(gidNumber == LU_VALUE_INVALID_ID);
		if (error)
			lu_error_free(&error);
		/* Create the group template. */
		lu_group_default(ctx, gid, FALSE, groupEnt);

		/* Try to add the group. */
		if (lu_group_add(ctx, groupEnt, &error))
			lu_nscd_flush_cache(LU_NSCD_CACHE_GROUP);
		else {
			/* Aargh!  Abandon all hope. */
			fprintf(stderr, _("Error creating group `%s': %s\n"),
				gid, lu_strerror(error));
			if (error) {
				lu_error_free(&error);
			}
			lu_end(ctx);
			return 1;
		}
	}

	/* Retrieve the group ID. */
	gidNumber = lu_ent_get_first_id(groupEnt, LU_GIDNUMBER);
	if (gidNumber == LU_VALUE_INVALID_ID) {
		fprintf(stderr, _("Error creating group `%s': %s\n"), gid,
			lu_strerror(error));
		if (error) {
			lu_error_free(&error);
		}
		lu_end(ctx);
		return 1;
	}
	g_assert(gidNumber != LU_VALUE_INVALID_ID);

	lu_ent_free(groupEnt);

	/* Create the user record. */
	ent = lu_ent_new();
	lu_user_default(ctx, name, system_account, ent);

	/* Modify the default UID if we had one passed in. */
	if (uidNumber != LU_VALUE_INVALID_ID)
		lu_ent_set_id(ent, LU_UIDNUMBER, uidNumber);

	/* Use the GID we've created, or the one which was passed in. */
	if (gidNumber != LU_VALUE_INVALID_ID)
		lu_ent_set_id(ent, LU_GIDNUMBER, gidNumber);

#define PARAM(ATTR, VAR)				\
	if ((VAR) != NULL)				\
		lu_ent_set_string(ent, (ATTR), (VAR));
	PARAM(LU_GECOS, gecos);
	PARAM(LU_HOMEDIRECTORY, homeDirectory);
	PARAM(LU_LOGINSHELL, loginShell);
	PARAM(LU_COMMONNAME, commonName);
	PARAM(LU_GIVENNAME, givenName);
	PARAM(LU_SN, surname);
	PARAM(LU_ROOMNUMBER, roomNumber);
	PARAM(LU_TELEPHONENUMBER, telephoneNumber);
	PARAM(LU_HOMEPHONE, homePhone);
#undef PARAM

	/* Moment-of-truth time. */
	if (lu_user_add(ctx, ent, &error) == FALSE) {
		fprintf(stderr, _("Account creation failed: %s.\n"),
			lu_strerror(error));
		return 3;
	}
        lu_nscd_flush_cache(LU_NSCD_CACHE_PASSWD);

	/* If we don't have the the don't-create-home flag, create the user's
	 * home directory. */
	if (!dont_create_home) {
		/* Read the user's UID. */
		uidNumber = lu_ent_get_first_id(ent, LU_UIDNUMBER);
		g_assert(uidNumber != LU_VALUE_INVALID_ID);

		/* Read the user's GID. */
		gidNumber = lu_ent_get_first_id(ent, LU_GIDNUMBER);
		g_assert(gidNumber != LU_VALUE_INVALID_ID);

		/* Read the user's home directory. */
		homeDirectory = lu_ent_get_first_string(ent, LU_HOMEDIRECTORY);

		if (lu_homedir_populate(ctx, skeleton, homeDirectory,
					uidNumber, gidNumber, 0700,
					&error) == FALSE) {
			fprintf(stderr, _("Error creating %s: %s.\n"),
				homeDirectory, lu_strerror(error));
			return 7;
		}

		/* Create a mail spool for the user. */
		if (lu_mail_spool_create(ctx, ent, &error) != TRUE) {
			fprintf(stderr, _("Error creating mail spool: %s\n"),
				lu_strerror(error));
			return 8;
		}
	}

	/* Set the password after creating the home directory to prevent the
	   user from seeing an incomplete home, and to prevent the user from
	   interfering with the creation of the home directory. */
	if (userPassword != NULL) {
		if (lu_user_setpass(ctx, ent, userPassword, FALSE, &error)
		    == FALSE) {
			fprintf(stderr, _("Error setting password for user "
					  "%s: %s.\n"), name,
				lu_strerror(error));
			return 3;
		}
	}
	if (cryptedUserPassword != NULL) {
		if (lu_user_setpass(ctx, ent, cryptedUserPassword, TRUE,
				    &error) == FALSE) {
			fprintf(stderr, _("Error setting password for user "
					  "%s: %s.\n"), name,
				lu_strerror(error));
			return 3;
		}
	}
	lu_nscd_flush_cache(LU_NSCD_CACHE_PASSWD);

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
