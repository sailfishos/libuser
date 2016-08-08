/*
 * Copyright (C) 2001, 2002, 2004, 2006 Red Hat, Inc.
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
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <popt.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/user.h"
#include "apputil.h"

int
main(int argc, const char **argv)
{
	struct lu_context *ctx;
	struct lu_error *error = NULL;
	struct lu_ent *ent, *groupEnt;
	int interactive = FALSE, nocreatehome = FALSE, nocreatemail = FALSE;
	int c;
	char *file = NULL;
	FILE *fp = stdin;
	char buf[LINE_MAX];
	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 N_("prompt for all information"), NULL},
		{"file", 'f', POPT_ARG_STRING, &file, 0,
		 N_("file with user information records"), N_("PATH")},
		{"nocreatehome", 'M', POPT_ARG_NONE, &nocreatehome, 0,
		 N_("don't create home directories"), NULL},
		{"nocreatemail", 'n', POPT_ARG_NONE, &nocreatemail, 0,
		 N_("don't create mail spools"), NULL},
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	/* Initialize i18n support. */
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	/* Parse arguments. */
	popt = poptGetContext("lnewusers", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...]"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}

	poptFreeContext(popt);

	/* Start up the library. */
	ctx = lu_start(NULL, lu_user, NULL, NULL,
		       interactive ? lu_prompt_console :
		       lu_prompt_console_quiet, NULL, &error);
	if (ctx == NULL) {
		fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE,
			lu_strerror(error));
		return 1;
	}

	/* Open the file we're going to look at. */
	if (file != NULL) {
		fp = fopen(file, "r");
		if (fp == NULL) {
			fprintf(stderr, _("Error opening `%s': %s.\n"),
				file, strerror(errno));
			return 2;
		}
	} else {
		fp = stdin;
	}

	ent = lu_ent_new();
	groupEnt = lu_ent_new();

	while (fgets(buf, sizeof(buf), fp)) {
		gboolean creategroup, dubious_homedir;
		char **fields, *homedir, *gidstring, *p;
		intmax_t imax;
		uid_t uid;
		gid_t gid;

		/* Strip off the end-of-line terminators. */
		p = strchr(buf, '\r');
		if (p != NULL)
			*p = '\0';
		p = strchr(buf, '\n');
		if (p != NULL)
			*p = '\0';

		/* Make sure the line splits into *exactly* seven fields. */
		fields = g_strsplit(buf, ":", 7);
		if (g_strv_length(fields) != 7) {
			fprintf(stderr,
				_("Error creating account for `%s': line "
				  "improperly formatted.\n"), buf);
			g_strfreev(fields);
			continue;
		}

		errno = 0;
		imax = strtoimax(fields[2], &p, 10);
		if (errno != 0 || *p != 0 || p == fields[2]
		    || (uid_t)imax != imax
		    || (uid_t)imax == LU_VALUE_INVALID_ID) {
			g_print(_("Invalid user ID %s\n"), fields[2]);
			g_strfreev(fields);
			continue;
		}
		/* Sorry, but we're bastards here.  No root accounts. */
		uid = imax;
		if (uid == 0) {
			g_print(_("Refusing to create account with UID 0.\n"));
			g_strfreev(fields);
			continue;
		}

		/* Try to figure out if the field is the name of a group, or
		 * a gid.  If it's just empty, make it the same as the user's
		 * name.  FIXME: provide some way to set a default other than
		 * the user's own name, like "users" or something. */
		if (strlen(fields[3]) > 0) {
			gidstring = fields[3];
		} else {
			gidstring = fields[0];
		}

		/* Try to convert the field to a number. */
		errno = 0;
		imax = strtoimax(gidstring, &p, 10);
		gid = LU_VALUE_INVALID_ID;
		if (errno != 0 || *p != '\0' || p == gidstring
		    || (gid_t)imax != imax) {
			/* It's not a number, so it's a group name --
			 * see if it's being used. */
			if (lu_group_lookup_name(ctx, gidstring, ent, &error)) {
				/* Retrieve the group's GID. */
				gid = lu_ent_get_first_id(ent, LU_GIDNUMBER);
				creategroup = FALSE;
			} else {
				/* Mark that we need to create a group for the
				 * user to be in. */
				creategroup = TRUE;
			}
		} else {
			/* It's a group number -- see if it's being used. */
			gid = imax;
			if (gid == LU_VALUE_INVALID_ID) {
				g_print(_("Invalid group ID %s\n"), gidstring);
				g_strfreev(fields);
				continue;
			}
			if (lu_group_lookup_id(ctx, gid, ent, &error)) {
				/* Retrieve the group's GID. */
				gid = lu_ent_get_first_id(ent, LU_GIDNUMBER);
				creategroup = FALSE;
			} else {
				/* Mark that we need to create a group for the
				 * user to be in. */
				creategroup = TRUE;
			}
		}
		/* If we need to create a group, create a template group and
		 * try to apply what the user has asked us to. */
		if (creategroup) {
			/* If we got a GID, then we need to use the user's name,
			 * otherwise we need to use the default group name. */
			if (gid != LU_VALUE_INVALID_ID) {
				lu_group_default(ctx, fields[0], FALSE, ent);
				lu_ent_set_id(ent, LU_GIDNUMBER, gid);
			} else {
				lu_group_default(ctx, gidstring, FALSE, ent);
			}
			/* Try to create the group, and if it works, get its
			 * GID, which we need to give to this user. */
			if (lu_group_add(ctx, ent, &error)) {
				lu_nscd_flush_cache(LU_NSCD_CACHE_GROUP);
				gid = lu_ent_get_first_id(ent, LU_GIDNUMBER);
				g_assert(gid != LU_VALUE_INVALID_ID);
			} else {
				/* Aargh!  Abandon all hope. */
				fprintf(stderr,
					_("Error creating group for `%s' with "
					  "GID %jd: %s\n"), fields[0], imax,
					lu_strerror(error));
				g_strfreev(fields);
				continue;
			}
		}

		/* Create a new user record, and set the user's primary GID. */
		lu_user_default(ctx, fields[0], FALSE, ent);
		lu_ent_set_id(ent, LU_UIDNUMBER, uid);
		lu_ent_set_id(ent, LU_GIDNUMBER, gid);

		/* Set other fields if we've got them. */
		if (strlen(fields[4]) > 0)
			lu_ent_set_string(ent, LU_GECOS, fields[4]);
		dubious_homedir = 0;
		if (strlen(fields[5]) > 0) {
			homedir = g_strdup(fields[5]);
			lu_ent_set_string(ent, LU_HOMEDIRECTORY, homedir);
		} else {
			const char *home;

			home = lu_ent_get_first_string(ent, LU_HOMEDIRECTORY);
			if (home != NULL)
				homedir = g_strdup(home);
			else {
				homedir = g_strconcat("/home/", fields[0],
						      (const gchar *)NULL);
				if (strcmp(fields[0], ".") == 0
				    || strcmp(fields[0], "..") == 0)
					dubious_homedir = 1;
			}
		}
		if (strlen(fields[6]) > 0)
			lu_ent_set_string(ent, LU_LOGINSHELL, fields[6]);

		/* Now try to add the user's account. */
		if (dubious_homedir)
			fprintf(stderr,
				_("Refusing to use dangerous home directory `%s' "
				  "for %s by default\n"), homedir, fields[0]);
		else if (lu_user_add(ctx, ent, &error)) {
			lu_nscd_flush_cache(LU_NSCD_CACHE_PASSWD);
			/* Unless the nocreatehomedirs flag was given, attempt
			 * to create the user's home directory. */
			if (!nocreatehome) {
				if (lu_homedir_populate(ctx, NULL, homedir,
							uid, gid, 0700, &error)
				    == FALSE) {
					fprintf(stderr,
						_("Error creating home "
						  "directory for %s: %s\n"),
						fields[0], lu_strerror(error));
					if (error) {
						lu_error_free(&error);
					}
				}
			}
			/* Unless the nocreatemail flag was given, give the
			 * user a mail spool. */
			if (!nocreatemail) {
				if (!lu_mail_spool_create(ctx, ent, &error)) {
					fprintf(stderr,
						_("Error creating mail spool "
						  "for %s: %s\n"), fields[0],
						lu_strerror(error));
					if (error) {
						lu_error_free(&error);
					}
				}
			}
			/* Set the password after creating the home directory
			   to prevent the user from seeing an incomplete
			   home, and to prevent the user from interfering with
			   the creation of the home directory. */
			if (!lu_user_setpass(ctx, ent, fields[1], FALSE,
					     &error)) {
				fprintf(stderr,
					_("Error setting initial password for "
					  "%s: %s\n"), fields[0],
					lu_strerror(error));
				if (error) {
					lu_error_free(&error);
				}
			}
			lu_nscd_flush_cache(LU_NSCD_CACHE_PASSWD);
		} else {
			fprintf(stderr,
				_("Error creating user account for %s: %s\n"),
				fields[0], lu_strerror(error));
			if (error) {
				lu_error_free(&error);
			}
		}

		g_free(homedir);
		g_strfreev(fields);
		lu_ent_clear_all(ent);
		lu_ent_clear_all(groupEnt);
	}

	lu_ent_free(groupEnt);
	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
