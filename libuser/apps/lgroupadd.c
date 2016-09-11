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
	const char *name, *gid_number_str = NULL;
	gid_t gidNumber = LU_VALUE_INVALID_ID;
	struct lu_context *ctx;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	int interactive = FALSE;
	int system_account = FALSE;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 N_("prompt for all information"), NULL},
		{"gid", 'g', POPT_ARG_STRING, &gid_number_str, 0,
		 N_("gid for new group"), N_("NUM")},
		{"reserved", 'r', POPT_ARG_NONE, &system_account, 0,
		 N_("create a system group"), NULL},
		POPT_AUTOHELP POPT_TABLEEND
	};

	/* Set up i18n. */
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	/* Parse arguments. */
	popt = poptGetContext("lgroupadd", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] group"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}
	name = poptGetArg(popt);

	/* We require a group name to be specified. */
	if (name == NULL) {
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

	/* Start up the library. */
	ctx = lu_start(NULL, 0, NULL, NULL,
		       interactive ? lu_prompt_console :
		       lu_prompt_console_quiet, NULL, &error);
	if (ctx == NULL) {
		fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE,
			lu_strerror(error));
		return 1;
	}

	/* Create a group entity object holding sensible defaults for a
	 * new group. */
	ent = lu_ent_new();
	lu_group_default(ctx, name, system_account, ent);

	/* If the user specified a particular GID number, override the
	 * default. */
	if (gidNumber != LU_VALUE_INVALID_ID)
		lu_ent_set_id(ent, LU_GIDNUMBER, gidNumber);

	/* Try to create the group. */
	if (lu_group_add(ctx, ent, &error) == FALSE) {
		fprintf(stderr, _("Group creation failed: %s\n"),
			lu_strerror(error));
		return 2;
	}

	lu_nscd_flush_cache(LU_NSCD_CACHE_GROUP);

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
