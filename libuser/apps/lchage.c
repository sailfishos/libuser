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
#include <sys/time.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <popt.h>
#include <glib.h>
#include "../lib/user.h"
#include "apputil.h"

#define INVALID_LONG LONG_MIN

/* Return the first G_TYPE_LONG value of ATTR if ENT, if exists, or -1 if the
   attribute is missing or invalid. */
static glong
read_ndays(struct lu_ent *ent, const char *attr)
{
	GValueArray *values;
	GValue *value;

	values = lu_ent_get(ent, attr);
	if (values == NULL)
		return -1;

	value = g_value_array_get_nth(values, 0);
	g_assert(G_VALUE_HOLDS_LONG(value));
	return g_value_get_long(value);
}

/* Format a count of days into a string that's intelligible to a user. */
static void
date_to_string(glong n_days, char *buf, size_t len)
{
	if ((n_days >= 0) && (n_days < 99999)) {
		GDate *date;

		date = g_date_new_dmy(1, G_DATE_JANUARY, 1970);
		g_date_add_days(date, n_days);
		g_date_strftime(buf, len, "%x", date);
		g_date_free(date);
	}
}

int
main(int argc, const char **argv)
{
	long shadowMin = INVALID_LONG, shadowMax = INVALID_LONG,
	     shadowLastChange = INVALID_LONG, shadowInactive = INVALID_LONG,
	     shadowExpire = INVALID_LONG, shadowWarning = INVALID_LONG;
	const char *user;
	struct lu_context *ctx;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	int interactive = FALSE;
	int list_only = FALSE;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 N_("prompt for all information"), NULL},
		{"list", 'l', POPT_ARG_NONE, &list_only, 0,
		 N_("list aging parameters for the user"), NULL},
		{"mindays", 'm', POPT_ARG_LONG, &shadowMin, 0,
		 N_("minimum days between password changes"), N_("DAYS")},
		{"maxdays", 'M', POPT_ARG_LONG, &shadowMax, 0,
		 N_("maximum days between password changes"), N_("DAYS")},
		{"date", 'd', POPT_ARG_LONG, &shadowLastChange, 0,
		 N_("date of last password change in days since 1/1/70"),
		 N_("DAYS")},
		{"inactive", 'I', POPT_ARG_LONG, &shadowInactive, 0,
		 N_("number of days after password expiration date when "
		    "account is considered inactive"), N_("DAYS")},
		{"expire", 'E', POPT_ARG_LONG, &shadowExpire, 0,
		 N_("password expiration date in days since 1/1/70"),
		 N_("DAYS")},
		{"warndays", 'W', POPT_ARG_LONG, &shadowWarning, 0,
		 N_("days before expiration to begin warning user"),
		 N_("DAYS")},
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	/* Set up i18n. */
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	/* Parse arguments. */
	popt = poptGetContext("lchage", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] user"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}
	user = poptGetArg(popt);

	/* We need exactly one argument, and that's the user's name. */
	if (user == NULL) {
		fprintf(stderr, _("No user name specified.\n"));
		poptPrintUsage(popt, stderr, 0);
		return 1;
	}

	poptFreeContext(popt);

	/* Start up the library. */
	ctx = lu_start(user, lu_user, NULL, NULL,
		       interactive ? lu_prompt_console :
		       lu_prompt_console_quiet, NULL, &error);
	if (ctx == NULL) {
		fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE,
			lu_strerror(error));
		return 1;
	}

	ent = lu_ent_new();

	/* Look up information about the user. */
	if (lu_user_lookup_name(ctx, user, ent, &error) == FALSE) {
		fprintf(stderr, _("User %s does not exist.\n"), user);
		return 2;
	}

	if (list_only) {
		char buf[LINE_MAX];

		/* Just print out what we can find out, in a format similar
		   to the chage(1) utility from the shadow suite.

		   To make it a little easier to understand, convert "-1" to
		   "0" in cases where the two have the same meaning. */
		if (lu_user_islocked(ctx, ent, &error)) {
			printf(_("Account is locked.\n"));
		} else {
			printf(_("Account is not locked.\n"));
		}

		shadowMin = read_ndays(ent, LU_SHADOWMIN);
		printf(_("Minimum:\t%ld\n"), shadowMin != -1 ? shadowMin : 0);

		shadowMax = read_ndays(ent, LU_SHADOWMAX);
		if (shadowMax != -1)
			printf(_("Maximum:\t%ld\n"), shadowMax);
		else
			printf(_("Maximum:\tNone\n"));

		shadowWarning = read_ndays(ent, LU_SHADOWWARNING);
		printf(_("Warning:\t%ld\n"),
		       shadowWarning != -1 ? shadowWarning : 0);

		shadowInactive = read_ndays(ent, LU_SHADOWINACTIVE);
		if (shadowInactive != -1)
			printf(_("Inactive:\t%ld\n"), shadowInactive);
		else
			printf(_("Inactive:\tNever\n"));

		shadowLastChange = read_ndays(ent, LU_SHADOWLASTCHANGE);
		if (shadowLastChange == 0)
			strcpy(buf, _("Must change password on next login"));
		else {
			strcpy(buf, _("Never"));
			date_to_string(shadowLastChange, buf, sizeof(buf));
		}
		printf(_("Last Change:\t%s\n"), buf);

		if (shadowLastChange == 0)
			strcpy(buf, _("Must change password on next login"));
		else {
			strcpy(buf, _("Never"));
			if (shadowLastChange != -1 && shadowMax != -1)
				date_to_string(shadowLastChange + shadowMax,
					       buf, sizeof(buf));
		}
		printf(_("Password Expires:\t%s\n"), buf);

		if (shadowLastChange == 0)
			strcpy(buf, _("Must change password on next login"));
		else {
			strcpy(buf, _("Never"));
			if (shadowLastChange != -1 && shadowMax != -1
			    && shadowInactive != -1)
				date_to_string(shadowLastChange + shadowMax
					       + shadowInactive, buf,
					       sizeof(buf));
		}
		printf(_("Password Inactive:\t%s\n"), buf);

		strcpy(buf, _("Never"));
		shadowExpire = read_ndays(ent, LU_SHADOWEXPIRE);
		if (shadowExpire != -1)
			date_to_string(shadowExpire, buf, sizeof(buf));
		printf(_("Account Expires:\t%s\n"), buf);
	} else {
		/* Set values using parameters given on the command-line. */
		if (shadowLastChange != INVALID_LONG)
			lu_ent_set_long(ent, LU_SHADOWLASTCHANGE,
					shadowLastChange);
		if (shadowMin != INVALID_LONG)
			lu_ent_set_long(ent, LU_SHADOWMIN, shadowMin);
		if (shadowMax != INVALID_LONG)
			lu_ent_set_long(ent, LU_SHADOWMAX, shadowMax);
		if (shadowWarning != INVALID_LONG)
			lu_ent_set_long(ent, LU_SHADOWWARNING, shadowWarning);
		if (shadowInactive != INVALID_LONG)
			lu_ent_set_long(ent, LU_SHADOWINACTIVE, shadowInactive);
		if (shadowExpire != INVALID_LONG)
			lu_ent_set_long(ent, LU_SHADOWEXPIRE, shadowExpire);

		/* Now actually modify the user's data in the system
		 * information store. */
		if (lu_user_modify(ctx, ent, &error) == FALSE) {
			fprintf(stderr,
				_("Failed to modify aging information for %s: "
				  "%s\n"), user, lu_strerror(error));
			return 3;
		}

		lu_nscd_flush_cache(LU_NSCD_CACHE_PASSWD);
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
