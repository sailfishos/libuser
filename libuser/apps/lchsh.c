/*
 * Copyright (C) 2001,2002, 2004, 2006 Red Hat, Inc.
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
#include <sys/stat.h>
#include <libintl.h>
#include <locale.h>
#include <popt.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../lib/user.h"
#include "apputil.h"

int
main(int argc, const char **argv)
{
	const char *user;
	struct lu_context *ctx;
	struct lu_error *error = NULL;
	struct lu_ent *ent;
	char *shell;
	int interactive = FALSE;
	int c;
	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 N_("prompt for all information"), NULL},
		POPT_AUTOHELP POPT_TABLEEND
	};

	/* Set up i18n. */
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	/* Parse arguments. */
	popt = poptGetContext("lchsh", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] [user]"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}
	user = poptGetArg(popt);

	/* If no user was specified, or we're setuid, force the user name to
	 * be that of the current user. */
	if ((user == NULL) || (geteuid() != getuid())) {
		struct passwd *pwd;

		pwd = getpwuid(getuid());
		if (pwd != NULL) {
			user = g_strdup(pwd->pw_name);
		} else {
			fprintf(stderr, _("No user name specified, no name for "
				"uid %d.\n"), getuid());
			poptPrintUsage(popt, stderr, 0);
			exit(1);
		}
	}

	poptFreeContext(popt);

	/* Give the user some idea of what's going on. */
	g_print(_("Changing shell for %s.\n"), user);

	/* Start up the library. */
	ctx = lu_start(user, lu_user, NULL, NULL,
		       interactive ? lu_prompt_console :
		       lu_prompt_console_quiet, NULL, &error);
	if (ctx == NULL) {
		fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE,
			lu_strerror(error));
		return 1;
	}

	/* Authenticate the user if we need to. */
	lu_authenticate_unprivileged(ctx, user, "chsh");

	/* Look up this user's record. */
	ent = lu_ent_new();
	if (lu_user_lookup_name(ctx, user, ent, &error) == FALSE) {
		fprintf(stderr, _("User %s does not exist.\n"), user);
		exit(1);
	}

	/* Read the user's shell. */
	shell = lu_ent_get_first_value_strdup(ent, LU_LOGINSHELL);
	if (shell != NULL) {
		struct lu_prompt prompts[1];

		/* Fill in the prompt structure using the user's shell. */
		memset(prompts, 0, sizeof(prompts));
		prompts[0].key = "lchfn/shell";
		prompts[0].prompt = N_("New Shell");
		prompts[0].domain = PACKAGE;
		prompts[0].visible = TRUE;
		prompts[0].default_value = shell;
		/* Prompt for a new shell. */
		if (lu_prompt_console(prompts, G_N_ELEMENTS(prompts),
				      NULL, &error) == FALSE) {
			fprintf(stderr, _("Shell not changed: %s\n"),
				lu_strerror(error));
			return 1;
		}
		/* Modify the in-memory structure's shell attribute. */
		lu_ent_set_string(ent, LU_LOGINSHELL, prompts[0].value);
		if (prompts[0].free_value != NULL) {
			prompts[0].free_value(prompts[0].value);
			prompts[0].value = NULL;
		}
		/* Modify the user's record in the information store. */
		if (lu_user_modify(ctx, ent, &error)) {
			g_print(_("Shell changed.\n"));
			lu_nscd_flush_cache(LU_NSCD_CACHE_PASSWD);
		} else {
			fprintf(stderr, _("Shell not changed: %s\n"),
				lu_strerror(error));
			return 1;
		}
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
