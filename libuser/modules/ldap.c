/*
 * Copyright (C) 2000-2002, 2004, 2005, 2008 Red Hat, Inc.
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
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <ldap.h>
#include <sasl/sasl.h>
#include "../lib/user_private.h"

#undef  DEBUG
#define LOCKCHAR '!'
#define LOCKSTRING "!"
#define USERBRANCH "ou=People"
#define GROUPBRANCH "ou=Group"
#define OBJECTCLASS "objectClass"
#define ACCOUNT       "account"
#define POSIXACCOUNT  "posixAccount"
#define POSIXGROUP    "posixGroup"
#define SHADOWACCOUNT "shadowAccount"
#define INETORGPERSON "inetOrgPerson"
#define DISTINGUISHED_NAME "dn"

LU_MODULE_INIT(libuser_ldap_init)

enum lock_op { LO_LOCK, LO_UNLOCK, LO_UNLOCK_NONEMPTY };

enum interact_indices {
	LU_LDAP_SERVER,
	LU_LDAP_BASEDN,
	LU_LDAP_BINDDN,
	LU_LDAP_PASSWORD,
	LU_LDAP_AUTHUSER,
	LU_LDAP_AUTHZUSER,
	LU_LDAP_MAX,
};

static const struct {
	const char *lu_attribute;
	const char *ldap_attribute;
	const char *objectclass;
	enum lu_entity_type type;
} ldap_attribute_map[] = {
	{LU_USERNAME, "uid", POSIXACCOUNT, lu_user},
	{LU_USERPASSWORD, "userPassword", POSIXACCOUNT, lu_user},
	{LU_UIDNUMBER, "uidNumber", POSIXACCOUNT, lu_user},
	{LU_GIDNUMBER, "gidNumber", POSIXACCOUNT, lu_user},
	{LU_GECOS, "gecos", POSIXACCOUNT, lu_user},
	{LU_HOMEDIRECTORY, "homeDirectory", POSIXACCOUNT, lu_user},
	{LU_LOGINSHELL, "loginShell", POSIXACCOUNT, lu_user},
	{LU_COMMONNAME, "cn", POSIXACCOUNT, lu_user},

	{LU_GROUPNAME, "cn", POSIXGROUP, lu_group},
	{LU_GROUPPASSWORD, "userPassword", POSIXGROUP, lu_group},
	{LU_GIDNUMBER, "gidNumber", POSIXGROUP, lu_group},
	{LU_MEMBERNAME, "memberUid", POSIXGROUP, lu_group},

	{LU_SHADOWLASTCHANGE, "shadowLastChange", SHADOWACCOUNT, lu_user},
	{LU_SHADOWMIN, "shadowMin", SHADOWACCOUNT, lu_user},
	{LU_SHADOWMAX, "shadowMax", SHADOWACCOUNT, lu_user},
	{LU_SHADOWWARNING, "shadowWarning", SHADOWACCOUNT, lu_user},
	{LU_SHADOWINACTIVE, "shadowInactive", SHADOWACCOUNT, lu_user},
	{LU_SHADOWEXPIRE, "shadowExpire", SHADOWACCOUNT, lu_user},
	{LU_SHADOWFLAG, "shadowFlag", SHADOWACCOUNT, lu_user},

	{LU_GIVENNAME, "givenName", INETORGPERSON, lu_user},
	{LU_SN, "sn", INETORGPERSON, lu_user},
	{LU_ROOMNUMBER, "roomNumber", INETORGPERSON, lu_user},
	{LU_TELEPHONENUMBER, "telephoneNumber", INETORGPERSON, lu_user},
	{LU_HOMEPHONE, "homePhone", INETORGPERSON, lu_user},
};

static const char *const lu_ldap_user_attributes[] = {
	LU_USERNAME,
	LU_USERPASSWORD,
	LU_UIDNUMBER,
	LU_GIDNUMBER,
	LU_GECOS,
	LU_HOMEDIRECTORY,
	LU_LOGINSHELL,

	/* Not LU_SHADOWPASSWORD: We can't allow modification of
	 * LU_USERPASSWORD and LU_SHADOWPASSWORD at the same time; LDAP simply
	 * doesn't implement LU_SHADOWPASSWORD. */
	LU_SHADOWLASTCHANGE,
	LU_SHADOWMIN,
	LU_SHADOWMAX,
	LU_SHADOWWARNING,
	LU_SHADOWINACTIVE,
	LU_SHADOWEXPIRE,
	LU_SHADOWFLAG,

	LU_COMMONNAME,
	LU_GIVENNAME,
	LU_SN,
	LU_ROOMNUMBER,
	LU_TELEPHONENUMBER,
	LU_HOMEPHONE,

	NULL
};

static const char *const lu_ldap_group_attributes[] = {
	LU_GROUPNAME,
	LU_GROUPPASSWORD,
	LU_GIDNUMBER,
	LU_MEMBERNAME,
	LU_ADMINISTRATORNAME,

	NULL
};

struct lu_ldap_context {
	struct lu_context *global_context;	/* The library context. */
	struct lu_module *module;		/* The module's structure. */
	struct lu_prompt prompts[LU_LDAP_MAX];	/* Questions and answers. */
	gboolean bind_simple, bind_sasl;	/* What kind of bind to use. */
	char *sasl_mechanism;	/* What sasl mechanism to use. */
	const char *user_branch, *group_branch;	/* Cached config values */
	char **mapped_user_attributes, **mapped_group_attributes;
	LDAP *ldap;				/* The connection. */
};

static void
close_server(LDAP *ldap)
{
	ldap_unbind_ext(ldap, NULL, NULL);
}

/* Get the name of the user running the calling application. */
static char *
getuser(void)
{
	char buf[LINE_MAX * 4];
	struct passwd pwd, *err;
	int i;
	i = getpwuid_r(getuid(), &pwd, buf, sizeof(buf), &err);
	return ((i == 0) && (err == &pwd)) ? g_strdup(pwd.pw_name) : NULL;
}

static gboolean
nonempty(const char *string)
{
	return (string != NULL) && (strlen(string) > 0);
}

/* Connect to the server. */
static LDAP *
connect_server(struct lu_ldap_context *context, struct lu_error **error)
{
	LDAP *ldap = NULL;
	int version, ret, start_tls;

	g_assert(context != NULL);
	LU_ERROR_CHECK(error);

	/* Create the LDAP context. */
	ret = ldap_initialize(&ldap, context->prompts[LU_LDAP_SERVER].value);
	if (ret == LDAP_SUCCESS)
		start_tls = FALSE;
	else {
		if (ldap_create(&ldap) != LDAP_SUCCESS)
			ldap = NULL;
		else if (ldap_set_option(ldap, LDAP_OPT_HOST_NAME,
					 context->prompts[LU_LDAP_SERVER]
					 .value) != LDAP_SUCCESS) {
			close_server(ldap);
			ldap = NULL;
		}
		start_tls = TRUE;
	}
	if (ldap == NULL) {
		lu_error_new(error, lu_error_init,
			     _("error initializing ldap library"));
		return NULL;
	}

	/* Switch to LDAPv3, which gives us some more features we need. */
	version = LDAP_VERSION3;
	ret = ldap_set_option(ldap,
			      LDAP_OPT_PROTOCOL_VERSION,
			      &version);
	if (ret != LDAP_OPT_SUCCESS) {
		lu_error_new(error, lu_error_init,
			     _("could not set LDAP protocol to version %d"),
			     version);
		close_server(ldap);
		return NULL;
	}

	/* Skip STARTTLS for ldapi: Even if the server is set up for TLS in
	   general, NSS doesn't support TLS over AF_UNIX; the STARTTLS
	   operation would be accepted, but ldap_start_tls_s() would fail,
	   keeping the connection broken to make authentication impossible.
	   TLS on AF_UNIX does not make much sense anyway. */
	if (strncmp(context->prompts[LU_LDAP_SERVER].value, "ldapi://", 8)
	    != 0) {
        	/* Try to start TLS. */
	        ret = ldap_start_tls_s(ldap, NULL, NULL);
		/* Note that TLS is not required for ldap:// URLs (unlike simple
		   server names). */
		if (ret != LDAP_SUCCESS && start_tls) {
			lu_error_new(error, lu_error_init,
				     _("could not negotiate TLS with LDAP "
				       "server"));
			close_server(ldap);
			return NULL;
		}
	}

	return ldap;
}

/* Authentication callback. */
static int
interact(LDAP *ld, unsigned flags, void *defs, void *xres)
{
	sasl_interact_t *res;
	struct lu_ldap_context *ctx = (struct lu_ldap_context*) defs;
	int i, retval = LDAP_SUCCESS;

	(void)ld;
	(void)flags;
	res = xres;
	for(i = 0; res && res[i].id != SASL_CB_LIST_END; i++) {
		res[i].result = NULL;
		switch(res[i].id) {
		case SASL_CB_USER:
			res[i].result = ctx->prompts[LU_LDAP_AUTHUSER].value;
			if (res[i].result == NULL)
				res[i].result = "";
#ifdef DEBUG
			g_print("Sending SASL user `%s'.\n",
				(const char *)res[i].result);
#endif
			break;
		case SASL_CB_AUTHNAME:
			res[i].result = ctx->prompts[LU_LDAP_AUTHZUSER].value;
#ifdef DEBUG
			g_print("Sending SASL auth user `%s'.\n",
				(const char *)res[i].result);
#endif
			break;
		case SASL_CB_GETREALM:
			/* Always tell sasl to find it on its own. */
			res[i].result = "";
			break;
		default:
#ifdef DEBUG
			g_print("Unhandled SASL Intreractive option `%lu'.\n",
				res[i].id);
#endif
			retval = LDAP_OTHER;
		}
		if (res[i].result != NULL)
			res[i].len = strlen(res[i].result);
		else
			res[i].len = 0;
	}
	return retval;
}

/* Authenticate to the server. */
static LDAP *
bind_server(struct lu_ldap_context *context, struct lu_error **error)
{
	LDAP *ldap;
	int ret, first_failure;
	const char *generated_binddn, *first_binddn;
	char *binddn, *tmp;
	char *user;
	char *password;
	struct lu_string_cache *scache = NULL;

	g_assert(context != NULL);
	LU_ERROR_CHECK(error);

	/* Create the connection. */
	ldap = connect_server(context, error);
	if (ldap == NULL) {
		return NULL;
	}

	/* Generate the DN we might want to bind to. */
	scache = context->global_context->scache;
	user = getuser();
	if (user) {
		tmp = scache->cache(scache, user);
		free(user);
		user = tmp;
	}
	if (nonempty(context->prompts[LU_LDAP_AUTHUSER].value)) {
		user = context->prompts[LU_LDAP_AUTHUSER].value;
	}
	tmp = g_strdup_printf("uid=%s,%s,%s", user, context->user_branch,
			      context->prompts[LU_LDAP_BASEDN].value);
	generated_binddn = scache->cache(scache, tmp);
	g_free(tmp);

	/* Try to bind to the server using SASL. */
	binddn = context->prompts[LU_LDAP_BINDDN].value;
	if (nonempty(context->prompts[LU_LDAP_AUTHUSER].value)) {
		ldap_set_option(ldap, LDAP_OPT_X_SASL_AUTHCID,
				context->prompts[LU_LDAP_AUTHUSER].value);
	}
	if (nonempty(context->prompts[LU_LDAP_AUTHZUSER].value)) {
		ldap_set_option(ldap, LDAP_OPT_X_SASL_AUTHZID,
				context->prompts[LU_LDAP_AUTHZUSER].value);
	}
	if (context->prompts[LU_LDAP_PASSWORD].value != NULL) {
		password = context->prompts[LU_LDAP_PASSWORD].value;
	} else {
		password = NULL;
	}

	ret = LDAP_SUCCESS + 1; /* Not LDAP_SUCCESS */
	first_failure = LDAP_SUCCESS; /* No failure known yet */
	first_binddn = NULL;

	if ((binddn != NULL) && (strlen(binddn) == 0)) {
		binddn = NULL;
	}
	if (context->bind_sasl) {
		/* Try to bind using SASL, and if that fails... */
		if (binddn != NULL) {
#ifdef DEBUG
			g_print("Attempting SASL bind to `%s'.\n", binddn);
#endif
			ret = ldap_sasl_interactive_bind_s(ldap, binddn,
							   context->sasl_mechanism,
							   NULL, NULL,
							   LDAP_SASL_AUTOMATIC,
							   interact,
							   context);
			if (ret != LDAP_SUCCESS) {
				first_failure = ret;
				first_binddn = binddn;
			}
		}
		if (ret != LDAP_SUCCESS) {
#ifdef DEBUG
			g_print("Attempting SASL bind to `%s'.\n",
				generated_binddn);
#endif
			ret = ldap_sasl_interactive_bind_s(ldap,
							   generated_binddn,
							   context->sasl_mechanism,
							   NULL, NULL,
							   LDAP_SASL_AUTOMATIC,
							   interact, context);
			if (ret != LDAP_SUCCESS
			    && first_failure == LDAP_SUCCESS) {
				first_failure = ret;
				first_binddn = generated_binddn;
			}
		}
	}
	if (ret != LDAP_SUCCESS && context->bind_simple) {
		/* try to bind using a password, and if that fails... */
		if ((password != NULL) && (strlen(password) > 0)) {
			BerValue cred;

			cred.bv_val = password;
			cred.bv_len = strlen(password);
			if (binddn != NULL) {
#ifdef DEBUG
				g_print("Attempting simple bind to `%s'.\n",
					binddn);
#endif
				ret = ldap_sasl_bind_s(ldap, binddn,
						       LDAP_SASL_SIMPLE, &cred,
						       NULL, NULL, NULL);
				if (ret != LDAP_SUCCESS
				    && first_failure == LDAP_SUCCESS) {
					first_failure = ret;
					first_binddn = binddn;
				}
			}
			if (ret != LDAP_SUCCESS) {
#ifdef DEBUG
				g_print("Attempting simple bind to `%s'.\n",
					generated_binddn);
#endif
				ret = ldap_sasl_bind_s(ldap, generated_binddn,
						       LDAP_SASL_SIMPLE, &cred,
						       NULL, NULL, NULL);
				if (ret != LDAP_SUCCESS
				    && first_failure == LDAP_SUCCESS) {
					first_failure = ret;
					first_binddn = generated_binddn;
				}
			}
		}
	}
	if (ret != LDAP_SUCCESS) {
		/* give up. */
		if (first_failure == LDAP_SUCCESS)
			lu_error_new(error, lu_error_init,
				     _("could not bind to LDAP server"));
		else
			lu_error_new(error, lu_error_init,
				     _("could not bind to LDAP server, first "
				       "attempt as `%s': %s"), first_binddn,
				     ldap_err2string(first_failure));
		close_server(ldap);
		return NULL;
	}
	return ldap;
}

/* Map an attribute name from an internal name to an LDAP atribute name. */
static const char *
map_to_ldap(struct lu_string_cache *cache, const char *libuser_attribute)
{
	size_t i;

	/* Luckily the only duplicate is LU_GIDNUMBER, which maps to the
	   same value in both cases. */
	for (i = 0; i < G_N_ELEMENTS(ldap_attribute_map); i++) {
		if (g_ascii_strcasecmp(ldap_attribute_map[i].lu_attribute,
				       libuser_attribute) == 0) {
			return ldap_attribute_map[i].ldap_attribute;
		}
	}
	return cache->cache(cache, libuser_attribute);
}

/* Generate the distinguished name which corresponds to the container where
 * the lu_ent structure's entry would be found. */
static const char *
lu_ldap_base(struct lu_module *module, const char *branch)
{
	struct lu_ldap_context *context;
	char *tmp, *ret;

	g_assert(module != NULL);
	context = module->module_context;

	/* Generate the branch DN. */
	if (strlen(branch) != 0)
		tmp = g_strconcat(branch, ",",
				  context->prompts[LU_LDAP_BASEDN].value,
				  (const gchar *)NULL);
	else
		tmp = g_strdup(context->prompts[LU_LDAP_BASEDN].value);

	ret = module->scache->cache(module->scache, tmp);

	g_free(tmp);

	return ret;
}

/* Discover the distinguished name which corresponds to an account. */
static const char *
lu_ldap_ent_to_dn(struct lu_module *module, const char *namingAttr,
		  const char *name, const char *branch)
{
	static char *noattrs[] = { NULL };

	const char *base, *mapped_naming_attr;
	char *tmp, *ret = NULL, *filter;
	struct lu_ldap_context *ctx;
	LDAPMessage *messages = NULL;

	g_assert(module != NULL);
	g_assert(namingAttr != NULL);
	g_assert(strlen(namingAttr) > 0);
	g_assert(name != NULL);
	g_assert(strlen(name) > 0);

	/* Search for the right object using the entity's current name. */
	base = lu_ldap_base(module, branch);
	ctx = module->module_context;

	mapped_naming_attr = map_to_ldap(module->scache, namingAttr);
	filter = g_strdup_printf("(%s=%s)", mapped_naming_attr, name);
	if (ldap_search_ext_s(ctx->ldap, base, LDAP_SCOPE_SUBTREE, filter,
			      noattrs, FALSE, NULL, NULL, NULL, LDAP_NO_LIMIT,
			      &messages) == LDAP_SUCCESS) {
		LDAPMessage *entry;

		entry = ldap_first_entry(ctx->ldap, messages);
		if (entry != NULL) {
			tmp = ldap_get_dn(ctx->ldap, entry);
			ret = module->scache->cache(module->scache, tmp);
			if (tmp)
				ldap_memfree(tmp);
		}
		ldap_msgfree(messages);
	}
	g_free(filter);

	if (ret == NULL) {
		/* Guess at the DN using the branch and the base. */
		tmp = g_strdup_printf("%s=%s,%s", mapped_naming_attr, name,
				      base);
		ret = module->scache->cache(module->scache, tmp);
		g_free(tmp);
	}

	return ret;
}

/* This is the lookup workhorse. */
static gboolean
lu_ldap_lookup(struct lu_module *module,
	       const char *namingAttr, const char *name,
	       struct lu_ent *ent, GPtrArray *ent_array, const char *branch,
	       const char *filter, const char *const *attributes,
	       enum lu_entity_type type, struct lu_error **error)
{
	LDAPMessage *messages = NULL, *entry = NULL;
	char *filt, **mapped_attributes;
	const char *dn = NULL;
	const char *base;
	gboolean ret = FALSE;
	struct lu_ldap_context *ctx;

	g_assert(module != NULL);
	g_assert(namingAttr != NULL);
	g_assert(strlen(namingAttr) > 0);
	name = name ?: "*";
	g_assert((ent != NULL) || (ent_array != NULL));
	if (ent != NULL) {
		g_assert(ent->magic == LU_ENT_MAGIC);
	}
	g_assert(attributes != NULL);
	g_assert(attributes[0] != NULL);
	LU_ERROR_CHECK(error);

	ctx = module->module_context;

	if (ent != NULL) {
		/* Try to use the dn the object already knows about. */
		dn = lu_ent_get_first_string(ent, DISTINGUISHED_NAME);
		if (dn == NULL)
			/* Map the user or group name to an LDAP object name. */
			dn = lu_ldap_ent_to_dn(module, namingAttr, name,
					       branch);
	}

	/* Get the entry in the directory under which we'll search for this
	 * entity. */
	base = lu_ldap_base(module, branch);

	/* Generate an LDAP filter, optionally including a filter supplied
	 * by the caller. */
	if (filter && (strlen(filter) > 0)) {
		filt = g_strdup_printf("(&%s(%s=%s))", filter,
				       namingAttr, name);
	} else {
		filt = g_strdup_printf("(%s=%s)", namingAttr, name);
	}

#ifdef DEBUG
	g_print("Looking up `%s' with filter `%s'.\n", dn, filt);
#endif

	if (attributes == lu_ldap_user_attributes)
		mapped_attributes = ctx->mapped_user_attributes;
	else if (attributes == lu_ldap_group_attributes)
		mapped_attributes = ctx->mapped_group_attributes;
	else {
		g_assert_not_reached();
		mapped_attributes = NULL;
	}

	if (ent != NULL) {
		/* Perform the search and read the first (hopefully only)
		 * entry. */
		if (ldap_search_ext_s(ctx->ldap, dn, LDAP_SCOPE_BASE, filt,
				      mapped_attributes, FALSE, NULL, NULL,
				      NULL, LDAP_NO_LIMIT, &messages)
		    == LDAP_SUCCESS) {
			entry = ldap_first_entry(ctx->ldap, messages);
		}
	}

	/* If there isn't an entry with this exact name, search for something
	 * which matches. */
	if (entry == NULL) {
#ifdef DEBUG
		g_print("Looking under `%s' with filter `%s'.\n", base,
			filt);
#endif
		if (messages != NULL) {
			ldap_msgfree(messages);
			messages = NULL;
		}
		if (ldap_search_ext_s(ctx->ldap, base, LDAP_SCOPE_SUBTREE,
				      filt, mapped_attributes, FALSE, NULL,
				      NULL, NULL, LDAP_NO_LIMIT, &messages)
		    == LDAP_SUCCESS) {
			entry = ldap_first_entry(ctx->ldap, messages);
		}
	}

	/* We don't need the generated filter any more, so free it. */
	g_free(filt);

	/* If we got an entry, read its contents into an entity structure. */
	while (entry != NULL) {
		GValue value;
		size_t i;
		char *p;

		/* Mark that the search succeeded. */
		ret = TRUE;
		/* If we need to add the data to the array, then create a new
		 * data item to hold the data. */
		if (ent_array != NULL)
			ent = lu_ent_new_typed(type);
		/* Set the distinguished name. */
		p = ldap_get_dn(ctx->ldap, entry);
		lu_ent_set_string_current(ent, DISTINGUISHED_NAME, p);
		ldap_memfree(p);

		/* Read each of the attributes we asked for. */
		memset(&value, 0, sizeof(value));
		for (i = 0; attributes[i]; i++) {
			BerValue **values;
			const char *attr;

			/* Get the values which correspond to this attribute. */
			attr = attributes[i];
			values = ldap_get_values_len(ctx->ldap, entry,
						     mapped_attributes[i]);
			/* If we got answers, add them. */
			if (values) {
				size_t j;

				lu_ent_clear_current(ent, attr);
				for (j = 0; values[j]; j++) {
					char *val;
					gboolean ok;
					struct lu_error *error;

					val = g_strndup(values[j]->bv_val,
							values[j]->bv_len);
#ifdef DEBUG
					g_print("Got `%s' = `%s'.\n", attr,
						val);
#endif
					error = NULL;
					ok = lu_value_init_set_attr_from_string
						(&value, attr, val, &error);
					if (ok == FALSE) {
						g_assert(error != NULL);
						g_warning(lu_strerror(error));
						lu_error_free(&error);
					} else {
						lu_ent_add_current(ent, attr,
								   &value);
						g_value_unset(&value);
					}
					g_free(val);
				}
				ldap_value_free_len(values);
			}
		}
		/* Stash the data in the array if we need to. */
		if (ent_array != NULL) {
			g_ptr_array_add(ent_array, ent);
			ent = NULL;
			/* Go to the next entry. */
			entry = ldap_next_entry(ctx->ldap, entry);
		} else {
			/* Stop here. */
			entry = NULL;
		}
	}
	/* Free all of the responses. */
	if (messages) {
		ldap_msgfree(messages);
	}

	return ret;
}

/* Look up a user by name. */
static gboolean
lu_ldap_user_lookup_name(struct lu_module *module, const char *name,
			 struct lu_ent *ent, struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_lookup(module, "uid", name, ent, NULL, ctx->user_branch,
			      "("OBJECTCLASS"="POSIXACCOUNT")",
			      lu_ldap_user_attributes, lu_user, error);
}

/* Look up a user by ID. */
static gboolean
lu_ldap_user_lookup_id(struct lu_module *module, uid_t uid,
		       struct lu_ent *ent, struct lu_error **error)
{
	struct lu_ldap_context *ctx;
	char uid_string[sizeof (uid) * CHAR_BIT + 1];

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	sprintf(uid_string, "%jd", (intmax_t)uid);
	return lu_ldap_lookup(module, "uidNumber", uid_string, ent, NULL,
			      ctx->user_branch,
			      "("OBJECTCLASS"="POSIXACCOUNT")",
			      lu_ldap_user_attributes, lu_user, error);
}

/* Look up a group by name. */
static gboolean
lu_ldap_group_lookup_name(struct lu_module *module, const char *name,
			  struct lu_ent *ent, struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_lookup(module, "cn", name, ent, NULL, ctx->group_branch,
			      "("OBJECTCLASS"="POSIXGROUP")",
			      lu_ldap_group_attributes, lu_group, error);
}

/* Look up a group by ID. */
static gboolean
lu_ldap_group_lookup_id(struct lu_module *module, gid_t gid,
			struct lu_ent *ent, struct lu_error **error)
{
	struct lu_ldap_context *ctx;
	char gid_string[sizeof (gid) * CHAR_BIT + 1];

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	sprintf(gid_string, "%jd", (intmax_t)gid);
	return lu_ldap_lookup(module, "gidNumber", gid_string, ent, NULL,
			      ctx->group_branch,
			      "("OBJECTCLASS"="POSIXGROUP")",
			      lu_ldap_group_attributes, lu_group, error);
}

/* Compare the contents of two GValueArrays, and return TRUE if they contain
 * the same set of values, though not necessarily in the same order. */
static gboolean
arrays_equal(GValueArray *a, GValueArray *b)
{
	GValue *aval, *bval;
	size_t i, j;

	for (i = 0; i < a->n_values; i++) {
		aval = g_value_array_get_nth(a, i);
		for (j = 0; j < b->n_values; j++) {
			bval = g_value_array_get_nth(b, j);
			if (G_VALUE_TYPE(aval) == G_VALUE_TYPE(bval)
			    && lu_values_equal(aval, bval))
				break;
		}
		if (j >= b->n_values) {
			return FALSE;
		}
	}
	for (j = 0; j < b->n_values; j++) {
		bval = g_value_array_get_nth(b, j);
		for (i = 0; i < a->n_values; i++) {
			aval = g_value_array_get_nth(a, i);
			if (G_VALUE_TYPE(aval) == G_VALUE_TYPE(bval)
			    && lu_values_equal(aval, bval))
				break;
		}
		if (i >= a->n_values) {
			return FALSE;
		}
	}
	return TRUE;
}

/* Check whether class is among old_values or new_values */
static int
objectclass_present(const char *dn, const char *class,
		    BerValue *const *old_values, size_t old_count,
		    BerValue *const *new_values, size_t new_count)
{
	size_t i, len;

	(void)dn;
	len = strlen(class);
	for (i = 0; i < old_count; i++) {
		const BerValue *val;

		val = old_values[i];
		if (val->bv_len == len
		    && memcmp(class, val->bv_val, len) == 0) {
#ifdef DEBUG
			g_print("Entity `%s' is already a `%.*s'.\n", dn,
				(int)val->bv_len, val->bv_val);
#endif
			return 1;
		}
	}
	for (i = 0; i < new_count; i++) {
		const BerValue *val;

		val = new_values[i];
		if (val->bv_len == len
		    && memcmp(class, val->bv_val, len) == 0) {
#ifdef DEBUG
			g_print("Entity `%s' was already determined to be a "
				"`%.*s'.\n", dn, (int)val->bv_len,
				val->bv_val);
#endif
			return 1;
		}
	}
	return 0;
}

/* Create a list of new object classes needed for representing all attributes,
 * assuming old_values (may be NULL).
 *
 * Returns NULL if no new object classes are needed. */
static BerValue **
lu_ldap_needed_objectclasses(const char *dn, struct lu_ent *ent,
			     BerValue **old_values)
{
	BerValue **new_values;
	size_t old_count, new_count;
	GList *attributes, *a;

	if (old_values)
		old_count = ldap_count_values_len(old_values);
	else
		old_count = 0;

	new_values = g_malloc_n(G_N_ELEMENTS(ldap_attribute_map) + 1 + 1,
				sizeof(*new_values));
	new_count = 0;

	/* Iterate over all of the attributes the object possesses. */
	attributes = lu_ent_get_attributes(ent);
	for (a = attributes; a != NULL; a = a->next) {
		size_t i;
		const char *attr;
		BerValue *bv;

		attr = a->data;
#ifdef DEBUG
		g_print("Entity `%s' has attribute `%s'.\n", dn, attr);
#endif
		/* Get the name of the next object class the object needs
		 * to be a member of. */
		for (i = 0; i < G_N_ELEMENTS(ldap_attribute_map); i++) {
			if (ldap_attribute_map[i].type == ent->type
			    && strcasecmp(ldap_attribute_map[i].lu_attribute,
					  attr) == 0) {
#ifdef DEBUG
				g_print("Entity `%s' needs to be a `%s'.\n",
					dn, ldap_attribute_map[i].objectclass);
#endif
				break;
			}
		}
		/* If the attribute doesn't map to a class, skip it. */
		if (i >= G_N_ELEMENTS(ldap_attribute_map))
			continue;
		/* Check if the object class the object needs to be in is
		 * already one of which it is a part or is already being
		 * added. */
		if (objectclass_present(dn, ldap_attribute_map[i].objectclass,
					old_values, old_count, new_values,
					new_count))
			continue;

		/* Add it to the class. */
		bv = g_malloc(sizeof (*bv));
		bv->bv_val = (char *)ldap_attribute_map[i].objectclass;
		bv->bv_len = strlen(bv->bv_val);
		new_values[new_count] = bv;
#ifdef DEBUG
		g_print("Adding entity `%s' to class `%s'.\n", dn,
			ldap_attribute_map[i].objectclass);
#endif
		new_count++;
	}
	g_list_free(attributes);
	/* Ugly, but implied by the fact that the basic account schemas are not
	 * structural.  We can't use INETORGPERSON unless LU_SN is present,
	 * which would already force usage of INETORGPERSON; so if
	 * INETORGPERSON is not used, we add ACCOUNT. */
	if (ent->type == lu_user
	    && !objectclass_present(dn, INETORGPERSON, old_values, old_count,
				    new_values, new_count)
	    && !objectclass_present(dn, ACCOUNT, old_values, old_count,
				    new_values, new_count)) {
		BerValue *bv;

		bv = g_malloc(sizeof (*bv));
		bv->bv_val = ACCOUNT;
		bv->bv_len = strlen(ACCOUNT);
		new_values[new_count++] = bv;
	}
	if (new_count != 0)
		new_values[new_count] = NULL;
	else {
		g_free(new_values);
		new_values = NULL;
	}
	return new_values;
}

/* Free the (non-NULL) result of ldap_needed_objectclasses */
static void
free_needed_objectclasses(BerValue **values)
{
	size_t i;

	for (i = 0; values[i] != NULL; i++)
		g_free(values[i]);
	g_free(values);
}


/* Build a list of LDAPMod structures for adding the entity object. */
static LDAPMod **
get_ent_adds(const char *dn, struct lu_ent *ent)
{
	LDAPMod **mods;
	GList *attrs;

	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);

	mods = NULL;
	/* If there are no attributes, then this is EASY. */
	attrs = lu_ent_get_attributes(ent);
	if (attrs) {
		BerValue **classes;
		size_t mod_count, i;
		LDAPMod *mod;
		GValueArray *vals;
		GValue *value;
		const GList *a;

		mods = g_malloc0_n(g_list_length(attrs) + 2 + 1, sizeof(*mods));
		mod_count = 0;
		for (a = attrs; a != NULL; a = a->next) {
			const char *attribute;

			attribute = a->data;
			if (strcasecmp(attribute, DISTINGUISHED_NAME) == 0)
				continue;
			/* We don't have shadow passwords.  Period. */
			if (strcasecmp(attribute, LU_SHADOWPASSWORD) == 0)
				continue;
			vals = lu_ent_get(ent, attribute);
			if (vals == NULL)
				continue;
			attribute = map_to_ldap(ent->cache, attribute);

			mod = g_malloc0(sizeof(*mod));
			mod->mod_op = LDAP_MOD_ADD;
			mod->mod_type = (char *)attribute;
			mod->mod_values = g_malloc0_n(vals->n_values + 1,
						      sizeof(*mod->mod_values));
			for (i = 0; i < vals->n_values; i++) {
				value = g_value_array_get_nth(vals, i);
				mod->mod_values[i] = lu_value_strdup(value);
			}
			mods[mod_count++] = mod;
		}
		/* We don't need the list of attributes any more. */
		g_list_free(attrs);
		classes = lu_ldap_needed_objectclasses(dn, ent, NULL);
		if (classes != NULL) {
			mod = g_malloc0(sizeof(*mod));
			mod->mod_op = LDAP_MOD_ADD;
			mod->mod_type = OBJECTCLASS;
			mod->mod_values
				= g_malloc0_n(ldap_count_values_len(classes)
					      + 1, sizeof(*mod->mod_values));
			for (i = 0; classes[i] != NULL; i++)
				mod->mod_values[i]
					= g_strdup(classes[i]->bv_val);
			free_needed_objectclasses(classes);
			mods[mod_count++] = mod;
		}
		/* Ugly hack:
		 *
		 * Make sure there is 'cn', posixAccount requires it. */
		if (ent->type == lu_user
		    && lu_ent_get(ent, LU_COMMONNAME) == NULL) {
			char *cn;

			cn = lu_ent_get_first_value_strdup(ent, LU_GECOS);
			if (cn != NULL) {
				char *p;

				p = strchr(cn, ',');
				if (p != NULL)
					*p = 0;
				/* Note that gecos may be empty, but
				   commonName (as a DirectoryString) is not
				   allowed to be empty. */
			}
			if (cn == NULL || *cn == 0) {
				g_free(cn);
				cn = lu_ent_get_first_value_strdup(ent,
								   LU_USERNAME);
				/* Guaranteed by lu_ldap_set() */
				g_assert (cn != NULL);
			}
			mod = g_malloc0(sizeof(*mod));
			mod->mod_op = LDAP_MOD_ADD;
			mod->mod_type = (char *)"cn";
			mod->mod_values
				= g_malloc0(2 * sizeof (*mod->mod_values));
			mod->mod_values[0] = cn;
			mods[mod_count++] = mod;
		}
	}
	return mods;
}

/* Build a list of LDAPMod structures based on the differences between the
 * pending and current values in the entity object. */
static LDAPMod **
get_ent_mods(struct lu_ent *ent, const char *namingAttr)
{
	LDAPMod **mods = NULL;
	GList *attrs;

	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);
	g_assert(namingAttr != NULL);
	g_assert(namingAttr[0] != 0);

	/* If there are no attributes, then this is EASY. */
	attrs = lu_ent_get_attributes(ent);
	if (attrs) {
		GValueArray *empty;
		size_t mod_count;
		LDAPMod *mod;
		const GList *a;

		empty = g_value_array_new(0);
		/* Allocate an array big enough to hold two LDAPMod structures
		 * for each attribute, in case all of them need changing. */
		mods = g_malloc0_n(2 * g_list_length(attrs) + 1, sizeof(*mods));
		mod_count = 0;
		for (a = attrs; a != NULL; a = a->next) {
			GValueArray *current, *pending, *additions, *deletions;
			GValue *value, *pvalue, *cvalue;
			char *attribute;
			size_t j, k;

			/* Get the name of the attribute, and its current and
			 * pending values. */
			attribute = a->data;
			if (strcasecmp(attribute, DISTINGUISHED_NAME) == 0
			    || strcasecmp(attribute, namingAttr) == 0)
				continue;
			current = lu_ent_get_current(ent, attribute) ?: empty;
			pending = lu_ent_get(ent, attribute) ?: empty;
			additions = g_value_array_new(0);
			deletions = g_value_array_new(0);
			attribute = (char *)map_to_ldap(ent->cache, attribute);

			/* Create a pair of modification request structures,
			 * using the LDAP name for the attribute, using
			 * elements from the first array which aren't in the
			 * second for the remove list, and elements which are
			 * in the second but not the first for the add list. */
			for (j = 0; j < current->n_values; j++) {
				cvalue = g_value_array_get_nth(current, j);
				/* Search for this value in the other array. */
				for (k = 0; k < pending->n_values; k++) {
					pvalue = g_value_array_get_nth(pending,
								       k);
					if (G_VALUE_TYPE(cvalue)
					    == G_VALUE_TYPE(pvalue)
					    && lu_values_equal(cvalue, pvalue))
						break;
				}
				/* If not found, it's a mod. */
				if (k >= pending->n_values)
					/* Delete this value. */
					g_value_array_append(deletions, cvalue);
			}
			/* If we have deletions, create an LDAPMod structure
			 * containing them. */
			if (deletions->n_values != 0) {
				mod = g_malloc0(sizeof(*mod));
				mod->mod_op = LDAP_MOD_DELETE;
				mod->mod_type = attribute;
				mod->mod_values
					= g_malloc0_n(deletions->n_values + 1,
						      sizeof(*mod->mod_values));
				for (j = 0; j < deletions->n_values; j++) {
					value = g_value_array_get_nth(deletions, j);
					mod->mod_values[j]
						= lu_value_strdup(value);
				}
				mods[mod_count++] = mod;
			}

			/* Now extract additions. */
			for (j = 0; j < pending->n_values; j++) {
				pvalue = g_value_array_get_nth(pending, j);
				/* Search for this value in the other array. */
				for (k = 0; k < current->n_values; k++) {
					cvalue = g_value_array_get_nth(current,
								       k);
					if (G_VALUE_TYPE(cvalue)
					    == G_VALUE_TYPE(pvalue)
					    && lu_values_equal(cvalue, pvalue))
						break;
				}
				/* If not found, it's a mod. */
				if (k >= current->n_values)
					/* Add this value. */
					g_value_array_append(additions, pvalue);
			}
			/* If we have additions, create an LDAPMod structure
			 * containing them. */
			if (additions->n_values != 0) {
				mod = g_malloc0(sizeof(*mod));
				mod->mod_op = LDAP_MOD_ADD;
				mod->mod_type = attribute;
				mod->mod_values
					= g_malloc0_n(additions->n_values + 1,
						      sizeof(*mod->mod_values));
				for (j = 0; j < additions->n_values; j++) {
					value = g_value_array_get_nth(additions, j);
					mod->mod_values[j]
						= lu_value_strdup(value);
				}
				mods[mod_count++] = mod;
			}

			g_value_array_free(additions);
			g_value_array_free(deletions);
		}
		g_value_array_free(empty);
		/* We don't need the list of attributes any more. */
		g_list_free(attrs);
	}
	return mods;
}

/* Free a set of modification structures generated by get_ent_mods(). */
static void
free_ent_mods(LDAPMod ** mods)
{
	size_t i;

	g_assert(mods != NULL);
	for (i = 0; mods && mods[i]; i++) {
		if (mods[i]->mod_values) {
			size_t j;

			for (j = 0; mods[i]->mod_values[j] != NULL; j++) {
				g_free(mods[i]->mod_values[j]);
			}
			g_free(mods[i]->mod_values);
		}
		g_free(mods[i]);
	}
	g_free(mods);
}

#ifdef DEBUG
/* Dump out the modifications structure.  For debugging only. */
static void
dump_mods(LDAPMod ** mods)
{
	size_t i;

	if (mods == NULL) {
		g_print("NULL modifications");
		return;
	}
	for (i = 0; mods[i]; i++) {
		g_print("%s (%d)\n", mods[i]->mod_type, mods[i]->mod_op);
		if (mods[i]->mod_values) {
			size_t j;

			for (j = 0; mods[i]->mod_values[j]; j++) {
				g_print(" = `%s'\n",
					mods[i]->mod_values[j]);
			}
		}
	}
}
#endif /* DEBUG */

/* Add an entity's LDAP object to the proper object classes to allow the
 * user to possess the attributes she needs to. */
static void
lu_ldap_fudge_objectclasses(struct lu_ldap_context *ctx,
			    const char *dn,
			    struct lu_ent *ent)
{
	static char *attrs[] = {
		OBJECTCLASS,
		NULL,
	};

	BerValue **old_values, **new_values;
	LDAPMessage *res = NULL;
	LDAPMessage *entry;

	/* Pull up this object's entry. */
	if (ldap_search_ext_s(ctx->ldap, dn, LDAP_SCOPE_BASE, NULL, attrs,
			      FALSE, NULL, NULL, NULL, LDAP_NO_LIMIT, &res)
	    != LDAP_SUCCESS) {
		return;
	}

	entry = ldap_first_entry(ctx->ldap, res);
	if (entry == NULL) {
		ldap_msgfree(res);
		return;
	}

	/* Get the list of object classes the object is in now. */
	old_values = ldap_get_values_len(ctx->ldap, entry, OBJECTCLASS);

	new_values = lu_ldap_needed_objectclasses(dn, ent, old_values);
	if (new_values != NULL) {
		int err;
		LDAPMod mod;
		LDAPMod *mods[] = { &mod, NULL };
#ifdef DEBUG
		g_print("Adding user `%s' to new classes.\n", dn);
#endif
		/* Set up the modify request. */
		memset(&mod, 0, sizeof(mod));
		mod.mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
		mod.mod_type = OBJECTCLASS;
		mod.mod_bvalues = new_values;

		/* Give it the old try. */
#ifdef DEBUG
		dump_mods(mods);
#endif
		err = ldap_modify_ext_s(ctx->ldap, dn, mods, NULL, NULL);
		(void)err;
#ifdef DEBUG
		g_message("Fudged: `%s'.\n", ldap_err2string(err));
#endif
		free_needed_objectclasses(new_values);
	}
	ldap_value_free_len(old_values);

	ldap_msgfree(res);
}

/* Apply the changes to a given entity structure, or add a new entitty. */
static gboolean
lu_ldap_set(struct lu_module *module, enum lu_entity_type type, int add,
	    struct lu_ent *ent, const char *branch, struct lu_error **error)
{
	LDAPMod **mods;
	GValueArray *name, *old_name;
	GValue *value;
	char *name_string;
	const char *dn, *namingAttr;
	int err;
	gboolean ret;
	struct lu_ldap_context *ctx;

	g_assert(module != NULL);
	g_assert((type == lu_user) || (type == lu_group));
	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);
	LU_ERROR_CHECK(error);

	ctx = module->module_context;

	/* Get the user/group's pending name, which may be different from the
	 * current name.  If so, we want to change it seperately, because it
	 * requires a renaming of the object in the directory. */
	if (type == lu_user)
		namingAttr = LU_USERNAME;
	else
		namingAttr = LU_GROUPNAME;
	name = lu_ent_get(ent, namingAttr);
	if (name == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("user object had no %s attribute"),
			     namingAttr);
		return FALSE;
	}

	/* Get the object's old (current) name. */
	old_name = lu_ent_get_current(ent, namingAttr);
	if (old_name == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("user object was created with no `%s'"),
			     namingAttr);
		return FALSE;
	}

	/* Get the object's current object name. */
	value = g_value_array_get_nth(add ? name : old_name, 0);
	name_string = lu_value_strdup(value);
	dn = lu_ldap_ent_to_dn(module, namingAttr, name_string, branch);
	g_free(name_string);

	if (add) {
		mods = get_ent_adds(dn, ent);
#ifdef DEBUG
		dump_mods(mods);
		g_message("Adding `%s'.\n", dn);
#endif
		err = ldap_add_ext_s(ctx->ldap, dn, mods, NULL, NULL);
		if (err != LDAP_SUCCESS) {
			lu_error_new(error, lu_error_write,
				     _("error creating a LDAP directory "
				       "entry: %s"), ldap_err2string(err));
			ret = FALSE;
			goto err_mods;
		}
	} else {
		mods = get_ent_mods(ent, namingAttr);
#ifdef DEBUG
		dump_mods(mods);
		g_message("Modifying `%s'.\n", dn);
#endif
		/* Attempt the modify operation.  The Fedora Directory server
		   rejects modify operations with no modifications. */
		if (mods != NULL && mods[0] != NULL) {
			err = ldap_modify_ext_s(ctx->ldap, dn, mods, NULL,
						NULL);
			if (err == LDAP_OBJECT_CLASS_VIOLATION) {
				/* AAAARGH!  The application decided it wanted
				 * to add some new attributes!  Damage
				 * control.... */
				lu_ldap_fudge_objectclasses(ctx, dn, ent);
				err = ldap_modify_ext_s(ctx->ldap, dn, mods,
							NULL, NULL);
			}
			if (err != LDAP_SUCCESS) {
				lu_error_new(error, lu_error_write,
					     _("error modifying LDAP "
					       "directory entry: %s"),
					     ldap_err2string(err));
				ret = FALSE;
				goto err_mods;
			}
		}

		/* If the name has changed, process a rename (modrdn). */
		if (arrays_equal(name, old_name) == FALSE) {
			char *tmp1, *tmp2;

			/* Format the name to rename it to. */
			value = g_value_array_get_nth(name, 0);
			tmp1 = lu_value_strdup(value);
			tmp2 = g_strconcat(map_to_ldap(module->scache,
						       namingAttr), "=",
					   tmp1, NULL);
			g_free (tmp1);
			/* Attempt the rename. */
			err = ldap_rename_s(ctx->ldap, dn, tmp2, NULL, TRUE,
					    NULL, NULL);
			g_free(tmp2);
			if (err != LDAP_SUCCESS) {
				lu_error_new(error, lu_error_write,
					     _("error renaming LDAP directory "
					       "entry: %s"),
					     ldap_err2string(err));
				ret = FALSE;
				goto err_mods;
			}
		}
	}
	ret = TRUE;

 err_mods:
	free_ent_mods(mods);

	return ret;
}

/* Remove an entry from the directory. */
static gboolean
lu_ldap_del(struct lu_module *module, enum lu_entity_type type,
	    struct lu_ent *ent, const char *branch, struct lu_error **error)
{
	char *name;
	const char *dn, *namingAttr;
	int err;
	gboolean ret = FALSE;
	struct lu_ldap_context *ctx;

	g_assert(module != NULL);
	g_assert((type == lu_user) || (type == lu_group));
	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);
	LU_ERROR_CHECK(error);

	ctx = module->module_context;

	/* Get the user or group's name. */
	if (type == lu_user) {
		namingAttr = LU_USERNAME;
	} else {
		namingAttr = LU_GROUPNAME;
	}

	name = lu_ent_get_first_value_strdup(ent, namingAttr);
	if (name == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("object had no %s attribute"), namingAttr);
		return FALSE;
	}

	/* Convert the name to a distinguished name. */
	dn = lu_ldap_ent_to_dn(module, namingAttr, name, branch);
	g_free(name);
	/* Process the removal. */
#ifdef DEBUG
	g_message("Removing `%s'.\n", dn);
#endif
	err = ldap_delete_ext_s(ctx->ldap, dn, NULL, NULL);
	if (err == LDAP_SUCCESS) {
		ret = TRUE;
	} else {
		lu_error_new(error, lu_error_write,
			     _("error removing LDAP directory entry: %s"),
			     ldap_err2string(err));
		return FALSE;
	}

	return ret;
}

/* Return TRUE if pw starts with a valid scheme specification */
static gboolean
userPassword_has_scheme(const char *pw)
{
#define ALPHA "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	static const char alpha[2*26] = ALPHA;
	static const char keystring_chars[] = ALPHA "0123456789-;";
#undef ALPHA

	/* { keystring }, keystring is defined in RFC2252. */
	if (*pw != '{' || memchr(alpha, pw[1], sizeof(alpha)) == NULL)
		return FALSE;
	pw += 2;
	pw += strspn(pw, keystring_chars);
	return *pw == '}';
}

/* Lock an account of some kind. */
static gboolean
lu_ldap_handle_lock(struct lu_module *module, struct lu_ent *ent,
		    const char *namingAttr, enum lock_op op,
		    const char *branch, struct lu_error **error)
{
	const char *dn;
	gboolean ret = FALSE;
	LDAPMod mod[2], *mods[3];
	char *result, *name, *oldpassword, *values[2][2];
	const char *tmp, *attribute;
	struct lu_ldap_context *ctx;
	int err;

	g_assert(module != NULL);
	g_assert(ent != NULL);
	g_assert(namingAttr != NULL);
	g_assert(strlen(namingAttr) > 0);
	LU_ERROR_CHECK(error);
	ctx = module->module_context;

	/* Get the entry's name. */
	name = lu_ent_get_first_value_strdup(ent, namingAttr);
	if (name == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("object has no %s attribute"), namingAttr);
		return FALSE;
	}

	/* Convert the name to a distinguished name. */
	dn = lu_ldap_ent_to_dn(module, namingAttr, name, branch);
	g_free(name);

	attribute = ent->type == lu_user ? LU_USERPASSWORD : LU_GROUPPASSWORD;

	/* Get the values for the entry's password.
	   Note that this handles only one userPassword value! */
	oldpassword = lu_ent_get_first_value_strdup_current(ent, attribute);
	if (oldpassword == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("object has no %s attribute"),
			     LU_USERPASSWORD);
		return FALSE;
	}

	/* We only know how to lock crypted passwords, so crypt it if it
	 * isn't already. */
	if (!g_str_has_prefix(oldpassword, LU_CRYPTED)) {
		char *salt;

		if (userPassword_has_scheme(oldpassword)) {
			lu_error_new(error, lu_error_generic,
				     _("unsupported password encryption "
				       "scheme"));
			g_free(oldpassword);
			return FALSE;
		}
		salt = lu_util_default_salt_specifier(module->lu_context);
		tmp = lu_make_crypted(oldpassword, salt);
		g_free(salt);
		if (tmp == NULL) {
			lu_error_new(error, lu_error_generic,
				     _("error encrypting password"));
			g_free(oldpassword);
			return FALSE;
		}
	} else
		tmp = ent->cache->cache(ent->cache,
					oldpassword + strlen(LU_CRYPTED));
	result = ent->cache->cache(ent->cache, tmp);

	/* Generate a new string with the modification applied. */
	switch (op) {
	case LO_LOCK:
		if (result[0] != LOCKCHAR)
			result = g_strdup_printf("%s%c%s", LU_CRYPTED,
						 LOCKCHAR, result);
		else
			result = g_strconcat(LU_CRYPTED, result,
					     (const gchar *)NULL);
		break;
	case LO_UNLOCK_NONEMPTY:
		if (result[0] == LOCKCHAR && result[1] == '\0') {
			lu_error_new(error, lu_error_unlock_empty, NULL);
			g_free(oldpassword);
			return FALSE;
		}
		/* no break: Fall through */
	case LO_UNLOCK:
		if (result[0] == LOCKCHAR)
			result = g_strconcat(LU_CRYPTED, result + 1,
					     (const gchar *)NULL);
		else
			result = g_strconcat(LU_CRYPTED, result,
					     (const gchar *)NULL);
		break;
	default:
		g_assert_not_reached();
	}
	/* Set up the LDAP modify operation. */
	mod[0].mod_op = LDAP_MOD_DELETE;
	mod[0].mod_type = (char *)map_to_ldap(ent->cache, attribute);
	values[0][0] = ent->cache->cache(ent->cache, oldpassword);
	values[0][1] = NULL;
	mod[0].mod_values = values[0];

	mod[1].mod_op = LDAP_MOD_ADD;
	mod[1].mod_type = mod[0].mod_type;
	values[1][0] = ent->cache->cache(ent->cache, result);
	values[1][1] = NULL;
	mod[1].mod_values = values[1];
	g_free(result);

	/* Set up the array to pass to the modification routines. */
	mods[0] = &mod[0];
	mods[1] = &mod[1];
	mods[2] = NULL;

	err = ldap_modify_ext_s(ctx->ldap, dn, mods, NULL, NULL);
	if (err == LDAP_SUCCESS) {
		ret = TRUE;
	} else {
		lu_error_new(error, lu_error_write,
			     _("error modifying LDAP directory entry: %s"),
			     ldap_err2string(err));
		ret = FALSE;
	}

	g_free(oldpassword);

	return ret;
}

/* Check if an account is locked. */
static gboolean
lu_ldap_is_locked(struct lu_module *module, struct lu_ent *ent,
		  const char *namingAttr, const char *branch,
		  struct lu_error **error)
{
	static const char mapped_password[] = "userPassword";

	const char *dn;
	char *name;
	struct lu_ldap_context *ctx = module->module_context;
	char *attributes[] = { NULL, NULL };
	BerValue **values;
	LDAPMessage *entry = NULL, *messages = NULL;
	int i;
	gboolean locked;

	/* Get the name of the user or group. */
	name = lu_ent_get_first_value_strdup(ent, namingAttr);
	if (name == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("object has no %s attribute"), namingAttr);
		return FALSE;
	}

	/* Convert the name to a distinguished name. */
	dn = lu_ldap_ent_to_dn(module, namingAttr, name, branch);
	g_free(name);
#ifdef DEBUG
	g_print("Looking up `%s'.\n", dn);
#endif

	/* Read the entry data. */
	attributes[0] = (char *)mapped_password;
	if (ldap_search_ext_s(ctx->ldap, dn, LDAP_SCOPE_BASE,
			      ent->type == lu_user
			      ? "("OBJECTCLASS"="POSIXACCOUNT")"
			      : "("OBJECTCLASS"="POSIXGROUP")", attributes,
			      FALSE, NULL, NULL, NULL, LDAP_NO_LIMIT,
			      &messages) == LDAP_SUCCESS) {
		entry = ldap_first_entry(ctx->ldap, messages);
	}
	if (entry == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("no such object in LDAP directory"));
		return FALSE;
	}

	/* Read the values for the attribute we want to change. */
	values = ldap_get_values_len(ctx->ldap, entry, mapped_password);
	if (values == NULL) {
		ldap_msgfree(messages);
#ifdef DEBUG
		g_print("No `%s' attribute found for entry.", mapped_password);
#endif
		lu_error_new(error, lu_error_generic,
			     _("no `%s' attribute found"), mapped_password);
		return FALSE;
	}
	/* Check any of the possibly-multiple passwords. */
	locked = FALSE;
	for (i = 0; values[i] != NULL; i++) {
		const BerValue *val;
		size_t prefix_len;

		val = values[i];
		prefix_len = strlen(LU_CRYPTED);
#ifdef DEBUG
		g_print("Got `%s' = `%.*s'.\n", mapped_password,
			(int)val->bv_len, val->bv_val);
#endif
		if (val->bv_len >= prefix_len
		    && memcmp(val->bv_val, LU_CRYPTED, prefix_len) == 0) {
			locked = (val->bv_len > prefix_len
				  && val->bv_val[prefix_len] == LOCKCHAR);
			break;
		}
	}
	/* Clean up and return. */
	ldap_value_free_len(values);
	if (messages != NULL) {
		ldap_msgfree(messages);
	}

	return locked;
}

/* Set the password for an account. */
static gboolean
lu_ldap_setpass(struct lu_module *module, const char *namingAttr,
		struct lu_ent *ent, const char *branch,
		const char *password, struct lu_error **error)
{
	static const char mapped_password[] = "userPassword";

	const char *dn;
	char *name;
	struct lu_ldap_context *ctx = module->module_context;
	char *attributes[] = { NULL, NULL };
	char *addvalues[] = { NULL, NULL }, *rmvalues[] = { NULL, NULL };
	BerValue **values;
	char *previous;
	int i;
	size_t j;
	LDAPMessage *messages = NULL;
	LDAPMod addmod, rmmod;
	LDAPMod *mods[3];
	char filter[LINE_MAX];

	/* Get the user or group's name. */
#ifdef DEBUG
	g_print("Setting password to `%s'.\n", password);
#endif
	name = lu_ent_get_first_value_strdup(ent, namingAttr);
	if (name == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("object has no %s attribute"), namingAttr);
		return FALSE;
	}

	/* Convert the name to a distinguished name. */
	dn = lu_ldap_ent_to_dn(module, namingAttr, name, branch);
#ifdef DEBUG
	g_print("Setting password for `%s'.\n", dn);
#endif

	snprintf(filter, sizeof(filter), "(%s=%s)",
		 map_to_ldap(module->scache, namingAttr), name);
	g_free(name);

	previous = NULL;
	values = NULL;
	attributes[0] = (char *)mapped_password;
	i = ldap_search_ext_s(ctx->ldap, dn, LDAP_SCOPE_BASE, filter,
			      attributes, FALSE, NULL, NULL, NULL,
			      LDAP_NO_LIMIT, &messages);
	if (i == LDAP_SUCCESS) {
		LDAPMessage *entry;

		entry = ldap_first_entry(ctx->ldap, messages);
		if (entry != NULL) {
			values = ldap_get_values_len(ctx->ldap, entry,
						     mapped_password);
			if (values) {
				for (j = 0; values[j] != NULL; j++) {
					char *val;

					val = g_strndup(values[j]->bv_val,
							values[j]->bv_len);
#ifdef DEBUG
					g_print("Got `%s' = `%s'.\n",
						mapped_password, val);
#endif
					if (g_str_has_prefix(val,
							     LU_CRYPTED)) {
#ifdef DEBUG
						g_print
						    ("Previous entry was `%s'.\n",
						     val);
#endif
						previous = val;
						break;
					}
					g_free(val);
				}
				ldap_value_free_len(values);
			}
		}
	} else {
#ifdef DEBUG
		g_print("Error searching LDAP directory for `%s': %s.\n",
			dn, ldap_err2string(i));
#endif
	}
	if (messages != NULL) {
		ldap_msgfree(messages);
	}

	if (g_str_has_prefix(password, LU_CRYPTED))
		addvalues[0] = (char *)password;
	else {
		const char *crypted;
		char *salt, *tmp;

		if (previous != NULL
		    && strcmp(previous + strlen(LU_CRYPTED),
			      LU_COMMON_DEFAULT_PASSWORD) != 0) {
			salt = previous + strlen(LU_CRYPTED);
			if (*salt == LOCKCHAR)
				salt++;
			salt = g_strdup(salt);
		} else
			salt = lu_util_default_salt_specifier(module
							      ->lu_context);
		crypted = lu_make_crypted(password, salt);
		g_free(salt);
		if (crypted == NULL) {
			lu_error_new(error, lu_error_generic,
				     _("error encrypting password"));
			g_free(previous);
			return FALSE;
		}
		tmp = g_strconcat(LU_CRYPTED, crypted, NULL);
		addvalues[0] = module->scache->cache(module->scache, tmp);
		g_free(tmp);
	}

	j = 0;
	if (values != NULL) {
		if (previous)
			rmvalues[0] = previous;
		/* else deletes all values */

		rmmod.mod_op = LDAP_MOD_DELETE;
		rmmod.mod_type = (char *)mapped_password;
		rmmod.mod_values = rmvalues;
		mods[j++] = &rmmod;
	}
	addmod.mod_op = LDAP_MOD_ADD;
	addmod.mod_type = (char *)mapped_password;
	addmod.mod_values = addvalues;
	mods[j++] = &addmod;
	mods[j] = NULL;

	i = ldap_modify_ext_s(ctx->ldap, dn, mods, NULL, NULL);
	g_free(previous);
	if (i != LDAP_SUCCESS) {
		lu_error_new(error, lu_error_generic,
			     _
			     ("error setting password in LDAP directory for %s: %s"),
			     dn, ldap_err2string(i));
		return FALSE;
	}

	return TRUE;
}

static gboolean
lu_ldap_user_removepass(struct lu_module *module, struct lu_ent *ent,
		        struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_setpass(module, LU_USERNAME, ent, ctx->user_branch,
			       LU_CRYPTED, error);
}

static gboolean
lu_ldap_group_removepass(struct lu_module *module, struct lu_ent *ent,
		         struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_setpass(module, LU_GROUPNAME, ent, ctx->group_branch,
			       LU_CRYPTED, error);
}

static GValueArray *
lu_ldap_enumerate(struct lu_module *module,
		  const char *searchAttr, const char *pattern,
		  const char *returnAttr, const char *branch,
		  struct lu_error **error)
{
	LDAPMessage *messages = NULL;
	char *base, *filt;
	GValue value;
	GValueArray *ret;
	struct lu_ldap_context *ctx;
	char *attributes[] = { (char *) returnAttr, NULL };

	g_assert(module != NULL);
	g_assert(searchAttr != NULL);
	g_assert(strlen(searchAttr) > 0);
	g_assert(returnAttr != NULL);
	g_assert(strlen(returnAttr) > 0);
	LU_ERROR_CHECK(error);

	ctx = module->module_context;

	/* Generate the base DN to search under. */
	/* FIXME: this is inconsistent with lu_ldap_base() usage elsewhere */
	base = g_strdup_printf("%s,%s", branch,
			       ctx->prompts[LU_LDAP_BASEDN].value &&
			       strlen(ctx->prompts[LU_LDAP_BASEDN].value) ?
			       ctx->prompts[LU_LDAP_BASEDN].value : "*");
	/* Generate the filter to search with. */
	filt = g_strdup_printf("(%s=%s)", searchAttr, pattern ?: "*");

#ifdef DEBUG
	g_print("Looking under `%s' with filter `%s'.\n", base, filt);
#endif

	/* Perform the search. */
	ret = g_value_array_new(0);
	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);
	if (ldap_search_ext_s(ctx->ldap, base, LDAP_SCOPE_SUBTREE, filt,
			      attributes, FALSE, NULL, NULL, NULL,
			      LDAP_NO_LIMIT, &messages) == LDAP_SUCCESS) {
		LDAPMessage *entry;

		entry = ldap_first_entry(ctx->ldap, messages);
		if (entry != NULL) {
			while (entry != NULL) {
				BerValue **values;
				size_t i;

				values = ldap_get_values_len(ctx->ldap, entry,
							     returnAttr);
				for (i = 0;
				     (values != NULL) && (values[i] != NULL);
				     i++) {
					char *val;

					val = g_strndup(values[i]->bv_val,
							values[i]->bv_len);
#ifdef DEBUG
					g_print("Got `%s' = `%s'.\n",
						returnAttr, val);
#endif
					g_value_take_string(&value, val);
					g_value_array_append(ret, &value);
				}
				ldap_value_free_len(values);
				entry = ldap_next_entry(ctx->ldap, entry);
			}
#ifdef DEBUG
		} else {
			g_print("No such entry found in LDAP, continuing.\n");
#endif
		}
	}
	if (messages != NULL) {
		ldap_msgfree(messages);
	}

	g_value_unset(&value);
	g_free(base);
	g_free(filt);

	return ret;
}

/* Add a user to the directory. */
static gboolean
lu_ldap_user_add_prep(struct lu_module *module, struct lu_ent *ent,
		      struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return TRUE;
}

static gboolean
lu_ldap_user_add(struct lu_module *module, struct lu_ent *ent,
		 struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_set(module, lu_user, 1, ent, ctx->user_branch, error);
}

/* Modify a user record in the directory. */
static gboolean
lu_ldap_user_mod(struct lu_module *module, struct lu_ent *ent,
		 struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_set(module, lu_user, 0, ent, ctx->user_branch, error);
}

/* Remove a user from the directory. */
static gboolean
lu_ldap_user_del(struct lu_module *module, struct lu_ent *ent,
		 struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_del(module, lu_user, ent, ctx->user_branch, error);
}

/* Lock a user account in the directory. */
static gboolean
lu_ldap_user_lock(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_handle_lock(module, ent, LU_USERNAME, LO_LOCK,
				   ctx->user_branch, error);
}

/* Unlock a user account in the directory. */
static gboolean
lu_ldap_user_unlock(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_handle_lock(module, ent, LU_USERNAME, LO_UNLOCK,
				   ctx->user_branch, error);
}

static gboolean
lu_ldap_user_unlock_nonempty(struct lu_module *module, struct lu_ent *ent,
			     struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_handle_lock(module, ent, LU_USERNAME,
				   LO_UNLOCK_NONEMPTY, ctx->user_branch,
				   error);
}

/* Check if a user account in the directory is locked. */
static gboolean
lu_ldap_user_is_locked(struct lu_module *module, struct lu_ent *ent,
		       struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_is_locked(module, ent, LU_USERNAME, ctx->user_branch,
				 error);
}

/* Set a user's password in the directory. */
static gboolean
lu_ldap_user_setpass(struct lu_module *module, struct lu_ent *ent,
		     const char *password, struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_setpass(module, LU_USERNAME, ent, ctx->user_branch,
			       password, error);
}

/* Add a group entry to the directory. */
static gboolean
lu_ldap_group_add_prep(struct lu_module *module, struct lu_ent *ent,
		       struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return TRUE;
}

static gboolean
lu_ldap_group_add(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_set(module, lu_group, 1, ent, ctx->group_branch, error);
}

/* Modify a group entry in the directory. */
static gboolean
lu_ldap_group_mod(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_set(module, lu_group, 0, ent, ctx->group_branch, error);
}

/* Remove a group entry from the directory. */
static gboolean
lu_ldap_group_del(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_del(module, lu_group, ent, ctx->group_branch, error);
}

/* Lock a group account in the directory. */
static gboolean
lu_ldap_group_lock(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_handle_lock(module, ent, LU_GROUPNAME, LO_LOCK,
				   ctx->group_branch, error);
}

/* Unlock a group account in the directory. */
static gboolean
lu_ldap_group_unlock(struct lu_module *module, struct lu_ent *ent,
		     struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_handle_lock(module, ent, LU_GROUPNAME, LO_UNLOCK,
				   ctx->group_branch, error);
}

static gboolean
lu_ldap_group_unlock_nonempty(struct lu_module *module, struct lu_ent *ent,
			      struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_handle_lock(module, ent, LU_GROUPNAME,
				   LO_UNLOCK_NONEMPTY, ctx->group_branch,
				   error);
}

/* Check if a group account in the directory is locked. */
static gboolean
lu_ldap_group_is_locked(struct lu_module *module, struct lu_ent *ent,
		        struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_is_locked(module, ent, LU_GROUPNAME, ctx->group_branch,
				 error);
}

/* Set a group's password in the directory. */
static gboolean
lu_ldap_group_setpass(struct lu_module *module, struct lu_ent *ent,
		      const char *password, struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_setpass(module, LU_GROUPNAME, ent, ctx->group_branch,
			       password, error);
}

/* Populate user or group structures with the proper defaults. */
static gboolean
lu_ldap_user_default(struct lu_module *module,
		     const char *user, gboolean is_system,
		     struct lu_ent *ent, struct lu_error **error)
{
	if (lu_ent_get(ent, LU_USERPASSWORD) == NULL)
		lu_ent_set_string(ent, LU_USERPASSWORD,
				  LU_CRYPTED LU_COMMON_DEFAULT_PASSWORD);
	/* This will set LU_SHADOWPASSWORD, which we ignore.  The default
	   LU_USERPASSWORD value, which is incompatibly formated by
	   lu_common_user_default(), will not be used because LU_USERPASSWORD
	   was set above. */
	return lu_common_user_default(module, user, is_system, ent, error) &&
	       lu_common_suser_default(module, user, is_system, ent, error);
}

static gboolean
lu_ldap_group_default(struct lu_module *module,
		      const char *group, gboolean is_system,
		      struct lu_ent *ent, struct lu_error **error)
{
	/* This sets LU_SHADOWPASSWORD, which is ignored by our backend.
	   LU_GROUPPASSWORD is not set. */
	return lu_common_group_default(module, group, is_system, ent, error) &&
	       lu_common_sgroup_default(module, group, is_system, ent, error);
}

/* Get a listing of all user names. */
static GValueArray *
lu_ldap_users_enumerate(struct lu_module *module, const char *pattern,
			struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_enumerate(module, "uid", pattern, "uid",
				 ctx->user_branch, error);
}

static GPtrArray *
lu_ldap_users_enumerate_full(struct lu_module *module, const char *pattern,
			     struct lu_error **error)
{
	struct lu_ldap_context *ctx;
	GPtrArray *array = g_ptr_array_new();

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	lu_ldap_lookup(module, "uid", pattern, NULL, array, ctx->user_branch,
		       "("OBJECTCLASS"="POSIXACCOUNT")",
		       lu_ldap_user_attributes, lu_user, error);
	return array;
}

/* Get a listing of all group names. */
static GValueArray *
lu_ldap_groups_enumerate(struct lu_module *module, const char *pattern,
			 struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	return lu_ldap_enumerate(module, "cn", pattern, "cn",
				 ctx->group_branch, error);
}

static GPtrArray *
lu_ldap_groups_enumerate_full(struct lu_module *module, const char *pattern,
			      struct lu_error **error)
{
	struct lu_ldap_context *ctx;

	GPtrArray *array = g_ptr_array_new();
	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	lu_ldap_lookup(module, "cn", pattern, NULL, array, ctx->group_branch,
		       "("OBJECTCLASS"="POSIXGROUP")",
		       lu_ldap_group_attributes, lu_group, error);
	return array;
}

/* Get a list of all users in a group, either via their primary or supplemental
 * group memberships. */
static GValueArray *
lu_ldap_users_enumerate_by_group(struct lu_module *module,
				 const char *group, gid_t gid,
				 struct lu_error **error)
{
	struct lu_ldap_context *ctx;
	GValueArray *ret;
	char grp[sizeof (gid) * CHAR_BIT + 1];

	LU_ERROR_CHECK(error);
	ctx = module->module_context;
	sprintf(grp, "%jd", (intmax_t)gid);

	ret = lu_ldap_enumerate(module, "gidNumber", grp, "uid",
				ctx->user_branch, error);
	if (*error == NULL) {
		GValueArray *secondaries;

		secondaries = lu_ldap_enumerate(module, "cn", group,
						"memberUid", ctx->group_branch,
						error);
		lu_util_append_values(ret, secondaries);
		g_value_array_free(secondaries);
	}

	return ret;
}

/* Get a list of all groups to which the user belongs, via either primary or
 * supplemental group memberships. */
static GValueArray *
lu_ldap_groups_enumerate_by_user(struct lu_module *module,
				 const char *user,
				 uid_t uid,
				 struct lu_error **error)
{
	struct lu_ldap_context *ctx;
	GValueArray *ret, *gids;
	GValue *value;
	size_t i;

	(void)uid;
	LU_ERROR_CHECK(error);
	ctx = module->module_context;

	/* Create an array to hold the values returned. */
	ret = g_value_array_new(0);

	/* Get the user's primary GID(s). */
	gids = lu_ldap_enumerate(module, "uid", user, "gidNumber",
				 ctx->user_branch, error);
	/* For each GID, look up the group.  Which has this GID. */
	for (i = 0; (gids != NULL) && (i < gids->n_values); i++) {
		gid_t gid;
		struct lu_ent *ent;

		value = g_value_array_get_nth(gids, i);
		gid = lu_value_get_id(value);
		if (gid == LU_VALUE_INVALID_ID)
			continue;
		ent = lu_ent_new();
		if (lu_group_lookup_id(module->lu_context, gid,
				       ent, error))
			/* Get the group's names and add them to the list
			 * of values to return. */
			lu_util_append_values(ret,
					      lu_ent_get(ent, LU_GROUPNAME));
		lu_ent_free(ent);
	}
	g_value_array_free(gids);
	/* Search for the supplemental groups which list this user as
	 * a member. */
	if (*error == NULL) {
		GValueArray *secondaries;

		secondaries = lu_ldap_enumerate(module, "memberUid", user,
						"cn", ctx->group_branch,
						error);
		lu_util_append_values(ret, secondaries);
		g_value_array_free(secondaries);
	}

#ifdef DEBUG
	for (i = 0; i < ret->n_values; i++) {
		value = g_value_array_get_nth(ret, i);
		g_print("`%s' is in `%s'\n", user,
			g_value_get_string(value));
	}
#endif

	return ret;
}

static gboolean
lu_ldap_close_module(struct lu_module *module)
{
	struct lu_ldap_context *ctx;
	size_t i;

	g_assert(module != NULL);

	ctx = module->module_context;
	close_server(ctx->ldap);

	module->scache->free(module->scache);
	for (i = 0; i < sizeof(ctx->prompts) / sizeof(ctx->prompts[0]);
	     i++) {
		if (ctx->prompts[i].value && ctx->prompts[i].free_value) {
			ctx->prompts[i].free_value(ctx->prompts[i].value);
		}
	}
	g_free(ctx->sasl_mechanism);
	g_free(ctx->mapped_user_attributes);
	g_free(ctx->mapped_group_attributes);
	g_free(ctx);
	memset(module, 0, sizeof(struct lu_module));
	g_free(module);

	return TRUE;
}

static gboolean
lu_ldap_valid_module_combination(struct lu_module *module, GValueArray *names,
				 struct lu_error **error)
{
	size_t i;

	g_assert(module != NULL);
	g_assert(names != NULL);
	LU_ERROR_CHECK(error);
	for (i = 0; i < names->n_values; i++) {
		const char *name;

		name = g_value_get_string(g_value_array_get_nth(names, i));
		if (strcmp(name, LU_MODULE_NAME_FILES) == 0
		    || strcmp(name, LU_MODULE_NAME_SHADOW) == 0) {
			/* These modules use an incompatible LU_*PASSWORD
			   format: the LU_CRYPTED prefix, or a similar
			   indicator of an LDAP-defined hashing method, is
			   missing. */
			lu_error_new(error, lu_error_invalid_module_combination,
				     _("the `%s' and `%s' modules can not be "
				       "combined"), module->name, name);
			return FALSE;
		}
	}
	return TRUE;
}

static gboolean
lu_ldap_uses_elevated_privileges(struct lu_module *module)
{
	(void)module;
	/* FIXME: do some checking, don't know what we need, though */
	return FALSE;
}

struct lu_module *
libuser_ldap_init(struct lu_context *context, struct lu_error **error)
{
	struct lu_module *ret;
	struct lu_ldap_context *ctx;
	struct lu_prompt prompts[G_N_ELEMENTS(ctx->prompts)];
	const char *bind_type;
	char **bind_types;
	size_t i;
	LDAP *ldap;

	g_assert(context != NULL);
	g_assert(context->prompter != NULL);
	LU_ERROR_CHECK(error);

	ctx = g_malloc0(sizeof(struct lu_ldap_context));
	ctx->global_context = context;

	/* Initialize the prompts structure. */
	ctx->prompts[LU_LDAP_SERVER].key = "ldap/server";
	ctx->prompts[LU_LDAP_SERVER].prompt = N_("LDAP Server Name");
	ctx->prompts[LU_LDAP_SERVER].default_value =
		lu_cfg_read_single(context, "ldap/server", "ldap");
	ctx->prompts[LU_LDAP_SERVER].visible = TRUE;

	ctx->prompts[LU_LDAP_BASEDN].key = "ldap/basedn";
	ctx->prompts[LU_LDAP_BASEDN].prompt = N_("LDAP Search Base DN");
	ctx->prompts[LU_LDAP_BASEDN].default_value =
		lu_cfg_read_single(context, "ldap/basedn", "dc=example,dc=com");
	ctx->prompts[LU_LDAP_BASEDN].visible = TRUE;

	ctx->prompts[LU_LDAP_BINDDN].key = "ldap/binddn";
	ctx->prompts[LU_LDAP_BINDDN].prompt = N_("LDAP Bind DN");
	ctx->prompts[LU_LDAP_BINDDN].visible = TRUE;
	ctx->prompts[LU_LDAP_BINDDN].default_value =
		lu_cfg_read_single(context, "ldap/binddn",
				   "cn=manager,dc=example,dc=com");

	ctx->prompts[LU_LDAP_PASSWORD].key = "ldap/password";
	ctx->prompts[LU_LDAP_PASSWORD].prompt = N_("LDAP Bind Password");
	ctx->prompts[LU_LDAP_PASSWORD].default_value =
		lu_cfg_read_single(context, "ldap/password", NULL);
	ctx->prompts[LU_LDAP_PASSWORD].visible = FALSE;

	ctx->prompts[LU_LDAP_AUTHUSER].key = "ldap/user";
	ctx->prompts[LU_LDAP_AUTHUSER].prompt = N_("LDAP SASL User");
	ctx->prompts[LU_LDAP_AUTHUSER].visible = TRUE;
	ctx->prompts[LU_LDAP_AUTHUSER].default_value =
		lu_cfg_read_single(context, "ldap/user", "");

	ctx->prompts[LU_LDAP_AUTHZUSER].key = "ldap/authuser";
	ctx->prompts[LU_LDAP_AUTHZUSER].prompt =
		N_("LDAP SASL Authorization User");
	ctx->prompts[LU_LDAP_AUTHZUSER].visible = TRUE;
	ctx->prompts[LU_LDAP_AUTHZUSER].default_value =
		lu_cfg_read_single(context, "ldap/authuser", "");

	/* Try to be somewhat smart and allow the user to specify which bind
	 * type to use, which should prevent us from asking for information
	 * we can be certain we don't have a use for. */
	bind_type = lu_cfg_read_single(context, "ldap/bindtype", "simple,sasl");
	bind_types = g_strsplit(bind_type, ",", 0);
	for (i = 0; (bind_types != NULL) && (bind_types[i] != NULL); i++) {
		if (g_ascii_strcasecmp(bind_types[i], "simple") == 0) {
			ctx->bind_simple = TRUE;
		} else
		if (g_ascii_strcasecmp(bind_types[i], "sasl") == 0) {
			ctx->bind_sasl = TRUE;
			ctx->sasl_mechanism = NULL;
		}
		if (g_ascii_strncasecmp(bind_types[i], "sasl/", 5) == 0) {
			ctx->bind_sasl = TRUE;
			ctx->sasl_mechanism = g_strdup(bind_types[i] + 5);
		}
	}
	g_strfreev(bind_types);

	/* Get the information we're sure we'll need. */
	i = 0;
	prompts[i++] = ctx->prompts[LU_LDAP_SERVER];
	prompts[i++] = ctx->prompts[LU_LDAP_BASEDN];
	if (ctx->bind_simple) {
		prompts[i++] = ctx->prompts[LU_LDAP_BINDDN];
		prompts[i++] = ctx->prompts[LU_LDAP_PASSWORD];
	}
	if (ctx->bind_sasl) {
		prompts[i++] = ctx->prompts[LU_LDAP_AUTHUSER];
		prompts[i++] = ctx->prompts[LU_LDAP_AUTHZUSER];
	}
	if (context->prompter(prompts, i,
			      context->prompter_data, error) == FALSE) {
		g_free(ctx);
		return NULL;
	}
	i = 0;
	ctx->prompts[LU_LDAP_SERVER] = prompts[i++];
	ctx->prompts[LU_LDAP_BASEDN] = prompts[i++];
	if (ctx->bind_simple) {
		ctx->prompts[LU_LDAP_BINDDN] = prompts[i++];
		ctx->prompts[LU_LDAP_PASSWORD] = prompts[i++];
	}
	if (ctx->bind_sasl) {
		ctx->prompts[LU_LDAP_AUTHUSER] = prompts[i++];
		ctx->prompts[LU_LDAP_AUTHZUSER] = prompts[i++];
	}

	/* Allocate the method structure. */
	ret = g_malloc0(sizeof(struct lu_module));
	ret->version = LU_MODULE_VERSION;
	ret->module_context = ctx;
	ret->scache = lu_string_cache_new(TRUE);
	ret->name = ret->scache->cache(ret->scache, LU_MODULE_NAME_LDAP);
	ctx->module = ret;

	ctx->user_branch = lu_cfg_read_single(context, "ldap/userBranch",
					      USERBRANCH);
	ctx->group_branch = lu_cfg_read_single(context, "ldap/groupBranch",
					       GROUPBRANCH);

	/* Try to bind to the server to verify that we can. */
	ldap = bind_server(ctx, error);
	if (ldap == NULL) {
		ret->scache->free(ret->scache);
		g_free(ret);
		g_free(ctx);
		return NULL;
	}
	ctx->ldap = ldap;

	ctx->mapped_user_attributes
		= g_malloc0_n(G_N_ELEMENTS(lu_ldap_user_attributes),
			      sizeof(*ctx->mapped_user_attributes));
	for (i = 0; i < G_N_ELEMENTS(lu_ldap_user_attributes); i++) {
		if (lu_ldap_user_attributes[i] != NULL)
			ctx->mapped_user_attributes[i] = (char *)
				map_to_ldap(ret->scache,
					    lu_ldap_user_attributes[i]);
		else
			ctx->mapped_user_attributes[i] = NULL;
	}

	ctx->mapped_group_attributes
		= g_malloc0_n(G_N_ELEMENTS(lu_ldap_group_attributes),
			      sizeof(*ctx->mapped_group_attributes));
	for (i = 0; i < G_N_ELEMENTS(lu_ldap_group_attributes); i++) {
		if (lu_ldap_group_attributes[i] != NULL)
			ctx->mapped_group_attributes[i] = (char *)
				map_to_ldap(ret->scache,
					    lu_ldap_group_attributes[i]);
		else
			ctx->mapped_group_attributes[i] = NULL;
	}

	/* Set the method pointers. */
	ret->valid_module_combination = lu_ldap_valid_module_combination;
	ret->uses_elevated_privileges = lu_ldap_uses_elevated_privileges;

	ret->user_lookup_name = lu_ldap_user_lookup_name;
	ret->user_lookup_id = lu_ldap_user_lookup_id;
	ret->user_default = lu_ldap_user_default;
	ret->user_add_prep = lu_ldap_user_add_prep;
	ret->user_add = lu_ldap_user_add;
	ret->user_mod = lu_ldap_user_mod;
	ret->user_del = lu_ldap_user_del;
	ret->user_lock = lu_ldap_user_lock;
	ret->user_unlock = lu_ldap_user_unlock;
	ret->user_unlock_nonempty = lu_ldap_user_unlock_nonempty;
	ret->user_is_locked = lu_ldap_user_is_locked;
	ret->user_setpass = lu_ldap_user_setpass;
	ret->user_removepass = lu_ldap_user_removepass;
	ret->users_enumerate = lu_ldap_users_enumerate;
	ret->users_enumerate_by_group = lu_ldap_users_enumerate_by_group;
	ret->users_enumerate_full = lu_ldap_users_enumerate_full;

	ret->group_lookup_name = lu_ldap_group_lookup_name;
	ret->group_lookup_id = lu_ldap_group_lookup_id;
	ret->group_default = lu_ldap_group_default;
	ret->group_add_prep = lu_ldap_group_add_prep;
	ret->group_add = lu_ldap_group_add;
	ret->group_mod = lu_ldap_group_mod;
	ret->group_del = lu_ldap_group_del;
	ret->group_lock = lu_ldap_group_lock;
	ret->group_unlock = lu_ldap_group_unlock;
	ret->group_unlock_nonempty = lu_ldap_group_unlock_nonempty;
	ret->group_is_locked = lu_ldap_group_is_locked;
	ret->group_setpass = lu_ldap_group_setpass;
	ret->group_removepass = lu_ldap_group_removepass;
	ret->groups_enumerate = lu_ldap_groups_enumerate;
	ret->groups_enumerate_by_user = lu_ldap_groups_enumerate_by_user;
	ret->groups_enumerate_full = lu_ldap_groups_enumerate_full;

	ret->close = lu_ldap_close_module;

	/* Done. */
	return ret;
}
