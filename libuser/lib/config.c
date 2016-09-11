/* Copyright (C) 2000-2002, 2005, 2008 Red Hat, Inc.
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
#include <assert.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <glib.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "user_private.h"
#include "internal.h"

/**
 * SECTION:config
 * @short_description: Routines for reading configuration information for the
 * libuser library.
 * @include: libuser/config.h
 *
 * These routines allow an application or module to read configuration data
 * from the libuser configuration.
 */

#if defined(HAVE_SECURE_GETENV)
#  define safe_getenv(string) secure_getenv(string)
#elif defined(HAVE___SECURE_GETENV)
#  define safe_getenv(string) __secure_getenv(string)
#else
#  error Neither secure_getenv not __secure_getenv are available
#endif

struct config_config {
	struct lu_string_cache *cache;
	GTree *sections; /* GList of "struct config_key" for each section */
};

/* A (key, values) pair. */
struct config_key {
	char *key;
	GList *values;
};

/* Compare two section names */
static int
compare_section_names(gconstpointer a, gconstpointer b)
{
	return g_ascii_strcasecmp(a, b);
}

/* Compare a struct config_key to a string */
static int
compare_key_string(gconstpointer xa, gconstpointer b)
{
	const struct config_key *a;

	a = xa;
	return g_ascii_strcasecmp(a->key, b);
}

/* Return TRUE if section/key is defined. */
static gboolean
key_defined(struct config_config *config, const char *section, const char *key)
{
	GList *sect;

	/* NULL (empty list) if not found */
	sect = g_tree_lookup(config->sections, section);
	return g_list_find_custom(sect, key, compare_key_string) != NULL;
}

/* Add value to section/key (all in config->cache). */
static void
key_add_cached(struct config_config *config, char *section, char *key,
	       char *value)
{
	GList *sect, *k;
	struct config_key *ck;

	/* NULL (empty list) if not found */
	sect = g_tree_lookup(config->sections, section);
	k = g_list_find_custom(sect, key, compare_key_string);
	if (k != NULL)
		ck = k->data;
	else {
		ck = g_malloc(sizeof (*ck));
		ck->key = key;
		ck->values = NULL;
		sect = g_list_append(sect, ck);
		g_tree_insert(config->sections, section, sect);
	}
	if (g_list_index(ck->values, value) == -1)
		ck->values = g_list_append(ck->values, value);
}

/* Open a file and read it to memory, appending a terminating '\0'.
   Return data for g_free (), or NULL on error. */
static char *
read_file(const char *filename, struct lu_error **error)
{
	int fd;
	struct stat st;
	char *data, *dest;
	size_t left;

	/* Try to open the file. */
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("could not open configuration file `%s': %s"),
			     filename, strerror(errno));
		goto err;
	}
	if (fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat,
			     _("could not stat configuration file `%s': %s"),
			     filename, strerror(errno));
		goto err_fd;
	}
	/* Read the file's contents in. */
	left = st.st_size;
	assert (sizeof (off_t) >= sizeof (size_t));
	if ((off_t)left != st.st_size) {
		lu_error_new(error, lu_error_generic,
			     _("configuration file `%s' is too large"),
			     filename);
		goto err_fd;
	}
	data = g_malloc(st.st_size + 1);
	dest = data;
	while (left != 0) {
		ssize_t res;

		res = read(fd, dest, left);
		if (res == 0)
			break;
		if (res == -1) {
			if (errno == EINTR)
				continue;
			lu_error_new(error, lu_error_read,
				     _("could not read configuration file "
				       "`%s': %s"), filename, strerror(errno));
			goto err_data;
		}
		dest += res;
		left -= res;
	}
	close(fd);
	*dest = 0;
	return data;

err_data:
	g_free(data);
err_fd:
	close(fd);
err:
	return NULL;
}

/* Process a line, and assuming it contains a value, return the key and value
 * it provides us.  If we encounter a section start, change the section. */
static void
process_line(char *line, struct lu_string_cache *cache,
	     char **section, char **key, char **value)
{
	char *equals, *p, *tmp;

	g_return_if_fail(line != NULL);
	g_return_if_fail(cache != NULL);
	g_return_if_fail(section != NULL);
	g_return_if_fail(key != NULL);
	g_return_if_fail(value != NULL);

	/* By default, return that we found nothing. */
	*key = NULL;
	*value = NULL;

	/* Skip initial whitespace. */
	while (isspace((unsigned char)*line) && (*line != '\0'))
		line++;

	/* If it's a comment, bail. */
	if (*line == '#') {
		return;
	}

	/* If it's the beginning of a section, process it and clear the key
	 * and value values. */
	if (*line == '[') {
		line++;
		p = strchr(line, ']');
		if (p) {
			tmp = g_strndup(line, p - line);
			*section = cache->cache(cache, tmp);
			g_free(tmp);
		}
		return;
	}

	/* If the line contains a value, split the key and the value, trim off
	 * any additional whitespace, and return them. */
	equals = strchr(line, '=');
	if (equals != NULL) {
		/* Trim any trailing whitespace off the key name. */
		for (p = equals; p != line && isspace((unsigned char)p[-1]);
		     p--)
			;

		/* Save the key. */
		tmp = g_strndup(line, p - line);
		*key = cache->cache(cache, tmp);
		g_free(tmp);

		/* Skip over any whitespace after the equal sign. */
		for (line = equals + 1;
		     isspace((unsigned char)*line) && *line != '\0'; line++)
			;

		/* Trim off any trailing whitespace. */
		p = strchr(line, '\0');
		while (p != line && isspace((unsigned char)p[-1]))
			p--;

		/* Save the value. */
		tmp = g_strndup(line, p - line);
		*value = cache->cache(cache, tmp);
		g_free(tmp);
	}
}

/* Forward declarations */
static gboolean import_login_defs(struct config_config *config,
				  const char *filename,
				  struct lu_error **error);
static gboolean import_default_useradd(struct config_config *config,
				       const char *filename,
				       struct lu_error **error);

/* Initialize the configuration structure. */
gboolean
lu_cfg_init(struct lu_context *context, struct lu_error **error)
{
	const char *filename = SYSCONFDIR "/libuser.conf";
	struct config_config *config;
	char *data, *line, *xstrtok_ptr, *section = NULL;

	g_assert(context != NULL);

	/* Allow the LIBUSER_CONF environment variable to override where
	 * we get the configuration file is, but only if we can trust the
	 * environment. */
	if ((getuid() == geteuid()) && (getgid() == getegid())) {
		const char *t;

		t = safe_getenv("LIBUSER_CONF");
		if (t != NULL)
			filename = t;
	}

	data = read_file(filename, error);
	if (data == NULL)
		goto err;

	/* Create a new structure to save the data. */
	config = g_malloc0(sizeof(struct config_config));
	config->cache = lu_string_cache_new(FALSE);
	config->sections = g_tree_new(compare_section_names);
	context->config = config;

	for (line = strtok_r(data, "\n", &xstrtok_ptr); line != NULL;
	     line = strtok_r(NULL, "\n", &xstrtok_ptr)) {
		char *key = NULL, *value = NULL;

		/* See what this line contains. */
		process_line(line, config->cache, &section, &key, &value);

		if (section && key && value &&
		    strlen(section) && strlen(key))
			key_add_cached(config, section, key, value);
	}
	g_free(data);

	filename = lu_cfg_read_single(context, "import/login_defs", NULL);
	if (filename != NULL) {
		if (import_login_defs(config, filename, error) == FALSE)
			goto err;
	}
	filename = lu_cfg_read_single(context, "import/default_useradd", NULL);
	if (filename != NULL) {
		if (import_default_useradd(config, filename, error) == FALSE)
			goto err;
	}
	return TRUE;

 err:
	return FALSE;
}

/* Deallocate xsection */
static gboolean
destroy_section (gpointer xkey, gpointer xsection, gpointer data)
{
	GList *section, *key;

	(void)xkey;
	(void)data;
	section = xsection;
	for (key = section; key != NULL; key = key->next) {
		struct config_key *ck;

		ck = key->data;
		g_list_free(ck->values);
		g_free(ck);
	}
	g_list_free(section);
	return FALSE;
}

/* Free a configuration context structure. */
void
lu_cfg_done(struct lu_context *context)
{
	struct config_config *config;

	g_assert(context != NULL);
	g_assert(context->config != NULL);

	config = context->config;

	g_tree_foreach(config->sections, destroy_section, NULL);
	/* The values in the tree now point to deallocated memory. */
	g_tree_destroy(config->sections);
	config->cache->free(config->cache);
	g_free(config);
	context->config = NULL;
}

/**
 * lu_cfg_read:
 * @context: A valid libuser library context.
 * @key: The value to be read from the configuration.  The key should be of the
 * form "section/key" for most purposes.  For example, the #files module uses
 * keys of the form "files/foo" for all of its configuration data.
 * @default_value: A default value to be returned in case none are found.  Can
 * be %NULL.
 *
 * Reads the list of values for a given key from the configuration space.
 *
 * Returns: A #GList of values, formatted as strings.  The list must be freed
 * by calling g_list_free().
 */
GList *
lu_cfg_read(struct lu_context *context, const char *key,
	    const char *default_value)
{
	struct config_config *config;
	char *section, *slash;
	GList *sect, *ret = NULL, *k;

	g_assert(context != NULL);
	g_assert(context->config != NULL);
	g_assert(key != NULL);
	g_assert(strlen(key) > 0);

	config = context->config;

	slash = strchr(key, '/');
	if (slash == NULL)
		goto end;

	section = g_strndup(key, slash - key);
	/* NULL (empty list) if not found */
	sect = g_tree_lookup(config->sections, section);
	g_free(section);
	k = g_list_find_custom(sect, slash + 1, compare_key_string);
	if (k != NULL) {
		struct config_key *ck;

		ck = k->data;
		ret = g_list_copy(ck->values);
	}

 end:
	/* If we still don't have data, return the default answer. */
	if (ret == NULL) {
		if (default_value != NULL) {
			char *def;

			def = context->scache->cache(context->scache,
						     default_value);
			ret = g_list_append(ret, def);
		}
	}

	return ret;
}


/**
 * lu_cfg_read_keys:
 * @context: A valid libuser library context.
 * @parent_key: The parent key under which the caller wishes to know which
 * subkeys are present.
 *
 * Read the names of all of the keys in a specified section of the configuration
 * space.  This function is typically used for walking the configuration space.
 *
 * Returns: A #GList of string representations of key names.  The list must be
 * freed using g_list_free().
 */
GList *
lu_cfg_read_keys(struct lu_context * context, const char *parent_key)
{
	struct config_config *config;
	GList *sect, *ret = NULL;

	g_assert(context != NULL);
	g_assert(context->config != NULL);
	g_assert(parent_key != NULL);
	g_assert(strlen(parent_key) > 0);

	config = context->config;

	/* NULL (empty list) if not found */
	for (sect = g_tree_lookup(config->sections, parent_key); sect != NULL;
	     sect = sect->next) {
		struct config_key *ck;

		ck = sect->data;
		ret = g_list_append(ret, ck->key);
	}

	return ret;
}

/**
 * lu_cfg_read_single:
 * @context: A valid libuser library context.
 * @key: The value to be read from the configuration.  The key should be of the
 * form "section/key" for most purposes.  For example, the #files module uses
 * keys of the form "files/foo" for all of its configuration data.
 * @default_value: A default value to be returned in case none are found.  Can
 * be %NULL.
 *
 * Read a single value set for a given key in the configuration space.  This is
 * a convenience function.  Additional values, if any, will be ignored.
 *
 * Returns: A string representation of one of the values set for the key.  This
 * string must not be freed.
 */
const char *
lu_cfg_read_single(struct lu_context *context, const char *key,
		   const char *default_value)
{
	GList *answers;
	const char *ret;

	g_assert(context != NULL);
	g_assert(context->config != NULL);

	/* Read the whole list. */
	answers = lu_cfg_read(context, key, NULL);
	if (answers && answers->data) {
		/* Save the first value, and free the list. */
		ret = context->scache->cache(context->scache, answers->data);
		g_list_free(answers);
	} else
		ret = context->scache->cache(context->scache, default_value);

	return ret;
}

 /* shadow config file compatibility */

/* Add value to section/key. */
static void
key_add(struct config_config *config, const char *section, const char *key,
	const char *value)
{
	struct lu_string_cache *cache;

	cache = config->cache;
	key_add_cached(config, cache->cache(cache, section),
		       cache->cache(cache, key), cache->cache(cache, value));
}

#define ATTR_DEFINED(CONFIG, SECTION, KEY)				\
(key_defined(CONFIG, SECTION, KEY) || key_defined(CONFIG, SECTION, #KEY))

struct handle_login_defs_key_data {
	struct config_config *config;
	GHashTable *hash;	/* login.defs key (char *) => value (char *) */
};

/* Convert a single /etc/login.defs key to config */
static void
handle_login_defs_key(gpointer xkey, gpointer xvalue, gpointer xv)
{
	static const struct conversion {
		gboolean number;
		const char *shadow, *section, *key, *key2;
	} conv[] = {
		/* ENCRYPT_METHOD values are upper-case, crypt_style values are
		   case-insensitive. */
		{ FALSE, "ENCRYPT_METHOD", "defaults", "crypt_style", NULL },
		{ TRUE, "GID_MIN", "groupdefaults", LU_GIDNUMBER,
		  G_STRINGIFY_ARG(LU_GIDNUMBER) },
		{ FALSE, "MAIL_DIR", "defaults", "mailspooldir", NULL },
		{ TRUE, "PASS_MAX_DAYS", "userdefaults", LU_SHADOWMAX,
		  G_STRINGIFY_ARG(LU_SHADOWMAX) },
		{ TRUE, "PASS_MIN_DAYS", "userdefaults", LU_SHADOWMIN,
		  G_STRINGIFY_ARG(LU_SHADOWMIN) },
		{ TRUE, "PASS_WARN_AGE", "userdefaults", LU_SHADOWWARNING,
		  G_STRINGIFY_ARG(LU_SHADOWWARNING) },
		{ TRUE, "SHA_CRYPT_MIN_ROUNDS", "defaults", "hash_rounds_min",
		  NULL },
		{ TRUE, "SHA_CRYPT_MAX_ROUNDS", "defaults", "hash_rounds_max",
		  NULL },
		{ TRUE, "UID_MIN", "userdefaults", LU_UIDNUMBER,
		  G_STRINGIFY_ARG(LU_UIDNUMBER) },
	};

	const char *key, *value;
	struct handle_login_defs_key_data *v;
	size_t i;

	value = xvalue;
	key = xkey;
	v = xv;
	/* This is the only case that requires value conversion */
	if (strcmp (key, "MD5_CRYPT_ENAB") == 0) {
		if (g_hash_table_lookup(v->hash, "ENCRYPT_METHOD") == NULL
		    && !key_defined(v->config, "defaults", "crypt_style"))
			key_add(v->config, "defaults", "crypt_style",
				g_ascii_strcasecmp(value, "yes") == 0 ? "md5"
				: "des");
		return;
	}
	for (i = 0; i < G_N_ELEMENTS(conv); i++) {
		if (strcmp (key, conv[i].shadow) != 0)
			continue;
		if (!key_defined(v->config, conv[i].section, conv[i].key)
		    && (conv[i].key2 == NULL
			|| !key_defined(v->config, conv[i].section,
					conv[i].key2))) {
			/* We need roughly 0.3 characters per bit,
			   this just is an obvious upper bound. */
			char buf[sizeof(intmax_t) * CHAR_BIT + 1];

			if (conv[i].number != 0) {
				intmax_t num;
				char *end;

				errno = 0;
				num = strtoimax(value, &end, 0);
				if (errno != 0 || *end != 0 || end == value)
					break; /* Ignore this invalid value */
				snprintf(buf, sizeof(buf), "%jd", num);
				value = buf;
			}
			key_add(v->config, conv[i].section, conv[i].key, value);
		}
		break;
	}
	/* Unimplemented: CREATE_HOME, GID_MAX, MAIL_FILE, SYSLOG_SG_ENAB,
	   UID_MAX, UMASK, USERDEL_CMD, USERGROUPS_ENAB */
}

/* Import data from /etc/login.defs if libuser.conf doesn't specify the
   values. */
static gboolean
import_login_defs(struct config_config *config, const char *filename,
		  struct lu_error **error)
{
	char *data, *line, *xstrtok_ptr;
	struct handle_login_defs_key_data v;

	data = read_file(filename, error);
	if (data == NULL)
		goto err;

	v.hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	for (line = strtok_r(data, "\n", &xstrtok_ptr); line != NULL;
	     line = strtok_r(NULL, "\n", &xstrtok_ptr)) {
		char *p, *key, *value;

		while (*line == ' ' || *line == '\t')
			line++;
		if (*line == 0 || *line == '#')
			continue;
		p = strpbrk(line, " \t");
		if (p == NULL)
			continue;
		key = g_strndup(line, p - line);
		for (line = p; *line == ' ' || *line == '\t' || *line == '"';
		     line++)
			;
		/* Note that shadow doesn't require that the quotes are either
		   both present or both absent. */
		p = strchr(line, '"');
		if (p == NULL) {
			for (p = strchr(line, '\0');
			     p != line && (p[-1] == ' ' || p[-1] == '\t'); p--)
				;
		}
		value = g_strndup(line, p - line);
		/* May replace an older value if there are multiple
		   definitions; that's what shadow does. */
		g_hash_table_insert(v.hash, key, value);
	}
	g_free(data);
	v.config = config;
	g_hash_table_foreach(v.hash, handle_login_defs_key, &v);
	g_hash_table_destroy(v.hash);

	return TRUE;

err:
	return FALSE;
}

/* Convert a single /etc/default/useradd to config */
static void
handle_default_useradd_key(gpointer xkey, gpointer xvalue, gpointer xconfig)
{
	const char *key, *value;
	struct config_config *config;

	value = xvalue;
	key = xkey;
	config = xconfig;
	if (strcmp(key, "EXPIRE") == 0) {
		if (!ATTR_DEFINED(config, "userdefaults", LU_SHADOWEXPIRE)) {
			intmax_t day;
			char buf[sizeof (day) * CHAR_BIT + 1];

			if (*value == 0)
				day = -1;
			else {
				time_t t;

				t = lu_get_date(value, NULL);
				if (t == -1)
					day = -1;
				else
					day = (t + (24 * 3600) / 2)
						/ (24 * 3600);
			}
			snprintf(buf, sizeof(buf), "%jd", day);
			key_add(config, "userdefaults", LU_SHADOWEXPIRE, buf);
		}
	} else if (strcmp(key, "GROUP") == 0) {
		if (!ATTR_DEFINED(config, "userdefaults", LU_GIDNUMBER)) {
			char buf[LINE_MAX * 4];
			intmax_t val;
			char *p;

			errno = 0;
			val = strtoimax(value, &p, 10);
			if (errno != 0 || *p != 0 || p == value
			    || (gid_t)val != val) {
				struct group grp, *g;

				getgrnam_r(value, &grp, buf, sizeof(buf), &g);
				if (g != NULL)
					value = g->gr_name;
				/* else ignore the entry */
			}
			key_add(config, "userdefaults", LU_GIDNUMBER, value);
		}
	} else if (strcmp(key, "HOME") == 0) {
		if (!ATTR_DEFINED(config, "userdefaults", LU_HOMEDIRECTORY)) {
			char *dir;

			dir = g_strconcat(value, "/%n", NULL);
			key_add(config, "userdefaults", LU_HOMEDIRECTORY, dir);
			g_free(dir);
		}
	} else if (strcmp(key, "INACTIVE") == 0) {
		if (!ATTR_DEFINED(config, "userdefaults", LU_SHADOWINACTIVE))
			key_add(config, "userdefaults", LU_SHADOWINACTIVE,
				value);
	} else if (strcmp(key, "SHELL") == 0) {
		if (!ATTR_DEFINED(config, "userdefaults", LU_LOGINSHELL))
			key_add(config, "userdefaults", LU_LOGINSHELL, value);
	} else if (strcmp(key, "SKEL") == 0) {
		if (!key_defined(config, "defaults", "skeleton"))
			key_add(config, "defaults", "skeleton", value);
	}
}

static gboolean
import_default_useradd(struct config_config *config, const char *filename,
		       struct lu_error **error)
{
  	GHashTable *hash;
	char *data, *line, *xstrtok_ptr;

	data = read_file(filename, error);
	if (data == NULL)
		goto err;

	hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	for (line = strtok_r(data, "\n", &xstrtok_ptr); line != NULL;
	     line = strtok_r(NULL, "\n", &xstrtok_ptr)) {
		char *p, *key, *value;

		p = strchr(line, '=');
		if (p == NULL)
			continue;
		key = g_strndup(line, p - line);
		value = g_strdup(p + 1);
		/* May replace an older value if there are multiple
		   definitions; that's what shadow does. */
		g_hash_table_insert(hash, key, value);
	}
	g_free(data);
	g_hash_table_foreach(hash, handle_default_useradd_key, config);
	g_hash_table_destroy(hash);

	return TRUE;

err:
	return FALSE;
}
