## Process this file with automake to produce Makefile.in

## Settings
pkgconfigdir = $(libdir)/pkgconfig

ACLOCAL_AMFLAGS = -I m4
AM_DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc --with-ldap

HGTAG = 'libuser-$(VERSION)'

AM_CPPFLAGS = $(GOBJECT_CFLAGS)
LOCALEDIR_CPPFLAGS = -DLOCALEDIR='"$(localedir)"'
PYTHON_CPPFLAGS = -I$(PYINCLUDEDIR)

AM_TESTS_ENVIRONMENT = PYTHON=$(PYTHON); export PYTHON;
# Ignore possibly lost, there are too many due to Python.  --gen-suppressions
# makes the run interactive, which is not good for regression testing - we
# are not there yet.
VG_EXECUTION = libtool --mode=execute \
	valgrind --quiet --suppressions=$(srcdir)/tests/valgrind.supp \
	--leak-check=full --num-callers=20 --log-fd=3 \
	--gen-suppressions=yes --show-possibly-lost=no
VG_ENVIRONMENT = G_SLICE=always-malloc \
	G_DEBUG=gc-friendly,resident-modules

## Targets
SUBDIRS = po docs
TESTS = tests/config_test.sh tests/fs_test tests/files_test tests/pwhash_test \
	tests/utils_test
if LDAP
TESTS += tests/default_pw_test tests/ldap_test
endif

EXTRA_DIST = \
	$(EXTRA_MANS) \
	python/modules.txt \
	samples/genusers \
	tests/config.conf.in tests/config_default_useradd \
	tests/config_import.conf.in tests/config_import2.conf.in \
	tests/config_login.defs tests/config_login2.defs \
	tests/config_override.conf.in tests/config_test.py \
	tests/config_test.sh \
	tests/default_pw.conf.in tests/default_pw_test tests/default_pw_test.py \
	tests/files.conf.in tests/files_test tests/files_test.py \
	tests/fs.conf.in tests/fs_test tests/fs_test.py \
	tests/ldap.conf.in tests/ldaprc tests/ldap_skel.ldif tests/ldap_test \
	tests/ldap_test.py \
	tests/pwhash.conf.in tests/pwhash.py tests/pwhash_test \
	tests/slapd.conf.in \
	tests/utils.conf.in tests/utils_group tests/utils_gshadow \
	tests/utils_passwd tests/utils_shadow tests/utils_test \
	tests/valgrind.supp

bin_PROGRAMS = apps/lchfn apps/lchsh
sbin_PROGRAMS = apps/lchage apps/lgroupadd apps/lgroupdel apps/lgroupmod \
	apps/lid apps/lnewusers apps/lpasswd apps/luseradd apps/luserdel \
	apps/lusermod
noinst_PROGRAMS = samples/enum samples/field samples/homedir samples/lookup \
	samples/prompt samples/testuser \
	tests/config_test
check_PROGRAMS = tests/alloc_port tests/wait_for_slapd_exit \
	tests/wait_for_slapd_start

noinst_LTLIBRARIES = apps/libapputil.la
lib_LTLIBRARIES = lib/libuser.la
pkglib_LTLIBRARIES = modules/libuser_files.la modules/libuser_shadow.la
if LDAP
pkglib_LTLIBRARIES += modules/libuser_ldap.la
endif
if SASL
pkglib_LTLIBRARIES += modules/libuser_sasldb.la
endif
if WITH_PYTHON
pyexec_LTLIBRARIES = python/libuser.la
endif

dist_man_MANS = apps/lgroupadd.1 apps/lgroupdel.1 apps/lgroupmod.1 \
	apps/lchage.1 apps/lchfn.1 apps/lchsh.1 apps/lid.1 apps/lnewusers.1 \
	apps/lpasswd.1 apps/luseradd.1 apps/luserdel.1 apps/lusermod.1

pkgconfig_DATA = $(PACKAGE).pc
dist_sysconf_DATA = libuser.conf

pkginclude_HEADERS = lib/config.h lib/entity.h lib/error.h lib/fs.h \
	lib/prompt.h lib/user.h lib/user_private.h

dist_noinst_SCRIPTS = python/ldap-script python/test-script


## Rules
force-tag:
	cd $(top_srcdir); hg tag -f $(HGTAG)

tag:
	cd $(top_srcdir); hg tag $(HGTAG)

archive:
	rm -fr /tmp/$(PACKAGE)-export-tmp
	hg clone -r $(HGTAG) $(abs_top_srcdir) /tmp/$(PACKAGE)-export-tmp
	cd /tmp/$(PACKAGE)-export-tmp; ./autogen.sh ; \
		./configure --sysconfdir=/etc --with-ldap --enable-gtk-doc \
		--without-sasl; make -C docs/reference; make dist
	mv /tmp/$(PACKAGE)-export-tmp/$(PACKAGE)-$(VERSION).tar.xz .
	rm -fr /tmp/$(PACKAGE)-export-tmp
	@echo Package is in \"$(PACKAGE)-$(VERSION).tar.xz\".

valgrind:
	VALGRIND='$(VG_EXECUTION)' \
		$(MAKE) check TESTS_ENVIRONMENT='$(VG_ENVIRONMENT)' 3>&2


## Dependency data
apps_libapputil_la_CPPFLAGS = $(AM_CPPFLAGS)
apps_libapputil_la_SOURCES = apps/apputil.c apps/apputil.h
apps_libapputil_la_LDFLAGS = $(GOBJECT_LIBS) -lpam -lpam_misc $(SELINUX_LIBS)

apps_lchage_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
apps_lchage_LDADD = lib/libuser.la $(LTLIBINTL)
apps_lchage_LDFLAGS = $(GMODULE_LIBS) -lpopt

apps_lchfn_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
apps_lchfn_LDADD = apps/libapputil.la lib/libuser.la $(LTLIBINTL)
apps_lchfn_LDFLAGS = $(GMODULE_LIBS) -lpopt

apps_lchsh_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
apps_lchsh_LDADD = apps/libapputil.la lib/libuser.la $(LTLIBINTL)
apps_lchsh_LDFLAGS = $(GMODULE_LIBS) -lpopt

apps_lgroupadd_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
apps_lgroupadd_LDADD = lib/libuser.la $(LTLIBINTL)
apps_lgroupadd_LDFLAGS = $(GMODULE_LIBS) -lpopt

apps_lgroupdel_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
apps_lgroupdel_LDADD = lib/libuser.la $(LTLIBINTL)
apps_lgroupdel_LDFLAGS = $(GMODULE_LIBS) -lpopt

apps_lgroupmod_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
apps_lgroupmod_LDADD = lib/libuser.la $(LTLIBINTL)
apps_lgroupmod_LDFLAGS = $(GMODULE_LIBS) -lpopt

apps_lid_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
apps_lid_LDADD = lib/libuser.la $(LTLIBINTL)
apps_lid_LDFLAGS = $(GMODULE_LIBS) -lpopt

apps_lnewusers_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
apps_lnewusers_LDADD = lib/libuser.la $(LTLIBINTL)
apps_lnewusers_LDFLAGS = $(GMODULE_LIBS) -lpopt

apps_lpasswd_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
apps_lpasswd_LDADD = apps/libapputil.la lib/libuser.la $(LTLIBINTL)
apps_lpasswd_LDFLAGS = $(GMODULE_LIBS) -lpopt

apps_luseradd_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
apps_luseradd_LDADD = lib/libuser.la $(LTLIBINTL)
apps_luseradd_LDFLAGS = $(GMODULE_LIBS) -lpopt

apps_luserdel_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
apps_luserdel_LDADD = lib/libuser.la $(LTLIBINTL)
apps_luserdel_LDFLAGS = $(GMODULE_LIBS) -lpopt

apps_lusermod_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
apps_lusermod_LDADD = lib/libuser.la $(LTLIBINTL)
apps_lusermod_LDFLAGS = $(GMODULE_LIBS) -lpopt

lib_libuser_la_SOURCES = lib/common.c lib/config.c lib/entity.c lib/error.c \
	lib/fs.c lib/getdate.y lib/internal.h lib/misc.c lib/modules.c \
	lib/prompt.c lib/scache.c lib/user.c lib/util.c
# -Ilib so that "../config.h" is the result of configure
lib_libuser_la_CPPFLAGS = $(GMODULE_CFLAGS) -Ilib $(LOCALEDIR_CPPFLAGS) \
	-DMODULEDIR='"$(pkglibdir)"' -DNSCD='"$(NSCD)"' \
	-DSYSCONFDIR='"$(sysconfdir)"'
lib_libuser_la_LDFLAGS = $(GMODULE_LIBS) $(CRYPT_LIBS) $(SELINUX_LIBS) \
	-version-info 6:2:5
lib_libuser_la_LIBADD = $(LTLIBINTL)

modules_libuser_files_la_SOURCES = modules/files.c
modules_libuser_files_la_LDFLAGS = -module -avoid-version $(GOBJECT_LIBS)
modules_libuser_files_la_LIBADD = lib/libuser.la

modules_libuser_shadow_la_SOURCES = modules/files.c
modules_libuser_shadow_la_LDFLAGS = -module -avoid-version $(GOBJECT_LIBS)
modules_libuser_shadow_la_LIBADD = lib/libuser.la

modules_libuser_ldap_la_SOURCES = modules/ldap.c
modules_libuser_ldap_la_LDFLAGS = -module -avoid-version $(GOBJECT_LIBS) -lldap
modules_libuser_ldap_la_LIBADD = lib/libuser.la

modules_libuser_sasldb_la_SOURCES = modules/sasldb.c
modules_libuser_sasldb_la_LDFLAGS = -module -avoid-version $(GOBJECT_LIBS) \
	-lsasl2
modules_libuser_sasldb_la_LIBADD = lib/libuser.la

python_libuser_la_SOURCES = python/admin.c python/ent.c \
	python/libusermodule.c python/misc.c python/common.h python/debug.h
python_libuser_la_CPPFLAGS = $(AM_CPPFLAGS) $(PYTHON_CPPFLAGS)
python_libuser_la_LDFLAGS = -module -avoid-version $(GOBJECT_LIBS)
python_libuser_la_LIBADD = lib/libuser.la

samples_enum_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
samples_enum_LDADD = lib/libuser.la $(GMODULE_LIBS)
samples_enum_LDFLAGS = -no-install

samples_field_LDADD = lib/libuser.la $(GMODULE_LIBS)
samples_field_LDFLAGS = -no-install

samples_homedir_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
samples_homedir_LDADD = lib/libuser.la $(GMODULE_LIBS)
samples_homedir_LDFLAGS = -no-install

samples_lookup_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
samples_lookup_LDADD = lib/libuser.la $(GMODULE_LIBS)
samples_lookup_LDFLAGS = -no-install

samples_prompt_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
samples_prompt_LDADD = lib/libuser.la $(GMODULE_LIBS)
samples_prompt_LDFLAGS = -no-install

samples_testuser_CPPFLAGS = $(AM_CPPFLAGS) $(LOCALEDIR_CPPFLAGS)
samples_testuser_LDADD = lib/libuser.la $(GMODULE_LIBS)
samples_testuser_LDFLAGS = -no-install

tests_alloc_port_LDFLAGS = -no-install

tests_config_test_LDADD = lib/libuser.la $(GMODULE_LIBS)
tests_config_test_LDFLAGS = -no-install

tests_wait_for_slapd_exit_LDFLAGS = -no-install

tests_wait_for_slapd_start_LDFLAGS = -no-install
