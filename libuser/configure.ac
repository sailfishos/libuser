AC_INIT([libuser], [0.62], [mitr@redhat.com], ,
        [https://fedorahosted.org/libuser/])
AC_PREREQ([2.63b])
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([lib/user.c])
AC_CONFIG_AUX_DIR([admin])
AM_INIT_AUTOMAKE([no-dist-gzip dist-xz subdir-objects -Wall])

AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AR
AC_CHECK_PROG([YACC], [bison -y], [bison -y], [:])
AC_PATH_PROG([NSCD], [nscd], [/usr/sbin/nscd],
	     [$PATH$PATH_SEPARATOR/usr/sbin$PATH_SEPARATOR/sbin])
AC_ARG_VAR([NSCD], [Path to nscd])
AC_SYS_LARGEFILE

LT_INIT([disable-static])

PKG_CHECK_MODULES(GLIB,[glib-2.0 gmodule-no-export-2.0])
PKG_CHECK_MODULES(GOBJECT,[glib-2.0 gobject-2.0])
PKG_CHECK_MODULES(GMODULE,[glib-2.0 gmodule-no-export-2.0 gobject-2.0])
AC_DEFINE(G_DISABLE_DEPRECATED,,
	[Stay away from deprecated glib functionality.])
# GValueArray is a part of external API of the library; warnings about it being
# deprecated do no good.
AC_DEFINE([GLIB_VERSION_MIN_REQUIRED], [GLIB_VERSION_2_30],
	[Shut up warnings about deprecated GValueArray])

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.18.2])

LIBSAVE="$LIBS"
AC_SEARCH_LIBS([crypt], [crypt])
CRYPT_LIBS="$LIBS"
LIBS="$LIBSAVE"
AC_SUBST(CRYPT_LIBS)

AC_ARG_WITH([popt], AS_HELP_STRING([--with-popt=DIR],
				   [use popt headers and libraries under DIR]),
[if test "x$withval" != x -a "x$withval" != xyes -a "x$withval" != xno -a \
	"x$withval" != x/usr ; then
	CPPFLAGS="$CPPFLAGS -I$popt/include"
	LDFLAGS="$LDFLAGS -L$popt/lib"
fi])

AC_ARG_WITH([ldap],
	    AS_HELP_STRING([--with-ldap=DIR],
			   [use OpenLDAP 2.x headers and libraries under DIR]),
[if test "x$withval" != x -a "x$withval" != xno ; then
	ldap=$withval
else
	ldap=no
fi
],ldap=no)

build_ldap=no
if test x$ldap != xno ; then
	LIBSAVE="$LIBS"
	if test x$ldap != xyes -a x$ldap != x/usr ; then
		CPPFLAGS="$CPPFLAGS -I$ldap/include"
		LDFLAGS="$LDFLAGS -L$ldap/lib"
	fi
	AC_SEARCH_LIBS([ldap_sasl_interactive_bind_s], [ldap])
	AC_CHECK_FUNC(ldap_sasl_interactive_bind_s,[
	AC_CHECK_FUNC(ldap_set_option,[
	AC_CHECK_FUNC(ldap_start_tls_s,[
	AC_CHECK_FUNC(ldap_modify_ext_s,[
	AC_CHECK_FUNC(ldap_delete_ext_s,[
	build_ldap=yes])])])])])
	LIBS="$LIBSAVE"
fi
AM_CONDITIONAL([LDAP], [test $build_ldap = yes])

AC_ARG_WITH([sasl],
	    AS_HELP_STRING([--with-sasl=DIR],
			   [use Cyrus SASL headers and libraries under DIR]),
[if test "x$withval" != x -a "x$withval" != xno ; then
	sasl=$withval
else
	sasl=no
fi
],sasl=no)

build_sasl=no
if test x$sasl != xno ; then
	LIBSAVE="$LIBS"
	if test x$sasl != xyes -a x$sasl != x/usr ; then
		CPPFLAGS="$CPPFLAGS -I$sasl/include"
		LDFLAGS="$LDFLAGS -L$sasl/lib"
	fi
	AC_SEARCH_LIBS([sasl_setpass], [sasl2], [build_sasl=yes])
	AC_CHECK_FUNCS_ONCE([sasl_user_exists])
	LIBS="$LIBSAVE"
fi
AM_CONDITIONAL([SASL], [test $build_sasl = yes])

AC_ARG_WITH([python],
	    AS_HELP_STRING([--with-python],
			   [build Python modules (default is YES)]), [],
	    [with_python=yes])
AM_CONDITIONAL([WITH_PYTHON], [test $with_python != no])
if test $with_python != no ; then
   AM_PATH_PYTHON
   PYINCLUDEDIR=`$PYTHON -c 'import sysconfig; print(sysconfig.get_path("include"))'`
fi
AC_SUBST(PYINCLUDEDIR)

AC_ARG_WITH([selinux],
	    AS_HELP_STRING([--with-selinux],
			   [work with SELinux extensions (default is NO)]),
	    [selinux=$withval], [selinux=no])
if test "x$selinux" != xno ; then
    SELINUX_LIBS=-lselinux
    AC_DEFINE([WITH_SELINUX], [1], [Define to 1 to use SELinux extensions])
fi
AC_SUBST(SELINUX_LIBS)

AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T

AC_CHECK_FUNCS([__secure_getenv secure_getenv])

# Modify CFLAGS after all tests are run (some of them could fail because
# of the -Werror).
if test "$GCC" = yes ; then
    AC_CACHE_CHECK([for available GCC warning flags],
		   [mitr_cv_prog_gcc_warnings],
    [mitr_cv_prog_gcc_warnings=""
    for i in -Wall -Wcast-align -Wmissing-noreturn -Wnested-externs dnl
-Wpointer-arith -Wstrict-prototypes -Wundef; do
        oldcflags=$CFLAGS
        CFLAGS="$CFLAGS $i"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [])],
		[mitr_cv_prog_gcc_warnings="$mitr_cv_prog_gcc_warnings $i"])
	CFLAGS=$oldcflags
     done])
     CFLAGS="$CFLAGS $mitr_cv_prog_gcc_warnings"
     AC_MSG_CHECKING([whether we should use -Werror])
     AC_ARG_ENABLE([Werror],
		   AS_HELP_STRING([--enable-Werror],
			[use -Werror if compiling with gcc (default is NO)]),
		   [], enable_Werror=no)
     if test "x$enable_Werror" != xno; then
	CFLAGS="$CFLAGS -Werror"
     fi
     AC_MSG_RESULT([$enable_Werror])
fi

GTK_DOC_CHECK

AC_CONFIG_FILES([Makefile po/Makefile.in docs/Makefile docs/reference/Makefile
libuser.pc])
AC_OUTPUT
