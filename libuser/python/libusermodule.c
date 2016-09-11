/* Copyright (C) 2001,2002 Red Hat, Inc.
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

#include <Python.h>
#include <config.h>
#include <pwd.h>
#include <grp.h>
#include <langinfo.h>
#include <stdlib.h>
#include <unistd.h>
#include <utmp.h>
#include <glib.h>
#include "../lib/user.h"
#include "../lib/user_private.h"
#include "common.h"

#ifdef DEBUG_BINDING
int indent = 0;

char *getindent()
{
	static char buf[LINE_MAX];
	g_return_val_if_fail(indent < sizeof(buf), "");
	memset(buf, 0, sizeof(buf));
	memset(buf, ' ', indent);
	return buf;
}
#endif

/* Return a list of the valid shells in the system, picked up from
 * getusershells(). */
PyObject *
libuser_get_user_shells(PyObject *self, PyObject *ignored)
{
	PyObject *ret;
	const char *shell;

	(void)self;
	(void)ignored;
	DEBUG_ENTRY;

	ret = PyList_New(0);
	setusershell();
	while ((shell = getusershell()) != NULL) {
		PyObject *str;

		str = PYSTRTYPE_FROMSTRING(shell);
		if (str == NULL)
			goto err;
		PyList_Append(ret, str);
		Py_DECREF(str);
	}
	endusershell();

	DEBUG_EXIT;
	return ret;

err:
	endusershell();
	Py_DECREF(ret);
	return NULL;
}

static PyObject *
libuser_validate_id_value(PyObject *self, PyObject *value)
{
	PY_LONG_LONG ll;

	DEBUG_ENTRY;
	ll = PyLong_AsLongLong(value);
	if (PyErr_Occurred())
		goto error;

	if ((id_t)ll != ll) {
		PyErr_SetString(PyExc_OverflowError, _("Value out of range"));
		goto error;
	}
	if (ll < 0) {
		PyErr_SetString(PyExc_ValueError, _("ID must not be negative"));
		goto error;
	}
	if (ll == LU_VALUE_INVALID_ID) {
		PyErr_SetString(PyExc_ValueError, _("Invalid ID value"));
		goto error;
	}
	DEBUG_EXIT;
	Py_RETURN_NONE;

error:
	DEBUG_EXIT;
	return NULL;
}

static PyMethodDef libuser_methods[] = {
	{"admin", (PyCFunction) libuser_admin_new, METH_VARARGS | METH_KEYWORDS,
	 "create a new administration context"},
	{"prompt", libuser_prompt_new, METH_NOARGS,
	 "create and return a new prompt record"},
	{"get_user_shells", libuser_get_user_shells, METH_NOARGS,
	 "return a list of valid shells"},
	{"ADMIN", (PyCFunction) libuser_admin_new, METH_VARARGS | METH_KEYWORDS,
	 "create a new administration context"},
	{"PROMPT", libuser_prompt_new, METH_NOARGS,
	 "create and return a new prompt record"},
	{"getUserShells", libuser_get_user_shells, METH_NOARGS,
	 "return a list of valid shells"},
	{"validateIdValue", libuser_validate_id_value, METH_O,
	 "validate an id_t value"},
	{NULL, NULL, 0, NULL},
};

static int
initialize_libuser_module(PyObject *module)
{
	if (PyType_Ready(&AdminType) < 0 || PyType_Ready(&EntityType) < 0
	    || PyType_Ready(&PromptType) < 0)
		return -1;

	PyModule_AddIntConstant(module, "USER", lu_user);
	PyModule_AddIntConstant(module, "GROUP", lu_group);

	/* User attributes. */
	PyModule_AddStringConstant(module, "USERNAME", LU_USERNAME);
	PyModule_AddStringConstant(module, "USERPASSWORD", LU_USERPASSWORD);
	PyModule_AddStringConstant(module, "UIDNUMBER", LU_UIDNUMBER);
	PyModule_AddStringConstant(module, "GIDNUMBER", LU_GIDNUMBER);
	PyModule_AddStringConstant(module, "GECOS", LU_GECOS);
	PyModule_AddStringConstant(module, "HOMEDIRECTORY", LU_HOMEDIRECTORY);
	PyModule_AddStringConstant(module, "LOGINSHELL", LU_LOGINSHELL);

	/* Group attributes. */
	PyModule_AddStringConstant(module, "GROUPNAME", LU_GROUPNAME);
	PyModule_AddStringConstant(module, "GROUPPASSWORD", LU_GROUPPASSWORD);
	PyModule_AddStringConstant(module, "ADMINISTRATORNAME",
				   LU_ADMINISTRATORNAME);
	PyModule_AddStringConstant(module, "MEMBERNAME", LU_MEMBERNAME);

	/* Shadow attributes. */
	PyModule_AddStringConstant(module, "SHADOWNAME", LU_SHADOWNAME);
	PyModule_AddStringConstant(module, "SHADOWPASSWORD", LU_SHADOWPASSWORD);
	PyModule_AddStringConstant(module, "SHADOWLASTCHANGE",
				   LU_SHADOWLASTCHANGE);
	PyModule_AddStringConstant(module, "SHADOWMIN", LU_SHADOWMIN);
	PyModule_AddStringConstant(module, "SHADOWMAX", LU_SHADOWMAX);
	PyModule_AddStringConstant(module, "SHADOWWARNING", LU_SHADOWWARNING);
	PyModule_AddStringConstant(module, "SHADOWINACTIVE", LU_SHADOWINACTIVE);
	PyModule_AddStringConstant(module, "SHADOWEXPIRE", LU_SHADOWEXPIRE);
	PyModule_AddStringConstant(module, "SHADOWFLAG", LU_SHADOWFLAG);

	/* Additional fields. */
	PyModule_AddStringConstant(module, "COMMONNAME", LU_COMMONNAME);
	PyModule_AddStringConstant(module, "GIVENNAME", LU_GIVENNAME);
	PyModule_AddStringConstant(module, "SN", LU_SN);
	PyModule_AddStringConstant(module, "ROOMNUMBER", LU_ROOMNUMBER);
	PyModule_AddStringConstant(module, "TELEPHONENUMBER",
				   LU_TELEPHONENUMBER);
	PyModule_AddStringConstant(module, "HOMEPHONE", LU_HOMEPHONE);
	PyModule_AddStringConstant(module, "EMAIL", LU_EMAIL);

	/* Miscellaneous. */
	PyModule_AddIntMacro(module, UT_NAMESIZE);
	PyModule_AddObject(module, "VALUE_INVALID_ID",
			   PyLong_FromLongLong(LU_VALUE_INVALID_ID));
	return 0;
}

PyDoc_STRVAR(libuser_module_doc, "Python bindings for the libuser library");

#if PY_MAJOR_VERSION < 3
PyMODINIT_FUNC
initlibuser(void)
{
	PyObject *module;

	DEBUG_ENTRY;
	module = Py_InitModule3("libuser", libuser_methods, libuser_module_doc);
	(void)initialize_libuser_module(module);
	DEBUG_EXIT;
}

#else /* PY_MAJOR_VERSION >= 3 */

static struct PyModuleDef libuser_module = {
	PyModuleDef_HEAD_INIT,
	"libuser",
	libuser_module_doc,
	-1,
	libuser_methods,
	NULL,
	NULL,
	NULL,
	NULL
};

PyMODINIT_FUNC
PyInit_libuser(void)
{
	char *encoding;
	PyObject *module;

	DEBUG_ENTRY;
	/* Python 3 makes it fairly difficult to use non-UTF-8 encodings for
	 * C strings.  Support for this is not likely to be needed (among
	 * other reasons because it is unlikely for other Python extensions to
	 * care), so just make sure to fail loudly instead of silently
	 * corrupting data.
	 *
	 * Python 3 always calls setlocale(LC_CTYPE, "") during initialization,
	 * so doing this check already at module import time will properly
	 * reflect system-wide encoding (the one we care for the system-wide
	 * account databases and file system paths), even if the application
	 * decided to locally override the locale to something else.
	 */
	encoding = nl_langinfo(CODESET);
	if (strcmp(encoding, "UTF-8") != 0) {
		PyErr_Format(PyExc_NotImplementedError,
			     "libuser does not support non-UTF-8 locales with "
			     "Python 3 (currently using %s)", encoding);
		goto err;
	}

	module = PyModule_Create(&libuser_module);
	if (module == NULL)
		goto err;
	if (initialize_libuser_module(module) < 0)
		goto err_module;
	DEBUG_EXIT;
	return module;

err_module:
	Py_DECREF(module);
err:
	DEBUG_EXIT;
	return NULL;
}
#endif /* PY_MAJOR_VERSION >= 3 */
