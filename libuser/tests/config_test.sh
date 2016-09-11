#! /bin/sh
# Automated config handling regression tester
#
# Copyright (c) 2004, 2005, 2008 Red Hat, Inc. All rights reserved.
#
# This is free software; you can redistribute it and/or modify it under
# the terms of the GNU Library General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
#
# Author: Miloslav Trmac <mitr@redhat.com>

srcdir=$srcdir/tests

workdir=$(pwd)/test_config

trap 'status=$?; rm -rf "$workdir"; exit $status' 0
trap '(exit 1); exit 1' 1 2 13 15

rm -rf "$workdir"
mkdir "$workdir"

# Set up the client
sed "s|@TOP_BUILDDIR@|$(pwd)|g" < "$srcdir"/config.conf.in \
	> "$workdir/libuser.conf"
sed -e "s|@TOP_BUILDDIR@|$(pwd)|g" -e "s|@SRCDIR@|$srcdir|g" \
	< "$srcdir"/config_import.conf.in > "$workdir/libuser_import.conf"
sed -e "s|@TOP_BUILDDIR@|$(pwd)|g" -e "s|@SRCDIR@|$srcdir|g" \
	< "$srcdir"/config_import2.conf.in > "$workdir/libuser_import2.conf"
sed -e "s|@TOP_BUILDDIR@|$(pwd)|g" -e "s|@SRCDIR@|$srcdir|g" \
	< "$srcdir"/config_override.conf.in > "$workdir/libuser_override.conf"

# Ugly non-portable hacks
LD_LIBRARY_PATH=$(pwd)/lib/.libs
export LD_LIBRARY_PATH
PYTHONPATH=$(pwd)/python/.libs
export PYTHONPATH

$VALGRIND tests/config_test "$workdir"

LIBUSER_CONF="$workdir/libuser_import.conf"
export LIBUSER_CONF
workdir="$workdir" $VALGRIND $PYTHON "$srcdir"/config_test.py
