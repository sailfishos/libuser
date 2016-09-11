# Helpers for fs_test.
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012 Red Hat, Inc. All rights reserved.
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
# Author: Miloslav Trmač <mitr@redhat.com>

import libuser
import sys

def main():
    if sys.argv[1] == '--remove':
        a = libuser.admin()
        u = a.initUser('fs_test_remove')
        u[libuser.HOMEDIRECTORY] = sys.argv[2]
        a.removeHome(u)
    elif sys.argv[1] == '--remove-if-owned':
        a = libuser.admin()
        u = a.initUser('fs_test_remove')
        u[libuser.HOMEDIRECTORY] = sys.argv[2]
        u[libuser.UIDNUMBER] = int(sys.argv[3])
        try:
            a.removeHomeIfOwned(u)
        except RuntimeError as e:
            sys.exit(str(e))
    elif sys.argv[1] == '--move':
        a = libuser.admin()
        u = a.initUser('fs_test_move')
        u[libuser.HOMEDIRECTORY] = sys.argv[2]
        try:
            a.moveHome(u, sys.argv[3])
        except RuntimeError as e:
            sys.exit(str(e))
    elif sys.argv[1] == '--populate':
        a = libuser.admin()
        u = a.initUser('fs_test_populate')
        u[libuser.HOMEDIRECTORY] = sys.argv[2]
        u[libuser.UIDNUMBER] = int(sys.argv[3])
        u[libuser.GIDNUMBER] = int(sys.argv[4])
        try:
            a.createHome(u)
        except RuntimeError as e:
            sys.exit(str(e))
    else:
        sys.exit('Unexpected mode')

if __name__ == '__main__':
    main()
