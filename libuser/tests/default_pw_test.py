import libuser
import sys
import unittest

def prompt_callback(prompts):
    for p in prompts:
        if p.key == 'ldap/password':
            p.value = 'password'
        else:
            p.value = p.default_value

valid_combination=int(sys.argv[1])
del sys.argv[1] # For unittest.main()

# This is ugly; ideally we would want a separate connection for each test case,
# but libssl REALLY doesn't like being unloaded (libcrypto is not unloaded
# and keeps pointers to unloaded libssl)
if valid_combination != 0:
    admin = libuser.admin(prompt = prompt_callback)
else:
    try:
        admin = libuser.admin(prompt = prompt_callback)
    except SystemError:
        print("Initialization error, as expected")
        sys.exit(0)
    sys.stderr.write("Initialization unexpectedly succeeded\n")
    sys.exit(1)

# Test case order matches the order of function pointers in struct lu_module
class Tests(unittest.TestCase):
    def setUp(self):
        # See the comment at the libuser.admin() call above
        self.a = admin

    def testGroupAddDefault(self):
        # Add a group with default attributes
        e = self.a.initGroup('group_default')
        self.a.addGroup(e)
        del e

    def testGroupAddSetpass(self):
        # Add a group, changing a password explicitly
        e = self.a.initGroup('group_setpass')
        self.a.addGroup(e)
        del e
        e = self.a.lookupGroupByName('group_setpass')
        self.a.setpassGroup(e, 'password', False)
        del e

    def testUserAddDefault(self):
        # Add an user with default attributes
        e = self.a.initUser('user_default')
        self.a.addUser(e, False, False)
        del e

    def testUserAddSetpass(self):
        # Add an user, changing password explicitly
        e = self.a.initUser('user_setpass')
        self.a.addUser(e, False, False)
        del e
        e = self.a.lookupUserByName('user_setpass')
        self.a.setpassUser(e, 'password', False)
        del e

    def tearDown(self):
        del self.a


if __name__ == '__main__':
    unittest.main()
