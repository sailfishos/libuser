import libuser
import unittest

LARGE_ID = 2147483648

class Tests(unittest.TestCase):
    def setUp(self):
        self.a = libuser.admin()

    def testGetFirstUnusedUid(self):
        self.assertEqual(self.a.getFirstUnusedUid(start=LARGE_ID + 100),
                         LARGE_ID + 100)
        self.assertEqual(self.a.getFirstUnusedUid(), 1239)

    def testGetFirstUnusedGid(self):
        self.assertEqual(self.a.getFirstUnusedGid(start=LARGE_ID + 200),
                         LARGE_ID + 200)
        self.assertEqual(self.a.getFirstUnusedGid(), 1234)


    def tearDown(self):
        del self.a


if __name__ == '__main__':
    unittest.main()
