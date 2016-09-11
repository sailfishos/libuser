import libuser

admin = libuser.admin()

e = admin.initUser('pwhash_user')
admin.addUser(e, False, False)
admin.setpassUser(e, 'password', False)
res = e[libuser.SHADOWPASSWORD][0]
admin.deleteUser(e, False, False)

print(res)
