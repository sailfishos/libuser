#!/usr/bin/python

import libuser
import os
import time

print("--------- Initializing.")
admin = libuser.admin()

print("--------- Listing.")
for item in sorted(admin.enumerateUsers("l*")):
	print("Found a user named \"" + item + "\".")

print("--------- Lookup.")
ldap = admin.lookupUserByName("ldap")

print("--------- Reading attribute (get).")
print(ldap.get(libuser.LOGINSHELL))
print("--------- Reading attribute (map).")
print(ldap[libuser.LOGINSHELL])
print("--------- Reading keys.")
print(list(ldap.keys()))

print("--------- Setting attribute.")
ldap.set(libuser.LOGINSHELL, ["/bin/true"])
ldap[libuser.LOGINSHELL] = "/bin/true"
ldap[libuser.LOGINSHELL] = ["/bin/true"]

print("--------- Reading attribute (get).")
print(ldap.get(libuser.LOGINSHELL))
print("--------- Reading attribute (map).")
print(ldap[libuser.LOGINSHELL])

print("--------- Getting directory list.")
dir(ldap)

print("--------- Modifying user.")
admin.modifyUser(ldap)

print("--------- Enumerating members of the wheel group.")
print(admin.enumerateUsersByGroup("wheel"))

print("--------- Looking up the wheel group.")
wheel = admin.lookupGroupByName("wheel")

print("--------- Reading attribute (memberUid).")
print(wheel[libuser.MEMBERNAME])

print("--------- Creating a new user (jimbo).")
jimbo = admin.initUser("jimbo")
for attr in jimbo.keys():
	print(" " + attr + ":", jimbo.get(attr))

print("--------- Adding the user.")
jimbo[libuser.HOMEDIRECTORY] = '/var/jimbo-home'
print("Set home directory to " + jimbo[libuser.HOMEDIRECTORY][0])
admin.addUser(jimbo)

print("--------- Grepping for the user.")
os.system("grep jimbo /etc/passwd /etc/group /etc/shadow /etc/gshadow")

try:
	dir = jimbo.get(libuser.HOMEDIRECTORY)
	print("--------- Looking at user's directory.")
	os.system("ls " + dir[0])
	print("--------- Looking at mail spool directory.")
	os.system("ls -l /var/mail/*")
except:
	pass

print("--------- Removing the user.")
admin.deleteUser(jimbo)
admin.removeHome(jimbo)
admin.removeMail(jimbo)
print("--------- Grepping for the user.")
os.system("grep jimbo /etc/passwd /etc/group /etc/shadow /etc/gshadow")

print("--------- Getting a list of all users.")
users = admin.enumerateUsersFull()
for user in users:
	print("  User `" + user[libuser.USERNAME][0] + "' has uid ", user[libuser.UIDNUMBER][0])
