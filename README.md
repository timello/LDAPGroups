LDAPGroups
==========

Bugzilla extension to map Bugzilla and LDAP groups.

## Installation

1. Copy the LDAPGroups/ to the Bugzilla extensions directory and run the checksetup.pl script.
2. You should be using 'LDAP' as one of the user_verify_class options.
3. Create or modify an existent group and add the 'LDAP DN' for it. This will be used to map the Bugzilla Group and the LDAP Group. It will add Bugzilla users to the group if they are also member of the related LDAP group. This will happen automatically when a Bugzilla group is created or modified.
4. The groups membership will be synced up everytime the user logs in.

