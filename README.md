LDAPGroups
==========

Bugzilla extension to map Bugzilla and LDAP groups.

## Installation

1. Copy the LDAPGroups/ to the Bugzilla extensions directory and run the checksetup.pl script.
2. You should be using 'LDAP' as one of the user_verify_class options.
3. Create or modify an existent group and add the 'LDAP DN' for it. This will be used to map the Bugzilla Group and the LDAP Group. It will add Bugzilla users to the group if they are also member of the related LDAP group. This will happen automatically when a Bugzilla group is created or modified.
4. The groups membership will be synced up everytime the user logs in.

## Important notes

> The extension does not verify if the user is indirect member of a certain group. That means,
the user will be added as member only for those groups he is directly member of.

> The extension has been tested using OpenLDAP with the virtual attribute 'memberOf' enabled. You have to customize the code if it does not reflect your LDIF. Example:
    > ldapsearch -x uid=jsmith memberof
    # extended LDIF
    #
    # LDAPv3
    # base <dc=ldap,dc=bugzilla> (default) with scope subtree
    # filter: uid=jsmith
    # requesting: memberof 
    #

    # John Smith, Users, ldap.bugzilla
    dn: cn=John Smith,ou=Users,dc=ldap,dc=bugzilla
    memberOf: cn=group2,ou=Groups,dc=ldap,dc=bugzilla

    # search result
    search: 2
    result: 0 Success

    # numResponses: 2
    # numEntries: 1
