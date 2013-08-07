#!/usr/bin/perl -w
# -*- Mode: perl; indent-tabs-mode: nil -*-
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This Source Code Form is "Incompatible With Secondary Licenses", as
# defined by the Mozilla Public License, v. 2.0.
#
# Script to syncronize group members with LDAP on an ad-hoc basis
#

use strict;
use warnings;
use lib qw(. lib);

use Bugzilla;
BEGIN { Bugzilla->extensions }

use Bugzilla::Extension::LDAPGroups::Util qw(sync_ldap);

# Get all groups where the ldap_dn has been set
sub get_groups_using_ldap_dn(){
    my @groups   = Bugzilla::Group->get_all;

    my @groups_with_ldap_dn;

    foreach my $group (@groups){
        if ($group->ldap_dn){
            push @groups_with_ldap_dn, $group;
        }
    }
    
    return @groups_with_ldap_dn;
}

sub main(){
    my @groups = get_groups_using_ldap_dn();

    # For every group that has a ldap_dn update
    # the groups' members according to LDAP
    foreach my $group (@groups){
        sync_ldap($group);
    }

    return;
}

main();
