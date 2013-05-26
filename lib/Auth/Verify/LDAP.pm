# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This Source Code Form is "Incompatible With Secondary Licenses", as
# defined by the Mozilla Public License, v. 2.0.

package Bugzilla::Extension::LDAPGroups::Auth::Verify::LDAP;
use strict;
use parent qw(Bugzilla::Auth::Verify::LDAP);

use Bugzilla::Error qw(ThrowCodeError);

use Net::LDAP::Util qw(escape_filter_value);


sub check_credentials {
    my ($self, $params) = @_;
    $params = $self->SUPER::check_credentials($params);
    my $ldap_group_dns = $self->_ldap_member_of_groups($params->{bz_username});
    $params->{ldap_group_dns} = $ldap_group_dns if scalar @$ldap_group_dns;
    return $params;
}

sub _ldap_member_of_groups {
    my ($self, $uid) = @_;

    $uid = escape_filter_value($uid);
    my $uid_attr = Bugzilla->params->{"LDAPuidattribute"};
    my $base_dn = Bugzilla->params->{"LDAPBaseDN"};
    my $dn_result = $self->ldap->search(( base   => $base_dn,
                                          scope  => 'sub',
                                          filter => "$uid_attr=$uid" ),
                                        attrs => ['memberof']);

    if ($dn_result->code) {
        ThrowCodeError('ldap_search_error',
            { errstr => $dn_result->error, username => $uid });
    }

    my @ldap_group_dns;
    push @ldap_group_dns, $_->get_value('memberof') for $dn_result->entries;

    return \@ldap_group_dns;
}

1;
