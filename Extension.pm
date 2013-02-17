# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This Source Code Form is "Incompatible With Secondary Licenses", as
# defined by the Mozilla Public License, v. 2.0.

package Bugzilla::Extension::LDAPGroups;

use 5.10.1;
use strict;
use parent qw(Bugzilla::Extension);

use Bugzilla::Extension::LDAPGroups::Util;

use Bugzilla::Util qw(diff_arrays);

use constant GRANT_LDAP => 3;

our $VERSION = '0.01';


BEGIN {
    no warnings 'redefine';
    *Bugzilla::Auth::Verify::_orig_create_or_update_user
        = \&Bugzilla::Auth::Verify::create_or_update_user;
    *Bugzilla::Auth::Verify::create_or_update_user = \&_create_or_update_user;
    *Bugzilla::Group::_orig_update = \&Bugzilla::Group::update;
    *Bugzilla::Group::update = \&_group_update;
    *Bugzilla::Group::_orig_create = \&Bugzilla::Group::create;
    *Bugzilla::Group::create = \&_group_create;
};

sub _create_or_update_user {
    my ($self, $params) = @_;
    my $dbh = Bugzilla->dbh;
    
    my $result = $self->_orig_create_or_update_user($params);

    if (exists $params->{ldap_group_dns}) {
       
        my $sth_add_mapping = $dbh->prepare(
            qq{INSERT INTO user_group_map
                 (user_id, group_id, isbless, grant_type)
               VALUES (?, ?, ?, ?)});

        my $sth_remove_mapping = $dbh->prepare(
            qq{DELETE FROM user_group_map
               WHERE user_id = ? AND group_id = ?});

        my $user = $result->{user};
        my @ldap_group_dns = @{ $params->{ldap_group_dns} || [] };
        my $qmarks = join(',', ('?') x @ldap_group_dns);
        my $group_ids = $dbh->selectcol_arrayref(
            "SELECT id FROM groups WHERE ldap_dn IN ($qmarks)", undef,
            @ldap_group_dns);

        my @user_group_ids;
        foreach my $group (@{ $user->groups || [] }) {
            push @user_group_ids, $group->id if defined $group->{ldap_dn};
        }

        my ($removed, $added) = diff_arrays(\@user_group_ids, \@$group_ids);

        use Data::Dumper;
        die Dumper($removed, $added, \@user_group_ids, $group_ids, $user);
        #XXX
    }

    return $result;
}

sub _group_update {
    my ($self, $params) = @_;
    $self->set('ldap_dn', Bugzilla->input_params->{ldap_dn});
    return $self->_orig_update($params);
}

sub _group_create {
    my ($class, $params) = @_;
    $params->{ldap_dn} = scalar Bugzilla->input_params->{ldap_dn};
    return $class->_orig_create($params);
}

sub install_update_db {
    my ($self, $args) = @_;
    my $dbh = Bugzilla->dbh;

    $dbh->bz_add_column('groups', 'ldap_dn',
        { TYPE => 'MEDIUMTEXT', DEFAULT => "''" });
}

sub auth_verify_methods {
    my ($self, $args) = @_;
    my $modules = $args->{modules};
    if (exists $modules->{LDAP}) {
        $modules->{LDAP} =
            'Bugzilla/Extension/LDAPGroups/Auth/Verify/LDAP.pm';
    }
}

sub object_update_columns {
    my ($self, $args) = @_;
    my ($object, $columns) = @$args{qw(object columns)};

    if ($object->isa('Bugzilla::Group')) {
        push (@$columns, 'ldap_dn');
    }
}

sub object_columns {
    my ($self, $args) = @_;

    my ($class, $columns) = @$args{qw(class columns)};

    if ($class->isa('Bugzilla::Group')) {
        push @$columns, qw(ldap_dn);
    }
}

sub object_validators {
    my ($self, $args) = @_;
    my ($class, $validators) = @$args{qw(class validators)};

    if ($class->isa('Bugzilla::Group')) {
        $validators->{ldap_dn} = \&_check_ldap_dn;
    }
}

sub _check_ldap_dn {
    my ($invocant, $value, $field, $params) = @_;
    #TODO(timello): Add DN validation.
    return $value;
}

__PACKAGE__->NAME;
