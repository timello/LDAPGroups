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

use Bugzilla::Error qw(ThrowUserError ThrowCodeError);
use Bugzilla::Util qw(diff_arrays trim clean_text);

use Scalar::Util qw(blessed);

use constant GRANT_LDAP => 3;

our $VERSION = '0.01';


BEGIN {
    no warnings 'redefine';
    *Bugzilla::ldap = \&_bugzilla_ldap;
    *Bugzilla::Auth::Verify::_orig_create_or_update_user
        = \&Bugzilla::Auth::Verify::create_or_update_user;
    *Bugzilla::Auth::Verify::create_or_update_user = \&_create_or_update_user;
    *Bugzilla::Group::_orig_update = \&Bugzilla::Group::update;
    *Bugzilla::Group::update = \&_group_update;
    *Bugzilla::Group::_orig_create = \&Bugzilla::Group::create;
    *Bugzilla::Group::create = \&_group_create;
    *Bugzilla::Group::ldap_dn = sub { $_[0]->{ldap_dn}; }
};

# From Bugzilla::Auth::Verify::LDAP
sub _bugzilla_ldap {
    my $class = shift;

    return $class->request_cache->{ldap}
        if defined $class->request_cache->{ldap};

    my @servers = split(/[\s,]+/, Bugzilla->params->{"LDAPserver"});
    ThrowCodeError("ldap_server_not_defined") unless @servers;

    require Net::LDAP;
    my $ldap;
    foreach (@servers) {
        $ldap = new Net::LDAP(trim($_));
        last if $ldap;
    }
    ThrowCodeError("ldap_connect_failed",
        { server => join(", ", @servers) }) unless $ldap;

    # try to start TLS if needed
    if (Bugzilla->params->{"LDAPstarttls"}) {
        my $mesg = $ldap->start_tls();
        ThrowCodeError("ldap_start_tls_failed", { error => $mesg->error() })
            if $mesg->code();
    }
    $class->request_cache->{ldap} = $ldap;

    return $class->request_cache->{ldap};
}

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
            push @user_group_ids, $group->id if defined $group->ldap_dn;
        }

        my ($removed, $added) = diff_arrays(\@user_group_ids, \@$group_ids);

        $sth_add_mapping->execute($user->id, $_, 0, GRANT_LDAP)
            foreach @{ $added || [] };

        $sth_remove_mapping->execute($user->id, $_)
            foreach @{ $removed || [] };
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
    my ($invocant, $ldap_dn, undef, $params) = @_;
    my $ldap = Bugzilla->ldap;

    $ldap_dn = clean_text($ldap_dn);

    # LDAP DN is optional, but we must validate it if it was
    # passed.
    return if !$ldap_dn;

    # We just want to check if the dn is valid.
    # 'filter' can't be empty neither omitted.
    my $dn_result = $ldap->search(( base   => $ldap_dn,
                                    scope  => 'sub',
                                    filter => '1=1' ));
    if ($dn_result->code) {
        ThrowUserError('group_ldap_dn_invalid', { ldap_dn => $ldap_dn });
    }

    # Group LDAP DN already in use.
    my ($group) = @{ Bugzilla::Group->match({ ldap_dn => $ldap_dn }) };
    my $group_id = blessed($invocant) ? $invocant->id : 0;
    if (defined $group and $group->id != $group_id) {
        ThrowUserError('group_ldap_dn_already_in_use',
            { ldap_dn => $ldap_dn });
    }

    return $ldap_dn;
}

sub group_end_of_create {
    my ($self, $args) = @_;
    my $group = $args->{'group'};
}

sub group_end_of_update {
    my ($self, $args) = @_;
    my ($group, $changes) = @$args{qw(group changes)};
    _sync_ldap($group) if $group->ldap_dn;
}

sub _sync_ldap {
    my ($group) = @_;
    my $dbh  = Bugzilla->dbh;
    my $ldap = Bugzilla->ldap;

    my $sth_add = $dbh->prepare("INSERT INTO user_group_map
                                 (user_id, group_id, grant_type, isbless)
                                 VALUES (?, ?, ?, 0)");

    my $sth_del = $dbh->prepare("DELETE FROM user_group_map
                                 WHERE user_id = ? AND group_id = ?
                                 AND grant_type = ? and isbless = 0");

    my $mail_attr = Bugzilla->params->{"LDAPmailattribute"};
    my $base_dn = Bugzilla->params->{"LDAPBaseDN"};

    # Search for members of the LDAP group.
    my $filter = "memberof=" . $group->ldap_dn;
    my @attrs = ($mail_attr);
    my $dn_result = $ldap->search(( base   => $base_dn,
                                    scope  => 'sub',
                                    filter => $filter ), attrs => \@attrs);

    if ($dn_result->code) {
        ThrowCodeError('ldap_search_error',
            { errstr => $dn_result->error, username => $group->name });
    }

    my @group_members;
    push @group_members, $_->get_value('mail') foreach $dn_result->entries;

    my $users = Bugzilla->dbh->selectall_hashref(
        "SELECT userid, group_id, login_name
         FROM profiles
         LEFT JOIN user_group_map
                ON user_group_map.user_id = profiles.userid
                   AND group_id = ?
                   AND grant_type = ?
                   AND isbless = 0
         WHERE extern_id IS NOT NULL", 
        'userid', undef, ($group->id, GRANT_LDAP));

    my @added;
    my @removed;
    foreach my $user (values %$users) {
        # User is no longer member of the group.
        if (defined $user->{group_id}
            and !grep { $_ eq $user->{login_name} } @group_members)
        {
            push @removed, $user->{userid};
        }

        # User has been added to the group.
        if (!defined $user->{group_id}
            and grep { $_ eq $user->{login_name} } @group_members)
        {

            push @added, $user->{userid};
        }
    }

    $sth_add->execute($_, $group->id, GRANT_LDAP) foreach @added;
    $sth_del->execute($_, $group->id, GRANT_LDAP) foreach @removed;

    return { added => \@added, removed => \@removed };
}


__PACKAGE__->NAME;
