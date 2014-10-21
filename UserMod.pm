package UserMod;

use strict;
use Carp;
use vars qw($VERSION);
$VERSION = 0.1;



sub new {
	my ($pkg, $name) = @_;
	my $usr = bless {
		"name" => $name,
	}, $pkg;
	return $usr;
}

sub show {
	my($usr, $field) = @_;
	return $usr->change($field);
}
sub change {
	my($usr, $field, $new_value, $salt) = @_;
	my($fields, @fields, $file, @F);
	my $username = $usr->{"name"};
	my $salt = $salt ? $salt : "13";
	$new_value = $new_value =~ /^([!-\/\w\s"]*)$/ ? $1 :  carp "Malicious data in new value";
 if($field eq "uid" || $field eq "gid" || $field eq "comment" || $field eq "home" || $field eq "shell") {
	my $file = "/etc/passwd";
	open(FH, "+<$file");
	flock(FH, 2);
	@F = <FH>;
	for (@F) {
		if(/^$username:/){
			@fields = split(/:/, $_, 7);
			CASE: {
				if($field eq "uid") { 
					$usr->{"uid"} = 
					($fields[2] = $new_value ? $new_value : $fields[2]); 
					last CASE }
				if($field eq "gid") { $usr->{"gid"} = 
					($fields[3] = $new_value ? $new_value : $fields[3]); 
					last CASE }
				if($field eq "comment") { $usr->{"comment"} = 
					($fields[4] = $new_value ? $new_value : $fields[4]); 
					last CASE }
				if($field eq "home") { $usr->{"home"} = 
					($fields[5] = $new_value ? $new_value : $fields[5]); 
					last CASE }
				if($field eq "shell") { $usr->{"shell"} = 
					($fields[6] = $new_value ? $new_value : $fields[6]); 
					last CASE }
			}
			$fields = join(":", @fields);
			$fields =~ s/\n//
		}
	}
	for(@F) { if(/^$username:/){  s/.*/$fields/; } }
	seek(FH, 0, 0) or die "cannot seek passwd file\n";
	print FH @F or die "cannot write to passwd file\n";
	truncate(FH, tell(FH)) or die "cannot truncate passwd file\n";
	close(FH);
	return $usr->{$field};
 } elsif($field eq "password" || $field eq "password_l" || $field eq "password_u" ||
	 $field eq "dsalch" || $field eq "may" || $field eq "must" || 
	 $field eq "warn" || $field eq "expire" || $field eq "dsdis") {
	my $file = "/etc/shadow";
	open(FH, "+<$file");
	flock(FH, 2);
	@F = <FH>;
	for (@F) {
		if(/^$username:/){
	  		@fields = split(/:/, $_, 8);
			CASE: {
				if($field eq "password") { $usr->{"password"} = ($fields[1] = $new_value ?
					crypt($new_value, substr($fields[1], 0, $salt)) : $fields[1]);
					last CASE
				}
				if($field eq "password_l") { 
					($fields[1] =~ s/(.*)/!$1/) if($fields[1] !~ /^!/);
					last CASE
				}
				if($field eq "password_u") { 
					($fields[1] =~ s/^!//) if($fields[1] =~ /^!/);
					last CASE
				}  
				if($field eq "dsalch") { $usr->{"dsalch"} = 
					($fields[2] = $new_value ? $new_value : $fields[2]); 
					last CASE }
				if($field eq "may") { $usr->{"may"} = 
					($fields[3] = $new_value ? $new_value : $fields[3]); 
					last CASE }
				if($field eq "must") { $usr->{"must"} = 
					($fields[4] = $new_value ? $new_value : $fields[4]); 
					last CASE }
				if($field eq "warn") { $usr->{"warn"} = 
					($fields[5] = $new_value ? $new_value : $fields[5]);
					 last CASE }
				if($field eq "expire") { $usr->{"expire"} =
					($fields[6] = $new_value ? $new_value : $fields[6]);
					 last CASE }
				if($field eq "dsadis") { $usr->{"dsadis"} = 
					($fields[7] = $new_value ? $new_value : $fields[7]);
					 last CASE }
			}
			$fields = join(":", @fields);
			$fields =~ s/\n//;
		}
	}
	for(@F) { if(/^$username:/){ s/.*/$fields/ } }
	seek(FH, 0, 0) or die "cannot seek shadow file\n";
	print FH @F or die "cannot write to shadow file\n";
	truncate(FH, tell(FH)) or die "cannot truncate shadow file\n";
	close(FH);
	return $usr->{$field};
 } else { return "Illegal field name!\n" }
}
sub lock {
	my($usr) = shift;
	$usr->change("password_l");
	return $usr->change("password");
}
sub unlock {
	my($usr) = shift;
	$usr->change("password_u");
	return $usr->change("password");
}

1;

__END__

=head1 NAME

UserMod - modify user accounts

=head1 SYNOPSIS

  use UserMod;

  $user = UserMod->new("username");
  
  $user->change($field_name, $new_value);
  $user->show($field_name);
  $user->lock;
  $user->unlock;

=head1 DESCRIPTION

B<UserMod> is a simple package which change or return fields from B</etc/passwd> and B</etc/shadow>
files. It acts like  B<usermod> (with the main exception it is OOPerl program).
The job is done entirely in B<change> which returns(B<show>s) the value of the field specified as a first argument. The second optional argument serves as a new value for the field. If password field is specified, You
can use third argument for the value of B<salt> which is 13 characters by default. The package implements a 
simple taint checking by 'carping'(warning) for input data which is not any of the following: '\w\s-!"/'.  

=head1 METHODS

=over 4

=item B<change> method - B<fields> take the following values:


=over 4

=item B<comment> -
comments or user full name

=item B<dsadis> -
days since Jan 1, 1970 that account is disabled

=item B<dsalch> -
days since Jan 1, 1970 that password was last changed

=item B<expire> -
days after password expired that account is disabled

=item B<gid> -
group id

=item B<home> -
home directory

=item B<may> - 
days before password may be changed

=item B<must> -
days after which password must be changed

=item B<password> - 
encoded password from shadow file

=item B<shell> -
login shell

=item B<uid> -
user id

=item B<warn> - 
days before password is to expire user is warned

=back

=item B<show> 

returns the field specified as its only argument. Equivalent to
B<change> when one argument is given.

=item B<lock>

Lock a user account ('!' at the beginning of the encoded password)

=item B<unlock> 

Unlock user account (removes '!' from the beginning of the encoded
password)

=back

=head1 FILES

B</etc/passwd>, B</etc/shadow>

=head1 SEE ALSO 

B<getpwent>(3), B<getpwnam>(3), B<usermod>(8), B<passwd>(8)

=head1 AUTHOR

Vidul Petrov, vidul@abv.bg

=cut
