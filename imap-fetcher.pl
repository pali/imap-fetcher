#!/usr/bin/perl

use strict;
use warnings;

use IO::Handle;
use IO::Socket::INET;
use IO::Socket::SSL;

use constant DEBUG => 0;

my $dir = $ARGV[0];
die "Error: No target directory specified\n" unless defined $dir;
die "Error: Target directory does not exist\n" unless -d $dir;

my $sock;

$SIG{TERM} = $SIG{INT} = sub {
	print "Exiting...\n";
	if ($sock) {
		print $sock "0 LOGOUT\r\n";
		$sock->close(SSL_ctx_free => 1);
	}
	exit;
};

mkdir "$dir/lock"
	or die "Error: Cannot lock directory `$dir': " . ($!{EEXIST} ? "Lock `$dir/lock' already exists" : $!) . "\n";

my $run_end = 1;
END { $run_end and rmdir "$dir/lock" }

my %config;

open my $fh, '<', "$dir/config"
	or die "Error: Config file `$dir/config' does not exist\n";
while (<$fh>) {
	chomp;
	next if /^#/ or /^$/;
	my ($key, $value) = split /=/, $_, 2;
	die "Error: Syntax error in file `$dir/config' at line $.\n" unless defined $key and defined $value;
	$config{lc $key} = $value;
}
close $fh;

LOGIN:
if ($config{ssl}) {
	$sock = IO::Socket::SSL->new(
			PeerHost => $config{server},
			PeerPort => $config{port},
		);
	die "Cannot connect to server: $!, $SSL_ERROR\n" unless $sock;
	$sock->blocking(1);
} else {
	$sock = IO::Socket::INET->new(
			PeerHost => $config{server},
			PeerPort => $config{port},
			Proto => 'tcp',
		);
	die "Cannot connect to server: $!\n" unless $sock;
}

my $num = 1;
my $done;

my $has_gmail;
print "Logging in...";
STDOUT->flush();
print $sock "$num LOGIN $config{user} $config{pass}\r\n";
$done = 0;
while (<$sock>) {
	$_ =~ s/\r?\n$//;
	DEBUG and warn "DEBUG: $_\n";
	if ($_ =~ /^\*\s+CAPABILITY\b/) {
		$has_gmail = ($_ =~ /\bX-GM-EXT-1\b/);
	} elsif ($_ =~ /^$num\b/) {
		die "Login failed: $_\n" if $_ !~ /^$num\s+OK\b/;
		$done = 1;
		last;
	} elsif ($_ =~ /^\*\s+BYE\b/) {
		die "Login failed: $_\n";
	}
}
die "Login failed: Connection closed\n" unless $done;
$num++;
print " done\n";

my $folder = $config{folder};
if (not defined $folder) {
	my $folder_flag = $config{folder_flag};
	die "At least folder or folder_flag must be specified\n" unless defined $folder_flag;
	print "Listing folders...";
	STDOUT->flush();
	print $sock "$num LIST \"\" \"*\"\r\n";
	$done = 0;
	while (<$sock>) {
		$_ =~ s/\r?\n$//;
		DEBUG and warn "DEBUG: $_\n";
		if (not defined $folder and $_ =~ /^\*\s+LIST\s+\((.*)\)\s+".*"\s+(".*")\s*$/) {
			if (grep { $_ eq $folder_flag } split / /, $1) {
				$folder = $2;
			}
		} elsif ($_ =~ /^$num\b/) {
			die "List failed: $_\n" if $_ !~ /^$num\s+OK\b/;
			$done = 1;
			last;
		} elsif ($_ =~ /^\*\s+BYE\b/) {
			die "List failed: $_\n";
		}
	}
	die "List failed: Connection closed\n" unless $done;
	$num++;
	print " done\n";
	die "Folder with flags `$folder_flag' was not found\n" unless defined $folder;
}

print "Examing folder $folder...";
STDOUT->flush();
print $sock "$num EXAMINE $folder\r\n";
$done = 0;
while (<$sock>) {
	$_ =~ s/\r?\n$//;
	DEBUG and warn "DEBUG: $_\n";
	if ($_ =~ /^$num\b/) {
		die "Examine failed: $_\n" if $_ !~ /^$num\s+OK\b/;
		$done = 1;
		last;
	} elsif ($_ =~ /^\*\s+BYE\b/) {
		die "Examine failed: $_\n";
	}
}
die "Examine failed: Connection closed\n" unless $done;
$num++;
print " done\n";

my $lastuid = 0;
if (open my $lastuid_fh, '<', "$dir/lastuid") {
	$lastuid = <$lastuid_fh>;
	close $lastuid_fh;
	chomp $lastuid;
	$lastuid = 0 unless $lastuid =~ /^[0-9]+$/;
}

while (1) {
	my ($lastid, $highestuid, $highestid);
	print "Checking for new messages...";
	STDOUT->flush();
	print $sock "$num UID FETCH " . ($lastuid != 0 ? "$lastuid," : "") . "* (UID)\r\n";
	$done = 0;
	while (<$sock>) {
		$_ =~ s/\r?\n$//;
		DEBUG and warn "DEBUG: $_\n";
		if ($_ =~ /^\*\s+([0-9]+)\s+FETCH\s+\(UID\s+([0-9]+)\)\s*$/) {
			$lastid = $1 if $lastuid != 0 and $lastuid == $2;
			$highestid = $1 if not defined $highestid or $highestid < $1;
			$highestuid = $2 if not defined $highestuid or $highestuid < $2;
		} elsif ($_ =~ /^$num\b/) {
			warn "Fetch highest uid failed: $_\n" if $_ !~ /^$num\s+OK\b/;
			$done = 1;
			last;
		} elsif ($_ =~ /^\s*\s+BYE\b/) {
			warn "Fetch highest uid failed: $_\n";
			last;
		}
	}
	if (not $done) {
		warn "Fetch highest uid failed: Connection closed\n";
		$sock->close(SSL_ctx_free => 1);
		goto LOGIN;
	}
	$num++;
	print " done\n";

	my $fetched = 0;
	if (not defined $highestuid or $lastuid < $highestuid) {
		print "\rFetching messages ?/$highestid (new 0/" . ($highestid-$lastid) . ")";
		STDOUT->flush();
		print $sock "$num UID FETCH " . ($lastuid+1) . ":* (RFC822 INTERNALDATE" . ($has_gmail ? " X-GM-LABELS" : "") . ")\r\n";
		$done = 0;
		while (<$sock>) {
			$_ =~ s/\r?\n$//;
			DEBUG and warn "DEBUG: $_\n";
			if ($_ =~ /^\*\s+([0-9]+)\s+FETCH\b/) {
				my $id = $1;
				$_ =~ s/^\*\s+[0-9]+\s+//;
				my ($message, $uid, $date, $status);
				my $result = [];
				push @{$result}, [ $result ];
				while (length $_) {
					if ($_ =~ s/^"((?:\\.|[^\\"])*)"(?:\s+|\Z|(\)))//) {
						$_ = $2 . $_ if defined $2;
						DEBUG and warn "PARSED ESC: $1 ; $_\n";
						my $data = $1;
						$data =~ s/^\\(.)/$1/g;
						push @{$result}, $data;
					} elsif ($_ =~ s/^\(\s*//) {
						DEBUG and warn "PARSED OPEN: $_\n";
						my $new = [ $result ];
						push @{$result}, $new;
						$result = $new;
					} elsif ($_ =~ s/^\)\s*//) {
						DEBUG and warn "PARSED CLOSE: $_\n";
						my $old = $result;
						$result = $result->[0];
						shift @{$old};
						die "Parsing failed: Incorrect nested level at: $_\n" unless scalar @{$result};
					} elsif ($_ =~ s/^\{([0-9]+)\}$//) {
						DEBUG and warn "PARSED RAW: '$1' ; $_\n";
						$sock->read(my $data, $1) or die "Reading failed: $!\n";
						$_ = <$sock>;
						$_ =~ s/\r?\n$//;
						$_ =~ s/^\s*//;
						push @{$result}, $data;
					} else {
						die "Parsing failed: Invalid identifier at: $_\n" unless $_ =~ s/^([^"()\s]+)\b\s*//;
						DEBUG and warn "PARSED LIT: $1 ; $_\n";
						push @{$result}, $1;
					}
				}
				shift @{$result};
				if (scalar @{$result} < 2 or $result->[0] ne "FETCH" or ref($result->[1]) ne "ARRAY") {
					warn "Not a fetch command\n";
				} else {
					my @fields = @{$result->[1]};
					if (scalar @fields % 2 != 0) {
						warn "Incorrect content of fetch command\n";
					} else {
						while (@fields) {
							my $key = shift @fields;
							my $value = shift @fields;
							if ($key eq "X-GM-LABELS") {
								if (ref($value) eq "ARRAY") {
									my @flags = grep { ref($_) ne "ARRAY" and $_ ne "\\\\Important" and $_ ne "\\\\Starred" } @{$value};
									$status = (not grep { $_ eq "\\\\Sent" } @flags) ? "Received" : @flags == 1 ? "Sent" : "Sent+Received";
								} else {
									$status = ($value eq "\\\\Sent") ? "Sent" : "Received";
								}
							} elsif ($key eq "UID") {
								$uid = $value if ref($value) ne "ARRAY";
							} elsif ($key eq "RFC822") {
								$message = $value if ref($value) ne "ARRAY";
							} elsif ($key eq "INTERNALDATE") {
								$date = $value if ref($value) ne "ARRAY";
							}
						}
					}
					if (defined $uid and defined $message and defined $date and $uid =~ /^[0-9]+$/ and $uid > $lastuid) {
						$status = "Unknown" unless defined $status;
						DEBUG and warn "MESSAGE: id=$id uid=$uid date=$date status=$status\n";
						open my $lastuid_fh, '>', "$dir/lastuid.new"
							or die "Cannot open file `$dir/lastuid.new': $!\n";
						print $lastuid_fh "$uid\n";
						close $lastuid_fh;
						if (defined $config{command}) {
							open my $command, "|-", "$config{command} \"$date\" \"$uid\" \"$status\""
								or warn "Cannot execute `$config{command}'";
							print $command $message;
							close $command;
						}
						rename "$dir/lastuid.new", "$dir/lastuid";
						$lastuid = $uid;
						$fetched++;
					}
				}
				print "\rFetching messages $id/$highestid (new " . ($id-$lastid) . "/" . ($highestid-$lastid) . ")";
				STDOUT->flush();
				DEBUG and warn "PROGRESS: $id/$highestid (" . ($id-$lastid) . "/" . ($highestid-$lastid) . " fetched: $fetched)\n";
			} elsif ($_ =~ /^$num\b/) {
				warn "Fetch failed: $_\n" if $_ !~ /^$num\s+OK\b/;
				$done = 1;
				last;
			} elsif ($_ =~ /^\*\s+BYE\b/) {
				warn "Fetch failed: $_\n";
				last;
			}
		}
		if (not $done) {
			warn "Fetch failed: Connection closed\n";
			$sock->close(SSL_ctx_free => 1);
			goto LOGIN;
		}
		$num++;
		print "\n";
	}
	my $stop = 0;
	local $SIG{ALRM} = sub {
		DEBUG and warn "SIGALRM\n";
		print $sock "DONE\r\n";
		$stop = 1;
	};
	print "No new messages... idling\n";
IDLE:
	print $sock "$num IDLE\r\n";
	$done = 0;
	alarm 60*15;
	while (<$sock>) {
		$_ =~ s/\r?\n$//;
		DEBUG and warn "DEBUG: $_\n";
		if ($_ =~ /^\*\s+[0-9]+\s+EXISTS$/) {
			print $sock "DONE\r\n" unless $stop;
			$stop = 2;
		} elsif ($_ =~ /^$num\b/) {
			if ($_ =~ /^$num\s+OK\b/) {
				if ($stop == 1) {
					DEBUG and warn "RESTART IDLE\n";
					$stop = 0;
					goto IDLE;
				}
			} else {
				warn "Idle failed: $_\n";
			}
			$done = 1;
			last;
		} elsif ($_ =~ /^\*\s+BYE\b/) {
			warn "Idle failed: $_\n";
			last;
		}
	}
	alarm 0;
	if (not $done) {
		warn "Idle failed: Connection closed\n";
		$sock->close(SSL_ctx_free => 1);
		goto LOGIN;
	}
	$num++;
}
