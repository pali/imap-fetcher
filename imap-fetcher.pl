#!/usr/bin/perl
# (c) Pali 2018-2022, Perl license

use strict;
use warnings;

use IO::Handle;
use IO::Socket::INET;
use IO::Socket::SSL;
use JSON::PP;
use HTTP::Tiny;
use MIME::Base64;
use Time::Piece;

use constant DEBUG => 0;

if (defined $ARGV[0] and $ARGV[0] eq '-h') {
	print <<"EOT";
$0 - Fast fetch of all messages from IMAP mailbox

Usage: $0 directory

This tool incrementally fetch all messages from specified IMAP mailbox.
Once there is no new message it waits in IMAP IDLE state. Information
about the last downloaded message is stored in `directory/lastuid' file.
If custom command is not specified then tool stores messages into mbox
file `directory/mbox'. This tool uses mkdir-based lock and in case it
is terminated abnormally it is required to remove `directory/lock`.

Configuration is done via `directory/config' file. For example to fetch
all messages from GMail account to mbox file use following options:

server=imap.gmail.com
port=993
user=username\@gmail.com
xoauth2_request_url=https://accounts.google.com/o/oauth2/token
xoauth2_client_id=public_id
xoauth2_client_secret=secret_key
xoauth2_refresh_token=secret_token
ssl=1
folder_flag=\\All

This is the fastest way how to incrementally download all messages from
GMail account, with ability to interrupt and continue downloading process.

IMAP mailbox folder may be specified also explicitly, instead of
'folder_flag' use e.g. 'folder=INBOX'.

To fetch all messages from folder INBOX on myimapserver:

server=myimapserver
port=993
user=username
pass=password
ssl=1
folder=INBOX

To process fetched messages via custom command instead of storing them
into mbox file, add config option 'command='.
EOT
	exit;
}

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

foreach (qw(server user)) {
	die "Error: Missing option '$_' in config file `$dir/config'\n" unless defined $config{$_};
}

if ((grep { defined $config{$_} } qw(pass xoauth2_request_url xoauth2_access_token)) != 1) {
	die "Error: Exactly one option 'pass', 'xoauth2_request_url' or 'xoauth2_access_token' must be specified in config file `$dir/config'\n";
}

if (defined $config{xoauth2_request_url}) {
	foreach (qw(xoauth2_client_id xoauth2_client_secret xoauth2_refresh_token)) {
		die "Error: Missing option '$_' in config file `$dir/config'\n" unless defined $config{$_};
	}
}

$config{port} = $config{ssl} ? 993 : 143 unless defined $config{port};

LOGIN:
if ($config{ssl}) {
	$sock = IO::Socket::SSL->new(
			PeerHost => $config{server},
			PeerPort => $config{port},
		);
	if (not $sock) {
		warn "Cannot connect to server: $!, $SSL_ERROR\n";
		sleep 10;
		goto LOGIN;
	}
	$sock->blocking(1);
} else {
	$sock = IO::Socket::INET->new(
			PeerHost => $config{server},
			PeerPort => $config{port},
			Proto => 'tcp',
		);
	if (not $sock) {
		warn "Cannot connect to server: $!\n";
		sleep 10;
		goto LOGIN;
	}
}

my $num = 1;
my $done;

my $has_gmail;

if (defined $config{xoauth2_request_url} or defined $config{xoauth2_access_token}) {
	my $has_xoauth2;

	print "Retrieving capabilities...";
	STDOUT->flush();
	print $sock "$num CAPABILITY\r\n";
	$done = 0;
	while (<$sock>) {
		$_ =~ s/\r?\n$//;
		DEBUG and warn "DEBUG: $_\n";
		if ($_ =~ /^\*\s+CAPABILITY\b/) {
			$has_gmail = ($_ =~ /\bX-GM-EXT-1\b/);
			$has_xoauth2 = ($_ =~ /\bSASL-IR\b/ and $_ =~ /\bAUTH=XOAUTH2\b/);
		} elsif ($_ =~ /^$num\b/) {
			die "CAPABILITY failed: $_\n" if $_ !~ /^$num\s+OK\b/;
			$done = 1;
			last;
		} elsif ($_ =~ /^\*\s+BYE\b/) {
			die "CAPABILITY failed: $_\n";
		}
	}
	die "CAPABILITY failed: Connection closed\n" unless $done;
	$num++;
	print " done\n";
	die "Server does not support XOAUTH2\n" unless $has_xoauth2;

	my $xoauth2_access_token;
	if (defined $config{xoauth2_access_token}) {
		$xoauth2_access_token = $config{xoauth2_access_token};
	} else {
		print "Requesting access token...";
		STDOUT->flush();
		my $http_response = HTTP::Tiny->new->post_form(
			$config{xoauth2_request_url},
			{
				client_id => $config{xoauth2_client_id},
				client_secret => $config{xoauth2_client_secret},
				refresh_token => $config{xoauth2_refresh_token},
				grant_type => 'refresh_token',
			}
		);
		DEBUG and warn "DEBUG: $http_response->{status} $http_response->{reason}\n$http_response->{content}\n";
		my $json_response = eval { decode_json($http_response->{content}) };
		die "Access token request failed: " . ($http_response->{status} || '') . " " . ($http_response->{reason} || '') . "\n" unless defined $json_response;
		die "Access token request failed: " . ($json_response->{error} || '') . " " . ($json_response->{error_description} || '') . "\n" if defined $json_response->{error} or defined $json_response->{error_description};
		$xoauth2_access_token = $json_response->{access_token};
		die "Access token request failed: Token is empty\n" unless defined $xoauth2_access_token and length $xoauth2_access_token;
		print " done\n";
	}

	print "Authenticating...";
	STDOUT->flush();
	print $sock "$num AUTHENTICATE XOAUTH2 " . encode_base64("user=$config{user}\x01auth=Bearer $xoauth2_access_token\x01\x01", '') . "\r\n";
} else {
	print "Logging in...";
	STDOUT->flush();
	print $sock "$num LOGIN $config{user} $config{pass}\r\n";
}

$done = 0;
while (<$sock>) {
	$_ =~ s/\r?\n$//;
	DEBUG and warn "DEBUG: $_\n";
	if ($_ =~ /^\*\s+CAPABILITY\b/) {
		$has_gmail = ($_ =~ /\bX-GM-EXT-1\b/);
	} elsif ($_ =~ /^\+\s+(.*)/) {
		my $note = eval { decode_base64($1) } || $1;
		DEBUG and warn "DEBUG: $note\n";
		my $status = eval { decode_json($note)->{status} };
		die "Login failed: $note\n" if defined $status and $status =~ /^[45]/;
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
	$lastid = 0;
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
									my $sent = grep { ref($_) ne "ARRAY" and $_ eq "\\Sent" } @{$value};
									my $received = grep { ref($_) ne "ARRAY" and $_ eq "\\Inbox" } @{$value};
									my $draft = grep { ref($_) ne "ARRAY" and $_ eq "\\Draft" } @{$value};
									$status = ($sent and $received) ? "Sent+Received" : $sent ? "Sent" : $draft ? "Draft" : "Received";
								} else {
									$status = ($value eq "\\Sent") ? "Sent" : ($value eq "\\Draft") ? "Draft" : "Received";
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
							open my $command, "|-", $config{command}, $date, $uid, $status
								or warn "Cannot execute `$config{command}'";
							if ($command) {
								print $command $message;
								close $command;
							}
						} else {
							my @days = qw(Sun Mon Tue Wed Thu Fri Sat);
							my @mons = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
							my $t = eval { Time::Piece->strptime($date, '%d-%b-%Y %H:%M:%S %z') } || scalar localtime;
							my $mbox_date = "$days[$t->_wday] $mons[$t->_mon] " . $t->strftime('%d %H:%M:%S %Y');
							my ($header) = ($message =~ /^(.*?)\r?\n\r?\n/s);
							$header = "" unless defined $header;
							$header =~ s/\r?\n(?=\s)//sg;
							my ($sender) = ($header =~ /^Return-Path:\s*(.*?)\s*$/mi);
							$sender = "" unless defined $sender;
							$sender =~ s/^<//;
							$sender =~ s/>$//;
							$sender =~ s/\s*//g;
							$sender = scalar getpwuid($<) unless length $sender;
							my $mbox_message = $message;
							$mbox_message =~ s/^(>*From )/>$1/mg;
							DEBUG and warn "MBOX sender=$sender mbox_date=$mbox_date\n";
							open my $mbox, '>>', "$dir/mbox"
								or warn "Cannot open `$dir/mbox': $!";
							if ($mbox) {
								print $mbox "From $sender  $mbox_date\r\n$mbox_message\r\n\r\n";
								close $mbox;
							}
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
	alarm 60*10;
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
