#
# Script to make whois for a list of domain and send alert when is near
# to expire
# Copyleft yoander, Licence: GPL
#
#
#!/usr/bin/perl
use strict;
use warnings;
use Log::Log4perl;
use Net::Whois::Raw;
use Text::Trim;
use Date::Simple('date', 'today');
use Mail::Send;
use LWP::UserAgent;

our $log;

sub make_domain_close_exp_report {
    my (@domains_close_exp) = @_;
    my ($domain, $expires_on, $registrar);
    my $REPORT_PATH = "domain-close-to-exp.txt";
    open DOMAIN_CLOSE_EXP_REPORT, "> $REPORT_PATH";

format DOMAIN_CLOSE_EXP_REPORT_TOP =
        @||||||||||||||||||||||||||||||||||||||||||||||||||
        "Domains close to expires (next 3 months)"

Domain                                            Expires On          Provider
--------------------------------------------------------------------------------------------
.

format DOMAIN_CLOSE_EXP_REPORT =
@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<         @<<<<<<<<<<         @<<<<<<<<<<<<<<<<<<<<<
$domain                                      ,$expires_on        ,$registrar
.

    foreach (@domains_close_exp) {
        ($domain, $expires_on, $registrar) = split/:/;
        write(DOMAIN_CLOSE_EXP_REPORT);
    }
    close DOMAIN_CLOSE_EXP_REPORT;
}

sub make_bad_sites_report {
    my (@bad_sites) = @_;
    my ($url, $status_line);
    my $FILE_NAME = "bad-sites.txt";
    open BAD_SITES_FILE, "> $FILE_NAME";

format BAD_SITES_FILE_TOP =
        @||||||||||||||||||||||||||||||||||||||||||||||||||
        "Bad sites"

Url                                        Status
----------------------------------------------------------------------------------------------------------------------
.

format BAD_SITES_FILE =
@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$url                                   ,$status_line
.

    foreach (@bad_sites) {
        ($url, $status_line) = split/:/;
        write(BAD_SITES_FILE);
    }
    close BAD_SITES_FILE;

}

sub send_mail {
    my ($subject, $filepath) = @_;
    open(BODY, "< $filepath");
    my @body = <BODY>;
    close BODY;
    my $msg = Mail::Send->new;
    $msg->to('mail1', 'mail2', 'mail3');
    $msg->subject("$subject");
    $msg->set('From', 'postmaster@domain');
    my $fh = $msg->open;
    print $fh "@body";
    $fh->close;
}

sub get_domain_info
{
    my ($domain) = @_;
    my @d_info;
    my $raw_info;
    eval {
        $raw_info = whois($domain);
    };
    if ($@) {
        $log->error("$@");
        return undef;
    }
        $log->info("Getting " . $domain . " info");
    if ($raw_info =~ /((reg_|)created( on|)|(regist|cre)(r?ation date|ered on)|date\-approved):\s*(.*)/i)
    {
        $d_info[0] = str2date( trim($6) );
        $log->info("Parsed created_on to: $d_info[0]");
    }
    if ($raw_info =~ /(expir(es)?( on|ation|)\s?(date)?|renewal[\-|\s]date):\s*(.*)/i)
    {
        $d_info[1] = str2date( trim($5) );
        $log->info("Parsed expires_on to:  $d_info[1]");
    }
    if ($raw_info =~ /((last )?updated\s?(on)?(date)?|date\-modified|changed):\s*(.*)/i)
    {
        $d_info[2] = str2date( trim($5) );
        $log->info("Parsed updated_on to:  $d_info[2]");
    }
    if ($raw_info =~ /(registrar|tech\-c):\s*(.*)/i)
    {
        $d_info[3] = trim($2);
        $log->info("Parsed registrar to: $d_info[3]");
    }
    if ($raw_info =~ /((domain |n(ame )?)server(s|).*:)\s*\n(.*)\n(.*)/i)
    {
        $d_info[4] = join(', ', trim($5), trim($6));
    }
    else
    {
        my @ns;
        while($raw_info =~ /((domain |n(ame )?)server(s|)|(ns1\-|ns2\-)hostname).*:\s*(.*)/gi)
        {
            @ns = (@ns, trim($6));
        }
        if (@ns)
        {
            $d_info[4] = join(', ', @ns);
                $log->info("Parsed name servers to: $d_info[4]");
        }
    }
    return \@d_info;
}

sub insert
{
}

sub update
{
}

sub str2date {
    my %MONTH = ("jan" => "01", "feb" => "02", "mar" => "02", "apr" => "04", "may" => "05", "jun" => "06", "jul" => "07", "aug" => "08", "sep" => "09", "oct" => "10", "nov" => "11", "dec" => "12");
    my ($date) = @_;
    if ($date =~ m!(\d{4})[-/](\d{2})[-/](\d{2})!) {
        return "$1-$2-$3";
    }
    if ($date =~ m!(\d{2})[-/](\w{3})[-/]((?:20)?\d{2})!i) {
        my ($d, $m, $y) = ($1, lc($2), $3);
        if ($y =~ /^\d{2}$/) {
            $y += 2000;
        }
        return "$y-$MONTH{$m}-$d";
    }
    if ($date =~ m/(\w{3})\s(\d{2})\s\d{2}:\d{2}:\d{2}\sGMT\s(\d{4})/i) {
        my ($d, $m, $y) = ($2, lc($1), $3);
        return "$y-$MONTH{$m}-$2";
    }
    return $date;

}

sub is_close_to_expire {
    my ($expires_on) = @_;
    return 1 if ((!$expires_on) or ((date(str2date($expires_on)) - today()) < 93 ));
    return 0;
}

sub check {
    my ($url) = @_;
    my $browser = LWP::UserAgent->new();
    #$DB::single=2;
    my $response = $browser->get($url);
    my $is_success = $response->is_success;
    my $status = $response->status_line;
    # Redefine status if site is available but without content
    if ('' eq $response->content) {
        $is_success = 0;
        $status = 'Empty site';
    }
    return ($is_success , $status);
}

main:
{
    my $FILE = "dominios.txt";
    my $NEW_FILE = "new.txt";
    my $LOGCONF = "dtlog.conf";
    Log::Log4perl->init("$LOGCONF");
    $log = Log::Log4perl->get_logger("");
    $log->info("Running on: " . today());
    open(FILEREAD, "< $FILE");
    open (FILEWRITE, "> $NEW_FILE");
    my @domain_close_exp;
    my @bad_sites;
    while (<FILEREAD>) {
        chomp();
        next if (/^#|^\s*$/);
        my ($domain, $url, $created_on, $expires_on, $updated_on, $type, $registrant, $registrar, $st, $ns) = split /\//;
        (my $is_success, $st) = check('http://' . $url);
        push(@bad_sites, join (':', $url, "$st")) if (!$is_success);
        next unless ( is_close_to_expire($expires_on) );
        my $d_info = get_domain_info($domain);
        next if (!$d_info);
        ($created_on, $expires_on, $updated_on, $registrar, $ns) = @$d_info;
        # domain list close to expire
        if ( is_close_to_expire($expires_on) ) {
            my $str = join(':', $domain, $expires_on, $registrar);
            push(@domain_close_exp, $str)
        }
        $_ = join( ":", $domain, $url, $created_on, $expires_on, $updated_on, $type, $registrant, $registrar, $st, $ns);
    } continue {
        # Write record to the new file
        print FILEWRITE "$_\n" or $log->error("Error writing $NEW_FILE: $!\n");
    }
    close FILEWRITE;
    close FILEREAD;
    # Backing up the original file
    rename $FILE, "$FILE.bak";
    unlink $FILE;
    rename $NEW_FILE, $FILE;
    if (@bad_sites) {
        make_bad_sites_report(@bad_sites);
        send_mail('Sitios fuera de servicio!!!', 'bad-sites.txt');
    }
    if (@domain_close_exp) {
        make_domain_close_exp_report(@domain_close_exp);
        send_mail('Dominios próximos a expirar!!!', 'domain-close-to-expires.txt');
    }
    $log->info("DONE!!");
}
