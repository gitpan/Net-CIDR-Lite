# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test;
use strict;
$|++;
BEGIN { plan tests => 21 };
use Net::CIDR::Lite;
ok(1); # If we made it this far, we're ok.

#########################

# Insert your test code below, the Test module is use()ed here so read
# its man page ( perldoc Test ) for help writing this test script.

my $cidr = Net::CIDR::Lite->new;

$cidr->add("209.152.214.112/30");
$cidr->add("209.152.214.116/31");
$cidr->add("209.152.214.118/31");

my @list = $cidr->list;
ok(scalar(@list), 1);
ok($list[0], "209.152.214.112/29");

ok($cidr->find('209.152.214.112'));
ok($cidr->find('209.152.214.114'));
ok(! $cidr->find('209.152.214.111'));
ok(! $cidr->find('209.152.214.120'));
ok($cidr->bin_find('209.152.214.114'));
ok(! $cidr->bin_find('209.152.214.111'));
ok(! $cidr->bin_find('209.152.214.120'));

my $cidr6 = Net::CIDR::Lite->new;

$cidr6->add("dead:beef:0000:0000:0000:0000:0000:0000/128");
$cidr6->add("dead:beef:0000:0000:0000:0000:0000:0001/128");
my @list6 = $cidr6->list;
ok(scalar(@list6), 1);
ok($list6[0], "dead:beef::/127");

my $cidr6a = Net::CIDR::Lite->new;
$cidr6a->add("dead:beef:0000:0000:0000:0000:0000:0002/127");
$cidr6a->add("dead:beef:0000:0000:0000:0000:0000:0004/127");
my @list6a = $cidr6a->list;
ok(scalar(@list6a), 2);
ok($list6a[0], "dead:beef::2/127");
ok($list6a[1], "dead:beef::4/127");

my $spanner = $cidr->spanner('HAL');
ok($spanner);
my @ips = qw(209.152.214.111 209.152.214.113);
my $lkup = $spanner->find(@ips);
ok(exists $lkup->{$ips[1]}{HAL});
ok(scalar(keys %{$lkup->{$ips[1]}}), 1);

# Add a new ip and make sure its in all ranges
my $new_ip = '209.152.214.114';
$spanner->add($new_ip,'label');
$spanner->prep_find;
$lkup = $spanner->find($new_ip);
ok($lkup->{$new_ip}{HAL});
ok($lkup->{$new_ip}{label});

# Force a binary find and make sure it all still works
$spanner->prep_find(50);
$lkup = $spanner->find($new_ip);
ok($lkup->{$new_ip}{HAL});
ok($lkup->{$new_ip}{label});

# Make sure 0.0.0.0 works
my $zero = Net::CIDR::Lite->new("0.0.0.0/8");
my @zero = $zero->list;
ok($zero[0] eq "0.0.0.0/8");

# Make sure list range works
my $cidr_tlist = Net::CIDR::Lite->new("156.147.0.0/16");
my @range = $cidr_tlist->list_range;
ok(@range == 1);
ok($range[0] eq "156.147.0.0-156.147.255.255");

# Test find in beginning of range
my $cidr_find =
  Net::CIDR::Lite->new('218.48.0.0/13','218.144.0.0/12','218.232.0.0/15');

ok($cidr_find->bin_find('218.144.0.0'));
