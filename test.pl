# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test;
use strict;
BEGIN { plan tests => 16 };
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
#2
ok(scalar(@list), 1);
ok($list[0], "209.152.214.112/29");

my $cidr6 = Net::CIDR::Lite->new;

$cidr6->add("dead:beef:0000:0000:0000:0000:0000:0000/128");
$cidr6->add("dead:beef:0000:0000:0000:0000:0000:0001/128");
my @list6 = $cidr6->list;
#4
ok(scalar(@list6), 1);
ok($list6[0], "dead:beef::/127");

my $cidr6a = Net::CIDR::Lite->new;
$cidr6a->add("dead:beef:0000:0000:0000:0000:0000:0002/127");
$cidr6a->add("dead:beef:0000:0000:0000:0000:0000:0004/127");
my @list6a = $cidr6a->list;
#6
ok(scalar(@list6a), 2);
ok($list6a[0], "dead:beef::2/127");
ok($list6a[1], "dead:beef::4/127");

my $spanner = $cidr->spanner('HAL');
#9
ok($spanner);
my @ips = qw(209.152.214.111 209.152.214.113);
my $lkup = $spanner->find(@ips);
#9
ok(scalar(keys %{$lkup->{$ips[1]}}) == 1);
ok(exists $lkup->{$ips[1]});
ok(exists $lkup->{$ips[1]}{HAL});

my $new_ip = '209.152.214.114';
ok(not exists $lkup->{$new_ip});
$spanner->add($new_ip,'label');
$spanner->prep_find;
$lkup = $spanner->find($new_ip);
ok(exists $lkup->{$new_ip});
ok($lkup->{$new_ip}{HAL});
ok($lkup->{$new_ip}{label});
