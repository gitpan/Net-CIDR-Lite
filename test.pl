# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test;
BEGIN { plan tests => 3 };
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

my $cidr6 = Net::CIDR::Lite->new;

$cidr6->add("dead:beef:0000:0000:0000:0000:0000:0000/128");
$cidr6->add("dead:beef:0000:0000:0000:0000:0000:0001/128");
my @list6 = $cidr6->list;
ok(scalar(@list6), 1);
ok($list6[0], "dead:beef::/127");
