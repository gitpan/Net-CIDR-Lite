package Net::CIDR::Lite;

use strict;
use vars qw($VERSION);
use Carp qw(confess);

$VERSION = '0.06';

my %masks;
my @fields = qw(PACK UNPACK NBITS MASKS);

# Preloaded methods go here.

sub new {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self = bless {}, $class;
    $self->add_any($_) for @_;
    $self;
}

sub add_any {
    my $self = shift;
    for (@_) {
        tr|/|| && do { $self->add($_), next };
        tr|-|| && do { $self->add_range($_), next };
        $self->add_ip($_), next;
    }
    $self;
}

sub add {
    my $self = shift;
    my ($ip, $mask) = split "/", shift;
    $self->_init($ip) || confess "Can't determine ip format" unless %$self;
    confess "Bad mask $mask"
        unless $mask =~ /^\d+$/ and 2 <= $mask and $mask <= $self->{NBITS};
    my $start = $self->{PACK}->($ip) & $self->{MASKS}[$mask]
        or confess "Bad ip address: $ip";
    my $end = $self->_add_bit($start, $mask);
    ++$$self{RANGES}{$start} || delete $$self{RANGES}{$start};
    --$$self{RANGES}{$end}   || delete $$self{RANGES}{$end};
    $self;
}

sub clean {
    my $self = shift;
    my $ranges = $$self{RANGES};
    my $total;
    $$self{RANGES} = {
      map { $total ? ($total+=$$ranges{$_})? () : ($_=>-1)
                   : do { $total+=$$ranges{$_}; ($_=>1) }
          } sort keys %$ranges
    };
    $self;
}

sub list {
    my $self = shift;
    my $nbits = $$self{NBITS};
    my ($start, $total);
    my @results;
    for my $ip (sort keys %{$$self{RANGES}}) {
        $start = $ip unless $total;
        $total += $$self{RANGES}{$ip};
        unless ($total) {
            while ($start lt $ip) {
                my ($end, $bits);
                my $sbit = $nbits-1;
                # Find the position of the last 1 bit
                $sbit-- while !vec($start, $sbit^7, 1);
                for my $pos ($sbit+1..$nbits) {
                    $end = $self->_add_bit($start, $pos);
                    $bits = $pos, last if $end le $ip;
                }
                push @results, $self->{UNPACK}->($start) . "/$bits";
                $start = $end;
            }
        }
    }
    wantarray ? @results : \@results;
}

sub list_range {
    my $self = shift;
    my $nbits = $$self{NBITS};
    my ($start, $total);
    my @results;
    for my $ip (sort keys %{$$self{RANGES}}) {
        $start = $ip unless $total;
        $total += $$self{RANGES}{$ip};
        unless ($total) {
            push @results,
                $self->{UNPACK}->($start) . "-" . $self->{UNPACK}->($ip);
        }
    }
    wantarray ? @results : \@results;
}

sub _init {
    my $self = shift;
    my $ip = shift;
    my ($nbits, $pack, $unpack);
    if (_pack_ipv4($ip)) {
        $nbits = 32;
        $pack = \&_pack_ipv4;
        $unpack = \&_unpack_ipv4;
    } elsif (_pack_ipv6($ip)) {
        $nbits = 128;
        $pack = \&_pack_ipv6;
        $unpack = \&_unpack_ipv6;
    } else {
        return;
    }
    $$self{PACK}  = $pack;
    $$self{UNPACK}  = $unpack;
    $$self{NBITS} = $nbits;
    $$self{MASKS} = $masks{$nbits} ||= [
      map { pack("B*", substr("1" x $_ . "0" x $nbits, 0, $nbits))
          } 0..$nbits
    ];
    $$self{RANGES} = {};
    $self;
}

sub _pack_ipv4 {
    my @nums = split /\./, shift(), -1;
    return unless @nums == 4;
    for (@nums) {
        return unless /^\d{1,3}$/ and $_ <= 255;
    }
    pack("C*", @nums);
}

sub _unpack_ipv4 {
    join(".", unpack("C*", shift));
}

sub _pack_ipv6 {
    my $ip = shift;
    return if $ip =~ /^:/ and $ip !~ s/^::/:/;
    return if $ip =~ /:$/ and $ip !~ s/::$/:/;
    my @nums = split /:/, $ip, -1;
    return unless @nums <= 8;
    my ($empty, $ipv4, $str) = (0,'','');
    for (@nums) {
        return if $ipv4;
        $str .= "0" x (4-length) . $_, next if /^[a-fA-F\d]{1,4}$/;
        do { return if $empty++ }, $str .= "X", next if $_ eq '';
        next if $ipv4 = _pack_ipv4($_);
        return;
    }
    return if $ipv4 and @nums > 6;
    $str =~ s/X/"0" x (($ipv4 ? 25 : 33)-length($str))/e if $empty;
    pack("H*", $str).$ipv4;
}

sub _unpack_ipv6 {
    _compress_ipv6(join(":", unpack("H*", shift) =~ /..../g)),
}

# Replace longest run of null blocks with a double colon
sub _compress_ipv6 {
    my $ip = shift;
    if (my @runs = $ip =~ /((?:(?:^|:)(?:0000))+:?)/g ) {
        my $max = $runs[0];
        for (@runs[1..$#runs]) {
            $max = $_ if length($max) < length;
        }
        $ip =~ s/$max/::/;
    }
    $ip =~ s/:0{1,3}/:/g;
    $ip;
}

# Add a single IP address
sub add_ip {
    my $self = shift;
    my $ip = shift;
    $self->_init($ip) || confess "Can't determine ip format" unless %$self;
    my $start = $self->{PACK}->($ip) or confess "Bad ip address: $ip";
    my $end = $self->_add_bit($start, $self->{NBITS});
    ++$$self{RANGES}{$start} || delete $$self{RANGES}{$start};
    --$$self{RANGES}{$end}   || delete $$self{RANGES}{$end};
    $self;
}

# Add a hyphenated range of IP addresses
sub add_range {
    my $self = shift;
    local $_ = shift;
    my ($ip_start, $ip_end) = split "-";
    $self->_init($ip_start) || confess "Can't determine ip format"
      unless %$self;
    my $start = $self->{PACK}->($ip_start)
      or confess "Bad ip address: $ip_start";
    my $end = $self->{PACK}->($ip_end)
      or confess "Bad ip address: $ip_end";
    confess "Start IP is greater than end IP" if $start gt $end;
    my $end = $self->_add_bit($end, $$self{NBITS});
    ++$$self{RANGES}{$start} || delete $$self{RANGES}{$start};
    --$$self{RANGES}{$end}   || delete $$self{RANGES}{$end};
    $self;
}

# Add ranges from another Net::CIDR::Lite object
sub add_cidr {
    my $self = shift;
    my $cidr = shift;
    unless (%$self) {
        @$self{@fields} = @$cidr{@fields};
    }
    $$self{RANGES}{$_} += $$cidr{RANGES}{$_} for keys %{$$cidr{RANGES}};
    $self;
}

# Increment the ip address at the given bit position
sub _add_bit {
    my $self= shift;
    my $base= shift;
    my $bits= shift()-1;
    while (vec($base, $bits^7, 1)) {
        vec($base, $bits^7, 1) = 0;
        $bits--;
        return "\xff"x(1+length($base))   if  $bits < 0;
    }
    vec($base, $bits^7, 1) = 1;
    return $base;
}

sub find {
    my $self = shift;
    $self->prep_find unless $self->{FIND};
    my $this_ip = $self->{PACK}->(shift);
    my $ranges = $self->{RANGES};
    my $last = -1;
    for my $ip (@{$self->{FIND}}) {
        last if $this_ip lt $ip;
        $last = $ranges->{$ip};
    }
    $last > 0;
}

sub prep_find {
    my $self = shift;
    $self->clean;
    $self->{FIND} = [];
    for my $ip (sort keys %{$self->{RANGES}}) {
        push @{$self->{FIND}}, $ip;
    }
    $self;
}

sub spanner {
    Net::CIDR::Lite::Span->new(@_);
}

sub ranges {
    sort keys %{shift->{RANGES}};
}

sub packer { shift->{PACK} }
sub unpacker { shift->{UNPACK} }

package Net::CIDR::Lite::Span;
use Carp qw(confess);

sub new {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self = bless {RANGES=>{}}, $class;
    $self->add(@_);
}

sub add {
    my $self = shift;
    my $ranges = $self->{RANGES};
    if (@_ && !$self->{PACK}) {
        $self->{PACK} = $_[0]->packer;
        $self->{UNPACK} = $_[0]->unpacker;
    }
    while (@_) {
        my ($cidr, $label) = (shift, shift);
        $cidr = Net::CIDR::Lite->new($cidr) unless ref($cidr);
        $cidr->clean;
        for my $ip ($cidr->ranges) {
            push @{$ranges->{$ip}}, $label;
        }
    }
    $self;
}

sub find {
    my $self = shift;
    my $unpack = $self->{UNPACK};
    my $ranges = $self->{RANGES};
    my @ips = sort map { $self->{PACK}->($_) || confess "Bad IP: $_" } @_;
    my (%results, %in_range);
    $self->prep_find unless $self->{FIND};
    my $last;
    for my $ip (@{$self->{FIND}}) {
        if ($ips[0] lt $ip) {
            my @keys = grep $in_range{$_}, sort keys %in_range;
            my $key_str = join "|", @keys;
            my $in_range = $self->{CACHE}{$key_str} ||= { map {$_=>1} @keys };
            $results{$unpack->(shift @ips)} = $in_range
                  while @ips and $ips[0] lt $ip;
        }
        last unless @ips;
        $in_range{$_} = ! $in_range{$_} for @{$ranges->{$ip}};
    }
    \%results;
}

sub prep_find {
    my $self = shift;
    $self->{FIND} = [ sort keys %{$self->{RANGES}} ];
    $self->{CACHE} = {};
    $self;
}

sub clean {
    my $self = shift;
    my $ip = $self->{PACK}->(shift) || return;
    $self->{UNPACK}->($ip);
}

1;
__END__

=head1 NAME

Net::CIDR::Lite - Perl extension for merging IPv4 or IPv6 CIDR addresses

=head1 SYNOPSIS

  use Net::CIDR::Lite;

  my $cidr = Net::CIDR::Lite->new;
  $cidr->add($cidr_address);
  @cidr_list = $cidr->list;

=head1 DESCRIPTION

Faster alternative to Net::CIDR when merging a large number
of CIDR address ranges. Works for IPv4 and IPv6 addresses.

=head1 METHODS

=item new() 

 $cidr = Net::CIDR::Lite->new

Creates an object to represent a list of CIDR address ranges.
No particular format is set yet; once an add method is called
with a IPv4 or IPv6 format, only that format may be added for this
cidr object.

=item add()

 $cidr->add($cidr_address)

Adds a CIDR address range to the list.

=item add_range()

 $cidr->add_range($ip_range)

Adds a hyphenated IP address range to the list.

=item add_cidr()

 $cidr1->add_cidr($cidr2)

Adds address ranges from one object to another object.

=item add_ip()

 $cidr->add_ip($ip_address)

Adds a single IP address to the list.

=item $cidr->clean()

 $cidr->clean;

If you are going to call the list method more than once on the
same data, then for optimal performance, you can call this to
purge null nodes in overlapping ranges from the list. Boundary
nodes in contiguous ranges are automatically purged during add().

=item $cidr->list()

 @cidr_list = $cidr->list;
 $list_ref  = $cidr->list;

Returns a list of the merged CIDR addresses. Returns an array if called
in list context, an array reference if not.

=item $cidr->find()

 $found = $cidr->find($ip);

Returns true if the ip address is found in the CIDR range. Undef if not.
Not extremely efficient, is O(n*log(n)) to sort the ranges in the
cidr object O(n) to search through the ranges in the cidr object.
The sort is cached on the first call and used in subsequent calls,
but if more addresses are added to the cidr object, prep_find() must
be called on the cidr object.

=item $cidr->prep_find()

Caches the result of sorting the ip addresses. Implicitly called on the first
find call, but must be explicitly called if more addresses are added to
the cidr object.

=item $cidr->spanner()

 $spanner = $cidr1->spanner($label1, $cidr2, $label2, ...);

Creates a spanner object to find out if multiple ip addresses are within
multiple labeled address ranges. May also be called as (with or without
any arguments):

 Net::CIDR::Lite->new($cidr1, $label1, $cidr2, $label2, ...);

=item $spanner->add()

 $spanner->add($cidr1, $label1, $cidr2, $label2,...);

Adds labeled address ranges to the spanner object. The 'address range' may
be a Net::CIDR::Lite object, a single CIDR address range, a single
hyphenated IP address range, or a single IP address.

=item $spanner->find()

 $href = $spanner->find(@ip_addresses);

Look up which range(s) ip addresses are in, and return a lookup table
of the results, with the keys being the ip addresses, and the value an
array reference of which address ranges the ip address is in.

=item $spanner->find_prep()

Called implicitly the first time $spanner->find(..) is called, must be called
again if more cidr objects are added to the spanner object.

=item $spanner->clean()

 $clean_address = $spanner->clean($ip_address);

Validates a returns a cleaned up version of an ip address (which is
what you will find as the key in the result from the $spanner->find(..),
not necessarily what the original argument looked like). E.g. removes
unnecessary leading zeros, removes null blocks from IPv6
addresses, etc.

=head1 CAVEATS

Garbage in/garbage out. This module does do validation, but maybe
not enough to suit your needs.

=head1 AUTHOR

Douglas Wilson, E<lt>dougw@cpan.orgE<gt>
w/numerous hints and ideas borrowed from Tye McQueen.

=head1 COPYRIGHT

 This module is free software; you can redistribute it and/or
 modify it under the same terms as Perl itself.

=head1 SEE ALSO

L<Net::CIDR>.

=cut
