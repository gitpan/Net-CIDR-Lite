package Net::CIDR::Lite;

use strict;
use vars qw($VERSION);
use Carp qw(confess);

$VERSION = '0.05';

my %masks;
my @fields = qw(PACK UNPACK NBITS MASKS);

# Preloaded methods go here.

sub new {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    bless {}, $class;
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
}

sub clean {
    my $self = shift;
    my $ranges = $$self{RANGES};
    my $total;
    $$self{RANGES} = {
      map { $total ? ($total+=$$ranges{$_})? () : ($_=>1)
                   : do { $total+=$$ranges{$_}; ($_=>-1) }
          } sort keys %$ranges
    };
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
    my $end = $self->_add_bit($end, $$self{NBITS});
    ++$$self{RANGES}{$start} || delete $$self{RANGES}{$start};
    --$$self{RANGES}{$end}   || delete $$self{RANGES}{$end};
}

# Add ranges from another Net::CIDR::Lite object
sub add_cidr {
    my $self = shift;
    my $cidr = shift;
    unless (%$self) {
        @$self{@fields} = @$cidr{@fields};
    }
    $$self{RANGES}{$_} += $$cidr{RANGES}{$_} for keys %{$$cidr{RANGES}};
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

=head1 CAVEATS

Garbage in/garbage out. This module does validate ip address formats
but does not (yet) validate the cidr mask value.

=head1 AUTHOR

Douglas Wilson, E<lt>dougw@cpan.orgE<gt>
w/numerous hints and ideas borrowed from Tye McQueen.

=head1 COPYRIGHT

 This module is free software; you can redistribute it and/or
 modify it under the same terms as Perl itself.

=head1 SEE ALSO

L<Net::CIDR>.

=cut
