package KeplerAs::Cubin;

use strict;
use Data::Dumper;
#template used to pack/unpack
my @Elf32_Hdr = qw(
    H8  magic           #a hex string,high nybble first.repeated 8 times,4 bytes
    C   fileClass       #an unsigned char,1byte
    C   encoding
    C   fileVersion
    H18 padding         
    S   type            #an unsigned short value,2 bytes
    S   machine
    L   version         #an unsigned long value,4bytes
    L   entry
    L   phOffset
    L   shOffset
    L   flags
    S   ehSize
    S   phEntSize
    S   phNum
    S   shEntSize
    S   shNum
    S   shStrIndx
);
my @Elf64_Hdr = qw(
    H8  magic
    C   fileClass
    C   encoding
    C   fileVersion
    H18 padding
    S   type
    S   machine
    L   version
    Q   entry           #an unsigned quads value,8 bytes
    Q   phOffset
    Q   shOffset
    L   flags
    S   ehSize
    S   phEntSize
    S   phNum
    S   shEntSize
    S   shNum
    S   shStrIndx
);
my @Elf32_PrgHdr = qw(
    L   type
    L   offset
    L   vaddr
    L   paddr
    L   fileSize
    L   memSize
    L   flags
    L   align
);
my @Elf64_PrgHdr = qw(
    L   type
    L   flags
    Q   offset
    Q   vaddr
    Q   paddr
    Q   fileSize
    Q   memSize
    Q   align
);
my @Elf32_SecHdr = qw(
    L   name
    L   type
    L   flags
    L   addr
    L   offset
    L   size
    L   link
    L   info
    L   align
    L   entSize
);
my @Elf64_SecHdr = qw(
    L   name
    L   type
    Q   flags
    Q   addr
    Q   offset
    Q   size
    L   link
    L   info
    Q   align
    Q   entSize
);
my @Elf32_SymEnt = qw(
    L   name
    L   value
    L   size
    C   info
    C   other
    S   shIndx
);
my @Elf64_SymEnt = qw(
    L   name
    C   info
    C   other
    S   shIndx
    Q   value
    Q   size
);
my @symBind = qw(LOCAL GLOBAL WEAK);

my (@elfHdrT, @prgHdrT, @secHdrT, @symHdrT, @elfHdrC, @prgHdrC, @secHdrC, @symHdrC);

$elfHdrT[1] = join '', grep { length($_) <= 3} @Elf32_Hdr;
$prgHdrT[1] = join '', grep { length($_) <= 3} @Elf32_PrgHdr;
$secHdrT[1] = join '', grep { length($_) <= 3} @Elf32_SecHdr;
$symHdrT[1] = join '', grep { length($_) <= 3} @Elf32_SymEnt;

$elfHdrT[2] = join '', grep { length($_) <= 3} @Elf64_Hdr;
$prgHdrT[2] = join '', grep { length($_) <= 3} @Elf64_PrgHdr;
$secHdrT[2] = join '', grep { length($_) <= 3} @Elf64_SecHdr;
$symHdrT[2] = join '', grep { length($_) <= 3} @Elf64_SymEnt;

$elfHdrC[1] = [ grep { length($_) > 3} @Elf32_Hdr    ];
$prgHdrC[1] = [ grep { length($_) > 3} @Elf32_PrgHdr ];
$secHdrC[1] = [ grep { length($_) > 3} @Elf32_SecHdr ];
$symHdrC[1] = [ grep { length($_) > 3} @Elf32_SymEnt ];

$elfHdrC[2] = [ grep { length($_) > 3} @Elf64_Hdr    ];
$prgHdrC[2] = [ grep { length($_) > 3} @Elf64_PrgHdr ];
$secHdrC[2] = [ grep { length($_) > 3} @Elf64_SecHdr ];
$symHdrC[2] = [ grep { length($_) > 3} @Elf64_SymEnt ];

sub new
{
    #the first param of new is the name of package,that is,KeplerAs::Cubin
    my ($package, $file) = @_;

    my $cubin = bless { fileName => $file }, $package;

    open my $fh, $file or die "$file: $!";
    #turn fh to be handled in binary mode.
    binmode($fh);

    my $data;
    #read 52(0x34) bytes from fh to data
    read $fh, $data, 0x34;
    #{} create an anoymous reference of hash
    my $elfHdr = $cubin->{elfHdr} = {};
   
    @{$elfHdr}{@{$elfHdrC[1]}} = unpack $elfHdrT[1], $data;

    my $class = $elfHdr->{fileClass};

    if ($class == 2)
    {
        #re-parse elf header
        seek $fh, 0, 0;
        #why is 0x46?I think it's inequal to the size computed from template.
        read $fh, $data, 0x46;
        #slice of a reference of hash
        @{$elfHdr}{@{$elfHdrC[$class]}} = unpack $elfHdrT[$class], $data;

        $cubin->{Class} = 64;
    }
    else
    {
        $cubin->{Class} = 32;
    }

    $cubin->{Arch} = "35";
    die "Cubin not in sm_35. Found: sm_$cubin->{Arch}\n" if $cubin->{Arch} != 35;
    $cubin->{AddressSize} = $elfHdr->{flags} & 0x400 ? 64 : 32;

    seek $fh, $elfHdr->{phOffset}, 0;
    foreach (1 .. $elfHdr->{phNum})
    {
        read $fh, $data, $elfHdr->{phEntSize};

        my %prgHdr = (Indx => $_ - 1);
        #hash切片,取prgHdr中key为{}中数组指定的所有位置
        @prgHdr{@{$prgHdrC[$class]}} = unpack $prgHdrT[$class], $data;
        #\%prgHdr is reference of %prgHdr,cubin->{prgHdrs} is a reference of array.the element of the array is reference of hash
        push @{$cubin->{prgHdrs}}, \%prgHdr;
    }

    seek $fh, $elfHdr->{shOffset}, 0;
    foreach (1 .. $elfHdr->{shNum})
    {
        read $fh, $data, $elfHdr->{shEntSize};

        my %secHdr = (Indx => $_ - 1);
        @secHdr{@{$secHdrC[$class]}} = unpack $secHdrT[$class], $data;
        push @{$cubin->{secHdrs}}, \%secHdr;
    }
    #secHdr id reference of hash
    foreach my $secHdr (@{$cubin->{secHdrs}})
    {
        $data = '';
        if ($secHdr->{size} && $secHdr->{type} != 8)
        {
            seek $fh, $secHdr->{offset}, 0;
            read $fh, $data, $secHdr->{size};
        }
        if ($secHdr->{type} == 3) # STRTAB
        {
            #strTab and secHdr->{StrTab} is reference of an anoymous hash
            my $strTab = $secHdr->{StrTab} = {};
            my $indx   = 0;
            foreach my $str (split "\0", $data)
            {
                $strTab->{$indx} = $str;
                #why add 1?
                $indx += 1 + length($str);
            }
        }
        if ($secHdr->{type} == 2) # SYMTAB
        {
            my $offset = 0;
            while ($offset < $secHdr->{size})
            {
                #symEnt is reference of anoymous hash
                my $symEnt = {};
                @{$symEnt}{@{$symHdrC[$class]}} = unpack $symHdrT[$class], substr($data, $offset, $secHdr->{entSize});
                $offset += $secHdr->{entSize};

                push @{$secHdr->{SymTab}}, $symEnt;
            }
        }
        $secHdr->{Data} = unpack 'H*', $data;
    }
    close $fh;

    my $shStrTab = $cubin->{secHdrs}[$elfHdr->{shStrIndx}]{StrTab};
    foreach my $secHdr (@{$cubin->{secHdrs}})
    {
        #name should be .nv.info.xxxx or .text.xxx
        $secHdr->{Name} = $shStrTab->{$secHdr->{name}};
        $cubin->{$secHdr->{Name}} = $secHdr;
    }

    my $strTab = $cubin->{'.strtab'}{StrTab};
    foreach my $symEnt (@{$cubin->{'.symtab'}{SymTab}})
    {
        $symEnt->{Name} = $strTab->{$symEnt->{name}};

        my $secHdr = $cubin->{secHdrs}[$symEnt->{shIndx}];
        $secHdr->{SymbolEnt} = $symEnt;

        if (($symEnt->{info} & 0x0f) == 0x02)
        {
            my $kernelSec = $cubin->{Kernels}{$symEnt->{Name}} = $secHdr;

            $kernelSec->{Linkage} = $symBind[($symEnt->{info} & 0xf0) >> 4];

            $kernelSec->{KernelData} = [ unpack "Q*", pack "H*", $kernelSec->{Data} ];

            $kernelSec->{BarCnt} = ($kernelSec->{flags} & 0x01f00000) >> 20;

            $kernelSec->{RegCnt} = ($kernelSec->{info} & 0xff000000) >> 24;

            my $sharedSec = $kernelSec->{SharedSec} = $cubin->{".nv.shared.$symEnt->{Name}"};
            $kernelSec->{SharedSize} = $sharedSec ? $sharedSec->{size} : 0;

            $kernelSec->{ConstantSec} = $cubin->{".nv.constant0.$symEnt->{Name}"};

            my $paramSec = $kernelSec->{ParamSec} = $cubin->{".nv.info.$symEnt->{Name}"};
            if ($paramSec)
            {
                my @data = unpack "L*", pack "H*", $paramSec->{Data};

                $paramSec->{ParamData} = \@data;
                $paramSec->{ParamHex} = [ map { sprintf '0x%08x', $_ } @data ];

                my $idx = 0;
                $idx++ while $idx < @data && $data[$idx] != 0x00080a04;

                my $first = $data[$idx+2] & 0xFFFF;
                $idx += 4;

                my @params;
                while ($idx < @data && $data[$idx] == 0x000c1704)
                {
                    my $ord    = $data[$idx+2] & 0xFFFF;
                    my $offset = sprintf '0x%02x', $first + ($data[$idx+2] >> 16);
                    my $psize  = $data[$idx+3] >> 18;
                    my $align  = $data[$idx+3] & 0x400 ? 1 << ($data[$idx+3] & 0x3ff) : 0;
                    unshift @params, "$ord:$offset:$psize:$align";
                    $idx += 4;
                }
                my @staticParams = @data[0 .. ($idx-1)];


                my ($maxregCount, @exitOffsets, @ctaidOffsets, $ctaidzUsed, @reqntid, @maxntid, @stackSize);
                while ($idx < @data)
                {
                    my $code = $data[$idx] & 0xffff;
                    my $size = $data[$idx] >> 16;
                    $idx++;


                    if ($code == 0x1b03)
                    {
                        $maxregCount = $size;
                    }
                    elsif ($code == 0x1d04)
                    {
                        while ($size > 0)
                        {
                            push @ctaidOffsets, $data[$idx++];
                            $size -= 4;
                        }
                    }
                    elsif ($code == 0x1c04)
                    {
                        while ($size > 0)
                        {
                            push @exitOffsets, $data[$idx++];
                            $size -= 4;
                        }
                    }
                    elsif ($code == 0x0401)
                    {
                        $ctaidzUsed = 1;
                    }
                    elsif ($code == 0x1004)
                    {
                        while ($size > 0)
                        {
                            push @reqntid, $data[$idx++];
                            $size -= 4;
                        }
                    }
                    elsif ($code == 0x0504)
                    {
                        while ($size > 0)
                        {
                            push @maxntid, $data[$idx++];
                            $size -= 4;
                        }
                    }
                    elsif ($code == 0x1e04)
                    {
                        while ($size > 0)
                        {
                            push @stackSize, $data[$idx++];
                            $size -= 4;
                        }
                    }
                    else
                    {
                        printf "Unknown Code 0x%02x (size:%d)\n", $code, $size;
                    }
                }
                $kernelSec->{Params}   = \@params;
                $kernelSec->{ParamCnt} = scalar @params;

                $paramSec->{StaticParams} = \@staticParams;
                $paramSec->{MAXREG_COUNT} = $maxregCount;
                $paramSec->{ExitOffsets}  = \@exitOffsets;
                $paramSec->{CTAIDOffsets} = \@ctaidOffsets;
                $paramSec->{CTAIDZUsed}   = $ctaidzUsed;
                $paramSec->{REQNTID}      = \@reqntid;
                $paramSec->{MAXNTID}      = \@maxntid;
                $paramSec->{STACKSIZE}    = \@stackSize;
            }
        }
        elsif (($symEnt->{info} & 0x10) == 0x10)
        {
            $cubin->{Symbols}{$symEnt->{Name}} = $symEnt;
        }
    }


    return $cubin;
}
sub class
{
    return shift()->{Class};
}
sub arch
{
    return shift()->{Arch};
}
sub address_size
{
    return shift()->{AddressSize};
}
sub listKernels
{
    #cubin->{Kernels} is refernece to a hash which mapping name to secHdr.
    return shift()->{Kernels};
}
sub listSymbols
{
    return shift()->{Symbols};
}
sub getKernel
{
    my ($cubin, $kernel) = @_;
    #the return value is a reference of hash
    return $cubin->{Kernels}{$kernel};
}

sub modifyKernel
{
    #params{Kernel} is about the secHdr and kernelSec in mothod new above.
    my ($cubin, %params) = @_;
    #copresponding,original kernel
    my $kernelSec    = $params{Kernel};
    my $newReg       = $params{RegCnt};
    my $newBar       = $params{BarCnt};
    my $exitOffsets  = $params{ExitOffsets};
    my $ctaidOffsets = $params{CTAIDOffsets};
    my $ctaidzUsed   = $params{CTAIDZUsed};
    my $newData      = $params{KernelData};
    my $newSize      = @$newData * 8;

    die "255 register max" if $newReg > 255;
    die "new kernel size must be multiple of 8 instructions (64 bytes)" if $newSize & 63;
    #Is barrier count the number of 'BAR.SYNC'?
    die "16 is max barrier count" if $newBar > 16;

    my $paramSec = $kernelSec->{ParamSec};
    my $kernelName = $kernelSec->{SymbolEnt}{Name};
    my $maxregCount = $paramSec->{MAXREG_COUNT};
    #stackSize is reference to array
    my $stackSize   = $paramSec->{STACKSIZE};

    $kernelSec->{KernelData} = $newData;
    $kernelSec->{Data}       = unpack "H*", pack "Q*", @$newData;
    
    if ($newReg != $kernelSec->{RegCnt})
    {
        print "Modified $kernelName RegCnt: $kernelSec->{RegCnt} => $newReg\n";
        $kernelSec->{RegCnt} = $newReg;
        $kernelSec->{info}  &= ~0xff000000;
        $kernelSec->{info}  |= $newReg << 24;
    }
    if ($newBar != $kernelSec->{BarCnt})
    {
        print "Modified $kernelName BarCnt: $kernelSec->{BarCnt} => $newBar\n";
        $kernelSec->{BarCnt} = $newBar;
        $kernelSec->{flags} &= ~0x01f00000;
        $kernelSec->{flags} |=  $newBar << 20;
    }
    #staticParams在修改kernel前后不变。下面的代码在staticParams后面填入paramSec的剩余部分。该部分可能发生变化，需要重新计算。
    my @paramData = @{$paramSec->{StaticParams}};
    if (defined $maxregCount)
    {
        push @paramData, ($maxregCount << 16) | 0x1b03;
    }


    my $newCTAIDs = join ',', map { sprintf '%04x', $_ } @$ctaidOffsets;
    my $oldCTAIDs = join ',', map { sprintf '%04x', $_ } @{$paramSec->{CTAIDOffsets}};

    if ($newCTAIDs ne $oldCTAIDs)
    {
        print "Modified $kernelName CTAID Offsets: '$oldCTAIDs' => '$newCTAIDs'\n";
    }
    if (@$ctaidOffsets)
    {
        push @paramData, (scalar(@$ctaidOffsets) << 18) | 0x1d04;
        push @paramData, @$ctaidOffsets;
    }

    my $newExits = join ',', map { sprintf '%04x', $_ } @$exitOffsets;
    my $oldExits = join ',', map { sprintf '%04x', $_ } @{$paramSec->{ExitOffsets}};

    if ($newExits ne $oldExits)
    {
        print "Modified $kernelName Exit Offsets: '$oldExits' => '$newExits'\n";
    }
    if (@$exitOffsets)
    {
        push @paramData, (scalar(@$exitOffsets) << 18) | 0x1c04;
        push @paramData, @$exitOffsets;
    }

    if ($ctaidzUsed != $paramSec->{CTAIDZUsed})
    {
        print "Modified $kernelName CTAID.Z Used: '$paramSec->{CTAIDZUsed}' => '$ctaidzUsed'\n";
    }
    if ($ctaidzUsed)
    {
        push @paramData, 0x0401;
    }
    #the following part will not change.
    if (@{$paramSec->{REQNTID}})
    {
        push @paramData, (scalar(@{$paramSec->{REQNTID}}) << 18) | 0x1004;
        push @paramData, @{$paramSec->{REQNTID}};
    }
    if (@{$paramSec->{MAXNTID}})
    {
        push @paramData, (scalar(@{$paramSec->{MAXNTID}}) << 18) | 0x0504;
        push @paramData, @{$paramSec->{MAXNTID}};
    }
    if (@$stackSize)
    {
        push @paramData, (scalar(@$stackSize) << 18) | 0x1e04;
        push @paramData, @$stackSize;
    }

    my $newParamSize  = scalar(@paramData)*4;
    $paramSec->{Data} = unpack "H*", pack "L*", @paramData;
    if ($newParamSize != $paramSec->{size})
    {
        print "Modified $kernelName ParamSecSize: $paramSec->{size} => $newParamSize\n";
        $cubin->updateSize($paramSec, $newParamSize);
    }

    if ($newSize != $kernelSec->{size})
    {
        print "Modified $kernelName KernelSize: $kernelSec->{size} => $newSize\n";
        $cubin->updateSize($kernelSec, $newSize, 1);
    }
}

sub updateSize
{
    my ($cubin, $sec, $newSize, $updatePrgSize) = @_;

    my $elfHdr = $cubin->{elfHdr};
    my $class  = $elfHdr->{fileClass};

    my $delta = $newSize - $sec->{size};
    $sec->{size} = $newSize;

    if ($sec->{SymbolEnt})
    {
        $sec->{SymbolEnt}{size} = $newSize;
        my $symSection = $cubin->{'.symtab'};
        $symSection->{Data} = '';
        foreach my $symEnt (@{$symSection->{SymTab}})
        {
            $symSection->{Data} .= unpack "H*", pack $symHdrT[$class], @{$symEnt}{@{$symHdrC[$class]}};
        }
    }

    my $pos = $elfHdr->{ehSize};
    my %sizeMap;

    foreach my $secHdr (@{$cubin->{secHdrs}})
    {
        next if $secHdr->{align} == 0;

        my $size = $secHdr->{type} == 8 ? 0 : $secHdr->{size};

        my $pad = $pos % $secHdr->{align};
        if ($pad > 0)
        {
            $pos += $secHdr->{align} - $pad;
        }
        $sizeMap{$secHdr->{offset}} = $pos;

        $secHdr->{offset} = $pos;

        $pos += $size;
    }

    my $shSize = $elfHdr->{phOffset} - $elfHdr->{shOffset};

    $sizeMap{$elfHdr->{shOffset}} = $pos;
    $sizeMap{$elfHdr->{phOffset}} = $pos + $shSize;

    $elfHdr->{shOffset} = $pos;
    $elfHdr->{phOffset} = $pos + $shSize;

    foreach my $prgHdr (@{$cubin->{prgHdrs}})
    {
        $prgHdr->{offset} = $sizeMap{$prgHdr->{offset}};

        if ($updatePrgSize && $prgHdr->{type} == 1 &&
            $sec->{offset} >= $prgHdr->{offset} &&
            $sec->{offset} < $prgHdr->{offset} + $prgHdr->{fileSize} + $delta)
        {
            $prgHdr->{fileSize} += $delta;
            $prgHdr->{memSize}  += $delta;
        }
    }
}

sub write
{
    my ($cubin, $file) = @_;

    open my $fh, ">$file" or die "Error: could not open $file for writing: $!";
    binmode($fh);

    my $elfHdr = $cubin->{elfHdr};
    my $class  = $elfHdr->{fileClass};

    print $fh pack $elfHdrT[$class], @{$elfHdr}{@{$elfHdrC[$class]}};
    my $pos = $elfHdr->{ehSize};

    foreach my $secHdr (@{$cubin->{secHdrs}})
    {
        next if $secHdr->{size} == 0 || $secHdr->{type} == 8;

        my $pad = $pos % $secHdr->{align};
        if ($pad > 0)
        {
            $pad = $secHdr->{align} - $pad;
            print $fh join '', "\0" x $pad;
            $pos += $pad;
        }

        print $fh pack 'H*', $secHdr->{Data};
        $pos += $secHdr->{size};
    }

    foreach my $secHdr (@{$cubin->{secHdrs}})
    {
        print $fh pack $secHdrT[$class], @{$secHdr}{@{$secHdrC[$class]}};
    }

    foreach my $prgHdr (@{$cubin->{prgHdrs}})
    {
        print $fh pack $prgHdrT[$class], @{$prgHdr}{@{$prgHdrC[$class]}};
    }
    close $fh;
}

__END__

