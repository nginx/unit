#!/usr/bin/perl

use warnings;
use strict;

# BLOCK_SIZE should be 128, 256, 512, etc.  The value 128 provides
# the minimum memory footprint for both 32-bit and 64-bit platforms.
use constant BLOCK_SIZE => 128;

my %lowcase;
my %blocks;
my $max_block = 0;
my $max_lowcase = 0;

while (<>) {
    if (/^(\w+); (C|S); (\w+);/) {
        my ($symbol, $folding) = (hex $1, hex $3);
        $lowcase{$symbol} = $folding;
        $blocks{int($symbol / BLOCK_SIZE)} = 1;

        if ($max_lowcase < $symbol) {
            $max_lowcase = $symbol;
        }
    }
}


my $last_block_size = $max_lowcase % BLOCK_SIZE + 1;


for my $block (sort { $a <=> $b } keys %blocks) {
    if ($max_block < $block) {
        $max_block = $block;
    }
}


my $blocks = scalar keys %blocks;

printf("\n/*\n" .
       " * %d %s-bytes blocks, %d pointers.\n" .
       " * %d bytes on 32-bit platforms, %d bytes on 64-bit platforms.\n" .
       " */\n\n",
       $blocks, BLOCK_SIZE, $max_block + 1,
       ($blocks - 1) * BLOCK_SIZE * 4 + $last_block_size + $max_block * 4,
       ($blocks - 1) * BLOCK_SIZE * 4 + $last_block_size+ $max_block * 8);

printf("#define NXT_UNICODE_MAX_LOWCASE  0x%05x\n\n", $max_lowcase);
printf("#define NXT_UNICODE_BLOCK_SIZE   %d\n\n\n", BLOCK_SIZE);


for my $block (sort { $a <=> $b } keys %blocks) {
    my $block_size = ($block != $max_block) ? BLOCK_SIZE : $last_block_size;

    print "static const uint32_t  ";
    printf("nxt_unicode_block_%03x[%d]  nxt_aligned(64) = {",
           $block, $block_size);

    for my $c (0 .. $block_size - 1) {
        printf "\n   " if $c % 8 == 0;

        my $n = $block * BLOCK_SIZE + $c;

        if (exists $lowcase{$n}) {
            printf(" 0x%05x,", $lowcase{$n});

        } else {
            #print " .......,";
            printf(" 0x%05x,", $n);
        }
    }

    print "\n};\n\n\n";
}


print "static const uint32_t  *nxt_unicode_blocks[]  nxt_aligned(64) = {\n";

for my $block (0 .. $max_block) {
    if (exists($blocks{$block})) {
        printf("    nxt_unicode_block_%03x,\n", $block);

    } else {
        print  "    NULL,\n";
    }
}

print "};\n";
