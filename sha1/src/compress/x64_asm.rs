//! SHA-1 hash in x86 assembly

/* Original Copyright notice:
 * Copyright (c) 2014 Project Nayuki. (MIT License)
 * https://www.nayuki.io/page/fast-sha1-hash-implementation-in-x86-assembly
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * - The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 * - The Software is provided "as is", without warranty of any kind, express or
 *   implied, including but not limited to the warranties of merchantability,
 *   fitness for a particular purpose and noninfringement. In no event shall the
 *   authors or copyright holders be liable for any claim, damages or other
 *   liability, whether in an action of contract, tort or otherwise, arising from,
 *   out of or in connection with the Software or the use or other dealings in the
 *   Software.
 */

use core::arch::asm;

macro_rules! c {
    ($($l:expr)*) => {
        concat!($($l ,)*)
    };
}

// #define ROUND0a(a, b, c, d, e, i)  \
//         movl    (i*4)(%rdi), %esi;  \
//         bswapl  %esi;               \
//         movl    %esi, (i*4)(%rsp);  \
//         addl    %esi, %e;           \
//         movl    %c, %esi;           \
//         xorl    %d, %esi;           \
//         andl    %b, %esi;           \
//         xorl    %d, %esi;           \
//         ROUNDTAIL(a, b, e, i, 0x5A827999)

macro_rules! round0a {
    ($a:literal, $b:literal, $c:literal, $d:literal, $e:literal, $i:literal) => {
        c!(
            "movl   (" $i " * 4)(%rdi), %esi;"
            "bswapl %esi;"
            "movl   %esi, (" $i " * 4)(%rsp);"
            "addl   %esi, " $e ";"
            "movl   " $c ", %esi;"
            "xorl   " $d ", %esi;"
            "andl   " $b ", %esi;"
            "xorl   " $d ", %esi;"
            roundtail!($a, $b, $e, $i, "0x5A827999")
        )
    };
}

// #define SCHEDULE(i, e)  \
//        movl  (((i- 3)&0xF)*4)(%rsp), %esi;  \
//        xorl  (((i- 8)&0xF)*4)(%rsp), %esi;  \
//        xorl  (((i-14)&0xF)*4)(%rsp), %esi;  \
//        xorl  (((i-16)&0xF)*4)(%rsp), %esi;  \
//        roll  $1, %esi;                      \
//        addl  %esi, %e;                      \
//        movl  %esi, ((i&0xF)*4)(%rsp);
macro_rules! scheldule {
    ($i:literal, $e:literal) => {
        c!(
            "movl (((" $i " -  3) & 0xF) * 4)(%rsp), %esi;"
            "xorl (((" $i " -  8) & 0xF) * 4)(%rsp), %esi;"
            "xorl (((" $i " - 14) & 0xF) * 4)(%rsp), %esi;"
            "xorl (((" $i " - 16) & 0xF) * 4)(%rsp), %esi;"
            "roll $1, %esi;"
            "addl %esi, " $e ";"
            "movl %esi, ((" $i " & 0xF) * 4)(%rsp);"
        )
    };
}

// #define ROUND0b(a, b, c, d, e, i)  \
//         SCHEDULE(i, e)   \
//         movl  %c, %esi;  \
//         xorl  %d, %esi;  \
//         andl  %b, %esi;  \
//         xorl  %d, %esi;  \
//         ROUNDTAIL(a, b, e, i, 0x5A827999)
macro_rules! round0b {
    ($a:literal, $b:literal, $c:literal, $d:literal, $e:literal, $i:literal) => {
        c!(
            scheldule!($i, $e)
            "movl  " $c ", %esi;"
            "xorl  " $d ", %esi;"
            "andl  " $b ", %esi;"
            "xorl  " $d ", %esi;"
            roundtail!($a, $b, $e, $i, "0x5A827999")
        )
    };
}

// #define ROUND1(a, b, c, d, e, i)  \
//         SCHEDULE(i, e)   \
//         movl  %b, %esi;  \
//         xorl  %c, %esi;  \
//         xorl  %d, %esi;  \
//         ROUNDTAIL(a, b, e, i, 0x6ED9EBA1)
macro_rules! round1 {
    ($a:literal, $b:literal, $c:literal, $d:literal, $e:literal, $i:literal) => {
        c!(
            scheldule!($i, $e)
            "movl " $b ", %esi;"
            "xorl " $b ", %esi;"
            "xorl " $d ", %esi;"
            roundtail!($a, $b, $e, $i, "0x6ED9EBA1")
        )
    };
}

// #define ROUND2(a, b, c, d, e, i)  \
//        SCHEDULE(i, e)     \
//        movl  %c, %esi;    \
//        movl  %c, %edi;    \
//        orl   %d, %esi;    \
//        andl  %b, %esi;    \
//        andl  %d, %edi;    \
//        orl   %edi, %esi;  \
//        ROUNDTAIL(a, b, e, i, -0x70E44324)
macro_rules! round2 {
    ($a:literal, $b:literal, $c:literal, $d:literal, $e:literal, $i:literal) => {
        c!(
            scheldule!($i, $e)
            "movl " $c ", %esi;"
            "movl " $c ", %edi;"
            "orl  " $d ", %esi;"
            "andl " $b ", %esi;"
            "andl " $d ", %edi;"
            "orl    %edi, %esi;"
            roundtail!($a, $b, $e, $i, "-0x70E44324")
        )
    };
}

// #define ROUND3(a, b, c, d, e, i)  \
//         SCHEDULE(i, e)   \
//         movl  %b, %esi;  \
//         xorl  %c, %esi;  \
//         xorl  %d, %esi;  \
//         ROUNDTAIL(a, b, e, i, -0x359D3E2A)
macro_rules! round3 {
    ($a:literal, $b:literal, $c:literal, $d:literal, $e:literal, $i:literal) => {
        c!(
            scheldule!($i, $e)
            "movl " $b ", %esi;"
            "xorl " $c ", %esi;"
            "xorl " $d ", %esi;"
            roundtail!($a, $b, $e, $i, "-0x359D3E2A")
        )
    };
}

// #define ROUNDTAIL(a, b, e, i, k)  \
//       roll  $30, %b;         \
//       leal  k(%e,%esi), %e;  \
//       movl  %a, %esi;        \
//       roll  $5, %esi;        \
//       addl  %esi, %e;
macro_rules! roundtail {
    ($a:literal, $b:literal, $e:literal, $i:literal, $k:literal) => {
        c!(
            "roll $30, " $b ";"
            "leal " $k "(" $e ", %esi), " $e ";"
            "movl " $a ", %esi;"
            "roll $5, %esi;"
            "addl %esi, " $e ";"
        )
    };
}

#[inline]
fn sha1_compress(state: &mut [u32; 5], block: &[u8; 64]) {
    // Storage usage:
    //   Bytes  Location  Description
    //       4  eax       SHA-1 state variable A
    //       4  ebx       SHA-1 state variable B
    //       4  ecx       SHA-1 state variable C
    //       4  edx       SHA-1 state variable D
    //       4  ebp       SHA-1 state variable E
    //       4  esi       Temporary for calculation per round
    //       4  edi       (Last 64 rounds) temporary for calculation per round
    //       8  rdi       (First 16 rounds) base address of block array argument (read-only)
    //       8  r8        Base address of state array argument (read-only)
    //       8  rsp       x86-64 stack pointer
    //      64  [rsp+0]   Circular buffer of most recent 16 key schedule items, 4 bytes each
    //      16  xmm0      Caller's value of rbx (only low 64 bits are used)
    //      16  xmm1      Caller's value of rbp (only low 64 bits are used)

    unsafe {
        asm!(
            // store registers
            "movq    %rbx, %xmm0",
            "movq    %rbp, %xmm1",
            // allocate scratch space
            "subq    $64, %rsp",

            // Load arguments
            "movq    %rdi, %r8",      // state backup
            "movl     0(%rdi), %eax", // a = state[0]
            "movl     4(%rdi), %ebx", // b = state[1]
            "movl     8(%rdi), %ecx", // c = state[2]
            "movl    12(%rdi), %edx", // d = state[3]
            "movl    16(%rdi), %ebp", // e = state[4]
            "movq    %rsi, %rdi",     // block

            // Rounds 1..80
            round0a!("%eax", "%ebx", "%ecx", "%edx", "%ebp",  0),
            round0a!("%ebp", "%eax", "%ebx", "%ecx", "%edx",  1),
            round0a!("%edx", "%ebp", "%eax", "%ebx", "%ecx",  2),
            round0a!("%ecx", "%edx", "%ebp", "%eax", "%ebx",  3),
            round0a!("%ebx", "%ecx", "%edx", "%ebp", "%eax",  4),
            round0a!("%eax", "%ebx", "%ecx", "%edx", "%ebp",  5),
            round0a!("%ebp", "%eax", "%ebx", "%ecx", "%edx",  6),
            round0a!("%edx", "%ebp", "%eax", "%ebx", "%ecx",  7),
            round0a!("%ecx", "%edx", "%ebp", "%eax", "%ebx",  8),
            round0a!("%ebx", "%ecx", "%edx", "%ebp", "%eax",  9),
            round0a!("%eax", "%ebx", "%ecx", "%edx", "%ebp", 10),
            round0a!("%ebp", "%eax", "%ebx", "%ecx", "%edx", 11),
            round0a!("%edx", "%ebp", "%eax", "%ebx", "%ecx", 12),
            round0a!("%ecx", "%edx", "%ebp", "%eax", "%ebx", 13),
            round0a!("%ebx", "%ecx", "%edx", "%ebp", "%eax", 14),
            round0a!("%eax", "%ebx", "%ecx", "%edx", "%ebp", 15),

            round0b!("%ebp", "%eax", "%ebx", "%ecx", "%edx", 16),
            round0b!("%edx", "%ebp", "%eax", "%ebx", "%ecx", 17),
            round0b!("%ecx", "%edx", "%ebp", "%eax", "%ebx", 18),
            round0b!("%ebx", "%ecx", "%edx", "%ebp", "%eax", 19),

            round1!("%eax", "%ebx", "%ecx", "%edx", "%ebp", 20),
            round1!("%ebp", "%eax", "%ebx", "%ecx", "%edx", 21),
            round1!("%edx", "%ebp", "%eax", "%ebx", "%ecx", 22),
            round1!("%ecx", "%edx", "%ebp", "%eax", "%ebx", 23),
            round1!("%ebx", "%ecx", "%edx", "%ebp", "%eax", 24),
            round1!("%eax", "%ebx", "%ecx", "%edx", "%ebp", 25),
            round1!("%ebp", "%eax", "%ebx", "%ecx", "%edx", 26),
            round1!("%edx", "%ebp", "%eax", "%ebx", "%ecx", 27),
            round1!("%ecx", "%edx", "%ebp", "%eax", "%ebx", 28),
            round1!("%ebx", "%ecx", "%edx", "%ebp", "%eax", 29),
            round1!("%eax", "%ebx", "%ecx", "%edx", "%ebp", 30),
            round1!("%ebp", "%eax", "%ebx", "%ecx", "%edx", 31),
            round1!("%edx", "%ebp", "%eax", "%ebx", "%ecx", 32),
            round1!("%ecx", "%edx", "%ebp", "%eax", "%ebx", 33),
            round1!("%ebx", "%ecx", "%edx", "%ebp", "%eax", 34),
            round1!("%eax", "%ebx", "%ecx", "%edx", "%ebp", 35),
            round1!("%ebp", "%eax", "%ebx", "%ecx", "%edx", 36),
            round1!("%edx", "%ebp", "%eax", "%ebx", "%ecx", 37),
            round1!("%ecx", "%edx", "%ebp", "%eax", "%ebx", 38),
            round1!("%ebx", "%ecx", "%edx", "%ebp", "%eax", 39),

            round2!("%eax", "%ebx", "%ecx", "%edx", "%ebp", 40),
            round2!("%ebp", "%eax", "%ebx", "%ecx", "%edx", 41),
            round2!("%edx", "%ebp", "%eax", "%ebx", "%ecx", 42),
            round2!("%ecx", "%edx", "%ebp", "%eax", "%ebx", 43),
            round2!("%ebx", "%ecx", "%edx", "%ebp", "%eax", 44),
            round2!("%eax", "%ebx", "%ecx", "%edx", "%ebp", 45),
            round2!("%ebp", "%eax", "%ebx", "%ecx", "%edx", 46),
            round2!("%edx", "%ebp", "%eax", "%ebx", "%ecx", 47),
            round2!("%ecx", "%edx", "%ebp", "%eax", "%ebx", 48),
            round2!("%ebx", "%ecx", "%edx", "%ebp", "%eax", 49),
            round2!("%eax", "%ebx", "%ecx", "%edx", "%ebp", 50),
            round2!("%ebp", "%eax", "%ebx", "%ecx", "%edx", 51),
            round2!("%edx", "%ebp", "%eax", "%ebx", "%ecx", 52),
            round2!("%ecx", "%edx", "%ebp", "%eax", "%ebx", 53),
            round2!("%ebx", "%ecx", "%edx", "%ebp", "%eax", 54),
            round2!("%eax", "%ebx", "%ecx", "%edx", "%ebp", 55),
            round2!("%ebp", "%eax", "%ebx", "%ecx", "%edx", 56),
            round2!("%edx", "%ebp", "%eax", "%ebx", "%ecx", 57),
            round2!("%ecx", "%edx", "%ebp", "%eax", "%ebx", 58),
            round2!("%ebx", "%ecx", "%edx", "%ebp", "%eax", 59),

            round3!("%eax", "%ebx", "%ecx", "%edx", "%ebp", 60),
            round3!("%ebp", "%eax", "%ebx", "%ecx", "%edx", 61),
            round3!("%edx", "%ebp", "%eax", "%ebx", "%ecx", 62),
            round3!("%ecx", "%edx", "%ebp", "%eax", "%ebx", 63),
            round3!("%ebx", "%ecx", "%edx", "%ebp", "%eax", 64),
            round3!("%eax", "%ebx", "%ecx", "%edx", "%ebp", 65),
            round3!("%ebp", "%eax", "%ebx", "%ecx", "%edx", 66),
            round3!("%edx", "%ebp", "%eax", "%ebx", "%ecx", 67),
            round3!("%ecx", "%edx", "%ebp", "%eax", "%ebx", 68),
            round3!("%ebx", "%ecx", "%edx", "%ebp", "%eax", 69),
            round3!("%eax", "%ebx", "%ecx", "%edx", "%ebp", 70),
            round3!("%ebp", "%eax", "%ebx", "%ecx", "%edx", 71),
            round3!("%edx", "%ebp", "%eax", "%ebx", "%ecx", 72),
            round3!("%ecx", "%edx", "%ebp", "%eax", "%ebx", 73),
            round3!("%ebx", "%ecx", "%edx", "%ebp", "%eax", 74),
            round3!("%eax", "%ebx", "%ecx", "%edx", "%ebp", 75),
            round3!("%ebp", "%eax", "%ebx", "%ecx", "%edx", 76),
            round3!("%edx", "%ebp", "%eax", "%ebx", "%ecx", 77),
            round3!("%ecx", "%edx", "%ebp", "%eax", "%ebx", 78),
            round3!("%ebx", "%ecx", "%edx", "%ebp", "%eax", 79),

            // Save updated state
            "addl    %eax,  0(%r8)",
            "addl    %ebx,  4(%r8)",
            "addl    %ecx,  8(%r8)",
            "addl    %edx, 12(%r8)",
            "addl    %ebp, 16(%r8)",

            // Restore registers
            "movq    %xmm0, %rbx",
            "movq    %xmm1, %rbp",
            "addq    $64, %rsp",

            // Arguments
            in("rdi") state.as_mut_ptr(),
            in("rsi") block.as_ptr(),

            // Clobber
            out("eax") _,
            // out("ebx") _, Manually stored with xmm1
            out("ecx") _,
            out("edx") _,
            // out("ebp") _, Manually stored with xmm0
            out("xmm0") _,
            out("xmm1") _,

            options(att_syntax)
        );
    }
}

pub fn compress(state: &mut [u32; 5], blocks: &[[u8; 64]]) {
    for block in blocks {
        sha1_compress(state, block);
    }
}
