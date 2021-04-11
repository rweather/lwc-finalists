#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "internal-gift128-config.h"
#if GIFT128_VARIANT_ASM && GIFT128_VARIANT == GIFT128_VARIANT_TINY
	.syntax unified
	.thumb
	.text

	.align	2
	.global	gift128b_init
	.thumb
	.thumb_func
	.type	gift128b_init, %function
gift128b_init:
	ldr	r2, [r1, #12]
	ldr	r3, [r1, #4]
	rev	r2, r2
	rev	r3, r3
	str	r2, [r0, #0]
	str	r3, [r0, #4]
	ldr	r2, [r1, #8]
	ldr	r3, [r1, #0]
	rev	r2, r2
	rev	r3, r3
	str	r2, [r0, #8]
	str	r3, [r0, #12]
	bx	lr
	.size	gift128b_init, .-gift128b_init

	.align	4
	.type	rconst, %object
rconst:
	.word	0x80000001
	.word	0x80000003
	.word	0x80000007
	.word	0x8000000f
	.word	0x8000001f
	.word	0x8000003e
	.word	0x8000003d
	.word	0x8000003b
	.word	0x80000037
	.word	0x8000002f
	.word	0x8000001e
	.word	0x8000003c
	.word	0x80000039
	.word	0x80000033
	.word	0x80000027
	.word	0x8000000e
	.word	0x8000001d
	.word	0x8000003a
	.word	0x80000035
	.word	0x8000002b
	.word	0x80000016
	.word	0x8000002c
	.word	0x80000018
	.word	0x80000030
	.word	0x80000021
	.word	0x80000002
	.word	0x80000005
	.word	0x8000000b
	.word	0x80000017
	.word	0x8000002e
	.word	0x8000001c
	.word	0x80000038
	.word	0x80000031
	.word	0x80000023
	.word	0x80000006
	.word	0x8000000d
	.word	0x8000001b
	.word	0x80000036
	.word	0x8000002d
	.word	0x8000001a
	.size	rconst, .-rconst

	.align	2
	.global	gift128b_encrypt_preloaded
	.thumb
	.thumb_func
	.type	gift128b_encrypt_preloaded, %function
gift128b_encrypt_preloaded:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r7, [r0, #12]
	ldr	r8, [r0, #4]
	ldr	r9, [r0, #8]
	ldr	r10, [r0, #0]
	ldr	r4, [r2, #0]
	ldr	r5, [r2, #4]
	ldr	r6, [r2, #8]
	ldr	r2, [r2, #12]
	mov	lr, #40
	adr	fp, rconst
.L1:
	and	r0, r4, r6
	eors	r5, r0
	and	r3, r5, r2
	eors	r4, r3
	orr	r0, r4, r5
	eors	r6, r0
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r0, r4, r5
	eors	r6, r0
	eor	r0, r2, r2, lsr #3
	eor	r3, r5, r5, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #3
	eor	r5, r5, r3, lsl #3
	eor	r0, r6, r6, lsr #3
	eor	r3, r4, r4, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #3
	eor	r4, r4, r3, lsl #3
	eor	r0, r2, r2, lsr #6
	eor	r3, r5, r5, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #6
	eor	r5, r5, r3, lsl #6
	eor	r0, r6, r6, lsr #6
	eor	r3, r4, r4, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #6
	eor	r4, r4, r3, lsl #6
	eor	r0, r2, r2, lsr #12
	eor	r3, r5, r5, lsr #12
	movw	ip, #61680
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #12
	eor	r5, r5, r3, lsl #12
	eor	r0, r6, r6, lsr #12
	eor	r3, r4, r4, lsr #12
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #12
	eor	r4, r4, r3, lsl #12
	eor	r0, r2, r2, lsr #24
	eor	r3, r5, r5, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #24
	eor	r5, r5, r3, lsl #24
	eor	r0, r6, r6, lsr #24
	eor	r3, r4, r4, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #24
	eor	r4, r4, r3, lsl #24
	ror	r2, r2, #24
	ror	r5, r5, #16
	ror	r6, r6, #8
	ldr	r0, [fp], #4
	eor	r6, r8
	eor	r5, r10
	eors	r4, r0
	lsr	r0, r10, #18
	lsl	r0, r0, #18
	and	r3, r10, #196608
	lsl	ip, r10, #4
	lsr	r0, r0, #2
	orr	r0, r0, r3, lsl #14
	uxth	ip, ip
	orr	r0, r0, ip
	ubfx	r10, r10, #12, #4
	orrs	r10, r10, r0
	and	r0, r2, r6
	eors	r5, r0
	and	r3, r5, r4
	eors	r2, r3
	orr	r0, r2, r5
	eors	r6, r0
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r0, r2, r5
	eors	r6, r0
	eor	r0, r4, r4, lsr #3
	eor	r3, r5, r5, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #3
	eor	r5, r5, r3, lsl #3
	eor	r0, r6, r6, lsr #3
	eor	r3, r2, r2, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #3
	eor	r2, r2, r3, lsl #3
	eor	r0, r4, r4, lsr #6
	eor	r3, r5, r5, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #6
	eor	r5, r5, r3, lsl #6
	eor	r0, r6, r6, lsr #6
	eor	r3, r2, r2, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #6
	eor	r2, r2, r3, lsl #6
	eor	r0, r4, r4, lsr #12
	eor	r3, r5, r5, lsr #12
	movw	ip, #61680
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #12
	eor	r5, r5, r3, lsl #12
	eor	r0, r6, r6, lsr #12
	eor	r3, r2, r2, lsr #12
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #12
	eor	r2, r2, r3, lsl #12
	eor	r0, r4, r4, lsr #24
	eor	r3, r5, r5, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #24
	eor	r5, r5, r3, lsl #24
	eor	r0, r6, r6, lsr #24
	eor	r3, r2, r2, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #24
	eor	r2, r2, r3, lsl #24
	ror	r4, r4, #24
	ror	r5, r5, #16
	ror	r6, r6, #8
	ldr	r0, [fp], #4
	eors	r6, r7
	eor	r5, r9
	eors	r2, r0
	lsr	r0, r9, #18
	lsl	r0, r0, #18
	and	r3, r9, #196608
	lsl	ip, r9, #4
	lsr	r0, r0, #2
	orr	r0, r0, r3, lsl #14
	uxth	ip, ip
	orr	r0, r0, ip
	ubfx	r9, r9, #12, #4
	orrs	r9, r9, r0
	and	r0, r4, r6
	eors	r5, r0
	and	r3, r5, r2
	eors	r4, r3
	orr	r0, r4, r5
	eors	r6, r0
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r0, r4, r5
	eors	r6, r0
	eor	r0, r2, r2, lsr #3
	eor	r3, r5, r5, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #3
	eor	r5, r5, r3, lsl #3
	eor	r0, r6, r6, lsr #3
	eor	r3, r4, r4, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #3
	eor	r4, r4, r3, lsl #3
	eor	r0, r2, r2, lsr #6
	eor	r3, r5, r5, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #6
	eor	r5, r5, r3, lsl #6
	eor	r0, r6, r6, lsr #6
	eor	r3, r4, r4, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #6
	eor	r4, r4, r3, lsl #6
	eor	r0, r2, r2, lsr #12
	eor	r3, r5, r5, lsr #12
	movw	ip, #61680
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #12
	eor	r5, r5, r3, lsl #12
	eor	r0, r6, r6, lsr #12
	eor	r3, r4, r4, lsr #12
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #12
	eor	r4, r4, r3, lsl #12
	eor	r0, r2, r2, lsr #24
	eor	r3, r5, r5, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #24
	eor	r5, r5, r3, lsl #24
	eor	r0, r6, r6, lsr #24
	eor	r3, r4, r4, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #24
	eor	r4, r4, r3, lsl #24
	ror	r2, r2, #24
	ror	r5, r5, #16
	ror	r6, r6, #8
	ldr	r0, [fp], #4
	eor	r6, r10
	eor	r5, r8
	eors	r4, r0
	lsr	r0, r8, #18
	lsl	r0, r0, #18
	and	r3, r8, #196608
	lsl	ip, r8, #4
	lsr	r0, r0, #2
	orr	r0, r0, r3, lsl #14
	uxth	ip, ip
	orr	r0, r0, ip
	ubfx	r8, r8, #12, #4
	orrs	r8, r8, r0
	and	r0, r2, r6
	eors	r5, r0
	and	r3, r5, r4
	eors	r2, r3
	orr	r0, r2, r5
	eors	r6, r0
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r0, r2, r5
	eors	r6, r0
	eor	r0, r4, r4, lsr #3
	eor	r3, r5, r5, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #3
	eor	r5, r5, r3, lsl #3
	eor	r0, r6, r6, lsr #3
	eor	r3, r2, r2, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #3
	eor	r2, r2, r3, lsl #3
	eor	r0, r4, r4, lsr #6
	eor	r3, r5, r5, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #6
	eor	r5, r5, r3, lsl #6
	eor	r0, r6, r6, lsr #6
	eor	r3, r2, r2, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #6
	eor	r2, r2, r3, lsl #6
	eor	r0, r4, r4, lsr #12
	eor	r3, r5, r5, lsr #12
	movw	ip, #61680
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #12
	eor	r5, r5, r3, lsl #12
	eor	r0, r6, r6, lsr #12
	eor	r3, r2, r2, lsr #12
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #12
	eor	r2, r2, r3, lsl #12
	eor	r0, r4, r4, lsr #24
	eor	r3, r5, r5, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #24
	eor	r5, r5, r3, lsl #24
	eor	r0, r6, r6, lsr #24
	eor	r3, r2, r2, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #24
	eor	r2, r2, r3, lsl #24
	ror	r4, r4, #24
	ror	r5, r5, #16
	ror	r6, r6, #8
	ldr	r0, [fp], #4
	eor	r6, r9
	eors	r5, r7
	eors	r2, r0
	lsr	r0, r7, #18
	lsl	r0, r0, #18
	and	r3, r7, #196608
	lsl	ip, r7, #4
	lsr	r0, r0, #2
	orr	r0, r0, r3, lsl #14
	uxth	ip, ip
	orr	r0, r0, ip
	ubfx	r7, r7, #12, #4
	orrs	r7, r7, r0
	subs	lr, lr, #4
	bne	.L1
	str	r4, [r1, #0]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r2, [r1, #12]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	gift128b_encrypt_preloaded, .-gift128b_encrypt_preloaded

#endif
#endif
