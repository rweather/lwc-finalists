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

	.syntax unified
	.thumb
	.text

	.align	2
	.global	sha256_transform
	.thumb
	.thumb_func
	.type	sha256_transform, %function
sha256_transform:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	ldr	r1, [r0, #0]
	ldr	r2, [r0, #4]
	ldr	r3, [r0, #8]
	ldr	r4, [r0, #12]
	ldr	r5, [r0, #16]
	ldr	r6, [r0, #20]
	ldr	r7, [r0, #24]
	ldr	r8, [r0, #28]
	ldr	r9, [r0, #32]
	rev	r9, r9
	str	r9, [r0, #32]
	movw	ip, #12184
	movt	ip, #17034
	add	r9, r8, r9
	add	r9, ip
	ror	r10, r5, #6
	eor	r10, r10, r5, ror #11
	eor	r10, r10, r5, ror #25
	add	r9, r10
	and	r10, r5, r6
	bic	ip, r7, r5
	eor	r10, ip
	add	r9, r10
	and	r10, r1, r2
	and	ip, r1, r3
	eor	r10, ip
	and	ip, r2, r3
	eor	r10, ip
	ror	ip, r1, #2
	eor	ip, ip, r1, ror #13
	eor	ip, ip, r1, ror #22
	add	r10, ip
	add	r4, r9
	add	r8, r9, r10
	ldr	r9, [r0, #36]
	rev	r9, r9
	str	r9, [r0, #36]
	movw	ip, #17553
	movt	ip, #28983
	add	r9, r7, r9
	add	r9, ip
	ror	r10, r4, #6
	eor	r10, r10, r4, ror #11
	eor	r10, r10, r4, ror #25
	add	r9, r10
	and	r10, r4, r5
	bic	ip, r6, r4
	eor	r10, ip
	add	r9, r10
	and	r10, r8, r1
	and	ip, r8, r2
	eor	r10, ip
	and	ip, r1, r2
	eor	r10, ip
	ror	ip, r8, #2
	eor	ip, ip, r8, ror #13
	eor	ip, ip, r8, ror #22
	add	r10, ip
	add	r3, r9
	add	r7, r9, r10
	ldr	r9, [r0, #40]
	rev	r9, r9
	str	r9, [r0, #40]
	movw	ip, #64463
	movt	ip, #46528
	add	r9, r6, r9
	add	r9, ip
	ror	r10, r3, #6
	eor	r10, r10, r3, ror #11
	eor	r10, r10, r3, ror #25
	add	r9, r10
	and	r10, r3, r4
	bic	ip, r5, r3
	eor	r10, ip
	add	r9, r10
	and	r10, r7, r8
	and	ip, r7, r1
	eor	r10, ip
	and	ip, r8, r1
	eor	r10, ip
	ror	ip, r7, #2
	eor	ip, ip, r7, ror #13
	eor	ip, ip, r7, ror #22
	add	r10, ip
	add	r2, r9
	add	r6, r9, r10
	ldr	r9, [r0, #44]
	rev	r9, r9
	str	r9, [r0, #44]
	movw	ip, #56229
	movt	ip, #59829
	add	r9, r5, r9
	add	r9, ip
	ror	r10, r2, #6
	eor	r10, r10, r2, ror #11
	eor	r10, r10, r2, ror #25
	add	r9, r10
	and	r10, r2, r3
	bic	ip, r4, r2
	eor	r10, ip
	add	r9, r10
	and	r10, r6, r7
	and	ip, r6, r8
	eor	r10, ip
	and	ip, r7, r8
	eor	r10, ip
	ror	ip, r6, #2
	eor	ip, ip, r6, ror #13
	eor	ip, ip, r6, ror #22
	add	r10, ip
	add	r1, r9
	add	r5, r9, r10
	ldr	r9, [r0, #48]
	rev	r9, r9
	str	r9, [r0, #48]
	movw	ip, #49755
	movt	ip, #14678
	add	r9, r4, r9
	add	r9, ip
	ror	r10, r1, #6
	eor	r10, r10, r1, ror #11
	eor	r10, r10, r1, ror #25
	add	r9, r10
	and	r10, r1, r2
	bic	ip, r3, r1
	eor	r10, ip
	add	r9, r10
	and	r10, r5, r6
	and	ip, r5, r7
	eor	r10, ip
	and	ip, r6, r7
	eor	r10, ip
	ror	ip, r5, #2
	eor	ip, ip, r5, ror #13
	eor	ip, ip, r5, ror #22
	add	r10, ip
	add	r8, r9
	add	r4, r9, r10
	ldr	r9, [r0, #52]
	rev	r9, r9
	str	r9, [r0, #52]
	movw	ip, #4593
	movt	ip, #23025
	add	r9, r3, r9
	add	r9, ip
	ror	r10, r8, #6
	eor	r10, r10, r8, ror #11
	eor	r10, r10, r8, ror #25
	add	r9, r10
	and	r10, r8, r1
	bic	ip, r2, r8
	eor	r10, ip
	add	r9, r10
	and	r10, r4, r5
	and	ip, r4, r6
	eor	r10, ip
	and	ip, r5, r6
	eor	r10, ip
	ror	ip, r4, #2
	eor	ip, ip, r4, ror #13
	eor	ip, ip, r4, ror #22
	add	r10, ip
	add	r7, r9
	add	r3, r9, r10
	ldr	r9, [r0, #56]
	rev	r9, r9
	str	r9, [r0, #56]
	movw	ip, #33444
	movt	ip, #37439
	add	r9, r2, r9
	add	r9, ip
	ror	r10, r7, #6
	eor	r10, r10, r7, ror #11
	eor	r10, r10, r7, ror #25
	add	r9, r10
	and	r10, r7, r8
	bic	ip, r1, r7
	eor	r10, ip
	add	r9, r10
	and	r10, r3, r4
	and	ip, r3, r5
	eor	r10, ip
	and	ip, r4, r5
	eor	r10, ip
	ror	ip, r3, #2
	eor	ip, ip, r3, ror #13
	eor	ip, ip, r3, ror #22
	add	r10, ip
	add	r6, r9
	add	r2, r9, r10
	ldr	r9, [r0, #60]
	rev	r9, r9
	str	r9, [r0, #60]
	movw	ip, #24277
	movt	ip, #43804
	add	r9, r1, r9
	add	r9, ip
	ror	r10, r6, #6
	eor	r10, r10, r6, ror #11
	eor	r10, r10, r6, ror #25
	add	r9, r10
	and	r10, r6, r7
	bic	ip, r8, r6
	eor	r10, ip
	add	r9, r10
	and	r10, r2, r3
	and	ip, r2, r4
	eor	r10, ip
	and	ip, r3, r4
	eor	r10, ip
	ror	ip, r2, #2
	eor	ip, ip, r2, ror #13
	eor	ip, ip, r2, ror #22
	add	r10, ip
	add	r5, r9
	add	r1, r9, r10
	ldr	r9, [r0, #64]
	rev	r9, r9
	str	r9, [r0, #64]
	movw	ip, #43672
	movt	ip, #55303
	add	r9, r8, r9
	add	r9, ip
	ror	r10, r5, #6
	eor	r10, r10, r5, ror #11
	eor	r10, r10, r5, ror #25
	add	r9, r10
	and	r10, r5, r6
	bic	ip, r7, r5
	eor	r10, ip
	add	r9, r10
	and	r10, r1, r2
	and	ip, r1, r3
	eor	r10, ip
	and	ip, r2, r3
	eor	r10, ip
	ror	ip, r1, #2
	eor	ip, ip, r1, ror #13
	eor	ip, ip, r1, ror #22
	add	r10, ip
	add	r4, r9
	add	r8, r9, r10
	ldr	r9, [r0, #68]
	rev	r9, r9
	str	r9, [r0, #68]
	movw	ip, #23297
	movt	ip, #4739
	add	r9, r7, r9
	add	r9, ip
	ror	r10, r4, #6
	eor	r10, r10, r4, ror #11
	eor	r10, r10, r4, ror #25
	add	r9, r10
	and	r10, r4, r5
	bic	ip, r6, r4
	eor	r10, ip
	add	r9, r10
	and	r10, r8, r1
	and	ip, r8, r2
	eor	r10, ip
	and	ip, r1, r2
	eor	r10, ip
	ror	ip, r8, #2
	eor	ip, ip, r8, ror #13
	eor	ip, ip, r8, ror #22
	add	r10, ip
	add	r3, r9
	add	r7, r9, r10
	ldr	r9, [r0, #72]
	rev	r9, r9
	str	r9, [r0, #72]
	movw	ip, #34238
	movt	ip, #9265
	add	r9, r6, r9
	add	r9, ip
	ror	r10, r3, #6
	eor	r10, r10, r3, ror #11
	eor	r10, r10, r3, ror #25
	add	r9, r10
	and	r10, r3, r4
	bic	ip, r5, r3
	eor	r10, ip
	add	r9, r10
	and	r10, r7, r8
	and	ip, r7, r1
	eor	r10, ip
	and	ip, r8, r1
	eor	r10, ip
	ror	ip, r7, #2
	eor	ip, ip, r7, ror #13
	eor	ip, ip, r7, ror #22
	add	r10, ip
	add	r2, r9
	add	r6, r9, r10
	ldr	r9, [r0, #76]
	rev	r9, r9
	str	r9, [r0, #76]
	movw	ip, #32195
	movt	ip, #21772
	add	r9, r5, r9
	add	r9, ip
	ror	r10, r2, #6
	eor	r10, r10, r2, ror #11
	eor	r10, r10, r2, ror #25
	add	r9, r10
	and	r10, r2, r3
	bic	ip, r4, r2
	eor	r10, ip
	add	r9, r10
	and	r10, r6, r7
	and	ip, r6, r8
	eor	r10, ip
	and	ip, r7, r8
	eor	r10, ip
	ror	ip, r6, #2
	eor	ip, ip, r6, ror #13
	eor	ip, ip, r6, ror #22
	add	r10, ip
	add	r1, r9
	add	r5, r9, r10
	ldr	r9, [r0, #80]
	rev	r9, r9
	str	r9, [r0, #80]
	movw	ip, #23924
	movt	ip, #29374
	add	r9, r4, r9
	add	r9, ip
	ror	r10, r1, #6
	eor	r10, r10, r1, ror #11
	eor	r10, r10, r1, ror #25
	add	r9, r10
	and	r10, r1, r2
	bic	ip, r3, r1
	eor	r10, ip
	add	r9, r10
	and	r10, r5, r6
	and	ip, r5, r7
	eor	r10, ip
	and	ip, r6, r7
	eor	r10, ip
	ror	ip, r5, #2
	eor	ip, ip, r5, ror #13
	eor	ip, ip, r5, ror #22
	add	r10, ip
	add	r8, r9
	add	r4, r9, r10
	ldr	r9, [r0, #84]
	rev	r9, r9
	str	r9, [r0, #84]
	movw	ip, #45566
	movt	ip, #32990
	add	r9, r3, r9
	add	r9, ip
	ror	r10, r8, #6
	eor	r10, r10, r8, ror #11
	eor	r10, r10, r8, ror #25
	add	r9, r10
	and	r10, r8, r1
	bic	ip, r2, r8
	eor	r10, ip
	add	r9, r10
	and	r10, r4, r5
	and	ip, r4, r6
	eor	r10, ip
	and	ip, r5, r6
	eor	r10, ip
	ror	ip, r4, #2
	eor	ip, ip, r4, ror #13
	eor	ip, ip, r4, ror #22
	add	r10, ip
	add	r7, r9
	add	r3, r9, r10
	ldr	r9, [r0, #88]
	rev	r9, r9
	str	r9, [r0, #88]
	movw	ip, #1703
	movt	ip, #39900
	add	r9, r2, r9
	add	r9, ip
	ror	r10, r7, #6
	eor	r10, r10, r7, ror #11
	eor	r10, r10, r7, ror #25
	add	r9, r10
	and	r10, r7, r8
	bic	ip, r1, r7
	eor	r10, ip
	add	r9, r10
	and	r10, r3, r4
	and	ip, r3, r5
	eor	r10, ip
	and	ip, r4, r5
	eor	r10, ip
	ror	ip, r3, #2
	eor	ip, ip, r3, ror #13
	eor	ip, ip, r3, ror #22
	add	r10, ip
	add	r6, r9
	add	r2, r9, r10
	ldr	r9, [r0, #92]
	rev	r9, r9
	str	r9, [r0, #92]
	movw	ip, #61812
	movt	ip, #49563
	add	r9, r1, r9
	add	r9, ip
	ror	r10, r6, #6
	eor	r10, r10, r6, ror #11
	eor	r10, r10, r6, ror #25
	add	r9, r10
	and	r10, r6, r7
	bic	ip, r8, r6
	eor	r10, ip
	add	r9, r10
	and	r10, r2, r3
	and	ip, r2, r4
	eor	r10, ip
	and	ip, r3, r4
	eor	r10, ip
	ror	ip, r2, #2
	eor	ip, ip, r2, ror #13
	eor	ip, ip, r2, ror #22
	add	r10, ip
	add	r5, r9
	add	r1, r9, r10
	ldr	r9, [r0, #36]
	ldr	r10, [r0, #88]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #32]
	ldr	r10, [r0, #68]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #32]
	movw	ip, #27073
	movt	ip, #58523
	add	r9, r8, r9
	add	r9, ip
	ror	r10, r5, #6
	eor	r10, r10, r5, ror #11
	eor	r10, r10, r5, ror #25
	add	r9, r10
	and	r10, r5, r6
	bic	ip, r7, r5
	eor	r10, ip
	add	r9, r10
	and	r10, r1, r2
	and	ip, r1, r3
	eor	r10, ip
	and	ip, r2, r3
	eor	r10, ip
	ror	ip, r1, #2
	eor	ip, ip, r1, ror #13
	eor	ip, ip, r1, ror #22
	add	r10, ip
	add	r4, r9
	add	r8, r9, r10
	ldr	r9, [r0, #40]
	ldr	r10, [r0, #92]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #36]
	ldr	r10, [r0, #72]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #36]
	movw	ip, #18310
	movt	ip, #61374
	add	r9, r7, r9
	add	r9, ip
	ror	r10, r4, #6
	eor	r10, r10, r4, ror #11
	eor	r10, r10, r4, ror #25
	add	r9, r10
	and	r10, r4, r5
	bic	ip, r6, r4
	eor	r10, ip
	add	r9, r10
	and	r10, r8, r1
	and	ip, r8, r2
	eor	r10, ip
	and	ip, r1, r2
	eor	r10, ip
	ror	ip, r8, #2
	eor	ip, ip, r8, ror #13
	eor	ip, ip, r8, ror #22
	add	r10, ip
	add	r3, r9
	add	r7, r9, r10
	ldr	r9, [r0, #44]
	ldr	r10, [r0, #32]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #40]
	ldr	r10, [r0, #76]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #40]
	movw	ip, #40390
	movt	ip, #4033
	add	r9, r6, r9
	add	r9, ip
	ror	r10, r3, #6
	eor	r10, r10, r3, ror #11
	eor	r10, r10, r3, ror #25
	add	r9, r10
	and	r10, r3, r4
	bic	ip, r5, r3
	eor	r10, ip
	add	r9, r10
	and	r10, r7, r8
	and	ip, r7, r1
	eor	r10, ip
	and	ip, r8, r1
	eor	r10, ip
	ror	ip, r7, #2
	eor	ip, ip, r7, ror #13
	eor	ip, ip, r7, ror #22
	add	r10, ip
	add	r2, r9
	add	r6, r9, r10
	ldr	r9, [r0, #48]
	ldr	r10, [r0, #36]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #44]
	ldr	r10, [r0, #80]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #44]
	movw	ip, #41420
	movt	ip, #9228
	add	r9, r5, r9
	add	r9, ip
	ror	r10, r2, #6
	eor	r10, r10, r2, ror #11
	eor	r10, r10, r2, ror #25
	add	r9, r10
	and	r10, r2, r3
	bic	ip, r4, r2
	eor	r10, ip
	add	r9, r10
	and	r10, r6, r7
	and	ip, r6, r8
	eor	r10, ip
	and	ip, r7, r8
	eor	r10, ip
	ror	ip, r6, #2
	eor	ip, ip, r6, ror #13
	eor	ip, ip, r6, ror #22
	add	r10, ip
	add	r1, r9
	add	r5, r9, r10
	ldr	r9, [r0, #52]
	ldr	r10, [r0, #40]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #48]
	ldr	r10, [r0, #84]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #48]
	movw	ip, #11375
	movt	ip, #11753
	add	r9, r4, r9
	add	r9, ip
	ror	r10, r1, #6
	eor	r10, r10, r1, ror #11
	eor	r10, r10, r1, ror #25
	add	r9, r10
	and	r10, r1, r2
	bic	ip, r3, r1
	eor	r10, ip
	add	r9, r10
	and	r10, r5, r6
	and	ip, r5, r7
	eor	r10, ip
	and	ip, r6, r7
	eor	r10, ip
	ror	ip, r5, #2
	eor	ip, ip, r5, ror #13
	eor	ip, ip, r5, ror #22
	add	r10, ip
	add	r8, r9
	add	r4, r9, r10
	ldr	r9, [r0, #56]
	ldr	r10, [r0, #44]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #52]
	ldr	r10, [r0, #88]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #52]
	movw	ip, #33962
	movt	ip, #19060
	add	r9, r3, r9
	add	r9, ip
	ror	r10, r8, #6
	eor	r10, r10, r8, ror #11
	eor	r10, r10, r8, ror #25
	add	r9, r10
	and	r10, r8, r1
	bic	ip, r2, r8
	eor	r10, ip
	add	r9, r10
	and	r10, r4, r5
	and	ip, r4, r6
	eor	r10, ip
	and	ip, r5, r6
	eor	r10, ip
	ror	ip, r4, #2
	eor	ip, ip, r4, ror #13
	eor	ip, ip, r4, ror #22
	add	r10, ip
	add	r7, r9
	add	r3, r9, r10
	ldr	r9, [r0, #60]
	ldr	r10, [r0, #48]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #56]
	ldr	r10, [r0, #92]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #56]
	movw	ip, #43484
	movt	ip, #23728
	add	r9, r2, r9
	add	r9, ip
	ror	r10, r7, #6
	eor	r10, r10, r7, ror #11
	eor	r10, r10, r7, ror #25
	add	r9, r10
	and	r10, r7, r8
	bic	ip, r1, r7
	eor	r10, ip
	add	r9, r10
	and	r10, r3, r4
	and	ip, r3, r5
	eor	r10, ip
	and	ip, r4, r5
	eor	r10, ip
	ror	ip, r3, #2
	eor	ip, ip, r3, ror #13
	eor	ip, ip, r3, ror #22
	add	r10, ip
	add	r6, r9
	add	r2, r9, r10
	ldr	r9, [r0, #64]
	ldr	r10, [r0, #52]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #60]
	ldr	r10, [r0, #32]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #60]
	movw	ip, #35034
	movt	ip, #30457
	add	r9, r1, r9
	add	r9, ip
	ror	r10, r6, #6
	eor	r10, r10, r6, ror #11
	eor	r10, r10, r6, ror #25
	add	r9, r10
	and	r10, r6, r7
	bic	ip, r8, r6
	eor	r10, ip
	add	r9, r10
	and	r10, r2, r3
	and	ip, r2, r4
	eor	r10, ip
	and	ip, r3, r4
	eor	r10, ip
	ror	ip, r2, #2
	eor	ip, ip, r2, ror #13
	eor	ip, ip, r2, ror #22
	add	r10, ip
	add	r5, r9
	add	r1, r9, r10
	ldr	r9, [r0, #68]
	ldr	r10, [r0, #56]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #64]
	ldr	r10, [r0, #36]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #64]
	movw	ip, #20818
	movt	ip, #38974
	add	r9, r8, r9
	add	r9, ip
	ror	r10, r5, #6
	eor	r10, r10, r5, ror #11
	eor	r10, r10, r5, ror #25
	add	r9, r10
	and	r10, r5, r6
	bic	ip, r7, r5
	eor	r10, ip
	add	r9, r10
	and	r10, r1, r2
	and	ip, r1, r3
	eor	r10, ip
	and	ip, r2, r3
	eor	r10, ip
	ror	ip, r1, #2
	eor	ip, ip, r1, ror #13
	eor	ip, ip, r1, ror #22
	add	r10, ip
	add	r4, r9
	add	r8, r9, r10
	ldr	r9, [r0, #72]
	ldr	r10, [r0, #60]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #68]
	ldr	r10, [r0, #40]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #68]
	movw	ip, #50797
	movt	ip, #43057
	add	r9, r7, r9
	add	r9, ip
	ror	r10, r4, #6
	eor	r10, r10, r4, ror #11
	eor	r10, r10, r4, ror #25
	add	r9, r10
	and	r10, r4, r5
	bic	ip, r6, r4
	eor	r10, ip
	add	r9, r10
	and	r10, r8, r1
	and	ip, r8, r2
	eor	r10, ip
	and	ip, r1, r2
	eor	r10, ip
	ror	ip, r8, #2
	eor	ip, ip, r8, ror #13
	eor	ip, ip, r8, ror #22
	add	r10, ip
	add	r3, r9
	add	r7, r9, r10
	ldr	r9, [r0, #76]
	ldr	r10, [r0, #64]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #72]
	ldr	r10, [r0, #44]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #72]
	movw	ip, #10184
	movt	ip, #45059
	add	r9, r6, r9
	add	r9, ip
	ror	r10, r3, #6
	eor	r10, r10, r3, ror #11
	eor	r10, r10, r3, ror #25
	add	r9, r10
	and	r10, r3, r4
	bic	ip, r5, r3
	eor	r10, ip
	add	r9, r10
	and	r10, r7, r8
	and	ip, r7, r1
	eor	r10, ip
	and	ip, r8, r1
	eor	r10, ip
	ror	ip, r7, #2
	eor	ip, ip, r7, ror #13
	eor	ip, ip, r7, ror #22
	add	r10, ip
	add	r2, r9
	add	r6, r9, r10
	ldr	r9, [r0, #80]
	ldr	r10, [r0, #68]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #76]
	ldr	r10, [r0, #48]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #76]
	movw	ip, #32711
	movt	ip, #48985
	add	r9, r5, r9
	add	r9, ip
	ror	r10, r2, #6
	eor	r10, r10, r2, ror #11
	eor	r10, r10, r2, ror #25
	add	r9, r10
	and	r10, r2, r3
	bic	ip, r4, r2
	eor	r10, ip
	add	r9, r10
	and	r10, r6, r7
	and	ip, r6, r8
	eor	r10, ip
	and	ip, r7, r8
	eor	r10, ip
	ror	ip, r6, #2
	eor	ip, ip, r6, ror #13
	eor	ip, ip, r6, ror #22
	add	r10, ip
	add	r1, r9
	add	r5, r9, r10
	ldr	r9, [r0, #84]
	ldr	r10, [r0, #72]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #80]
	ldr	r10, [r0, #52]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #80]
	movw	ip, #3059
	movt	ip, #50912
	add	r9, r4, r9
	add	r9, ip
	ror	r10, r1, #6
	eor	r10, r10, r1, ror #11
	eor	r10, r10, r1, ror #25
	add	r9, r10
	and	r10, r1, r2
	bic	ip, r3, r1
	eor	r10, ip
	add	r9, r10
	and	r10, r5, r6
	and	ip, r5, r7
	eor	r10, ip
	and	ip, r6, r7
	eor	r10, ip
	ror	ip, r5, #2
	eor	ip, ip, r5, ror #13
	eor	ip, ip, r5, ror #22
	add	r10, ip
	add	r8, r9
	add	r4, r9, r10
	ldr	r9, [r0, #88]
	ldr	r10, [r0, #76]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #84]
	ldr	r10, [r0, #56]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #84]
	movw	ip, #37191
	movt	ip, #54695
	add	r9, r3, r9
	add	r9, ip
	ror	r10, r8, #6
	eor	r10, r10, r8, ror #11
	eor	r10, r10, r8, ror #25
	add	r9, r10
	and	r10, r8, r1
	bic	ip, r2, r8
	eor	r10, ip
	add	r9, r10
	and	r10, r4, r5
	and	ip, r4, r6
	eor	r10, ip
	and	ip, r5, r6
	eor	r10, ip
	ror	ip, r4, #2
	eor	ip, ip, r4, ror #13
	eor	ip, ip, r4, ror #22
	add	r10, ip
	add	r7, r9
	add	r3, r9, r10
	ldr	r9, [r0, #92]
	ldr	r10, [r0, #80]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #88]
	ldr	r10, [r0, #60]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #88]
	movw	ip, #25425
	movt	ip, #1738
	add	r9, r2, r9
	add	r9, ip
	ror	r10, r7, #6
	eor	r10, r10, r7, ror #11
	eor	r10, r10, r7, ror #25
	add	r9, r10
	and	r10, r7, r8
	bic	ip, r1, r7
	eor	r10, ip
	add	r9, r10
	and	r10, r3, r4
	and	ip, r3, r5
	eor	r10, ip
	and	ip, r4, r5
	eor	r10, ip
	ror	ip, r3, #2
	eor	ip, ip, r3, ror #13
	eor	ip, ip, r3, ror #22
	add	r10, ip
	add	r6, r9
	add	r2, r9, r10
	ldr	r9, [r0, #32]
	ldr	r10, [r0, #84]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #92]
	ldr	r10, [r0, #64]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #92]
	movw	ip, #10599
	movt	ip, #5161
	add	r9, r1, r9
	add	r9, ip
	ror	r10, r6, #6
	eor	r10, r10, r6, ror #11
	eor	r10, r10, r6, ror #25
	add	r9, r10
	and	r10, r6, r7
	bic	ip, r8, r6
	eor	r10, ip
	add	r9, r10
	and	r10, r2, r3
	and	ip, r2, r4
	eor	r10, ip
	and	ip, r3, r4
	eor	r10, ip
	ror	ip, r2, #2
	eor	ip, ip, r2, ror #13
	eor	ip, ip, r2, ror #22
	add	r10, ip
	add	r5, r9
	add	r1, r9, r10
	ldr	r9, [r0, #36]
	ldr	r10, [r0, #88]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #32]
	ldr	r10, [r0, #68]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #32]
	movw	ip, #2693
	movt	ip, #10167
	add	r9, r8, r9
	add	r9, ip
	ror	r10, r5, #6
	eor	r10, r10, r5, ror #11
	eor	r10, r10, r5, ror #25
	add	r9, r10
	and	r10, r5, r6
	bic	ip, r7, r5
	eor	r10, ip
	add	r9, r10
	and	r10, r1, r2
	and	ip, r1, r3
	eor	r10, ip
	and	ip, r2, r3
	eor	r10, ip
	ror	ip, r1, #2
	eor	ip, ip, r1, ror #13
	eor	ip, ip, r1, ror #22
	add	r10, ip
	add	r4, r9
	add	r8, r9, r10
	ldr	r9, [r0, #40]
	ldr	r10, [r0, #92]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #36]
	ldr	r10, [r0, #72]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #36]
	movw	ip, #8504
	movt	ip, #11803
	add	r9, r7, r9
	add	r9, ip
	ror	r10, r4, #6
	eor	r10, r10, r4, ror #11
	eor	r10, r10, r4, ror #25
	add	r9, r10
	and	r10, r4, r5
	bic	ip, r6, r4
	eor	r10, ip
	add	r9, r10
	and	r10, r8, r1
	and	ip, r8, r2
	eor	r10, ip
	and	ip, r1, r2
	eor	r10, ip
	ror	ip, r8, #2
	eor	ip, ip, r8, ror #13
	eor	ip, ip, r8, ror #22
	add	r10, ip
	add	r3, r9
	add	r7, r9, r10
	ldr	r9, [r0, #44]
	ldr	r10, [r0, #32]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #40]
	ldr	r10, [r0, #76]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #40]
	movw	ip, #28156
	movt	ip, #19756
	add	r9, r6, r9
	add	r9, ip
	ror	r10, r3, #6
	eor	r10, r10, r3, ror #11
	eor	r10, r10, r3, ror #25
	add	r9, r10
	and	r10, r3, r4
	bic	ip, r5, r3
	eor	r10, ip
	add	r9, r10
	and	r10, r7, r8
	and	ip, r7, r1
	eor	r10, ip
	and	ip, r8, r1
	eor	r10, ip
	ror	ip, r7, #2
	eor	ip, ip, r7, ror #13
	eor	ip, ip, r7, ror #22
	add	r10, ip
	add	r2, r9
	add	r6, r9, r10
	ldr	r9, [r0, #48]
	ldr	r10, [r0, #36]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #44]
	ldr	r10, [r0, #80]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #44]
	movw	ip, #3347
	movt	ip, #21304
	add	r9, r5, r9
	add	r9, ip
	ror	r10, r2, #6
	eor	r10, r10, r2, ror #11
	eor	r10, r10, r2, ror #25
	add	r9, r10
	and	r10, r2, r3
	bic	ip, r4, r2
	eor	r10, ip
	add	r9, r10
	and	r10, r6, r7
	and	ip, r6, r8
	eor	r10, ip
	and	ip, r7, r8
	eor	r10, ip
	ror	ip, r6, #2
	eor	ip, ip, r6, ror #13
	eor	ip, ip, r6, ror #22
	add	r10, ip
	add	r1, r9
	add	r5, r9, r10
	ldr	r9, [r0, #52]
	ldr	r10, [r0, #40]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #48]
	ldr	r10, [r0, #84]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #48]
	movw	ip, #29524
	movt	ip, #25866
	add	r9, r4, r9
	add	r9, ip
	ror	r10, r1, #6
	eor	r10, r10, r1, ror #11
	eor	r10, r10, r1, ror #25
	add	r9, r10
	and	r10, r1, r2
	bic	ip, r3, r1
	eor	r10, ip
	add	r9, r10
	and	r10, r5, r6
	and	ip, r5, r7
	eor	r10, ip
	and	ip, r6, r7
	eor	r10, ip
	ror	ip, r5, #2
	eor	ip, ip, r5, ror #13
	eor	ip, ip, r5, ror #22
	add	r10, ip
	add	r8, r9
	add	r4, r9, r10
	ldr	r9, [r0, #56]
	ldr	r10, [r0, #44]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #52]
	ldr	r10, [r0, #88]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #52]
	movw	ip, #2747
	movt	ip, #30314
	add	r9, r3, r9
	add	r9, ip
	ror	r10, r8, #6
	eor	r10, r10, r8, ror #11
	eor	r10, r10, r8, ror #25
	add	r9, r10
	and	r10, r8, r1
	bic	ip, r2, r8
	eor	r10, ip
	add	r9, r10
	and	r10, r4, r5
	and	ip, r4, r6
	eor	r10, ip
	and	ip, r5, r6
	eor	r10, ip
	ror	ip, r4, #2
	eor	ip, ip, r4, ror #13
	eor	ip, ip, r4, ror #22
	add	r10, ip
	add	r7, r9
	add	r3, r9, r10
	ldr	r9, [r0, #60]
	ldr	r10, [r0, #48]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #56]
	ldr	r10, [r0, #92]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #56]
	movw	ip, #51502
	movt	ip, #33218
	add	r9, r2, r9
	add	r9, ip
	ror	r10, r7, #6
	eor	r10, r10, r7, ror #11
	eor	r10, r10, r7, ror #25
	add	r9, r10
	and	r10, r7, r8
	bic	ip, r1, r7
	eor	r10, ip
	add	r9, r10
	and	r10, r3, r4
	and	ip, r3, r5
	eor	r10, ip
	and	ip, r4, r5
	eor	r10, ip
	ror	ip, r3, #2
	eor	ip, ip, r3, ror #13
	eor	ip, ip, r3, ror #22
	add	r10, ip
	add	r6, r9
	add	r2, r9, r10
	ldr	r9, [r0, #64]
	ldr	r10, [r0, #52]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #60]
	ldr	r10, [r0, #32]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #60]
	movw	ip, #11397
	movt	ip, #37490
	add	r9, r1, r9
	add	r9, ip
	ror	r10, r6, #6
	eor	r10, r10, r6, ror #11
	eor	r10, r10, r6, ror #25
	add	r9, r10
	and	r10, r6, r7
	bic	ip, r8, r6
	eor	r10, ip
	add	r9, r10
	and	r10, r2, r3
	and	ip, r2, r4
	eor	r10, ip
	and	ip, r3, r4
	eor	r10, ip
	ror	ip, r2, #2
	eor	ip, ip, r2, ror #13
	eor	ip, ip, r2, ror #22
	add	r10, ip
	add	r5, r9
	add	r1, r9, r10
	ldr	r9, [r0, #68]
	ldr	r10, [r0, #56]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #64]
	ldr	r10, [r0, #36]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #64]
	movw	ip, #59553
	movt	ip, #41663
	add	r9, r8, r9
	add	r9, ip
	ror	r10, r5, #6
	eor	r10, r10, r5, ror #11
	eor	r10, r10, r5, ror #25
	add	r9, r10
	and	r10, r5, r6
	bic	ip, r7, r5
	eor	r10, ip
	add	r9, r10
	and	r10, r1, r2
	and	ip, r1, r3
	eor	r10, ip
	and	ip, r2, r3
	eor	r10, ip
	ror	ip, r1, #2
	eor	ip, ip, r1, ror #13
	eor	ip, ip, r1, ror #22
	add	r10, ip
	add	r4, r9
	add	r8, r9, r10
	ldr	r9, [r0, #72]
	ldr	r10, [r0, #60]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #68]
	ldr	r10, [r0, #40]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #68]
	movw	ip, #26187
	movt	ip, #43034
	add	r9, r7, r9
	add	r9, ip
	ror	r10, r4, #6
	eor	r10, r10, r4, ror #11
	eor	r10, r10, r4, ror #25
	add	r9, r10
	and	r10, r4, r5
	bic	ip, r6, r4
	eor	r10, ip
	add	r9, r10
	and	r10, r8, r1
	and	ip, r8, r2
	eor	r10, ip
	and	ip, r1, r2
	eor	r10, ip
	ror	ip, r8, #2
	eor	ip, ip, r8, ror #13
	eor	ip, ip, r8, ror #22
	add	r10, ip
	add	r3, r9
	add	r7, r9, r10
	ldr	r9, [r0, #76]
	ldr	r10, [r0, #64]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #72]
	ldr	r10, [r0, #44]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #72]
	movw	ip, #35696
	movt	ip, #49739
	add	r9, r6, r9
	add	r9, ip
	ror	r10, r3, #6
	eor	r10, r10, r3, ror #11
	eor	r10, r10, r3, ror #25
	add	r9, r10
	and	r10, r3, r4
	bic	ip, r5, r3
	eor	r10, ip
	add	r9, r10
	and	r10, r7, r8
	and	ip, r7, r1
	eor	r10, ip
	and	ip, r8, r1
	eor	r10, ip
	ror	ip, r7, #2
	eor	ip, ip, r7, ror #13
	eor	ip, ip, r7, ror #22
	add	r10, ip
	add	r2, r9
	add	r6, r9, r10
	ldr	r9, [r0, #80]
	ldr	r10, [r0, #68]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #76]
	ldr	r10, [r0, #48]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #76]
	movw	ip, #20899
	movt	ip, #51052
	add	r9, r5, r9
	add	r9, ip
	ror	r10, r2, #6
	eor	r10, r10, r2, ror #11
	eor	r10, r10, r2, ror #25
	add	r9, r10
	and	r10, r2, r3
	bic	ip, r4, r2
	eor	r10, ip
	add	r9, r10
	and	r10, r6, r7
	and	ip, r6, r8
	eor	r10, ip
	and	ip, r7, r8
	eor	r10, ip
	ror	ip, r6, #2
	eor	ip, ip, r6, ror #13
	eor	ip, ip, r6, ror #22
	add	r10, ip
	add	r1, r9
	add	r5, r9, r10
	ldr	r9, [r0, #84]
	ldr	r10, [r0, #72]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #80]
	ldr	r10, [r0, #52]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #80]
	movw	ip, #59417
	movt	ip, #53650
	add	r9, r4, r9
	add	r9, ip
	ror	r10, r1, #6
	eor	r10, r10, r1, ror #11
	eor	r10, r10, r1, ror #25
	add	r9, r10
	and	r10, r1, r2
	bic	ip, r3, r1
	eor	r10, ip
	add	r9, r10
	and	r10, r5, r6
	and	ip, r5, r7
	eor	r10, ip
	and	ip, r6, r7
	eor	r10, ip
	ror	ip, r5, #2
	eor	ip, ip, r5, ror #13
	eor	ip, ip, r5, ror #22
	add	r10, ip
	add	r8, r9
	add	r4, r9, r10
	ldr	r9, [r0, #88]
	ldr	r10, [r0, #76]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #84]
	ldr	r10, [r0, #56]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #84]
	movw	ip, #1572
	movt	ip, #54937
	add	r9, r3, r9
	add	r9, ip
	ror	r10, r8, #6
	eor	r10, r10, r8, ror #11
	eor	r10, r10, r8, ror #25
	add	r9, r10
	and	r10, r8, r1
	bic	ip, r2, r8
	eor	r10, ip
	add	r9, r10
	and	r10, r4, r5
	and	ip, r4, r6
	eor	r10, ip
	and	ip, r5, r6
	eor	r10, ip
	ror	ip, r4, #2
	eor	ip, ip, r4, ror #13
	eor	ip, ip, r4, ror #22
	add	r10, ip
	add	r7, r9
	add	r3, r9, r10
	ldr	r9, [r0, #92]
	ldr	r10, [r0, #80]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #88]
	ldr	r10, [r0, #60]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #88]
	movw	ip, #13701
	movt	ip, #62478
	add	r9, r2, r9
	add	r9, ip
	ror	r10, r7, #6
	eor	r10, r10, r7, ror #11
	eor	r10, r10, r7, ror #25
	add	r9, r10
	and	r10, r7, r8
	bic	ip, r1, r7
	eor	r10, ip
	add	r9, r10
	and	r10, r3, r4
	and	ip, r3, r5
	eor	r10, ip
	and	ip, r4, r5
	eor	r10, ip
	ror	ip, r3, #2
	eor	ip, ip, r3, ror #13
	eor	ip, ip, r3, ror #22
	add	r10, ip
	add	r6, r9
	add	r2, r9, r10
	ldr	r9, [r0, #32]
	ldr	r10, [r0, #84]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #92]
	ldr	r10, [r0, #64]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #92]
	movw	ip, #41072
	movt	ip, #4202
	add	r9, r1, r9
	add	r9, ip
	ror	r10, r6, #6
	eor	r10, r10, r6, ror #11
	eor	r10, r10, r6, ror #25
	add	r9, r10
	and	r10, r6, r7
	bic	ip, r8, r6
	eor	r10, ip
	add	r9, r10
	and	r10, r2, r3
	and	ip, r2, r4
	eor	r10, ip
	and	ip, r3, r4
	eor	r10, ip
	ror	ip, r2, #2
	eor	ip, ip, r2, ror #13
	eor	ip, ip, r2, ror #22
	add	r10, ip
	add	r5, r9
	add	r1, r9, r10
	ldr	r9, [r0, #36]
	ldr	r10, [r0, #88]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #32]
	ldr	r10, [r0, #68]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #32]
	movw	ip, #49430
	movt	ip, #6564
	add	r9, r8, r9
	add	r9, ip
	ror	r10, r5, #6
	eor	r10, r10, r5, ror #11
	eor	r10, r10, r5, ror #25
	add	r9, r10
	and	r10, r5, r6
	bic	ip, r7, r5
	eor	r10, ip
	add	r9, r10
	and	r10, r1, r2
	and	ip, r1, r3
	eor	r10, ip
	and	ip, r2, r3
	eor	r10, ip
	ror	ip, r1, #2
	eor	ip, ip, r1, ror #13
	eor	ip, ip, r1, ror #22
	add	r10, ip
	add	r4, r9
	add	r8, r9, r10
	ldr	r9, [r0, #40]
	ldr	r10, [r0, #92]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #36]
	ldr	r10, [r0, #72]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #36]
	movw	ip, #27656
	movt	ip, #7735
	add	r9, r7, r9
	add	r9, ip
	ror	r10, r4, #6
	eor	r10, r10, r4, ror #11
	eor	r10, r10, r4, ror #25
	add	r9, r10
	and	r10, r4, r5
	bic	ip, r6, r4
	eor	r10, ip
	add	r9, r10
	and	r10, r8, r1
	and	ip, r8, r2
	eor	r10, ip
	and	ip, r1, r2
	eor	r10, ip
	ror	ip, r8, #2
	eor	ip, ip, r8, ror #13
	eor	ip, ip, r8, ror #22
	add	r10, ip
	add	r3, r9
	add	r7, r9, r10
	ldr	r9, [r0, #44]
	ldr	r10, [r0, #32]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #40]
	ldr	r10, [r0, #76]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #40]
	movw	ip, #30540
	movt	ip, #10056
	add	r9, r6, r9
	add	r9, ip
	ror	r10, r3, #6
	eor	r10, r10, r3, ror #11
	eor	r10, r10, r3, ror #25
	add	r9, r10
	and	r10, r3, r4
	bic	ip, r5, r3
	eor	r10, ip
	add	r9, r10
	and	r10, r7, r8
	and	ip, r7, r1
	eor	r10, ip
	and	ip, r8, r1
	eor	r10, ip
	ror	ip, r7, #2
	eor	ip, ip, r7, ror #13
	eor	ip, ip, r7, ror #22
	add	r10, ip
	add	r2, r9
	add	r6, r9, r10
	ldr	r9, [r0, #48]
	ldr	r10, [r0, #36]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #44]
	ldr	r10, [r0, #80]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #44]
	movw	ip, #48309
	movt	ip, #13488
	add	r9, r5, r9
	add	r9, ip
	ror	r10, r2, #6
	eor	r10, r10, r2, ror #11
	eor	r10, r10, r2, ror #25
	add	r9, r10
	and	r10, r2, r3
	bic	ip, r4, r2
	eor	r10, ip
	add	r9, r10
	and	r10, r6, r7
	and	ip, r6, r8
	eor	r10, ip
	and	ip, r7, r8
	eor	r10, ip
	ror	ip, r6, #2
	eor	ip, ip, r6, ror #13
	eor	ip, ip, r6, ror #22
	add	r10, ip
	add	r1, r9
	add	r5, r9, r10
	ldr	r9, [r0, #52]
	ldr	r10, [r0, #40]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #48]
	ldr	r10, [r0, #84]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #48]
	movw	ip, #3251
	movt	ip, #14620
	add	r9, r4, r9
	add	r9, ip
	ror	r10, r1, #6
	eor	r10, r10, r1, ror #11
	eor	r10, r10, r1, ror #25
	add	r9, r10
	and	r10, r1, r2
	bic	ip, r3, r1
	eor	r10, ip
	add	r9, r10
	and	r10, r5, r6
	and	ip, r5, r7
	eor	r10, ip
	and	ip, r6, r7
	eor	r10, ip
	ror	ip, r5, #2
	eor	ip, ip, r5, ror #13
	eor	ip, ip, r5, ror #22
	add	r10, ip
	add	r8, r9
	add	r4, r9, r10
	ldr	r9, [r0, #56]
	ldr	r10, [r0, #44]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #52]
	ldr	r10, [r0, #88]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #52]
	movw	ip, #43594
	movt	ip, #20184
	add	r9, r3, r9
	add	r9, ip
	ror	r10, r8, #6
	eor	r10, r10, r8, ror #11
	eor	r10, r10, r8, ror #25
	add	r9, r10
	and	r10, r8, r1
	bic	ip, r2, r8
	eor	r10, ip
	add	r9, r10
	and	r10, r4, r5
	and	ip, r4, r6
	eor	r10, ip
	and	ip, r5, r6
	eor	r10, ip
	ror	ip, r4, #2
	eor	ip, ip, r4, ror #13
	eor	ip, ip, r4, ror #22
	add	r10, ip
	add	r7, r9
	add	r3, r9, r10
	ldr	r9, [r0, #60]
	ldr	r10, [r0, #48]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #56]
	ldr	r10, [r0, #92]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #56]
	movw	ip, #51791
	movt	ip, #23452
	add	r9, r2, r9
	add	r9, ip
	ror	r10, r7, #6
	eor	r10, r10, r7, ror #11
	eor	r10, r10, r7, ror #25
	add	r9, r10
	and	r10, r7, r8
	bic	ip, r1, r7
	eor	r10, ip
	add	r9, r10
	and	r10, r3, r4
	and	ip, r3, r5
	eor	r10, ip
	and	ip, r4, r5
	eor	r10, ip
	ror	ip, r3, #2
	eor	ip, ip, r3, ror #13
	eor	ip, ip, r3, ror #22
	add	r10, ip
	add	r6, r9
	add	r2, r9, r10
	ldr	r9, [r0, #64]
	ldr	r10, [r0, #52]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #60]
	ldr	r10, [r0, #32]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #60]
	movw	ip, #28659
	movt	ip, #26670
	add	r9, r1, r9
	add	r9, ip
	ror	r10, r6, #6
	eor	r10, r10, r6, ror #11
	eor	r10, r10, r6, ror #25
	add	r9, r10
	and	r10, r6, r7
	bic	ip, r8, r6
	eor	r10, ip
	add	r9, r10
	and	r10, r2, r3
	and	ip, r2, r4
	eor	r10, ip
	and	ip, r3, r4
	eor	r10, ip
	ror	ip, r2, #2
	eor	ip, ip, r2, ror #13
	eor	ip, ip, r2, ror #22
	add	r10, ip
	add	r5, r9
	add	r1, r9, r10
	ldr	r9, [r0, #68]
	ldr	r10, [r0, #56]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #64]
	ldr	r10, [r0, #36]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #64]
	movw	ip, #33518
	movt	ip, #29839
	add	r9, r8, r9
	add	r9, ip
	ror	r10, r5, #6
	eor	r10, r10, r5, ror #11
	eor	r10, r10, r5, ror #25
	add	r9, r10
	and	r10, r5, r6
	bic	ip, r7, r5
	eor	r10, ip
	add	r9, r10
	and	r10, r1, r2
	and	ip, r1, r3
	eor	r10, ip
	and	ip, r2, r3
	eor	r10, ip
	ror	ip, r1, #2
	eor	ip, ip, r1, ror #13
	eor	ip, ip, r1, ror #22
	add	r10, ip
	add	r4, r9
	add	r8, r9, r10
	ldr	r9, [r0, #72]
	ldr	r10, [r0, #60]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #68]
	ldr	r10, [r0, #40]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #68]
	movw	ip, #25455
	movt	ip, #30885
	add	r9, r7, r9
	add	r9, ip
	ror	r10, r4, #6
	eor	r10, r10, r4, ror #11
	eor	r10, r10, r4, ror #25
	add	r9, r10
	and	r10, r4, r5
	bic	ip, r6, r4
	eor	r10, ip
	add	r9, r10
	and	r10, r8, r1
	and	ip, r8, r2
	eor	r10, ip
	and	ip, r1, r2
	eor	r10, ip
	ror	ip, r8, #2
	eor	ip, ip, r8, ror #13
	eor	ip, ip, r8, ror #22
	add	r10, ip
	add	r3, r9
	add	r7, r9, r10
	ldr	r9, [r0, #76]
	ldr	r10, [r0, #64]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #72]
	ldr	r10, [r0, #44]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #72]
	movw	ip, #30740
	movt	ip, #33992
	add	r9, r6, r9
	add	r9, ip
	ror	r10, r3, #6
	eor	r10, r10, r3, ror #11
	eor	r10, r10, r3, ror #25
	add	r9, r10
	and	r10, r3, r4
	bic	ip, r5, r3
	eor	r10, ip
	add	r9, r10
	and	r10, r7, r8
	and	ip, r7, r1
	eor	r10, ip
	and	ip, r8, r1
	eor	r10, ip
	ror	ip, r7, #2
	eor	ip, ip, r7, ror #13
	eor	ip, ip, r7, ror #22
	add	r10, ip
	add	r2, r9
	add	r6, r9, r10
	ldr	r9, [r0, #80]
	ldr	r10, [r0, #68]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #76]
	ldr	r10, [r0, #48]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #76]
	movw	ip, #520
	movt	ip, #36039
	add	r9, r5, r9
	add	r9, ip
	ror	r10, r2, #6
	eor	r10, r10, r2, ror #11
	eor	r10, r10, r2, ror #25
	add	r9, r10
	and	r10, r2, r3
	bic	ip, r4, r2
	eor	r10, ip
	add	r9, r10
	and	r10, r6, r7
	and	ip, r6, r8
	eor	r10, ip
	and	ip, r7, r8
	eor	r10, ip
	ror	ip, r6, #2
	eor	ip, ip, r6, ror #13
	eor	ip, ip, r6, ror #22
	add	r10, ip
	add	r1, r9
	add	r5, r9, r10
	ldr	r9, [r0, #84]
	ldr	r10, [r0, #72]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #80]
	ldr	r10, [r0, #52]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #80]
	movw	ip, #65530
	movt	ip, #37054
	add	r9, r4, r9
	add	r9, ip
	ror	r10, r1, #6
	eor	r10, r10, r1, ror #11
	eor	r10, r10, r1, ror #25
	add	r9, r10
	and	r10, r1, r2
	bic	ip, r3, r1
	eor	r10, ip
	add	r9, r10
	and	r10, r5, r6
	and	ip, r5, r7
	eor	r10, ip
	and	ip, r6, r7
	eor	r10, ip
	ror	ip, r5, #2
	eor	ip, ip, r5, ror #13
	eor	ip, ip, r5, ror #22
	add	r10, ip
	add	r8, r9
	add	r4, r9, r10
	ldr	r9, [r0, #88]
	ldr	r10, [r0, #76]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #84]
	ldr	r10, [r0, #56]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #84]
	movw	ip, #27883
	movt	ip, #42064
	add	r9, r3, r9
	add	r9, ip
	ror	r10, r8, #6
	eor	r10, r10, r8, ror #11
	eor	r10, r10, r8, ror #25
	add	r9, r10
	and	r10, r8, r1
	bic	ip, r2, r8
	eor	r10, ip
	add	r9, r10
	and	r10, r4, r5
	and	ip, r4, r6
	eor	r10, ip
	and	ip, r5, r6
	eor	r10, ip
	ror	ip, r4, #2
	eor	ip, ip, r4, ror #13
	eor	ip, ip, r4, ror #22
	add	r10, ip
	add	r7, r9
	add	r3, r9, r10
	ldr	r9, [r0, #92]
	ldr	r10, [r0, #80]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #88]
	ldr	r10, [r0, #60]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #88]
	movw	ip, #41975
	movt	ip, #48889
	add	r9, r2, r9
	add	r9, ip
	ror	r10, r7, #6
	eor	r10, r10, r7, ror #11
	eor	r10, r10, r7, ror #25
	add	r9, r10
	and	r10, r7, r8
	bic	ip, r1, r7
	eor	r10, ip
	add	r9, r10
	and	r10, r3, r4
	and	ip, r3, r5
	eor	r10, ip
	and	ip, r4, r5
	eor	r10, ip
	ror	ip, r3, #2
	eor	ip, ip, r3, ror #13
	eor	ip, ip, r3, ror #22
	add	r10, ip
	add	r6, r9
	add	r2, r9, r10
	ldr	r9, [r0, #32]
	ldr	r10, [r0, #84]
	lsr	ip, r9, #3
	eor	ip, ip, r9, ror #7
	eor	r9, ip, r9, ror #18
	lsr	ip, r10, #10
	eor	ip, ip, r10, ror #17
	eor	r10, ip, r10, ror #19
	add	r9, r10
	ldr	ip, [r0, #92]
	ldr	r10, [r0, #64]
	add	r9, ip
	add	r9, r10
	str	r9, [r0, #92]
	movw	ip, #30962
	movt	ip, #50801
	add	r9, r1, r9
	add	r9, ip
	ror	r10, r6, #6
	eor	r10, r10, r6, ror #11
	eor	r10, r10, r6, ror #25
	add	r9, r10
	and	r10, r6, r7
	bic	ip, r8, r6
	eor	r10, ip
	add	r9, r10
	and	r10, r2, r3
	and	ip, r2, r4
	eor	r10, ip
	and	ip, r3, r4
	eor	r10, ip
	ror	ip, r2, #2
	eor	ip, ip, r2, ror #13
	eor	ip, ip, r2, ror #22
	add	r10, ip
	add	r5, r9
	add	r1, r9, r10
	ldr	r9, [r0, #0]
	ldr	r10, [r0, #4]
	add	r1, r9
	add	r2, r10
	str	r1, [r0, #0]
	str	r2, [r0, #4]
	ldr	r9, [r0, #8]
	ldr	r10, [r0, #12]
	add	r3, r9
	add	r4, r10
	str	r3, [r0, #8]
	str	r4, [r0, #12]
	ldr	r9, [r0, #16]
	ldr	r10, [r0, #20]
	add	r5, r9
	add	r6, r10
	str	r5, [r0, #16]
	str	r6, [r0, #20]
	ldr	r9, [r0, #24]
	ldr	r10, [r0, #28]
	add	r7, r9
	add	r8, r10
	str	r7, [r0, #24]
	str	r8, [r0, #28]
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	sha256_transform, .-sha256_transform

#endif
