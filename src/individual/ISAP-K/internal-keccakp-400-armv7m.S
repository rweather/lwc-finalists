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
	.type	rconst, %object
rconst:
	.byte	0x01
	.byte	0x00
	.byte	0x82
	.byte	0x80
	.byte	0x8a
	.byte	0x80
	.byte	0x00
	.byte	0x80
	.byte	0x8b
	.byte	0x80
	.byte	0x01
	.byte	0x00
	.byte	0x81
	.byte	0x80
	.byte	0x09
	.byte	0x80
	.byte	0x8a
	.byte	0x00
	.byte	0x88
	.byte	0x00
	.byte	0x09
	.byte	0x80
	.byte	0x0a
	.byte	0x00
	.byte	0x8b
	.byte	0x80
	.byte	0x8b
	.byte	0x00
	.byte	0x89
	.byte	0x80
	.byte	0x03
	.byte	0x80
	.byte	0x02
	.byte	0x80
	.byte	0x80
	.byte	0x00
	.byte	0x0a
	.byte	0x80
	.byte	0x0a
	.byte	0x00
	.size	rconst, .-rconst

	.align	2
	.global	keccakp_400_permute
	.thumb
	.thumb_func
	.type	keccakp_400_permute, %function
keccakp_400_permute:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldrh	r7, [r0, #0]
	ldrh	r8, [r0, #2]
	ldrh	r9, [r0, #4]
	ldrh	r10, [r0, #6]
	ldrh	fp, [r0, #8]
	mov	lr, #40
	sub	lr, lr, r1, lsl #1
.L1:
	ldrh	r1, [r0, #10]
	eors	r1, r7
	ldrh	r6, [r0, #20]
	eors	r1, r6
	ldrh	r6, [r0, #30]
	eors	r1, r6
	ldrh	r6, [r0, #40]
	eors	r1, r6
	ldrh	r2, [r0, #12]
	eor	r2, r8
	ldrh	r6, [r0, #22]
	eors	r2, r6
	ldrh	r6, [r0, #32]
	eors	r2, r6
	ldrh	r6, [r0, #42]
	eors	r2, r6
	ldrh	r3, [r0, #14]
	eor	r3, r9
	ldrh	r6, [r0, #24]
	eors	r3, r6
	ldrh	r6, [r0, #34]
	eors	r3, r6
	ldrh	r6, [r0, #44]
	eors	r3, r6
	ldrh	r4, [r0, #16]
	eor	r4, r10
	ldrh	r6, [r0, #26]
	eors	r4, r6
	ldrh	r6, [r0, #36]
	eors	r4, r6
	ldrh	r6, [r0, #46]
	eors	r4, r6
	ldrh	ip, [r0, #18]
	eor	ip, fp
	ldrh	r6, [r0, #28]
	eor	ip, r6
	ldrh	r6, [r0, #38]
	eor	ip, r6
	ldrh	r6, [r0, #48]
	eor	ip, r6
	lsl	r5, r1, #1
	orr	r5, r5, r1, lsr #15
	eors	r5, r4
	uxth	r5, r5
	eor	fp, r5
	eors	r6, r5
	strh	r6, [r0, #48]
	ldrh	r6, [r0, #38]
	eors	r6, r5
	strh	r6, [r0, #38]
	ldrh	r6, [r0, #28]
	eors	r6, r5
	strh	r6, [r0, #28]
	ldrh	r6, [r0, #18]
	eors	r6, r5
	strh	r6, [r0, #18]
	lsl	r5, ip, #1
	orr	r5, r5, ip, lsr #15
	eors	r5, r3
	uxth	r5, r5
	eor	r10, r5
	ldrh	r6, [r0, #46]
	eors	r6, r5
	strh	r6, [r0, #46]
	ldrh	r6, [r0, #36]
	eors	r6, r5
	strh	r6, [r0, #36]
	ldrh	r6, [r0, #26]
	eors	r6, r5
	strh	r6, [r0, #26]
	ldrh	r6, [r0, #16]
	eors	r6, r5
	strh	r6, [r0, #16]
	lsl	r5, r4, #1
	orr	r5, r5, r4, lsr #15
	eors	r5, r2
	uxth	r5, r5
	eor	r9, r5
	ldrh	r6, [r0, #44]
	eors	r6, r5
	strh	r6, [r0, #44]
	ldrh	r6, [r0, #34]
	eors	r6, r5
	strh	r6, [r0, #34]
	ldrh	r6, [r0, #24]
	eors	r6, r5
	strh	r6, [r0, #24]
	ldrh	r6, [r0, #14]
	eors	r6, r5
	strh	r6, [r0, #14]
	lsl	r5, r3, #1
	orr	r5, r5, r3, lsr #15
	eors	r5, r1
	uxth	r5, r5
	eor	r8, r5
	ldrh	r6, [r0, #42]
	eors	r6, r5
	strh	r6, [r0, #42]
	ldrh	r6, [r0, #32]
	eors	r6, r5
	strh	r6, [r0, #32]
	ldrh	r6, [r0, #22]
	eors	r6, r5
	strh	r6, [r0, #22]
	ldrh	r6, [r0, #12]
	eors	r6, r5
	strh	r6, [r0, #12]
	lsl	r5, r2, #1
	orr	r5, r5, r2, lsr #15
	eor	r5, ip
	uxth	r5, r5
	eors	r7, r5
	ldrh	r6, [r0, #40]
	eors	r6, r5
	strh	r6, [r0, #40]
	ldrh	r6, [r0, #30]
	eors	r6, r5
	strh	r6, [r0, #30]
	ldrh	r6, [r0, #20]
	eors	r6, r5
	strh	r6, [r0, #20]
	ldrh	r6, [r0, #10]
	eors	r6, r5
	strh	r6, [r0, #10]
	lsl	r1, r8, #1
	orr	r1, r1, r8, lsr #15
	ldrh	r2, [r0, #12]
	lsl	r2, r2, #12
	orr	r8, r2, r2, lsr #16
	ldrh	r2, [r0, #18]
	lsl	r2, r2, #4
	orr	r3, r2, r2, lsr #16
	strh	r3, [r0, #12]
	ldrh	r2, [r0, #44]
	lsl	r2, r2, #13
	orr	r3, r2, r2, lsr #16
	strh	r3, [r0, #18]
	ldrh	r2, [r0, #28]
	lsl	r2, r2, #7
	orr	r3, r2, r2, lsr #16
	strh	r3, [r0, #44]
	ldrh	r2, [r0, #40]
	lsl	r2, r2, #2
	orr	r3, r2, r2, lsr #16
	strh	r3, [r0, #28]
	lsl	r9, r9, #14
	orr	r3, r9, r9, lsr #16
	strh	r3, [r0, #40]
	ldrh	r2, [r0, #24]
	lsl	r2, r2, #11
	orr	r9, r2, r2, lsr #16
	ldrh	r2, [r0, #26]
	lsl	r2, r2, #9
	orr	r3, r2, r2, lsr #16
	strh	r3, [r0, #24]
	ldrh	r2, [r0, #38]
	rev16	r3, r2
	strh	r3, [r0, #26]
	ldrh	r2, [r0, #46]
	rev16	r3, r2
	strh	r3, [r0, #38]
	ldrh	r2, [r0, #30]
	lsl	r2, r2, #9
	orr	r3, r2, r2, lsr #16
	strh	r3, [r0, #46]
	lsl	fp, fp, #11
	orr	r3, fp, fp, lsr #16
	strh	r3, [r0, #30]
	ldrh	r2, [r0, #48]
	lsl	r2, r2, #14
	orr	fp, r2, r2, lsr #16
	ldrh	r2, [r0, #42]
	lsl	r2, r2, #2
	orr	r3, r2, r2, lsr #16
	strh	r3, [r0, #48]
	ldrh	r2, [r0, #16]
	lsl	r2, r2, #7
	orr	r3, r2, r2, lsr #16
	strh	r3, [r0, #42]
	ldrh	r2, [r0, #32]
	lsl	r2, r2, #13
	orr	r3, r2, r2, lsr #16
	strh	r3, [r0, #16]
	ldrh	r2, [r0, #10]
	lsl	r2, r2, #4
	orr	r3, r2, r2, lsr #16
	strh	r3, [r0, #32]
	lsl	r10, r10, #12
	orr	r3, r10, r10, lsr #16
	strh	r3, [r0, #10]
	ldrh	r2, [r0, #36]
	lsl	r2, r2, #5
	orr	r10, r2, r2, lsr #16
	ldrh	r2, [r0, #34]
	lsl	r2, r2, #15
	orr	r3, r2, r2, lsr #16
	strh	r3, [r0, #36]
	ldrh	r2, [r0, #22]
	lsl	r2, r2, #10
	orr	r3, r2, r2, lsr #16
	strh	r3, [r0, #34]
	ldrh	r2, [r0, #14]
	lsl	r2, r2, #6
	orr	r3, r2, r2, lsr #16
	strh	r3, [r0, #22]
	ldrh	r2, [r0, #20]
	lsl	r2, r2, #3
	orr	r3, r2, r2, lsr #16
	strh	r3, [r0, #14]
	strh	r1, [r0, #20]
	ldrh	r1, [r0, #40]
	ldrh	r2, [r0, #42]
	ldrh	r3, [r0, #44]
	ldrh	r4, [r0, #46]
	ldrh	ip, [r0, #48]
	bic	r6, r3, r2
	eors	r6, r1
	strh	r6, [r0, #40]
	bic	r6, r4, r3
	eors	r6, r2
	strh	r6, [r0, #42]
	bic	r6, ip, r4
	eors	r6, r3
	strh	r6, [r0, #44]
	bic	r6, r1, ip
	eors	r6, r4
	strh	r6, [r0, #46]
	bic	r6, r2, r1
	eor	r6, ip
	strh	r6, [r0, #48]
	ldrh	r1, [r0, #30]
	ldrh	r2, [r0, #32]
	ldrh	r3, [r0, #34]
	ldrh	r4, [r0, #36]
	ldrh	ip, [r0, #38]
	bic	r6, r3, r2
	eors	r6, r1
	strh	r6, [r0, #30]
	bic	r6, r4, r3
	eors	r6, r2
	strh	r6, [r0, #32]
	bic	r6, ip, r4
	eors	r6, r3
	strh	r6, [r0, #34]
	bic	r6, r1, ip
	eors	r6, r4
	strh	r6, [r0, #36]
	bic	r6, r2, r1
	eor	r6, ip
	strh	r6, [r0, #38]
	ldrh	r1, [r0, #20]
	ldrh	r2, [r0, #22]
	ldrh	r3, [r0, #24]
	ldrh	r4, [r0, #26]
	ldrh	ip, [r0, #28]
	bic	r6, r3, r2
	eors	r6, r1
	strh	r6, [r0, #20]
	bic	r6, r4, r3
	eors	r6, r2
	strh	r6, [r0, #22]
	bic	r6, ip, r4
	eors	r6, r3
	strh	r6, [r0, #24]
	bic	r6, r1, ip
	eors	r6, r4
	strh	r6, [r0, #26]
	bic	r6, r2, r1
	eor	r6, ip
	strh	r6, [r0, #28]
	ldrh	r1, [r0, #10]
	ldrh	r2, [r0, #12]
	ldrh	r3, [r0, #14]
	ldrh	r4, [r0, #16]
	ldrh	ip, [r0, #18]
	bic	r6, r3, r2
	eors	r6, r1
	strh	r6, [r0, #10]
	bic	r6, r4, r3
	eors	r6, r2
	strh	r6, [r0, #12]
	bic	r6, ip, r4
	eors	r6, r3
	strh	r6, [r0, #14]
	bic	r6, r1, ip
	eors	r6, r4
	strh	r6, [r0, #16]
	bic	r6, r2, r1
	eor	r6, ip
	strh	r6, [r0, #18]
	bic	r1, r9, r8
	bic	r2, r10, r9
	bic	r3, fp, r10
	bic	r4, r7, fp
	bic	ip, r8, r7
	eors	r1, r7
	eor	r2, r8
	eor	r3, r9
	eor	r4, r10
	eor	ip, fp
	adr	r5, rconst
	uxth	r8, r2
	ldrh	r6, [r5, lr]
	uxth	r9, r3
	eor	r7, r1, r6
	uxth	r10, r4
	uxth	r7, r7
	uxth	fp, ip
	add	lr, #2
	cmp	lr, #40
	bne	.L1
	strh	r7, [r0, #0]
	strh	r8, [r0, #2]
	strh	r9, [r0, #4]
	strh	r10, [r0, #6]
	strh	fp, [r0, #8]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	keccakp_400_permute, .-keccakp_400_permute

#endif
