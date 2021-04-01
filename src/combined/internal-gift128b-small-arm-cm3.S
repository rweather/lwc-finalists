#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
#include "internal-gift128-config.h"
#if GIFT128_VARIANT_ASM && GIFT128_VARIANT == GIFT128_VARIANT_SMALL
	.syntax unified
	.thumb
	.text

	.align	2
	.global	gift128b_init
	.thumb
	.thumb_func
	.type	gift128b_init, %function
gift128b_init:
	push	{r4, r5, r6, r7, r8, r9}
	ldr	r2, [r1, #0]
	ldr	r3, [r1, #4]
	ldr	r4, [r1, #8]
	ldr	r5, [r1, #12]
	rev	r2, r2
	rev	r3, r3
	rev	r4, r4
	rev	r5, r5
	str	r2, [r0, #12]
	str	r3, [r0, #4]
	str	r4, [r0, #8]
	str	r5, [r0, #0]
	str	r3, [r0, #16]
	lsr	r6, r5, #18
	lsl	r6, r6, #18
	and	r7, r5, #196608
	lsl	r8, r5, #4
	lsr	r6, r6, #2
	orr	r6, r6, r7, lsl #14
	uxth	r8, r8
	orr	r6, r6, r8
	ubfx	r5, r5, #12, #4
	orrs	r5, r5, r6
	str	r5, [r0, #20]
	str	r2, [r0, #24]
	lsr	r6, r4, #18
	lsl	r6, r6, #18
	and	r7, r4, #196608
	lsl	r8, r4, #4
	lsr	r6, r6, #2
	orr	r6, r6, r7, lsl #14
	uxth	r8, r8
	orr	r6, r6, r8
	ubfx	r4, r4, #12, #4
	orrs	r4, r4, r6
	str	r4, [r0, #28]
	str	r5, [r0, #32]
	lsr	r6, r3, #18
	lsl	r6, r6, #18
	and	r7, r3, #196608
	lsl	r8, r3, #4
	lsr	r6, r6, #2
	orr	r6, r6, r7, lsl #14
	uxth	r8, r8
	orr	r6, r6, r8
	ubfx	r3, r3, #12, #4
	orrs	r3, r3, r6
	str	r3, [r0, #36]
	str	r4, [r0, #40]
	lsr	r6, r2, #18
	lsl	r6, r6, #18
	and	r7, r2, #196608
	lsl	r8, r2, #4
	lsr	r6, r6, #2
	orr	r6, r6, r7, lsl #14
	uxth	r8, r8
	orr	r6, r6, r8
	ubfx	r2, r2, #12, #4
	orrs	r2, r2, r6
	str	r2, [r0, #44]
	str	r3, [r0, #48]
	lsr	r6, r5, #18
	lsl	r6, r6, #18
	and	r7, r5, #196608
	lsl	r8, r5, #4
	lsr	r6, r6, #2
	orr	r6, r6, r7, lsl #14
	uxth	r8, r8
	orr	r6, r6, r8
	ubfx	r5, r5, #12, #4
	orrs	r5, r5, r6
	str	r5, [r0, #52]
	str	r2, [r0, #56]
	lsr	r6, r4, #18
	lsl	r6, r6, #18
	and	r7, r4, #196608
	lsl	r8, r4, #4
	lsr	r6, r6, #2
	orr	r6, r6, r7, lsl #14
	uxth	r8, r8
	orr	r6, r6, r8
	ubfx	r4, r4, #12, #4
	orrs	r4, r4, r6
	str	r4, [r0, #60]
	str	r5, [r0, #64]
	lsr	r6, r3, #18
	lsl	r6, r6, #18
	and	r7, r3, #196608
	lsl	r8, r3, #4
	lsr	r6, r6, #2
	orr	r6, r6, r7, lsl #14
	uxth	r8, r8
	orr	r6, r6, r8
	ubfx	r3, r3, #12, #4
	orrs	r3, r3, r6
	str	r3, [r0, #68]
	str	r4, [r0, #72]
	lsr	r6, r2, #18
	lsl	r6, r6, #18
	and	r7, r2, #196608
	lsl	r8, r2, #4
	lsr	r6, r6, #2
	orr	r6, r6, r7, lsl #14
	uxth	r8, r8
	orr	r6, r6, r8
	ubfx	r2, r2, #12, #4
	orrs	r2, r2, r6
	str	r2, [r0, #76]
	ldr	r2, [r0, #0]
	ldr	r3, [r0, #4]
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
	eor	r6, r2, r2, lsr #9
	eor	r7, r3, r3, lsr #9
	eor	r8, r4, r4, lsr #9
	eor	ip, r5, r5, lsr #9
	and	r6, r6, #5570645
	and	r7, r7, #5570645
	and	r8, r8, #5570645
	and	ip, ip, #5570645
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #9
	eor	r3, r3, r7, lsl #9
	eor	r4, r4, r8, lsl #9
	eor	r5, r5, ip, lsl #9
	eor	r6, r2, r2, lsr #12
	eor	r7, r3, r3, lsr #12
	eor	r8, r4, r4, lsr #12
	eor	ip, r5, r5, lsr #12
	and	r6, r6, #983055
	and	r7, r7, #983055
	and	r8, r8, #983055
	and	ip, ip, #983055
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #12
	eor	r3, r3, r7, lsl #12
	eor	r4, r4, r8, lsl #12
	eor	r5, r5, ip, lsl #12
	movw	r9, #13107
	eor	r6, r2, r2, lsr #18
	eor	r7, r3, r3, lsr #18
	eor	r8, r4, r4, lsr #18
	eor	ip, r5, r5, lsr #18
	and	r6, r6, r9
	and	r7, r7, r9
	and	r8, r8, r9
	and	ip, ip, r9
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #18
	eor	r3, r3, r7, lsl #18
	eor	r4, r4, r8, lsl #18
	eor	r5, r5, ip, lsl #18
	eor	r6, r2, r2, lsr #24
	eor	r7, r3, r3, lsr #24
	eor	r8, r4, r4, lsr #24
	eor	ip, r5, r5, lsr #24
	and	r6, r6, #255
	and	r7, r7, #255
	and	r8, r8, #255
	and	ip, ip, #255
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #24
	eor	r3, r3, r7, lsl #24
	eor	r4, r4, r8, lsl #24
	eor	r5, r5, ip, lsl #24
	str	r2, [r0, #0]
	str	r3, [r0, #4]
	str	r4, [r0, #40]
	str	r5, [r0, #44]
	ldr	r2, [r0, #8]
	ldr	r3, [r0, #12]
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
	eor	r6, r2, r2, lsr #3
	eor	r7, r3, r3, lsr #3
	eor	r8, r4, r4, lsr #3
	eor	ip, r5, r5, lsr #3
	and	r6, r6, #286331153
	and	r7, r7, #286331153
	and	r8, r8, #286331153
	and	ip, ip, #286331153
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #3
	eor	r3, r3, r7, lsl #3
	eor	r4, r4, r8, lsl #3
	eor	r5, r5, ip, lsl #3
	eor	r6, r2, r2, lsr #6
	eor	r7, r3, r3, lsr #6
	eor	r8, r4, r4, lsr #6
	eor	ip, r5, r5, lsr #6
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #50529027
	and	ip, ip, #50529027
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #6
	eor	r3, r3, r7, lsl #6
	eor	r4, r4, r8, lsl #6
	eor	r5, r5, ip, lsl #6
	eor	r6, r2, r2, lsr #12
	eor	r7, r3, r3, lsr #12
	eor	r8, r4, r4, lsr #12
	eor	ip, r5, r5, lsr #12
	and	r6, r6, #983055
	and	r7, r7, #983055
	and	r8, r8, #983055
	and	ip, ip, #983055
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #12
	eor	r3, r3, r7, lsl #12
	eor	r4, r4, r8, lsl #12
	eor	r5, r5, ip, lsl #12
	eor	r6, r2, r2, lsr #24
	eor	r7, r3, r3, lsr #24
	eor	r8, r4, r4, lsr #24
	eor	ip, r5, r5, lsr #24
	and	r6, r6, #255
	and	r7, r7, #255
	and	r8, r8, #255
	and	ip, ip, #255
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #24
	eor	r3, r3, r7, lsl #24
	eor	r4, r4, r8, lsl #24
	eor	r5, r5, ip, lsl #24
	str	r2, [r0, #8]
	str	r3, [r0, #12]
	str	r4, [r0, #48]
	str	r5, [r0, #52]
	ldr	r2, [r0, #16]
	ldr	r3, [r0, #20]
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
	movw	r9, #43690
	eor	r6, r2, r2, lsr #15
	eor	r7, r3, r3, lsr #15
	eor	r8, r4, r4, lsr #15
	eor	ip, r5, r5, lsr #15
	and	r6, r6, r9
	and	r7, r7, r9
	and	r8, r8, r9
	and	ip, ip, r9
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #15
	eor	r3, r3, r7, lsl #15
	eor	r4, r4, r8, lsl #15
	eor	r5, r5, ip, lsl #15
	movw	r9, #13107
	eor	r6, r2, r2, lsr #18
	eor	r7, r3, r3, lsr #18
	eor	r8, r4, r4, lsr #18
	eor	ip, r5, r5, lsr #18
	and	r6, r6, r9
	and	r7, r7, r9
	and	r8, r8, r9
	and	ip, ip, r9
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #18
	eor	r3, r3, r7, lsl #18
	eor	r4, r4, r8, lsl #18
	eor	r5, r5, ip, lsl #18
	movw	r9, #61680
	eor	r6, r2, r2, lsr #12
	eor	r7, r3, r3, lsr #12
	eor	r8, r4, r4, lsr #12
	eor	ip, r5, r5, lsr #12
	and	r6, r6, r9
	and	r7, r7, r9
	and	r8, r8, r9
	and	ip, ip, r9
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #12
	eor	r3, r3, r7, lsl #12
	eor	r4, r4, r8, lsl #12
	eor	r5, r5, ip, lsl #12
	eor	r6, r2, r2, lsr #24
	eor	r7, r3, r3, lsr #24
	eor	r8, r4, r4, lsr #24
	eor	ip, r5, r5, lsr #24
	and	r6, r6, #255
	and	r7, r7, #255
	and	r8, r8, #255
	and	ip, ip, #255
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #24
	eor	r3, r3, r7, lsl #24
	eor	r4, r4, r8, lsl #24
	eor	r5, r5, ip, lsl #24
	str	r2, [r0, #16]
	str	r3, [r0, #20]
	str	r4, [r0, #56]
	str	r5, [r0, #60]
	ldr	r2, [r0, #24]
	ldr	r3, [r0, #28]
	ldr	r4, [r0, #64]
	ldr	r5, [r0, #68]
	eor	r6, r2, r2, lsr #3
	eor	r7, r3, r3, lsr #3
	eor	r8, r4, r4, lsr #3
	eor	ip, r5, r5, lsr #3
	and	r6, r6, #168430090
	and	r7, r7, #168430090
	and	r8, r8, #168430090
	and	ip, ip, #168430090
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #3
	eor	r3, r3, r7, lsl #3
	eor	r4, r4, r8, lsl #3
	eor	r5, r5, ip, lsl #3
	eor	r6, r2, r2, lsr #6
	eor	r7, r3, r3, lsr #6
	eor	r8, r4, r4, lsr #6
	eor	ip, r5, r5, lsr #6
	and	r6, r6, #13369548
	and	r7, r7, #13369548
	and	r8, r8, #13369548
	and	ip, ip, #13369548
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #6
	eor	r3, r3, r7, lsl #6
	eor	r4, r4, r8, lsl #6
	eor	r5, r5, ip, lsl #6
	movw	r9, #61680
	eor	r6, r2, r2, lsr #12
	eor	r7, r3, r3, lsr #12
	eor	r8, r4, r4, lsr #12
	eor	ip, r5, r5, lsr #12
	and	r6, r6, r9
	and	r7, r7, r9
	and	r8, r8, r9
	and	ip, ip, r9
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #12
	eor	r3, r3, r7, lsl #12
	eor	r4, r4, r8, lsl #12
	eor	r5, r5, ip, lsl #12
	eor	r6, r2, r2, lsr #24
	eor	r7, r3, r3, lsr #24
	eor	r8, r4, r4, lsr #24
	eor	ip, r5, r5, lsr #24
	and	r6, r6, #255
	and	r7, r7, #255
	and	r8, r8, #255
	and	ip, ip, #255
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #24
	eor	r3, r3, r7, lsl #24
	eor	r4, r4, r8, lsl #24
	eor	r5, r5, ip, lsl #24
	str	r2, [r0, #24]
	str	r3, [r0, #28]
	str	r4, [r0, #64]
	str	r5, [r0, #68]
	pop	{r4, r5, r6, r7, r8, r9}
	bx	lr
	.size	gift128b_init, .-gift128b_init

	.align	2
	.global	gift128b_encrypt_preloaded
	.thumb
	.thumb_func
	.type	gift128b_encrypt_preloaded, %function
gift128b_encrypt_preloaded:
	push	{r4, r5, r6, r7, r8, r9, r10, fp}
	mov	fp, sp
	sub	sp, sp, #80
	ldr	r4, [r2, #0]
	ldr	r5, [r2, #4]
	ldr	r6, [r2, #8]
	ldr	r2, [r2, #12]
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r2, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r2, r2, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r2, ip, r2, lsl #3
	ldr	r7, [r0, #0]
	ldr	r8, [r0, #4]
	movw	ip, #8
	movt	ip, #4096
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #8]
	ldr	r8, [r0, #12]
	movw	ip, #32768
	movt	ip, #32769
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r2, r2, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r9
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [r0, #16]
	ldr	r8, [r0, #20]
	movw	ip, #2
	movt	ip, #21504
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r4, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r4, r4, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r4, r7, r4, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [r0, #24]
	ldr	r8, [r0, #28]
	movw	ip, #385
	movt	ip, #257
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r2, r2, #24
	ldr	r7, [r0, #32]
	ldr	r8, [r0, #36]
	movw	ip, #31
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r4, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r4, r4, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r4, ip, r4, lsl #3
	ldr	r7, [r0, #40]
	ldr	r8, [r0, #44]
	movw	ip, #34944
	movt	ip, #4232
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #48]
	ldr	r8, [r0, #52]
	movw	ip, #57344
	movt	ip, #24577
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r4, r4, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r9
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [r0, #56]
	ldr	r8, [r0, #60]
	movw	ip, #2
	movt	ip, #20816
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r2, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r2, r2, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r2, r7, r2, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [r0, #64]
	ldr	r8, [r0, #68]
	movw	ip, #384
	movt	ip, #771
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r4, r4, #24
	ldr	r7, [r0, #72]
	ldr	r8, [r0, #76]
	movw	ip, #47
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	ldr	r3, [r0, #0]
	ldr	r10, [r0, #4]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, r3, #858993459
	and	r8, r3, #3435973836
	ror	r7, r7, #24
	orr	r3, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, r3, r3, lsr #1
	and	r7, r7, r9
	eors	r3, r7
	eor	r3, r3, r7, lsl #1
	str	r10, [fp, #-80]
	str	r3, [fp, #-76]
	ldr	r3, [r0, #8]
	ldr	r10, [r0, #12]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, r3, #6
	and	r7, r7, #50332416
	and	r8, r3, #1056980736
	lsl	r8, r8, #2
	lsr	ip, r3, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, r3, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-72]
	str	r3, [fp, #-68]
	ldr	r3, [r0, #16]
	ldr	r10, [r0, #20]
	and	r7, r10, #2863311530
	and	r9, r3, #2863311530
	and	r8, r10, #1431655765
	and	ip, r3, #1431655765
	ror	r10, r7, #24
	ror	r3, ip, #24
	orr	r10, r10, r8, ror #16
	orr	r3, r3, r9, ror #20
	str	r10, [fp, #-64]
	str	r3, [fp, #-60]
	ldr	r3, [r0, #24]
	ldr	r10, [r0, #28]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, r3, #18
	and	r7, r7, r9
	and	r8, r3, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, r3, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, r3, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, r3, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, r3, r9
	lsl	r8, r8, #19
	orr	r3, r7, ip
	orr	r3, r3, r8
	str	r10, [fp, #-56]
	str	r3, [fp, #-52]
	ldr	r3, [r0, #32]
	ldr	r10, [r0, #36]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, r3, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, r3, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, r3, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, r3, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-48]
	str	r3, [fp, #-44]
	ldr	r3, [r0, #40]
	ldr	r10, [r0, #44]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, r3, #858993459
	and	r8, r3, #3435973836
	ror	r7, r7, #24
	orr	r3, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, r3, r3, lsr #1
	and	r7, r7, r9
	eors	r3, r7
	eor	r3, r3, r7, lsl #1
	str	r10, [fp, #-40]
	str	r3, [fp, #-36]
	ldr	r3, [r0, #48]
	ldr	r10, [r0, #52]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, r3, #6
	and	r7, r7, #50332416
	and	r8, r3, #1056980736
	lsl	r8, r8, #2
	lsr	ip, r3, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, r3, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-32]
	str	r3, [fp, #-28]
	ldr	r3, [r0, #56]
	ldr	r10, [r0, #60]
	and	r7, r10, #2863311530
	and	r9, r3, #2863311530
	and	r8, r10, #1431655765
	and	ip, r3, #1431655765
	ror	r10, r7, #24
	ror	r3, ip, #24
	orr	r10, r10, r8, ror #16
	orr	r3, r3, r9, ror #20
	str	r10, [fp, #-24]
	str	r3, [fp, #-20]
	ldr	r3, [r0, #64]
	ldr	r10, [r0, #68]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, r3, #18
	and	r7, r7, r9
	and	r8, r3, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, r3, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, r3, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, r3, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, r3, r9
	lsl	r8, r8, #19
	orr	r3, r7, ip
	orr	r3, r3, r8
	str	r10, [fp, #-16]
	str	r3, [fp, #-12]
	ldr	r3, [r0, #72]
	ldr	r10, [r0, #76]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, r3, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, r3, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, r3, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, r3, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-8]
	str	r3, [fp, #-4]
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r2, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r2, r2, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r2, ip, r2, lsl #3
	ldr	r7, [fp, #-80]
	ldr	r8, [fp, #-76]
	movw	ip, #34944
	movt	ip, #4104
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-72]
	ldr	r8, [fp, #-68]
	movw	ip, #24576
	movt	ip, #24577
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r2, r2, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r9
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [fp, #-64]
	ldr	r8, [fp, #-60]
	movw	ip, #2
	movt	ip, #16720
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r4, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r4, r4, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r4, r7, r4, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-56]
	ldr	r8, [fp, #-52]
	movw	ip, #128
	movt	ip, #771
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r2, r2, #24
	ldr	r7, [fp, #-48]
	ldr	r8, [fp, #-44]
	movw	ip, #39
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r4, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r4, r4, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r4, ip, r4, lsl #3
	ldr	r7, [fp, #-40]
	ldr	r8, [fp, #-36]
	movw	ip, #34944
	movt	ip, #4096
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-32]
	ldr	r8, [fp, #-28]
	movw	ip, #57344
	movt	ip, #16385
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r4, r4, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r9
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [fp, #-24]
	ldr	r8, [fp, #-20]
	movw	ip, #2
	movt	ip, #4432
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r2, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r2, r2, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r2, r7, r2, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-16]
	ldr	r8, [fp, #-12]
	movw	ip, #384
	movt	ip, #770
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r4, r4, #24
	ldr	r7, [fp, #-8]
	ldr	r8, [fp, #-4]
	movw	ip, #43
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	ldr	r3, [fp, #-80]
	ldr	r10, [fp, #-76]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, r3, #858993459
	and	r8, r3, #3435973836
	ror	r7, r7, #24
	orr	r3, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, r3, r3, lsr #1
	and	r7, r7, r9
	eors	r3, r7
	eor	r3, r3, r7, lsl #1
	str	r10, [fp, #-80]
	str	r3, [fp, #-76]
	ldr	r3, [fp, #-72]
	ldr	r10, [fp, #-68]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, r3, #6
	and	r7, r7, #50332416
	and	r8, r3, #1056980736
	lsl	r8, r8, #2
	lsr	ip, r3, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, r3, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-72]
	str	r3, [fp, #-68]
	ldr	r3, [fp, #-64]
	ldr	r10, [fp, #-60]
	and	r7, r10, #2863311530
	and	r9, r3, #2863311530
	and	r8, r10, #1431655765
	and	ip, r3, #1431655765
	ror	r10, r7, #24
	ror	r3, ip, #24
	orr	r10, r10, r8, ror #16
	orr	r3, r3, r9, ror #20
	str	r10, [fp, #-64]
	str	r3, [fp, #-60]
	ldr	r3, [fp, #-56]
	ldr	r10, [fp, #-52]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, r3, #18
	and	r7, r7, r9
	and	r8, r3, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, r3, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, r3, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, r3, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, r3, r9
	lsl	r8, r8, #19
	orr	r3, r7, ip
	orr	r3, r3, r8
	str	r10, [fp, #-56]
	str	r3, [fp, #-52]
	ldr	r3, [fp, #-48]
	ldr	r10, [fp, #-44]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, r3, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, r3, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, r3, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, r3, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-48]
	str	r3, [fp, #-44]
	ldr	r3, [fp, #-40]
	ldr	r10, [fp, #-36]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, r3, #858993459
	and	r8, r3, #3435973836
	ror	r7, r7, #24
	orr	r3, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, r3, r3, lsr #1
	and	r7, r7, r9
	eors	r3, r7
	eor	r3, r3, r7, lsl #1
	str	r10, [fp, #-40]
	str	r3, [fp, #-36]
	ldr	r3, [fp, #-32]
	ldr	r10, [fp, #-28]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, r3, #6
	and	r7, r7, #50332416
	and	r8, r3, #1056980736
	lsl	r8, r8, #2
	lsr	ip, r3, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, r3, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-32]
	str	r3, [fp, #-28]
	ldr	r3, [fp, #-24]
	ldr	r10, [fp, #-20]
	and	r7, r10, #2863311530
	and	r9, r3, #2863311530
	and	r8, r10, #1431655765
	and	ip, r3, #1431655765
	ror	r10, r7, #24
	ror	r3, ip, #24
	orr	r10, r10, r8, ror #16
	orr	r3, r3, r9, ror #20
	str	r10, [fp, #-24]
	str	r3, [fp, #-20]
	ldr	r3, [fp, #-16]
	ldr	r10, [fp, #-12]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, r3, #18
	and	r7, r7, r9
	and	r8, r3, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, r3, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, r3, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, r3, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, r3, r9
	lsl	r8, r8, #19
	orr	r3, r7, ip
	orr	r3, r3, r8
	str	r10, [fp, #-16]
	str	r3, [fp, #-12]
	ldr	r3, [fp, #-8]
	ldr	r10, [fp, #-4]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, r3, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, r3, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, r3, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, r3, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-8]
	str	r3, [fp, #-4]
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r2, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r2, r2, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r2, ip, r2, lsl #3
	ldr	r7, [fp, #-80]
	ldr	r8, [fp, #-76]
	movw	ip, #2176
	movt	ip, #4104
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-72]
	ldr	r8, [fp, #-68]
	movw	ip, #16384
	movt	ip, #24577
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r2, r2, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r9
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [fp, #-64]
	ldr	r8, [fp, #-60]
	movw	ip, #2
	movt	ip, #320
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r4, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r4, r4, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r4, r7, r4, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-56]
	ldr	r8, [fp, #-52]
	movw	ip, #128
	movt	ip, #514
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r2, r2, #24
	ldr	r7, [fp, #-48]
	ldr	r8, [fp, #-44]
	movw	ip, #33
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r4, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r4, r4, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r4, ip, r4, lsl #3
	ldr	r7, [fp, #-40]
	ldr	r8, [fp, #-36]
	movw	ip, #128
	movt	ip, #4096
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-32]
	ldr	r8, [fp, #-28]
	movw	ip, #49152
	movt	ip, #1
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r4, r4, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r9
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [fp, #-24]
	ldr	r8, [fp, #-20]
	movw	ip, #2
	movt	ip, #20736
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r2, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r2, r2, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r2, r7, r2, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-16]
	ldr	r8, [fp, #-12]
	movw	ip, #384
	movt	ip, #769
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r4, r4, #24
	ldr	r7, [fp, #-8]
	ldr	r8, [fp, #-4]
	movw	ip, #46
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	ldr	r3, [fp, #-80]
	ldr	r10, [fp, #-76]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, r3, #858993459
	and	r8, r3, #3435973836
	ror	r7, r7, #24
	orr	r3, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, r3, r3, lsr #1
	and	r7, r7, r9
	eors	r3, r7
	eor	r3, r3, r7, lsl #1
	str	r10, [fp, #-80]
	str	r3, [fp, #-76]
	ldr	r3, [fp, #-72]
	ldr	r10, [fp, #-68]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, r3, #6
	and	r7, r7, #50332416
	and	r8, r3, #1056980736
	lsl	r8, r8, #2
	lsr	ip, r3, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, r3, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-72]
	str	r3, [fp, #-68]
	ldr	r3, [fp, #-64]
	ldr	r10, [fp, #-60]
	and	r7, r10, #2863311530
	and	r9, r3, #2863311530
	and	r8, r10, #1431655765
	and	ip, r3, #1431655765
	ror	r10, r7, #24
	ror	r3, ip, #24
	orr	r10, r10, r8, ror #16
	orr	r3, r3, r9, ror #20
	str	r10, [fp, #-64]
	str	r3, [fp, #-60]
	ldr	r3, [fp, #-56]
	ldr	r10, [fp, #-52]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, r3, #18
	and	r7, r7, r9
	and	r8, r3, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, r3, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, r3, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, r3, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, r3, r9
	lsl	r8, r8, #19
	orr	r3, r7, ip
	orr	r3, r3, r8
	str	r10, [fp, #-56]
	str	r3, [fp, #-52]
	ldr	r3, [fp, #-48]
	ldr	r10, [fp, #-44]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, r3, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, r3, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, r3, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, r3, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-48]
	str	r3, [fp, #-44]
	ldr	r3, [fp, #-40]
	ldr	r10, [fp, #-36]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, r3, #858993459
	and	r8, r3, #3435973836
	ror	r7, r7, #24
	orr	r3, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, r3, r3, lsr #1
	and	r7, r7, r9
	eors	r3, r7
	eor	r3, r3, r7, lsl #1
	str	r10, [fp, #-40]
	str	r3, [fp, #-36]
	ldr	r3, [fp, #-32]
	ldr	r10, [fp, #-28]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, r3, #6
	and	r7, r7, #50332416
	and	r8, r3, #1056980736
	lsl	r8, r8, #2
	lsr	ip, r3, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, r3, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-32]
	str	r3, [fp, #-28]
	ldr	r3, [fp, #-24]
	ldr	r10, [fp, #-20]
	and	r7, r10, #2863311530
	and	r9, r3, #2863311530
	and	r8, r10, #1431655765
	and	ip, r3, #1431655765
	ror	r10, r7, #24
	ror	r3, ip, #24
	orr	r10, r10, r8, ror #16
	orr	r3, r3, r9, ror #20
	str	r10, [fp, #-24]
	str	r3, [fp, #-20]
	ldr	r3, [fp, #-16]
	ldr	r10, [fp, #-12]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, r3, #18
	and	r7, r7, r9
	and	r8, r3, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, r3, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, r3, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, r3, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, r3, r9
	lsl	r8, r8, #19
	orr	r3, r7, ip
	orr	r3, r3, r8
	str	r10, [fp, #-16]
	str	r3, [fp, #-12]
	ldr	r3, [fp, #-8]
	ldr	r10, [fp, #-4]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, r3, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, r3, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, r3, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, r3, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-8]
	str	r3, [fp, #-4]
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r2, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r2, r2, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r2, ip, r2, lsl #3
	ldr	r7, [fp, #-80]
	ldr	r8, [fp, #-76]
	movw	ip, #34816
	movt	ip, #4104
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-72]
	ldr	r8, [fp, #-68]
	movw	ip, #8192
	movt	ip, #24577
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r2, r2, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r9
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [fp, #-64]
	ldr	r8, [fp, #-60]
	movw	ip, #2
	movt	ip, #16464
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r4, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r4, r4, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r4, r7, r4, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-56]
	ldr	r8, [fp, #-52]
	movw	ip, #128
	movt	ip, #259
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r2, r2, #24
	ldr	r7, [fp, #-48]
	ldr	r8, [fp, #-44]
	movw	ip, #6
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r4, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r4, r4, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r4, ip, r4, lsl #3
	ldr	r7, [fp, #-40]
	ldr	r8, [fp, #-36]
	movw	ip, #34824
	movt	ip, #4096
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-32]
	ldr	r8, [fp, #-28]
	movw	ip, #40960
	movt	ip, #49153
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r4, r4, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r9
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [fp, #-24]
	ldr	r8, [fp, #-20]
	movw	ip, #2
	movt	ip, #5200
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r2, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r2, r2, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r2, r7, r2, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-16]
	ldr	r8, [fp, #-12]
	movw	ip, #385
	movt	ip, #258
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r4, r4, #24
	ldr	r7, [fp, #-8]
	ldr	r8, [fp, #-4]
	movw	ip, #26
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	str	r4, [r1, #0]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r2, [r1, #12]
	mov	sp, fp
	pop	{r4, r5, r6, r7, r8, r9, r10, fp}
	bx	lr
	.size	gift128b_encrypt_preloaded, .-gift128b_encrypt_preloaded

#endif
#endif
