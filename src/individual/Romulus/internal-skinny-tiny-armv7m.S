#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
#include "internal-skinny-plus-config.h"
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_TINY
	.syntax unified
	.thumb
	.text

	.align	2
	.global	skinny_plus_init_without_tk1
	.thumb
	.thumb_func
	.type	skinny_plus_init_without_tk1, %function
skinny_plus_init_without_tk1:
	ldr	r2, [r1, #0]
	ldr	r3, [r2, #16]
	str	r2, [r0, #16]
	str	r3, [r0, #32]
	ldr	r2, [r1, #4]
	ldr	r3, [r2, #20]
	str	r2, [r0, #20]
	str	r3, [r0, #36]
	ldr	r2, [r1, #8]
	ldr	r3, [r2, #24]
	str	r2, [r0, #24]
	str	r3, [r0, #40]
	ldr	r2, [r1, #12]
	ldr	r3, [r2, #28]
	str	r2, [r0, #28]
	str	r3, [r0, #44]
	bx	lr
	.size	skinny_plus_init_without_tk1, .-skinny_plus_init_without_tk1

	.align	2
	.global	skinny_plus_encrypt
	.thumb
	.thumb_func
	.type	skinny_plus_encrypt, %function
skinny_plus_encrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	mov	fp, sp
	sub	sp, sp, #48
	ldr	r3, [r2, #0]
	ldr	r4, [r2, #4]
	ldr	r5, [r2, #8]
	ldr	r6, [r2, #12]
	ldr	r7, [r0, #0]
	ldr	r8, [r0, #4]
	ldr	r9, [r0, #8]
	ldr	r10, [r0, #12]
	str	r9, [fp, #-8]
	str	r10, [fp, #-4]
	ldr	lr, [r0, #16]
	ldr	ip, [r0, #20]
	str	lr, [fp, #-48]
	str	ip, [fp, #-44]
	ldr	lr, [r0, #24]
	ldr	ip, [r0, #28]
	str	lr, [fp, #-40]
	str	ip, [fp, #-36]
	ldr	r9, [r0, #32]
	ldr	r10, [r0, #36]
	str	r9, [fp, #-32]
	str	r10, [fp, #-28]
	ldr	lr, [r0, #40]
	ldr	ip, [r0, #44]
	str	lr, [fp, #-24]
	str	ip, [fp, #-20]
	movs	r2, #0
	movs	r0, #10
.L1:
	mvns	r3, r3
	lsr	ip, r3, #2
	and	ip, ip, r3, lsr #3
	and	ip, ip, #0x11111111
	eor	r3, ip
	lsl	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r3, #5
	and	ip, ip, r3, lsl #4
	and	ip, ip, #0x40404040
	eor	r3, ip
	eor	r3, lr
	lsl	lr, r3, #2
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r3, #2
	and	ip, ip, r3, lsl #1
	and	ip, ip, #0x02020202
	eor	r3, ip
	eor	r3, lr
	lsr	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r3, #1
	and	ip, ip, r3, lsr #2
	and	ip, ip, #0x08080808
	eor	r3, ip
	eor	r3, lr
	mvn	lr, r3
	and	r3, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r3, r3, #1
	orr	r3, r3, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r3, r3, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r3, r3, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r3, r3, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r3, r3, ip, lsr #2
	mvns	r4, r4
	lsr	ip, r4, #2
	and	ip, ip, r4, lsr #3
	and	ip, ip, #0x11111111
	eor	r4, ip
	lsl	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r4, #5
	and	ip, ip, r4, lsl #4
	and	ip, ip, #0x40404040
	eor	r4, ip
	eor	r4, lr
	lsl	lr, r4, #2
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r4, #2
	and	ip, ip, r4, lsl #1
	and	ip, ip, #0x02020202
	eor	r4, ip
	eor	r4, lr
	lsr	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r4, #1
	and	ip, ip, r4, lsr #2
	and	ip, ip, #0x08080808
	eor	r4, ip
	eor	r4, lr
	mvn	lr, r4
	and	r4, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r4, r4, #1
	orr	r4, r4, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r4, r4, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r4, r4, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r4, r4, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r4, r4, ip, lsr #2
	mvns	r5, r5
	lsr	ip, r5, #2
	and	ip, ip, r5, lsr #3
	and	ip, ip, #0x11111111
	eor	r5, ip
	lsl	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r5, #5
	and	ip, ip, r5, lsl #4
	and	ip, ip, #0x40404040
	eor	r5, ip
	eor	r5, lr
	lsl	lr, r5, #2
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r5, #2
	and	ip, ip, r5, lsl #1
	and	ip, ip, #0x02020202
	eor	r5, ip
	eor	r5, lr
	lsr	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r5, #1
	and	ip, ip, r5, lsr #2
	and	ip, ip, #0x08080808
	eor	r5, ip
	eor	r5, lr
	mvn	lr, r5
	and	r5, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r5, r5, #1
	orr	r5, r5, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r5, r5, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r5, r5, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r5, r5, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r5, r5, ip, lsr #2
	mvns	r6, r6
	lsr	ip, r6, #2
	and	ip, ip, r6, lsr #3
	and	ip, ip, #0x11111111
	eor	r6, ip
	lsl	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r6, #5
	and	ip, ip, r6, lsl #4
	and	ip, ip, #0x40404040
	eor	r6, ip
	eor	r6, lr
	lsl	lr, r6, #2
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r6, #2
	and	ip, ip, r6, lsl #1
	and	ip, ip, #0x02020202
	eor	r6, ip
	eor	r6, lr
	lsr	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r6, #1
	and	ip, ip, r6, lsr #2
	and	ip, ip, #0x08080808
	eor	r6, ip
	eor	r6, lr
	mvn	lr, r6
	and	r6, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r6, r6, #1
	orr	r6, r6, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r6, r6, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r6, r6, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r6, r6, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r6, r6, ip, lsr #2
	lsr	lr, r2, #5
	eor	lr, lr, r2, lsr #4
	eor	lr, lr, #1
	and	lr, lr, #1
	eor	r2, lr, r2, lsl #1
	and	r2, r2, #0x3F
	eors	r3, r7
	eor	r4, r8
	eor	r5, r5, #2
	ldr	lr, [fp, #-48]
	ldr	ip, [fp, #-44]
	eor	r3, r9
	eor	r4, r10
	eor	r3, lr
	eor	r4, ip
	and	lr, r2, #0x0F
	eor	r4, r4, r2, lsr #4
	eor	r3, lr
	ror	r4, r4, #24
	ror	r5, r5, #16
	ror	r6, r6, #8
	eors	r4, r5
	eors	r5, r3
	eors	r6, r5
	str	r7, [fp, #-16]
	str	r8, [fp, #-12]
	ldr	r7, [fp, #-8]
	ldr	r8, [fp, #-4]
	mov	lr, r7
	ror	ip, r8, #16
	uxtb	r7, lr, ror #8
	bfi	r7, lr, #16, #8
	and	r8, ip, #0xFF00FF00
	orr	r7, r8
	uxtb	r8, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r8, lr
	bfi	r8, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r8, ip
	ldr	r9, [fp, #-40]
	ldr	r10, [fp, #-36]
	mov	lr, r9
	ror	ip, r10, #16
	uxtb	r9, lr, ror #8
	bfi	r9, lr, #16, #8
	and	r10, ip, #0xFF00FF00
	orr	r9, r10
	uxtb	r10, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r10, lr
	bfi	r10, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r10, ip
	lsl	lr, r9, #1
	lsl	ip, r10, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r9, r9, #5
	lsr	r10, r10, #5
	eor	r9, r9, r9, lsr #2
	eor	r10, r10, r10, lsr #2
	and	r9, r9, #0x01010101
	and	r10, r10, #0x01010101
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-40]
	str	r10, [fp, #-36]
	ldr	r9, [fp, #-24]
	ldr	r10, [fp, #-20]
	mov	lr, r9
	ror	ip, r10, #16
	uxtb	r9, lr, ror #8
	bfi	r9, lr, #16, #8
	and	r10, ip, #0xFF00FF00
	orr	r9, r10
	uxtb	r10, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r10, lr
	bfi	r10, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r10, ip
	lsr	lr, r9, #1
	lsr	ip, r10, #1
	and	lr, lr, #0x7F7F7F7F
	and	ip, ip, #0x7F7F7F7F
	lsl	r9, r9, #1
	lsl	r10, r10, #1
	eor	r9, r9, r9, lsl #6
	eor	r10, r10, r10, lsl #6
	and	r9, r9, #0x80808080
	and	r10, r10, #0x80808080
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-24]
	str	r10, [fp, #-20]
	mvns	r6, r6
	lsr	ip, r6, #2
	and	ip, ip, r6, lsr #3
	and	ip, ip, #0x11111111
	eor	r6, ip
	lsl	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r6, #5
	and	ip, ip, r6, lsl #4
	and	ip, ip, #0x40404040
	eor	r6, ip
	eor	r6, lr
	lsl	lr, r6, #2
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r6, #2
	and	ip, ip, r6, lsl #1
	and	ip, ip, #0x02020202
	eor	r6, ip
	eor	r6, lr
	lsr	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r6, #1
	and	ip, ip, r6, lsr #2
	and	ip, ip, #0x08080808
	eor	r6, ip
	eor	r6, lr
	mvn	lr, r6
	and	r6, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r6, r6, #1
	orr	r6, r6, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r6, r6, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r6, r6, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r6, r6, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r6, r6, ip, lsr #2
	mvns	r3, r3
	lsr	ip, r3, #2
	and	ip, ip, r3, lsr #3
	and	ip, ip, #0x11111111
	eor	r3, ip
	lsl	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r3, #5
	and	ip, ip, r3, lsl #4
	and	ip, ip, #0x40404040
	eor	r3, ip
	eor	r3, lr
	lsl	lr, r3, #2
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r3, #2
	and	ip, ip, r3, lsl #1
	and	ip, ip, #0x02020202
	eor	r3, ip
	eor	r3, lr
	lsr	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r3, #1
	and	ip, ip, r3, lsr #2
	and	ip, ip, #0x08080808
	eor	r3, ip
	eor	r3, lr
	mvn	lr, r3
	and	r3, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r3, r3, #1
	orr	r3, r3, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r3, r3, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r3, r3, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r3, r3, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r3, r3, ip, lsr #2
	mvns	r4, r4
	lsr	ip, r4, #2
	and	ip, ip, r4, lsr #3
	and	ip, ip, #0x11111111
	eor	r4, ip
	lsl	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r4, #5
	and	ip, ip, r4, lsl #4
	and	ip, ip, #0x40404040
	eor	r4, ip
	eor	r4, lr
	lsl	lr, r4, #2
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r4, #2
	and	ip, ip, r4, lsl #1
	and	ip, ip, #0x02020202
	eor	r4, ip
	eor	r4, lr
	lsr	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r4, #1
	and	ip, ip, r4, lsr #2
	and	ip, ip, #0x08080808
	eor	r4, ip
	eor	r4, lr
	mvn	lr, r4
	and	r4, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r4, r4, #1
	orr	r4, r4, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r4, r4, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r4, r4, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r4, r4, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r4, r4, ip, lsr #2
	mvns	r5, r5
	lsr	ip, r5, #2
	and	ip, ip, r5, lsr #3
	and	ip, ip, #0x11111111
	eor	r5, ip
	lsl	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r5, #5
	and	ip, ip, r5, lsl #4
	and	ip, ip, #0x40404040
	eor	r5, ip
	eor	r5, lr
	lsl	lr, r5, #2
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r5, #2
	and	ip, ip, r5, lsl #1
	and	ip, ip, #0x02020202
	eor	r5, ip
	eor	r5, lr
	lsr	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r5, #1
	and	ip, ip, r5, lsr #2
	and	ip, ip, #0x08080808
	eor	r5, ip
	eor	r5, lr
	mvn	lr, r5
	and	r5, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r5, r5, #1
	orr	r5, r5, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r5, r5, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r5, r5, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r5, r5, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r5, r5, ip, lsr #2
	lsr	lr, r2, #5
	eor	lr, lr, r2, lsr #4
	eor	lr, lr, #1
	and	lr, lr, #1
	eor	r2, lr, r2, lsl #1
	and	r2, r2, #0x3F
	eors	r6, r7
	eor	r3, r8
	eor	r4, r4, #2
	ldr	lr, [fp, #-40]
	ldr	ip, [fp, #-36]
	eor	r6, r9
	eor	r3, r10
	eor	r6, lr
	eor	r3, ip
	and	lr, r2, #0x0F
	eor	r3, r3, r2, lsr #4
	eor	r6, lr
	ror	r3, r3, #24
	ror	r4, r4, #16
	ror	r5, r5, #8
	eors	r3, r4
	eors	r4, r6
	eors	r5, r4
	str	r7, [fp, #-8]
	str	r8, [fp, #-4]
	ldr	r7, [fp, #-16]
	ldr	r8, [fp, #-12]
	mov	lr, r7
	ror	ip, r8, #16
	uxtb	r7, lr, ror #8
	bfi	r7, lr, #16, #8
	and	r8, ip, #0xFF00FF00
	orr	r7, r8
	uxtb	r8, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r8, lr
	bfi	r8, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r8, ip
	ldr	r9, [fp, #-48]
	ldr	r10, [fp, #-44]
	mov	lr, r9
	ror	ip, r10, #16
	uxtb	r9, lr, ror #8
	bfi	r9, lr, #16, #8
	and	r10, ip, #0xFF00FF00
	orr	r9, r10
	uxtb	r10, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r10, lr
	bfi	r10, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r10, ip
	lsl	lr, r9, #1
	lsl	ip, r10, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r9, r9, #5
	lsr	r10, r10, #5
	eor	r9, r9, r9, lsr #2
	eor	r10, r10, r10, lsr #2
	and	r9, r9, #0x01010101
	and	r10, r10, #0x01010101
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-48]
	str	r10, [fp, #-44]
	ldr	r9, [fp, #-32]
	ldr	r10, [fp, #-28]
	mov	lr, r9
	ror	ip, r10, #16
	uxtb	r9, lr, ror #8
	bfi	r9, lr, #16, #8
	and	r10, ip, #0xFF00FF00
	orr	r9, r10
	uxtb	r10, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r10, lr
	bfi	r10, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r10, ip
	lsr	lr, r9, #1
	lsr	ip, r10, #1
	and	lr, lr, #0x7F7F7F7F
	and	ip, ip, #0x7F7F7F7F
	lsl	r9, r9, #1
	lsl	r10, r10, #1
	eor	r9, r9, r9, lsl #6
	eor	r10, r10, r10, lsl #6
	and	r9, r9, #0x80808080
	and	r10, r10, #0x80808080
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-32]
	str	r10, [fp, #-28]
	mvns	r5, r5
	lsr	ip, r5, #2
	and	ip, ip, r5, lsr #3
	and	ip, ip, #0x11111111
	eor	r5, ip
	lsl	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r5, #5
	and	ip, ip, r5, lsl #4
	and	ip, ip, #0x40404040
	eor	r5, ip
	eor	r5, lr
	lsl	lr, r5, #2
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r5, #2
	and	ip, ip, r5, lsl #1
	and	ip, ip, #0x02020202
	eor	r5, ip
	eor	r5, lr
	lsr	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r5, #1
	and	ip, ip, r5, lsr #2
	and	ip, ip, #0x08080808
	eor	r5, ip
	eor	r5, lr
	mvn	lr, r5
	and	r5, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r5, r5, #1
	orr	r5, r5, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r5, r5, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r5, r5, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r5, r5, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r5, r5, ip, lsr #2
	mvns	r6, r6
	lsr	ip, r6, #2
	and	ip, ip, r6, lsr #3
	and	ip, ip, #0x11111111
	eor	r6, ip
	lsl	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r6, #5
	and	ip, ip, r6, lsl #4
	and	ip, ip, #0x40404040
	eor	r6, ip
	eor	r6, lr
	lsl	lr, r6, #2
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r6, #2
	and	ip, ip, r6, lsl #1
	and	ip, ip, #0x02020202
	eor	r6, ip
	eor	r6, lr
	lsr	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r6, #1
	and	ip, ip, r6, lsr #2
	and	ip, ip, #0x08080808
	eor	r6, ip
	eor	r6, lr
	mvn	lr, r6
	and	r6, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r6, r6, #1
	orr	r6, r6, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r6, r6, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r6, r6, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r6, r6, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r6, r6, ip, lsr #2
	mvns	r3, r3
	lsr	ip, r3, #2
	and	ip, ip, r3, lsr #3
	and	ip, ip, #0x11111111
	eor	r3, ip
	lsl	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r3, #5
	and	ip, ip, r3, lsl #4
	and	ip, ip, #0x40404040
	eor	r3, ip
	eor	r3, lr
	lsl	lr, r3, #2
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r3, #2
	and	ip, ip, r3, lsl #1
	and	ip, ip, #0x02020202
	eor	r3, ip
	eor	r3, lr
	lsr	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r3, #1
	and	ip, ip, r3, lsr #2
	and	ip, ip, #0x08080808
	eor	r3, ip
	eor	r3, lr
	mvn	lr, r3
	and	r3, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r3, r3, #1
	orr	r3, r3, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r3, r3, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r3, r3, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r3, r3, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r3, r3, ip, lsr #2
	mvns	r4, r4
	lsr	ip, r4, #2
	and	ip, ip, r4, lsr #3
	and	ip, ip, #0x11111111
	eor	r4, ip
	lsl	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r4, #5
	and	ip, ip, r4, lsl #4
	and	ip, ip, #0x40404040
	eor	r4, ip
	eor	r4, lr
	lsl	lr, r4, #2
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r4, #2
	and	ip, ip, r4, lsl #1
	and	ip, ip, #0x02020202
	eor	r4, ip
	eor	r4, lr
	lsr	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r4, #1
	and	ip, ip, r4, lsr #2
	and	ip, ip, #0x08080808
	eor	r4, ip
	eor	r4, lr
	mvn	lr, r4
	and	r4, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r4, r4, #1
	orr	r4, r4, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r4, r4, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r4, r4, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r4, r4, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r4, r4, ip, lsr #2
	lsr	lr, r2, #5
	eor	lr, lr, r2, lsr #4
	eor	lr, lr, #1
	and	lr, lr, #1
	eor	r2, lr, r2, lsl #1
	and	r2, r2, #0x3F
	eors	r5, r7
	eor	r6, r8
	eor	r3, r3, #2
	ldr	lr, [fp, #-48]
	ldr	ip, [fp, #-44]
	eor	r5, r9
	eor	r6, r10
	eor	r5, lr
	eor	r6, ip
	and	lr, r2, #0x0F
	eor	r6, r6, r2, lsr #4
	eor	r5, lr
	ror	r6, r6, #24
	ror	r3, r3, #16
	ror	r4, r4, #8
	eors	r6, r3
	eors	r3, r5
	eors	r4, r3
	str	r7, [fp, #-16]
	str	r8, [fp, #-12]
	ldr	r7, [fp, #-8]
	ldr	r8, [fp, #-4]
	mov	lr, r7
	ror	ip, r8, #16
	uxtb	r7, lr, ror #8
	bfi	r7, lr, #16, #8
	and	r8, ip, #0xFF00FF00
	orr	r7, r8
	uxtb	r8, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r8, lr
	bfi	r8, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r8, ip
	ldr	r9, [fp, #-40]
	ldr	r10, [fp, #-36]
	mov	lr, r9
	ror	ip, r10, #16
	uxtb	r9, lr, ror #8
	bfi	r9, lr, #16, #8
	and	r10, ip, #0xFF00FF00
	orr	r9, r10
	uxtb	r10, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r10, lr
	bfi	r10, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r10, ip
	lsl	lr, r9, #1
	lsl	ip, r10, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r9, r9, #5
	lsr	r10, r10, #5
	eor	r9, r9, r9, lsr #2
	eor	r10, r10, r10, lsr #2
	and	r9, r9, #0x01010101
	and	r10, r10, #0x01010101
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-40]
	str	r10, [fp, #-36]
	ldr	r9, [fp, #-24]
	ldr	r10, [fp, #-20]
	mov	lr, r9
	ror	ip, r10, #16
	uxtb	r9, lr, ror #8
	bfi	r9, lr, #16, #8
	and	r10, ip, #0xFF00FF00
	orr	r9, r10
	uxtb	r10, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r10, lr
	bfi	r10, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r10, ip
	lsr	lr, r9, #1
	lsr	ip, r10, #1
	and	lr, lr, #0x7F7F7F7F
	and	ip, ip, #0x7F7F7F7F
	lsl	r9, r9, #1
	lsl	r10, r10, #1
	eor	r9, r9, r9, lsl #6
	eor	r10, r10, r10, lsl #6
	and	r9, r9, #0x80808080
	and	r10, r10, #0x80808080
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-24]
	str	r10, [fp, #-20]
	mvns	r4, r4
	lsr	ip, r4, #2
	and	ip, ip, r4, lsr #3
	and	ip, ip, #0x11111111
	eor	r4, ip
	lsl	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r4, #5
	and	ip, ip, r4, lsl #4
	and	ip, ip, #0x40404040
	eor	r4, ip
	eor	r4, lr
	lsl	lr, r4, #2
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r4, #2
	and	ip, ip, r4, lsl #1
	and	ip, ip, #0x02020202
	eor	r4, ip
	eor	r4, lr
	lsr	lr, r4, #5
	and	lr, lr, r4, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r4, #1
	and	ip, ip, r4, lsr #2
	and	ip, ip, #0x08080808
	eor	r4, ip
	eor	r4, lr
	mvn	lr, r4
	and	r4, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r4, r4, #1
	orr	r4, r4, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r4, r4, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r4, r4, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r4, r4, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r4, r4, ip, lsr #2
	mvns	r5, r5
	lsr	ip, r5, #2
	and	ip, ip, r5, lsr #3
	and	ip, ip, #0x11111111
	eor	r5, ip
	lsl	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r5, #5
	and	ip, ip, r5, lsl #4
	and	ip, ip, #0x40404040
	eor	r5, ip
	eor	r5, lr
	lsl	lr, r5, #2
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r5, #2
	and	ip, ip, r5, lsl #1
	and	ip, ip, #0x02020202
	eor	r5, ip
	eor	r5, lr
	lsr	lr, r5, #5
	and	lr, lr, r5, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r5, #1
	and	ip, ip, r5, lsr #2
	and	ip, ip, #0x08080808
	eor	r5, ip
	eor	r5, lr
	mvn	lr, r5
	and	r5, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r5, r5, #1
	orr	r5, r5, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r5, r5, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r5, r5, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r5, r5, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r5, r5, ip, lsr #2
	mvns	r6, r6
	lsr	ip, r6, #2
	and	ip, ip, r6, lsr #3
	and	ip, ip, #0x11111111
	eor	r6, ip
	lsl	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r6, #5
	and	ip, ip, r6, lsl #4
	and	ip, ip, #0x40404040
	eor	r6, ip
	eor	r6, lr
	lsl	lr, r6, #2
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r6, #2
	and	ip, ip, r6, lsl #1
	and	ip, ip, #0x02020202
	eor	r6, ip
	eor	r6, lr
	lsr	lr, r6, #5
	and	lr, lr, r6, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r6, #1
	and	ip, ip, r6, lsr #2
	and	ip, ip, #0x08080808
	eor	r6, ip
	eor	r6, lr
	mvn	lr, r6
	and	r6, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r6, r6, #1
	orr	r6, r6, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r6, r6, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r6, r6, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r6, r6, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r6, r6, ip, lsr #2
	mvns	r3, r3
	lsr	ip, r3, #2
	and	ip, ip, r3, lsr #3
	and	ip, ip, #0x11111111
	eor	r3, ip
	lsl	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r3, #5
	and	ip, ip, r3, lsl #4
	and	ip, ip, #0x40404040
	eor	r3, ip
	eor	r3, lr
	lsl	lr, r3, #2
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r3, #2
	and	ip, ip, r3, lsl #1
	and	ip, ip, #0x02020202
	eor	r3, ip
	eor	r3, lr
	lsr	lr, r3, #5
	and	lr, lr, r3, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r3, #1
	and	ip, ip, r3, lsr #2
	and	ip, ip, #0x08080808
	eor	r3, ip
	eor	r3, lr
	mvn	lr, r3
	and	r3, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r3, r3, #1
	orr	r3, r3, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r3, r3, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r3, r3, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r3, r3, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r3, r3, ip, lsr #2
	lsr	lr, r2, #5
	eor	lr, lr, r2, lsr #4
	eor	lr, lr, #1
	and	lr, lr, #1
	eor	r2, lr, r2, lsl #1
	and	r2, r2, #0x3F
	eors	r4, r7
	eor	r5, r8
	eor	r6, r6, #2
	ldr	lr, [fp, #-40]
	ldr	ip, [fp, #-36]
	eor	r4, r9
	eor	r5, r10
	eor	r4, lr
	eor	r5, ip
	and	lr, r2, #0x0F
	eor	r5, r5, r2, lsr #4
	eor	r4, lr
	ror	r5, r5, #24
	ror	r6, r6, #16
	ror	r3, r3, #8
	eors	r5, r6
	eors	r6, r4
	eors	r3, r6
	str	r7, [fp, #-8]
	str	r8, [fp, #-4]
	ldr	r7, [fp, #-16]
	ldr	r8, [fp, #-12]
	mov	lr, r7
	ror	ip, r8, #16
	uxtb	r7, lr, ror #8
	bfi	r7, lr, #16, #8
	and	r8, ip, #0xFF00FF00
	orr	r7, r8
	uxtb	r8, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r8, lr
	bfi	r8, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r8, ip
	ldr	r9, [fp, #-48]
	ldr	r10, [fp, #-44]
	mov	lr, r9
	ror	ip, r10, #16
	uxtb	r9, lr, ror #8
	bfi	r9, lr, #16, #8
	and	r10, ip, #0xFF00FF00
	orr	r9, r10
	uxtb	r10, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r10, lr
	bfi	r10, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r10, ip
	lsl	lr, r9, #1
	lsl	ip, r10, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r9, r9, #5
	lsr	r10, r10, #5
	eor	r9, r9, r9, lsr #2
	eor	r10, r10, r10, lsr #2
	and	r9, r9, #0x01010101
	and	r10, r10, #0x01010101
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-48]
	str	r10, [fp, #-44]
	ldr	r9, [fp, #-32]
	ldr	r10, [fp, #-28]
	mov	lr, r9
	ror	ip, r10, #16
	uxtb	r9, lr, ror #8
	bfi	r9, lr, #16, #8
	and	r10, ip, #0xFF00FF00
	orr	r9, r10
	uxtb	r10, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r10, lr
	bfi	r10, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r10, ip
	lsr	lr, r9, #1
	lsr	ip, r10, #1
	and	lr, lr, #0x7F7F7F7F
	and	ip, ip, #0x7F7F7F7F
	lsl	r9, r9, #1
	lsl	r10, r10, #1
	eor	r9, r9, r9, lsl #6
	eor	r10, r10, r10, lsl #6
	and	r9, r9, #0x80808080
	and	r10, r10, #0x80808080
	eor	r9, r9, lr
	eor	r10, r10, ip
	str	r9, [fp, #-32]
	str	r10, [fp, #-28]
	subs	r0, r0, #1
	bne	.L1
	str	r3, [r1, #0]
	str	r4, [r1, #4]
	str	r5, [r1, #8]
	str	r6, [r1, #12]
	mov	sp, fp
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	skinny_plus_encrypt, .-skinny_plus_encrypt
	.global	skinny_plus_encrypt_tk_full
	.set	skinny_plus_encrypt_tk_full,skinny_plus_encrypt

#endif
#endif
