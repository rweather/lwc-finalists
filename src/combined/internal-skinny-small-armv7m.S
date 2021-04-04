#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
#include "internal-skinny-plus-config.h"
#if SKINNY_PLUS_VARIANT == SKINNY_PLUS_VARIANT_SMALL
	.syntax unified
	.thumb
	.text

	.align	2
	.global	skinny_plus_init
	.thumb
	.thumb_func
	.type	skinny_plus_init, %function
skinny_plus_init:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	ldr	r10, [r1, #0]
	ldr	ip, [r1, #4]
	str	r10, [r0, #0]
	str	ip, [r0, #4]
	ldr	r10, [r1, #8]
	ldr	ip, [r1, #12]
	str	r10, [r0, #8]
	str	ip, [r0, #12]
	ldr	r2, [r1, #16]
	ldr	r3, [r1, #20]
	ldr	r4, [r1, #24]
	ldr	r5, [r1, #28]
	ldr	r6, [r1, #32]
	ldr	r7, [r1, #36]
	ldr	r8, [r1, #40]
	ldr	r9, [r1, #44]
	mov	lr, #0
	movs	r1, #20
.L1:
	add	r0, #16
	lsr	r10, lr, #5
	eor	r10, r10, lr, lsr #4
	eor	r10, r10, #1
	and	r10, r10, #1
	eor	lr, r10, lr, lsl #1
	and	lr, lr, #0x3F
	and	r10, lr, #0x0F
	lsr	ip, lr, #4
	eor	r10, r2
	eor	ip, r3
	eor	r10, r6
	eor	ip, r7
	str	r10, [r0, #0]
	str	ip, [r0, #4]
	mov	r10, r4
	ror	ip, r5, #16
	uxtb	r4, r10, ror #8
	bfi	r4, r10, #16, #8
	and	r5, ip, #0xFF00FF00
	orrs	r4, r5
	uxtb	r5, r10, ror #16
	and	r10, r10, #0xFF000000
	orr	r5, r10
	bfi	r5, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r5, ip
	mov	r10, r8
	ror	ip, r9, #16
	uxtb	r8, r10, ror #8
	bfi	r8, r10, #16, #8
	and	r9, ip, #0xFF00FF00
	orr	r8, r9
	uxtb	r9, r10, ror #16
	and	r10, r10, #0xFF000000
	orr	r9, r10
	bfi	r9, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r9, ip
	lsl	r10, r4, #1
	lsl	ip, r5, #1
	and	r10, r10, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r4, r4, #5
	lsr	r5, r5, #5
	eor	r4, r4, r4, lsr #2
	eor	r5, r5, r5, lsr #2
	and	r4, r4, #0x01010101
	and	r5, r5, #0x01010101
	eor	r4, r4, r10
	eor	r5, r5, ip
	lsr	r10, r8, #1
	lsr	ip, r9, #1
	and	r10, r10, #0x7F7F7F7F
	and	ip, ip, #0x7F7F7F7F
	lsl	r8, r8, #1
	lsl	r9, r9, #1
	eor	r8, r8, r8, lsl #6
	eor	r9, r9, r9, lsl #6
	and	r8, r8, #0x80808080
	and	r9, r9, #0x80808080
	eor	r8, r8, r10
	eor	r9, r9, ip
	lsr	r10, lr, #5
	eor	r10, r10, lr, lsr #4
	eor	r10, r10, #1
	and	r10, r10, #1
	eor	lr, r10, lr, lsl #1
	and	lr, lr, #0x3F
	and	r10, lr, #0x0F
	lsr	ip, lr, #4
	eor	r10, r4
	eor	ip, r5
	eor	r10, r8
	eor	ip, r9
	str	r10, [r0, #8]
	str	ip, [r0, #12]
	mov	r10, r2
	ror	ip, r3, #16
	uxtb	r2, r10, ror #8
	bfi	r2, r10, #16, #8
	and	r3, ip, #0xFF00FF00
	orrs	r2, r3
	uxtb	r3, r10, ror #16
	and	r10, r10, #0xFF000000
	orr	r3, r10
	bfi	r3, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r3, ip
	mov	r10, r6
	ror	ip, r7, #16
	uxtb	r6, r10, ror #8
	bfi	r6, r10, #16, #8
	and	r7, ip, #0xFF00FF00
	orrs	r6, r7
	uxtb	r7, r10, ror #16
	and	r10, r10, #0xFF000000
	orr	r7, r10
	bfi	r7, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r7, ip
	lsl	r10, r2, #1
	lsl	ip, r3, #1
	and	r10, r10, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r2, r2, #5
	lsr	r3, r3, #5
	eor	r2, r2, r2, lsr #2
	eor	r3, r3, r3, lsr #2
	and	r2, r2, #0x01010101
	and	r3, r3, #0x01010101
	eor	r2, r2, r10
	eor	r3, r3, ip
	lsr	r10, r6, #1
	lsr	ip, r7, #1
	and	r10, r10, #0x7F7F7F7F
	and	ip, ip, #0x7F7F7F7F
	lsl	r6, r6, #1
	lsl	r7, r7, #1
	eor	r6, r6, r6, lsl #6
	eor	r7, r7, r7, lsl #6
	and	r6, r6, #0x80808080
	and	r7, r7, #0x80808080
	eor	r6, r6, r10
	eor	r7, r7, ip
	subs	r1, r1, #1
	bne	.L1
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	skinny_plus_init, .-skinny_plus_init

	.align	2
	.global	skinny_plus_encrypt
	.thumb
	.thumb_func
	.type	skinny_plus_encrypt, %function
skinny_plus_encrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	ldr	r3, [r2, #0]
	ldr	r4, [r2, #4]
	ldr	r5, [r2, #8]
	ldr	r6, [r2, #12]
	ldr	r7, [r0, #0]
	ldr	r8, [r0, #4]
	ldr	r9, [r0, #8]
	ldr	r10, [r0, #12]
	movs	r2, #10
.L2:
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
	ldr	lr, [r0, #16]
	ldr	ip, [r0, #20]
	eor	r5, r5, #2
	eors	r3, r7
	eor	r4, r8
	eor	r3, lr
	eor	r4, ip
	ror	r4, r4, #24
	ror	r5, r5, #16
	ror	r6, r6, #8
	eors	r4, r5
	eors	r5, r3
	eors	r6, r5
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
	ldr	lr, [r0, #24]
	ldr	ip, [r0, #28]
	eor	r4, r4, #2
	eor	r6, r9
	eor	r3, r10
	eor	r6, lr
	eor	r3, ip
	ror	r3, r3, #24
	ror	r4, r4, #16
	ror	r5, r5, #8
	eors	r3, r4
	eors	r4, r6
	eors	r5, r4
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
	ldr	lr, [r0, #32]
	ldr	ip, [r0, #36]
	eor	r3, r3, #2
	eors	r5, r7
	eor	r6, r8
	eor	r5, lr
	eor	r6, ip
	ror	r6, r6, #24
	ror	r3, r3, #16
	ror	r4, r4, #8
	eors	r6, r3
	eors	r3, r5
	eors	r4, r3
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
	ldr	lr, [r0, #40]
	ldr	ip, [r0, #44]
	eor	r6, r6, #2
	eor	r4, r9
	eor	r5, r10
	eor	r4, lr
	eor	r5, ip
	ror	r5, r5, #24
	ror	r6, r6, #16
	ror	r3, r3, #8
	eors	r5, r6
	eors	r6, r4
	eors	r3, r6
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
	add	r0, #32
	subs	r2, r2, #1
	bne	.L2
	str	r3, [r1, #0]
	str	r4, [r1, #4]
	str	r5, [r1, #8]
	str	r6, [r1, #12]
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	skinny_plus_encrypt, .-skinny_plus_encrypt

	.align	2
	.global	skinny_plus_encrypt_tk2
	.thumb
	.thumb_func
	.type	skinny_plus_encrypt_tk2, %function
skinny_plus_encrypt_tk2:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	mov	fp, sp
	sub	sp, sp, #32
	ldr	r4, [r2, #0]
	ldr	r5, [r2, #4]
	ldr	r6, [r2, #8]
	ldr	r7, [r2, #12]
	ldr	r8, [r0, #0]
	ldr	r9, [r0, #4]
	ldr	lr, [r0, #8]
	ldr	ip, [r0, #12]
	str	lr, [fp, #-8]
	str	ip, [fp, #-4]
	ldr	lr, [r3, #8]
	ldr	ip, [r3, #12]
	ldr	r10, [r3, #0]
	ldr	r3, [r3, #4]
	str	lr, [fp, #-24]
	str	ip, [fp, #-20]
	str	r10, [fp, #-32]
	str	r3, [fp, #-28]
	movs	r2, #10
.L3:
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
	mvns	r7, r7
	lsr	ip, r7, #2
	and	ip, ip, r7, lsr #3
	and	ip, ip, #0x11111111
	eor	r7, ip
	lsl	lr, r7, #5
	and	lr, lr, r7, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r7, #5
	and	ip, ip, r7, lsl #4
	and	ip, ip, #0x40404040
	eor	r7, ip
	eor	r7, lr
	lsl	lr, r7, #2
	and	lr, lr, r7, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r7, #2
	and	ip, ip, r7, lsl #1
	and	ip, ip, #0x02020202
	eor	r7, ip
	eor	r7, lr
	lsr	lr, r7, #5
	and	lr, lr, r7, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r7, #1
	and	ip, ip, r7, lsr #2
	and	ip, ip, #0x08080808
	eor	r7, ip
	eor	r7, lr
	mvn	lr, r7
	and	r7, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r7, r7, #1
	orr	r7, r7, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r7, r7, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r7, r7, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r7, r7, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r7, r7, ip, lsr #2
	ldr	lr, [r0, #16]
	ldr	ip, [r0, #20]
	eor	r6, r6, #2
	eor	r4, r8
	eor	r5, r9
	eor	r4, lr
	eor	r5, ip
	eor	r4, r10
	eors	r5, r3
	ror	r5, r5, #24
	ror	r6, r6, #16
	ror	r7, r7, #8
	eors	r5, r6
	eors	r6, r4
	eors	r7, r6
	str	r8, [fp, #-16]
	str	r9, [fp, #-12]
	ldr	r8, [fp, #-8]
	ldr	r9, [fp, #-4]
	mov	lr, r8
	ror	ip, r9, #16
	uxtb	r8, lr, ror #8
	bfi	r8, lr, #16, #8
	and	r9, ip, #0xFF00FF00
	orr	r8, r9
	uxtb	r9, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r9, lr
	bfi	r9, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r9, ip
	ldr	r10, [fp, #-24]
	ldr	r3, [fp, #-20]
	mov	lr, r10
	ror	ip, r3, #16
	uxtb	r10, lr, ror #8
	bfi	r10, lr, #16, #8
	and	r3, ip, #0xFF00FF00
	orr	r10, r3
	uxtb	r3, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r3, lr
	bfi	r3, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r3, ip
	lsl	lr, r10, #1
	lsl	ip, r3, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r10, r10, #5
	lsr	r3, r3, #5
	eor	r10, r10, r10, lsr #2
	eor	r3, r3, r3, lsr #2
	and	r10, r10, #0x01010101
	and	r3, r3, #0x01010101
	eor	r10, r10, lr
	eor	r3, r3, ip
	str	r10, [fp, #-24]
	str	r3, [fp, #-20]
	mvns	r7, r7
	lsr	ip, r7, #2
	and	ip, ip, r7, lsr #3
	and	ip, ip, #0x11111111
	eor	r7, ip
	lsl	lr, r7, #5
	and	lr, lr, r7, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r7, #5
	and	ip, ip, r7, lsl #4
	and	ip, ip, #0x40404040
	eor	r7, ip
	eor	r7, lr
	lsl	lr, r7, #2
	and	lr, lr, r7, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r7, #2
	and	ip, ip, r7, lsl #1
	and	ip, ip, #0x02020202
	eor	r7, ip
	eor	r7, lr
	lsr	lr, r7, #5
	and	lr, lr, r7, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r7, #1
	and	ip, ip, r7, lsr #2
	and	ip, ip, #0x08080808
	eor	r7, ip
	eor	r7, lr
	mvn	lr, r7
	and	r7, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r7, r7, #1
	orr	r7, r7, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r7, r7, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r7, r7, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r7, r7, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r7, r7, ip, lsr #2
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
	ldr	lr, [r0, #24]
	ldr	ip, [r0, #28]
	eor	r5, r5, #2
	eor	r7, r8
	eor	r4, r9
	eor	r7, lr
	eor	r4, ip
	eor	r7, r10
	eors	r4, r3
	ror	r4, r4, #24
	ror	r5, r5, #16
	ror	r6, r6, #8
	eors	r4, r5
	eors	r5, r7
	eors	r6, r5
	str	r8, [fp, #-8]
	str	r9, [fp, #-4]
	ldr	r8, [fp, #-16]
	ldr	r9, [fp, #-12]
	mov	lr, r8
	ror	ip, r9, #16
	uxtb	r8, lr, ror #8
	bfi	r8, lr, #16, #8
	and	r9, ip, #0xFF00FF00
	orr	r8, r9
	uxtb	r9, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r9, lr
	bfi	r9, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r9, ip
	ldr	r10, [fp, #-32]
	ldr	r3, [fp, #-28]
	mov	lr, r10
	ror	ip, r3, #16
	uxtb	r10, lr, ror #8
	bfi	r10, lr, #16, #8
	and	r3, ip, #0xFF00FF00
	orr	r10, r3
	uxtb	r3, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r3, lr
	bfi	r3, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r3, ip
	lsl	lr, r10, #1
	lsl	ip, r3, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r10, r10, #5
	lsr	r3, r3, #5
	eor	r10, r10, r10, lsr #2
	eor	r3, r3, r3, lsr #2
	and	r10, r10, #0x01010101
	and	r3, r3, #0x01010101
	eor	r10, r10, lr
	eor	r3, r3, ip
	str	r10, [fp, #-32]
	str	r3, [fp, #-28]
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
	mvns	r7, r7
	lsr	ip, r7, #2
	and	ip, ip, r7, lsr #3
	and	ip, ip, #0x11111111
	eor	r7, ip
	lsl	lr, r7, #5
	and	lr, lr, r7, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r7, #5
	and	ip, ip, r7, lsl #4
	and	ip, ip, #0x40404040
	eor	r7, ip
	eor	r7, lr
	lsl	lr, r7, #2
	and	lr, lr, r7, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r7, #2
	and	ip, ip, r7, lsl #1
	and	ip, ip, #0x02020202
	eor	r7, ip
	eor	r7, lr
	lsr	lr, r7, #5
	and	lr, lr, r7, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r7, #1
	and	ip, ip, r7, lsr #2
	and	ip, ip, #0x08080808
	eor	r7, ip
	eor	r7, lr
	mvn	lr, r7
	and	r7, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r7, r7, #1
	orr	r7, r7, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r7, r7, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r7, r7, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r7, r7, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r7, r7, ip, lsr #2
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
	ldr	lr, [r0, #32]
	ldr	ip, [r0, #36]
	eor	r4, r4, #2
	eor	r6, r8
	eor	r7, r9
	eor	r6, lr
	eor	r7, ip
	eor	r6, r10
	eors	r7, r3
	ror	r7, r7, #24
	ror	r4, r4, #16
	ror	r5, r5, #8
	eors	r7, r4
	eors	r4, r6
	eors	r5, r4
	str	r8, [fp, #-16]
	str	r9, [fp, #-12]
	ldr	r8, [fp, #-8]
	ldr	r9, [fp, #-4]
	mov	lr, r8
	ror	ip, r9, #16
	uxtb	r8, lr, ror #8
	bfi	r8, lr, #16, #8
	and	r9, ip, #0xFF00FF00
	orr	r8, r9
	uxtb	r9, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r9, lr
	bfi	r9, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r9, ip
	ldr	r10, [fp, #-24]
	ldr	r3, [fp, #-20]
	mov	lr, r10
	ror	ip, r3, #16
	uxtb	r10, lr, ror #8
	bfi	r10, lr, #16, #8
	and	r3, ip, #0xFF00FF00
	orr	r10, r3
	uxtb	r3, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r3, lr
	bfi	r3, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r3, ip
	lsl	lr, r10, #1
	lsl	ip, r3, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r10, r10, #5
	lsr	r3, r3, #5
	eor	r10, r10, r10, lsr #2
	eor	r3, r3, r3, lsr #2
	and	r10, r10, #0x01010101
	and	r3, r3, #0x01010101
	eor	r10, r10, lr
	eor	r3, r3, ip
	str	r10, [fp, #-24]
	str	r3, [fp, #-20]
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
	mvns	r7, r7
	lsr	ip, r7, #2
	and	ip, ip, r7, lsr #3
	and	ip, ip, #0x11111111
	eor	r7, ip
	lsl	lr, r7, #5
	and	lr, lr, r7, lsl #1
	and	lr, lr, #0x20202020
	lsl	ip, r7, #5
	and	ip, ip, r7, lsl #4
	and	ip, ip, #0x40404040
	eor	r7, ip
	eor	r7, lr
	lsl	lr, r7, #2
	and	lr, lr, r7, lsl #1
	and	lr, lr, #0x80808080
	lsr	ip, r7, #2
	and	ip, ip, r7, lsl #1
	and	ip, ip, #0x02020202
	eor	r7, ip
	eor	r7, lr
	lsr	lr, r7, #5
	and	lr, lr, r7, lsl #1
	and	lr, lr, #0x04040404
	lsr	ip, r7, #1
	and	ip, ip, r7, lsr #2
	and	ip, ip, #0x08080808
	eor	r7, ip
	eor	r7, lr
	mvn	lr, r7
	and	r7, lr, #0x08080808
	and	ip, lr, #0x32323232
	lsl	r7, r7, #1
	orr	r7, r7, ip, lsl #2
	and	ip, lr, #0x01010101
	orr	r7, r7, ip, lsl #5
	and	ip, lr, #0x80808080
	orr	r7, r7, ip, lsr #6
	and	ip, lr, #0x40404040
	orr	r7, r7, ip, lsr #4
	and	ip, lr, #0x04040404
	orr	r7, r7, ip, lsr #2
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
	ldr	lr, [r0, #40]
	ldr	ip, [r0, #44]
	eor	r7, r7, #2
	eor	r5, r8
	eor	r6, r9
	eor	r5, lr
	eor	r6, ip
	eor	r5, r10
	eors	r6, r3
	ror	r6, r6, #24
	ror	r7, r7, #16
	ror	r4, r4, #8
	eors	r6, r7
	eors	r7, r5
	eors	r4, r7
	str	r8, [fp, #-8]
	str	r9, [fp, #-4]
	ldr	r8, [fp, #-16]
	ldr	r9, [fp, #-12]
	mov	lr, r8
	ror	ip, r9, #16
	uxtb	r8, lr, ror #8
	bfi	r8, lr, #16, #8
	and	r9, ip, #0xFF00FF00
	orr	r8, r9
	uxtb	r9, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r9, lr
	bfi	r9, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r9, ip
	ldr	r10, [fp, #-32]
	ldr	r3, [fp, #-28]
	mov	lr, r10
	ror	ip, r3, #16
	uxtb	r10, lr, ror #8
	bfi	r10, lr, #16, #8
	and	r3, ip, #0xFF00FF00
	orr	r10, r3
	uxtb	r3, lr, ror #16
	and	lr, lr, #0xFF000000
	orr	r3, lr
	bfi	r3, ip, #8, #8
	and	ip, ip, #0x00FF0000
	orr	r3, ip
	lsl	lr, r10, #1
	lsl	ip, r3, #1
	and	lr, lr, #0xFEFEFEFE
	and	ip, ip, #0xFEFEFEFE
	lsr	r10, r10, #5
	lsr	r3, r3, #5
	eor	r10, r10, r10, lsr #2
	eor	r3, r3, r3, lsr #2
	and	r10, r10, #0x01010101
	and	r3, r3, #0x01010101
	eor	r10, r10, lr
	eor	r3, r3, ip
	str	r10, [fp, #-32]
	str	r3, [fp, #-28]
	add	r0, #32
	subs	r2, r2, #1
	bne	.L3
	str	r4, [r1, #0]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	mov	sp, fp
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	skinny_plus_encrypt_tk2, .-skinny_plus_encrypt_tk2

	.align	2
	.global	skinny_plus_encrypt_tk_full
	.thumb
	.thumb_func
	.type	skinny_plus_encrypt_tk_full, %function
skinny_plus_encrypt_tk_full:
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
.L4:
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
	bne	.L4
	str	r3, [r1, #0]
	str	r4, [r1, #4]
	str	r5, [r1, #8]
	str	r6, [r1, #12]
	mov	sp, fp
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	skinny_plus_encrypt_tk_full, .-skinny_plus_encrypt_tk_full

#endif
#endif
