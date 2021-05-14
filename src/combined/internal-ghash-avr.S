#if defined(__AVR__)
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

#include <avr/io.h>
/* Automatically generated - do not edit */

	.text
.global ghash_init
	.type ghash_init, @function
ghash_init:
	movw r30,r24
	movw r26,r22
.L__stack_usage = 2
	ld r18,X+
	ld r19,X+
	ld r20,X+
	ld r21,X+
	st Z,r18
	std Z+1,r19
	std Z+2,r20
	std Z+3,r21
	ld r18,X+
	ld r19,X+
	ld r20,X+
	ld r21,X+
	std Z+4,r18
	std Z+5,r19
	std Z+6,r20
	std Z+7,r21
	ld r18,X+
	ld r19,X+
	ld r20,X+
	ld r21,X+
	std Z+8,r18
	std Z+9,r19
	std Z+10,r20
	std Z+11,r21
	ld r18,X+
	ld r19,X+
	ld r20,X+
	ld r21,X+
	std Z+12,r18
	std Z+13,r19
	std Z+14,r20
	std Z+15,r21
	std Z+16,r1
	std Z+17,r1
	std Z+18,r1
	std Z+19,r1
	std Z+20,r1
	std Z+21,r1
	std Z+22,r1
	std Z+23,r1
	std Z+24,r1
	std Z+25,r1
	std Z+26,r1
	std Z+27,r1
	std Z+28,r1
	std Z+29,r1
	std Z+30,r1
	std Z+31,r1
	std Z+32,r1
	std Z+33,r1
	std Z+34,r1
	std Z+35,r1
	ret
	.size ghash_init, .-ghash_init

	.text
.global ghash_mul
	.type ghash_mul, @function
ghash_mul:
	push r28
	push r29
	push r2
	push r3
	push r4
	push r5
	push r6
	push r7
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	movw r30,r24
	in r28,0x3d
	in r29,0x3e
	sbiw r28,16
	in r0,0x3f
	cli
	out 0x3e,r29
	out 0x3f,r0
	out 0x3d,r28
.L__stack_usage = 31
	std Y+1,r1
	std Y+2,r1
	std Y+3,r1
	std Y+4,r1
	std Y+5,r1
	std Y+6,r1
	std Y+7,r1
	std Y+8,r1
	std Y+9,r1
	std Y+10,r1
	std Y+11,r1
	std Y+12,r1
	std Y+13,r1
	std Y+14,r1
	std Y+15,r1
	std Y+16,r1
	ld r11,Z+
	ld r10,Z+
	ld r9,Z+
	ld r8,Z+
	ld r7,Z+
	ld r6,Z+
	ld r5,Z+
	ld r4,Z+
	ld r3,Z+
	ld r2,Z+
	ld r27,Z+
	ld r26,Z+
	ld r23,Z+
	ld r22,Z+
	ld r21,Z+
	ld r20,Z+
	ldi r18,16
33:
	ld r12,Z+
	mov r13,r1
	lsl r12
	sbc r13,r1
	rcall 70f
	mov r13,r1
	lsl r12
	sbc r13,r1
	rcall 70f
	mov r13,r1
	lsl r12
	sbc r13,r1
	rcall 70f
	mov r13,r1
	lsl r12
	sbc r13,r1
	rcall 70f
	mov r13,r1
	lsl r12
	sbc r13,r1
	rcall 70f
	mov r13,r1
	lsl r12
	sbc r13,r1
	rcall 70f
	mov r13,r1
	lsl r12
	sbc r13,r1
	rcall 70f
	mov r13,r1
	lsl r12
	sbc r13,r1
	rcall 70f
	dec r18
	brne 33b
	rjmp 172f
70:
	ldd r19,Y+1
	mov r14,r20
	and r14,r13
	eor r19,r14
	std Y+1,r19
	ldd r19,Y+2
	mov r14,r21
	and r14,r13
	eor r19,r14
	std Y+2,r19
	ldd r19,Y+3
	mov r14,r22
	and r14,r13
	eor r19,r14
	std Y+3,r19
	ldd r19,Y+4
	mov r14,r23
	and r14,r13
	eor r19,r14
	std Y+4,r19
	ldd r19,Y+5
	mov r14,r26
	and r14,r13
	eor r19,r14
	std Y+5,r19
	ldd r19,Y+6
	mov r14,r27
	and r14,r13
	eor r19,r14
	std Y+6,r19
	ldd r19,Y+7
	mov r14,r2
	and r14,r13
	eor r19,r14
	std Y+7,r19
	ldd r19,Y+8
	mov r14,r3
	and r14,r13
	eor r19,r14
	std Y+8,r19
	ldd r19,Y+9
	mov r14,r4
	and r14,r13
	eor r19,r14
	std Y+9,r19
	ldd r19,Y+10
	mov r14,r5
	and r14,r13
	eor r19,r14
	std Y+10,r19
	ldd r19,Y+11
	mov r14,r6
	and r14,r13
	eor r19,r14
	std Y+11,r19
	ldd r19,Y+12
	mov r14,r7
	and r14,r13
	eor r19,r14
	std Y+12,r19
	ldd r19,Y+13
	mov r14,r8
	and r14,r13
	eor r19,r14
	std Y+13,r19
	ldd r19,Y+14
	mov r14,r9
	and r14,r13
	eor r19,r14
	std Y+14,r19
	ldd r19,Y+15
	mov r14,r10
	and r14,r13
	eor r19,r14
	std Y+15,r19
	ldd r19,Y+16
	mov r14,r11
	and r14,r13
	eor r19,r14
	std Y+16,r19
	mov r19,r1
	lsr r11
	ror r10
	ror r9
	ror r8
	ror r7
	ror r6
	ror r5
	ror r4
	ror r3
	ror r2
	ror r27
	ror r26
	ror r23
	ror r22
	ror r21
	ror r20
	sbc r19,r1
	andi r19,225
	eor r11,r19
	ret 
172:
	ldd r20,Y+1
	ldd r21,Y+2
	ldd r22,Y+3
	ldd r23,Y+4
	ldd r26,Y+5
	ldd r27,Y+6
	ldd r2,Y+7
	ldd r3,Y+8
	ldd r4,Y+9
	ldd r5,Y+10
	ldd r6,Y+11
	ldd r7,Y+12
	ldd r8,Y+13
	ldd r9,Y+14
	ldd r10,Y+15
	ldd r11,Y+16
	st -Z,r20
	st -Z,r21
	st -Z,r22
	st -Z,r23
	st -Z,r26
	st -Z,r27
	st -Z,r2
	st -Z,r3
	st -Z,r4
	st -Z,r5
	st -Z,r6
	st -Z,r7
	st -Z,r8
	st -Z,r9
	st -Z,r10
	st -Z,r11
	adiw r28,16
	in r0,0x3f
	cli
	out 0x3e,r29
	out 0x3f,r0
	out 0x3d,r28
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop r7
	pop r6
	pop r5
	pop r4
	pop r3
	pop r2
	pop r29
	pop r28
	ret
	.size ghash_mul, .-ghash_mul

#endif
