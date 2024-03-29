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
.global keccakp_400_permute
	.type keccakp_400_permute, @function
keccakp_400_permute:
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
	push r15
	push r17
	movw r30,r24
.L__stack_usage = 17
	ld r6,Z
	ldd r7,Z+1
	ldd r8,Z+2
	ldd r9,Z+3
	ldd r10,Z+4
	ldd r11,Z+5
	ldd r12,Z+6
	ldd r13,Z+7
	ldd r14,Z+8
	ldd r15,Z+9
	cpi r22,20
	brcs 15f
	rcall 153f
	ldi r23,1
	eor r6,r23
15:
	cpi r22,19
	brcs 23f
	rcall 153f
	ldi r23,130
	eor r6,r23
	ldi r17,128
	eor r7,r17
23:
	cpi r22,18
	brcs 31f
	rcall 153f
	ldi r23,138
	eor r6,r23
	ldi r17,128
	eor r7,r17
31:
	cpi r22,17
	brcs 37f
	rcall 153f
	ldi r23,128
	eor r7,r23
37:
	cpi r22,16
	brcs 45f
	rcall 153f
	ldi r23,139
	eor r6,r23
	ldi r17,128
	eor r7,r17
45:
	cpi r22,15
	brcs 51f
	rcall 153f
	ldi r23,1
	eor r6,r23
51:
	cpi r22,14
	brcs 59f
	rcall 153f
	ldi r23,129
	eor r6,r23
	ldi r17,128
	eor r7,r17
59:
	cpi r22,13
	brcs 67f
	rcall 153f
	ldi r23,9
	eor r6,r23
	ldi r17,128
	eor r7,r17
67:
	cpi r22,12
	brcs 73f
	rcall 153f
	ldi r23,138
	eor r6,r23
73:
	cpi r22,11
	brcs 79f
	rcall 153f
	ldi r23,136
	eor r6,r23
79:
	cpi r22,10
	brcs 87f
	rcall 153f
	ldi r23,9
	eor r6,r23
	ldi r17,128
	eor r7,r17
87:
	cpi r22,9
	brcs 93f
	rcall 153f
	ldi r23,10
	eor r6,r23
93:
	cpi r22,8
	brcs 101f
	rcall 153f
	ldi r23,139
	eor r6,r23
	ldi r17,128
	eor r7,r17
101:
	cpi r22,7
	brcs 107f
	rcall 153f
	ldi r23,139
	eor r6,r23
107:
	cpi r22,6
	brcs 115f
	rcall 153f
	ldi r23,137
	eor r6,r23
	ldi r17,128
	eor r7,r17
115:
	cpi r22,5
	brcs 123f
	rcall 153f
	ldi r23,3
	eor r6,r23
	ldi r17,128
	eor r7,r17
123:
	cpi r22,4
	brcs 131f
	rcall 153f
	ldi r23,2
	eor r6,r23
	ldi r17,128
	eor r7,r17
131:
	cpi r22,3
	brcs 137f
	rcall 153f
	ldi r23,128
	eor r6,r23
137:
	cpi r22,2
	brcs 145f
	rcall 153f
	ldi r23,10
	eor r6,r23
	ldi r17,128
	eor r7,r17
145:
	cpi r22,1
	brcs 151f
	rcall 153f
	ldi r23,10
	eor r6,r23
151:
	rjmp 1004f
153:
	movw r18,r6
	ldd r0,Z+10
	eor r18,r0
	ldd r0,Z+11
	eor r19,r0
	ldd r0,Z+20
	eor r18,r0
	ldd r0,Z+21
	eor r19,r0
	ldd r0,Z+30
	eor r18,r0
	ldd r0,Z+31
	eor r19,r0
	ldd r0,Z+40
	eor r18,r0
	ldd r0,Z+41
	eor r19,r0
	movw r20,r8
	ldd r0,Z+12
	eor r20,r0
	ldd r0,Z+13
	eor r21,r0
	ldd r0,Z+22
	eor r20,r0
	ldd r0,Z+23
	eor r21,r0
	ldd r0,Z+32
	eor r20,r0
	ldd r0,Z+33
	eor r21,r0
	ldd r0,Z+42
	eor r20,r0
	ldd r0,Z+43
	eor r21,r0
	movw r26,r10
	ldd r0,Z+14
	eor r26,r0
	ldd r0,Z+15
	eor r27,r0
	ldd r0,Z+24
	eor r26,r0
	ldd r0,Z+25
	eor r27,r0
	ldd r0,Z+34
	eor r26,r0
	ldd r0,Z+35
	eor r27,r0
	ldd r0,Z+44
	eor r26,r0
	ldd r0,Z+45
	eor r27,r0
	movw r2,r12
	ldd r0,Z+16
	eor r2,r0
	ldd r0,Z+17
	eor r3,r0
	ldd r0,Z+26
	eor r2,r0
	ldd r0,Z+27
	eor r3,r0
	ldd r0,Z+36
	eor r2,r0
	ldd r0,Z+37
	eor r3,r0
	ldd r0,Z+46
	eor r2,r0
	ldd r0,Z+47
	eor r3,r0
	movw r4,r14
	ldd r0,Z+18
	eor r4,r0
	ldd r0,Z+19
	eor r5,r0
	ldd r0,Z+28
	eor r4,r0
	ldd r0,Z+29
	eor r5,r0
	ldd r0,Z+38
	eor r4,r0
	ldd r0,Z+39
	eor r5,r0
	ldd r0,Z+48
	eor r4,r0
	ldd r0,Z+49
	eor r5,r0
	movw r24,r20
	lsl r24
	rol r25
	adc r24,r1
	eor r24,r4
	eor r25,r5
	eor r6,r24
	eor r7,r25
	ldd r0,Z+10
	eor r0,r24
	std Z+10,r0
	ldd r0,Z+11
	eor r0,r25
	std Z+11,r0
	ldd r0,Z+20
	eor r0,r24
	std Z+20,r0
	ldd r0,Z+21
	eor r0,r25
	std Z+21,r0
	ldd r0,Z+30
	eor r0,r24
	std Z+30,r0
	ldd r0,Z+31
	eor r0,r25
	std Z+31,r0
	ldd r0,Z+40
	eor r0,r24
	std Z+40,r0
	ldd r0,Z+41
	eor r0,r25
	std Z+41,r0
	movw r24,r26
	lsl r24
	rol r25
	adc r24,r1
	eor r24,r18
	eor r25,r19
	eor r8,r24
	eor r9,r25
	ldd r0,Z+12
	eor r0,r24
	std Z+12,r0
	ldd r0,Z+13
	eor r0,r25
	std Z+13,r0
	ldd r0,Z+22
	eor r0,r24
	std Z+22,r0
	ldd r0,Z+23
	eor r0,r25
	std Z+23,r0
	ldd r0,Z+32
	eor r0,r24
	std Z+32,r0
	ldd r0,Z+33
	eor r0,r25
	std Z+33,r0
	ldd r0,Z+42
	eor r0,r24
	std Z+42,r0
	ldd r0,Z+43
	eor r0,r25
	std Z+43,r0
	movw r24,r2
	lsl r24
	rol r25
	adc r24,r1
	eor r24,r20
	eor r25,r21
	eor r10,r24
	eor r11,r25
	ldd r0,Z+14
	eor r0,r24
	std Z+14,r0
	ldd r0,Z+15
	eor r0,r25
	std Z+15,r0
	ldd r0,Z+24
	eor r0,r24
	std Z+24,r0
	ldd r0,Z+25
	eor r0,r25
	std Z+25,r0
	ldd r0,Z+34
	eor r0,r24
	std Z+34,r0
	ldd r0,Z+35
	eor r0,r25
	std Z+35,r0
	ldd r0,Z+44
	eor r0,r24
	std Z+44,r0
	ldd r0,Z+45
	eor r0,r25
	std Z+45,r0
	movw r24,r4
	lsl r24
	rol r25
	adc r24,r1
	eor r24,r26
	eor r25,r27
	eor r12,r24
	eor r13,r25
	ldd r0,Z+16
	eor r0,r24
	std Z+16,r0
	ldd r0,Z+17
	eor r0,r25
	std Z+17,r0
	ldd r0,Z+26
	eor r0,r24
	std Z+26,r0
	ldd r0,Z+27
	eor r0,r25
	std Z+27,r0
	ldd r0,Z+36
	eor r0,r24
	std Z+36,r0
	ldd r0,Z+37
	eor r0,r25
	std Z+37,r0
	ldd r0,Z+46
	eor r0,r24
	std Z+46,r0
	ldd r0,Z+47
	eor r0,r25
	std Z+47,r0
	movw r24,r18
	lsl r24
	rol r25
	adc r24,r1
	eor r24,r2
	eor r25,r3
	eor r14,r24
	eor r15,r25
	ldd r0,Z+18
	eor r0,r24
	std Z+18,r0
	ldd r0,Z+19
	eor r0,r25
	std Z+19,r0
	ldd r0,Z+28
	eor r0,r24
	std Z+28,r0
	ldd r0,Z+29
	eor r0,r25
	std Z+29,r0
	ldd r0,Z+38
	eor r0,r24
	std Z+38,r0
	ldd r0,Z+39
	eor r0,r25
	std Z+39,r0
	ldd r0,Z+48
	eor r0,r24
	std Z+48,r0
	ldd r0,Z+49
	eor r0,r25
	std Z+49,r0
	movw r24,r8
	ldd r8,Z+12
	ldd r9,Z+13
	mov r0,r9
	mov r9,r8
	mov r8,r0
	lsl r8
	rol r9
	adc r8,r1
	lsl r8
	rol r9
	adc r8,r1
	lsl r8
	rol r9
	adc r8,r1
	lsl r8
	rol r9
	adc r8,r1
	ldd r18,Z+18
	ldd r19,Z+19
	lsl r18
	rol r19
	adc r18,r1
	lsl r18
	rol r19
	adc r18,r1
	lsl r18
	rol r19
	adc r18,r1
	lsl r18
	rol r19
	adc r18,r1
	std Z+12,r18
	std Z+13,r19
	ldd r18,Z+44
	ldd r19,Z+45
	mov r0,r1
	lsr r19
	ror r18
	ror r0
	lsr r19
	ror r18
	ror r0
	lsr r19
	ror r18
	ror r0
	or r19,r0
	std Z+18,r18
	std Z+19,r19
	ldd r18,Z+28
	ldd r19,Z+29
	mov r0,r19
	mov r19,r18
	mov r18,r0
	bst r18,0
	lsr r19
	ror r18
	bld r19,7
	std Z+44,r18
	std Z+45,r19
	ldd r18,Z+40
	ldd r19,Z+41
	lsl r18
	rol r19
	adc r18,r1
	lsl r18
	rol r19
	adc r18,r1
	std Z+28,r18
	std Z+29,r19
	movw r18,r10
	mov r0,r1
	lsr r19
	ror r18
	ror r0
	lsr r19
	ror r18
	ror r0
	or r19,r0
	std Z+40,r18
	std Z+41,r19
	ldd r10,Z+24
	ldd r11,Z+25
	mov r0,r11
	mov r11,r10
	mov r10,r0
	lsl r10
	rol r11
	adc r10,r1
	lsl r10
	rol r11
	adc r10,r1
	lsl r10
	rol r11
	adc r10,r1
	ldd r18,Z+26
	ldd r19,Z+27
	mov r0,r19
	mov r19,r18
	mov r18,r0
	lsl r18
	rol r19
	adc r18,r1
	std Z+24,r18
	std Z+25,r19
	ldd r18,Z+38
	ldd r19,Z+39
	mov r0,r19
	mov r19,r18
	mov r18,r0
	std Z+26,r18
	std Z+27,r19
	ldd r18,Z+46
	ldd r19,Z+47
	mov r0,r19
	mov r19,r18
	mov r18,r0
	std Z+38,r18
	std Z+39,r19
	ldd r18,Z+30
	ldd r19,Z+31
	mov r0,r19
	mov r19,r18
	mov r18,r0
	lsl r18
	rol r19
	adc r18,r1
	std Z+46,r18
	std Z+47,r19
	movw r18,r14
	mov r0,r19
	mov r19,r18
	mov r18,r0
	lsl r18
	rol r19
	adc r18,r1
	lsl r18
	rol r19
	adc r18,r1
	lsl r18
	rol r19
	adc r18,r1
	std Z+30,r18
	std Z+31,r19
	ldd r14,Z+48
	ldd r15,Z+49
	mov r0,r1
	lsr r15
	ror r14
	ror r0
	lsr r15
	ror r14
	ror r0
	or r15,r0
	ldd r18,Z+42
	ldd r19,Z+43
	lsl r18
	rol r19
	adc r18,r1
	lsl r18
	rol r19
	adc r18,r1
	std Z+48,r18
	std Z+49,r19
	ldd r18,Z+16
	ldd r19,Z+17
	mov r0,r19
	mov r19,r18
	mov r18,r0
	bst r18,0
	lsr r19
	ror r18
	bld r19,7
	std Z+42,r18
	std Z+43,r19
	ldd r18,Z+32
	ldd r19,Z+33
	mov r0,r1
	lsr r19
	ror r18
	ror r0
	lsr r19
	ror r18
	ror r0
	lsr r19
	ror r18
	ror r0
	or r19,r0
	std Z+16,r18
	std Z+17,r19
	ldd r18,Z+10
	ldd r19,Z+11
	lsl r18
	rol r19
	adc r18,r1
	lsl r18
	rol r19
	adc r18,r1
	lsl r18
	rol r19
	adc r18,r1
	lsl r18
	rol r19
	adc r18,r1
	std Z+32,r18
	std Z+33,r19
	movw r18,r12
	mov r0,r19
	mov r19,r18
	mov r18,r0
	lsl r18
	rol r19
	adc r18,r1
	lsl r18
	rol r19
	adc r18,r1
	lsl r18
	rol r19
	adc r18,r1
	lsl r18
	rol r19
	adc r18,r1
	std Z+10,r18
	std Z+11,r19
	ldd r12,Z+36
	ldd r13,Z+37
	mov r0,r13
	mov r13,r12
	mov r12,r0
	mov r0,r1
	lsr r13
	ror r12
	ror r0
	lsr r13
	ror r12
	ror r0
	lsr r13
	ror r12
	ror r0
	or r13,r0
	ldd r18,Z+34
	ldd r19,Z+35
	bst r18,0
	lsr r19
	ror r18
	bld r19,7
	std Z+36,r18
	std Z+37,r19
	ldd r18,Z+22
	ldd r19,Z+23
	mov r0,r19
	mov r19,r18
	mov r18,r0
	lsl r18
	rol r19
	adc r18,r1
	lsl r18
	rol r19
	adc r18,r1
	std Z+34,r18
	std Z+35,r19
	ldd r18,Z+14
	ldd r19,Z+15
	mov r0,r19
	mov r19,r18
	mov r18,r0
	mov r0,r1
	lsr r19
	ror r18
	ror r0
	lsr r19
	ror r18
	ror r0
	or r19,r0
	std Z+22,r18
	std Z+23,r19
	ldd r18,Z+20
	ldd r19,Z+21
	lsl r18
	rol r19
	adc r18,r1
	lsl r18
	rol r19
	adc r18,r1
	lsl r18
	rol r19
	adc r18,r1
	std Z+14,r18
	std Z+15,r19
	lsl r24
	rol r25
	adc r24,r1
	std Z+20,r24
	std Z+21,r25
	movw r18,r6
	movw r20,r8
	movw r26,r10
	movw r2,r12
	movw r4,r14
	movw r6,r26
	mov r0,r20
	com r0
	and r6,r0
	mov r0,r21
	com r0
	and r7,r0
	eor r6,r18
	eor r7,r19
	movw r8,r2
	mov r0,r26
	com r0
	and r8,r0
	mov r0,r27
	com r0
	and r9,r0
	eor r8,r20
	eor r9,r21
	movw r10,r4
	mov r0,r2
	com r0
	and r10,r0
	mov r0,r3
	com r0
	and r11,r0
	eor r10,r26
	eor r11,r27
	movw r12,r18
	mov r0,r4
	com r0
	and r12,r0
	mov r0,r5
	com r0
	and r13,r0
	eor r12,r2
	eor r13,r3
	movw r14,r20
	mov r0,r18
	com r0
	and r14,r0
	mov r0,r19
	com r0
	and r15,r0
	eor r14,r4
	eor r15,r5
	ldd r18,Z+10
	ldd r19,Z+11
	ldd r20,Z+12
	ldd r21,Z+13
	ldd r26,Z+14
	ldd r27,Z+15
	ldd r2,Z+16
	ldd r3,Z+17
	ldd r4,Z+18
	ldd r5,Z+19
	movw r24,r26
	mov r0,r20
	com r0
	and r24,r0
	mov r0,r21
	com r0
	and r25,r0
	eor r24,r18
	eor r25,r19
	std Z+10,r24
	std Z+11,r25
	movw r24,r2
	mov r0,r26
	com r0
	and r24,r0
	mov r0,r27
	com r0
	and r25,r0
	eor r24,r20
	eor r25,r21
	std Z+12,r24
	std Z+13,r25
	movw r24,r4
	mov r0,r2
	com r0
	and r24,r0
	mov r0,r3
	com r0
	and r25,r0
	eor r24,r26
	eor r25,r27
	std Z+14,r24
	std Z+15,r25
	movw r24,r18
	mov r0,r4
	com r0
	and r24,r0
	mov r0,r5
	com r0
	and r25,r0
	eor r24,r2
	eor r25,r3
	std Z+16,r24
	std Z+17,r25
	movw r24,r20
	mov r0,r18
	com r0
	and r24,r0
	mov r0,r19
	com r0
	and r25,r0
	eor r24,r4
	eor r25,r5
	std Z+18,r24
	std Z+19,r25
	ldd r18,Z+20
	ldd r19,Z+21
	ldd r20,Z+22
	ldd r21,Z+23
	ldd r26,Z+24
	ldd r27,Z+25
	ldd r2,Z+26
	ldd r3,Z+27
	ldd r4,Z+28
	ldd r5,Z+29
	movw r24,r26
	mov r0,r20
	com r0
	and r24,r0
	mov r0,r21
	com r0
	and r25,r0
	eor r24,r18
	eor r25,r19
	std Z+20,r24
	std Z+21,r25
	movw r24,r2
	mov r0,r26
	com r0
	and r24,r0
	mov r0,r27
	com r0
	and r25,r0
	eor r24,r20
	eor r25,r21
	std Z+22,r24
	std Z+23,r25
	movw r24,r4
	mov r0,r2
	com r0
	and r24,r0
	mov r0,r3
	com r0
	and r25,r0
	eor r24,r26
	eor r25,r27
	std Z+24,r24
	std Z+25,r25
	movw r24,r18
	mov r0,r4
	com r0
	and r24,r0
	mov r0,r5
	com r0
	and r25,r0
	eor r24,r2
	eor r25,r3
	std Z+26,r24
	std Z+27,r25
	movw r24,r20
	mov r0,r18
	com r0
	and r24,r0
	mov r0,r19
	com r0
	and r25,r0
	eor r24,r4
	eor r25,r5
	std Z+28,r24
	std Z+29,r25
	ldd r18,Z+30
	ldd r19,Z+31
	ldd r20,Z+32
	ldd r21,Z+33
	ldd r26,Z+34
	ldd r27,Z+35
	ldd r2,Z+36
	ldd r3,Z+37
	ldd r4,Z+38
	ldd r5,Z+39
	movw r24,r26
	mov r0,r20
	com r0
	and r24,r0
	mov r0,r21
	com r0
	and r25,r0
	eor r24,r18
	eor r25,r19
	std Z+30,r24
	std Z+31,r25
	movw r24,r2
	mov r0,r26
	com r0
	and r24,r0
	mov r0,r27
	com r0
	and r25,r0
	eor r24,r20
	eor r25,r21
	std Z+32,r24
	std Z+33,r25
	movw r24,r4
	mov r0,r2
	com r0
	and r24,r0
	mov r0,r3
	com r0
	and r25,r0
	eor r24,r26
	eor r25,r27
	std Z+34,r24
	std Z+35,r25
	movw r24,r18
	mov r0,r4
	com r0
	and r24,r0
	mov r0,r5
	com r0
	and r25,r0
	eor r24,r2
	eor r25,r3
	std Z+36,r24
	std Z+37,r25
	movw r24,r20
	mov r0,r18
	com r0
	and r24,r0
	mov r0,r19
	com r0
	and r25,r0
	eor r24,r4
	eor r25,r5
	std Z+38,r24
	std Z+39,r25
	ldd r18,Z+40
	ldd r19,Z+41
	ldd r20,Z+42
	ldd r21,Z+43
	ldd r26,Z+44
	ldd r27,Z+45
	ldd r2,Z+46
	ldd r3,Z+47
	ldd r4,Z+48
	ldd r5,Z+49
	movw r24,r26
	mov r0,r20
	com r0
	and r24,r0
	mov r0,r21
	com r0
	and r25,r0
	eor r24,r18
	eor r25,r19
	std Z+40,r24
	std Z+41,r25
	movw r24,r2
	mov r0,r26
	com r0
	and r24,r0
	mov r0,r27
	com r0
	and r25,r0
	eor r24,r20
	eor r25,r21
	std Z+42,r24
	std Z+43,r25
	movw r24,r4
	mov r0,r2
	com r0
	and r24,r0
	mov r0,r3
	com r0
	and r25,r0
	eor r24,r26
	eor r25,r27
	std Z+44,r24
	std Z+45,r25
	movw r24,r18
	mov r0,r4
	com r0
	and r24,r0
	mov r0,r5
	com r0
	and r25,r0
	eor r24,r2
	eor r25,r3
	std Z+46,r24
	std Z+47,r25
	movw r24,r20
	mov r0,r18
	com r0
	and r24,r0
	mov r0,r19
	com r0
	and r25,r0
	eor r24,r4
	eor r25,r5
	std Z+48,r24
	std Z+49,r25
	ret 
1004:
	st Z,r6
	std Z+1,r7
	std Z+2,r8
	std Z+3,r9
	std Z+4,r10
	std Z+5,r11
	std Z+6,r12
	std Z+7,r13
	std Z+8,r14
	std Z+9,r15
	pop r17
	pop r15
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
	ret
	.size keccakp_400_permute, .-keccakp_400_permute

#endif
