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

	.section	.progmem.data,"a",@progbits
	.p2align	8
	.type	table_0, @object
	.size	table_0, 256
table_0:
	.byte	238
	.byte	237
	.byte	235
	.byte	224
	.byte	226
	.byte	225
	.byte	228
	.byte	239
	.byte	231
	.byte	234
	.byte	232
	.byte	229
	.byte	233
	.byte	236
	.byte	227
	.byte	230
	.byte	222
	.byte	221
	.byte	219
	.byte	208
	.byte	210
	.byte	209
	.byte	212
	.byte	223
	.byte	215
	.byte	218
	.byte	216
	.byte	213
	.byte	217
	.byte	220
	.byte	211
	.byte	214
	.byte	190
	.byte	189
	.byte	187
	.byte	176
	.byte	178
	.byte	177
	.byte	180
	.byte	191
	.byte	183
	.byte	186
	.byte	184
	.byte	181
	.byte	185
	.byte	188
	.byte	179
	.byte	182
	.byte	14
	.byte	13
	.byte	11
	.byte	0
	.byte	2
	.byte	1
	.byte	4
	.byte	15
	.byte	7
	.byte	10
	.byte	8
	.byte	5
	.byte	9
	.byte	12
	.byte	3
	.byte	6
	.byte	46
	.byte	45
	.byte	43
	.byte	32
	.byte	34
	.byte	33
	.byte	36
	.byte	47
	.byte	39
	.byte	42
	.byte	40
	.byte	37
	.byte	41
	.byte	44
	.byte	35
	.byte	38
	.byte	30
	.byte	29
	.byte	27
	.byte	16
	.byte	18
	.byte	17
	.byte	20
	.byte	31
	.byte	23
	.byte	26
	.byte	24
	.byte	21
	.byte	25
	.byte	28
	.byte	19
	.byte	22
	.byte	78
	.byte	77
	.byte	75
	.byte	64
	.byte	66
	.byte	65
	.byte	68
	.byte	79
	.byte	71
	.byte	74
	.byte	72
	.byte	69
	.byte	73
	.byte	76
	.byte	67
	.byte	70
	.byte	254
	.byte	253
	.byte	251
	.byte	240
	.byte	242
	.byte	241
	.byte	244
	.byte	255
	.byte	247
	.byte	250
	.byte	248
	.byte	245
	.byte	249
	.byte	252
	.byte	243
	.byte	246
	.byte	126
	.byte	125
	.byte	123
	.byte	112
	.byte	114
	.byte	113
	.byte	116
	.byte	127
	.byte	119
	.byte	122
	.byte	120
	.byte	117
	.byte	121
	.byte	124
	.byte	115
	.byte	118
	.byte	174
	.byte	173
	.byte	171
	.byte	160
	.byte	162
	.byte	161
	.byte	164
	.byte	175
	.byte	167
	.byte	170
	.byte	168
	.byte	165
	.byte	169
	.byte	172
	.byte	163
	.byte	166
	.byte	142
	.byte	141
	.byte	139
	.byte	128
	.byte	130
	.byte	129
	.byte	132
	.byte	143
	.byte	135
	.byte	138
	.byte	136
	.byte	133
	.byte	137
	.byte	140
	.byte	131
	.byte	134
	.byte	94
	.byte	93
	.byte	91
	.byte	80
	.byte	82
	.byte	81
	.byte	84
	.byte	95
	.byte	87
	.byte	90
	.byte	88
	.byte	85
	.byte	89
	.byte	92
	.byte	83
	.byte	86
	.byte	158
	.byte	157
	.byte	155
	.byte	144
	.byte	146
	.byte	145
	.byte	148
	.byte	159
	.byte	151
	.byte	154
	.byte	152
	.byte	149
	.byte	153
	.byte	156
	.byte	147
	.byte	150
	.byte	206
	.byte	205
	.byte	203
	.byte	192
	.byte	194
	.byte	193
	.byte	196
	.byte	207
	.byte	199
	.byte	202
	.byte	200
	.byte	197
	.byte	201
	.byte	204
	.byte	195
	.byte	198
	.byte	62
	.byte	61
	.byte	59
	.byte	48
	.byte	50
	.byte	49
	.byte	52
	.byte	63
	.byte	55
	.byte	58
	.byte	56
	.byte	53
	.byte	57
	.byte	60
	.byte	51
	.byte	54
	.byte	110
	.byte	109
	.byte	107
	.byte	96
	.byte	98
	.byte	97
	.byte	100
	.byte	111
	.byte	103
	.byte	106
	.byte	104
	.byte	101
	.byte	105
	.byte	108
	.byte	99
	.byte	102

	.text
.global spongent160_permute
	.type spongent160_permute, @function
spongent160_permute:
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
	push r15
	movw r30,r24
.L__stack_usage = 16
	ld r22,Z
	ldd r23,Z+1
	ldd r28,Z+2
	ldd r29,Z+3
	ldd r2,Z+4
	ldd r3,Z+5
	ldd r4,Z+6
	ldd r5,Z+7
	ldd r6,Z+8
	ldd r7,Z+9
	ldd r8,Z+10
	ldd r9,Z+11
	ldd r10,Z+12
	ldd r11,Z+13
	ldd r12,Z+14
	ldd r13,Z+15
	ldd r14,Z+16
	ldd r15,Z+17
	ldd r24,Z+18
	ldd r25,Z+19
	movw r26,r30
	ldi r30,lo8(table_0)
	ldi r31,hi8(table_0)
#if defined(RAMPZ)
	ldi r21,hh8(table_0)
	in r0,_SFR_IO_ADDR(RAMPZ)
	push r0
	out _SFR_IO_ADDR(RAMPZ),r21
#endif
	ldi r18,80
	ldi r19,117
	ldi r20,174
25:
	eor r22,r19
	eor r25,r20
	lsl r19
	bst r19,7
	bld r19,0
	mov r0,r1
	bst r19,6
	bld r0,0
	eor r19,r0
	andi r19,127
	lsr r20
	bst r20,0
	bld r20,7
	mov r0,r1
	bst r20,1
	bld r0,7
	eor r20,r0
	andi r20,254
	mov r30,r22
#if defined(RAMPZ)
	elpm r22,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r22,Z
#elif defined(__AVR_TINY__)
	ld r22,Z
#else
	lpm
	mov r22,r0
#endif
	mov r30,r23
#if defined(RAMPZ)
	elpm r23,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r23,Z
#elif defined(__AVR_TINY__)
	ld r23,Z
#else
	lpm
	mov r23,r0
#endif
	mov r30,r28
#if defined(RAMPZ)
	elpm r28,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r28,Z
#elif defined(__AVR_TINY__)
	ld r28,Z
#else
	lpm
	mov r28,r0
#endif
	mov r30,r29
#if defined(RAMPZ)
	elpm r29,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r29,Z
#elif defined(__AVR_TINY__)
	ld r29,Z
#else
	lpm
	mov r29,r0
#endif
	mov r30,r2
#if defined(RAMPZ)
	elpm r2,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r2,Z
#elif defined(__AVR_TINY__)
	ld r2,Z
#else
	lpm
	mov r2,r0
#endif
	mov r30,r3
#if defined(RAMPZ)
	elpm r3,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r3,Z
#elif defined(__AVR_TINY__)
	ld r3,Z
#else
	lpm
	mov r3,r0
#endif
	mov r30,r4
#if defined(RAMPZ)
	elpm r4,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r4,Z
#elif defined(__AVR_TINY__)
	ld r4,Z
#else
	lpm
	mov r4,r0
#endif
	mov r30,r5
#if defined(RAMPZ)
	elpm r5,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r5,Z
#elif defined(__AVR_TINY__)
	ld r5,Z
#else
	lpm
	mov r5,r0
#endif
	mov r30,r6
#if defined(RAMPZ)
	elpm r6,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r6,Z
#elif defined(__AVR_TINY__)
	ld r6,Z
#else
	lpm
	mov r6,r0
#endif
	mov r30,r7
#if defined(RAMPZ)
	elpm r7,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r7,Z
#elif defined(__AVR_TINY__)
	ld r7,Z
#else
	lpm
	mov r7,r0
#endif
	mov r30,r8
#if defined(RAMPZ)
	elpm r8,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r8,Z
#elif defined(__AVR_TINY__)
	ld r8,Z
#else
	lpm
	mov r8,r0
#endif
	mov r30,r9
#if defined(RAMPZ)
	elpm r9,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r9,Z
#elif defined(__AVR_TINY__)
	ld r9,Z
#else
	lpm
	mov r9,r0
#endif
	mov r30,r10
#if defined(RAMPZ)
	elpm r10,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r10,Z
#elif defined(__AVR_TINY__)
	ld r10,Z
#else
	lpm
	mov r10,r0
#endif
	mov r30,r11
#if defined(RAMPZ)
	elpm r11,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r11,Z
#elif defined(__AVR_TINY__)
	ld r11,Z
#else
	lpm
	mov r11,r0
#endif
	mov r30,r12
#if defined(RAMPZ)
	elpm r12,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r12,Z
#elif defined(__AVR_TINY__)
	ld r12,Z
#else
	lpm
	mov r12,r0
#endif
	mov r30,r13
#if defined(RAMPZ)
	elpm r13,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r13,Z
#elif defined(__AVR_TINY__)
	ld r13,Z
#else
	lpm
	mov r13,r0
#endif
	mov r30,r14
#if defined(RAMPZ)
	elpm r14,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r14,Z
#elif defined(__AVR_TINY__)
	ld r14,Z
#else
	lpm
	mov r14,r0
#endif
	mov r30,r15
#if defined(RAMPZ)
	elpm r15,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r15,Z
#elif defined(__AVR_TINY__)
	ld r15,Z
#else
	lpm
	mov r15,r0
#endif
	mov r30,r24
#if defined(RAMPZ)
	elpm r24,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r24,Z
#elif defined(__AVR_TINY__)
	ld r24,Z
#else
	lpm
	mov r24,r0
#endif
	mov r30,r25
#if defined(RAMPZ)
	elpm r25,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r25,Z
#elif defined(__AVR_TINY__)
	ld r25,Z
#else
	lpm
	mov r25,r0
#endif
	bst r22,1
	bld r0,0
	bst r22,4
	bld r22,1
	bst r28,0
	bld r22,4
	bst r6,0
	bld r28,0
	bst r10,1
	bld r6,0
	bst r6,6
	bld r10,1
	bst r13,1
	bld r6,6
	bst r22,7
	bld r13,1
	bst r29,4
	bld r22,7
	bst r12,0
	bld r29,4
	bst r14,2
	bld r12,0
	bst r3,3
	bld r14,2
	bst r23,5
	bld r3,3
	bst r4,4
	bld r23,5
	bst r4,1
	bld r4,4
	bst r2,5
	bld r4,1
	bst r24,4
	bld r2,5
	bst r12,3
	bld r24,4
	bst r15,6
	bld r12,3
	bst r9,3
	bld r15,6
	bst r3,6
	bld r9,3
	bst r29,1
	bld r3,6
	bst r10,4
	bld r29,1
	bst r8,2
	bld r10,4
	bst r23,2
	bld r8,2
	bst r3,0
	bld r23,2
	bst r0,0
	bld r3,0
	bst r22,2
	bld r0,0
	bst r23,0
	bld r22,2
	bst r2,0
	bld r23,0
	bst r14,0
	bld r2,0
	bst r2,3
	bld r14,0
	bst r15,4
	bld r2,3
	bst r8,3
	bld r15,4
	bst r23,6
	bld r8,3
	bst r5,0
	bld r23,6
	bst r6,1
	bld r5,0
	bst r10,5
	bld r6,1
	bst r8,6
	bld r10,5
	bst r29,2
	bld r8,6
	bst r11,0
	bld r29,2
	bst r10,2
	bld r11,0
	bst r7,2
	bld r10,2
	bst r15,1
	bld r7,2
	bst r6,7
	bld r15,1
	bst r13,5
	bld r6,7
	bst r28,7
	bld r13,5
	bst r9,4
	bld r28,7
	bst r4,2
	bld r9,4
	bst r3,1
	bld r4,2
	bst r22,5
	bld r3,1
	bst r28,4
	bld r22,5
	bst r8,0
	bld r28,4
	bst r0,0
	bld r8,0
	bst r22,3
	bld r0,0
	bst r23,4
	bld r22,3
	bst r4,0
	bld r23,4
	bst r2,1
	bld r4,0
	bst r14,4
	bld r2,1
	bst r4,3
	bld r14,4
	bst r3,5
	bld r4,3
	bst r28,5
	bld r3,5
	bst r8,4
	bld r28,5
	bst r28,2
	bld r8,4
	bst r7,0
	bld r28,2
	bst r14,1
	bld r7,0
	bst r2,7
	bld r14,1
	bst r25,4
	bld r2,7
	bst r24,3
	bld r25,4
	bst r11,7
	bld r24,3
	bst r13,6
	bld r11,7
	bst r29,3
	bld r13,6
	bst r11,4
	bld r29,3
	bst r12,2
	bld r11,4
	bst r15,2
	bld r12,2
	bst r7,3
	bld r15,2
	bst r15,5
	bld r7,3
	bst r8,7
	bld r15,5
	bst r29,6
	bld r8,7
	bst r13,0
	bld r29,6
	bst r0,0
	bld r13,0
	bst r22,6
	bld r0,0
	bst r29,0
	bld r22,6
	bst r10,0
	bld r29,0
	bst r6,2
	bld r10,0
	bst r11,1
	bld r6,2
	bst r10,6
	bld r11,1
	bst r9,2
	bld r10,6
	bst r3,2
	bld r9,2
	bst r23,1
	bld r3,2
	bst r2,4
	bld r23,1
	bst r24,0
	bld r2,4
	bst r10,3
	bld r24,0
	bst r7,6
	bld r10,3
	bst r25,1
	bld r7,6
	bst r14,7
	bld r25,1
	bst r5,7
	bld r14,7
	bst r9,5
	bld r5,7
	bst r4,6
	bld r9,5
	bst r5,1
	bld r4,6
	bst r6,5
	bld r5,1
	bst r12,5
	bld r6,5
	bst r24,6
	bld r12,5
	bst r13,3
	bld r24,6
	bst r23,7
	bld r13,3
	bst r5,4
	bld r23,7
	bst r8,1
	bld r5,4
	bst r0,0
	bld r8,1
	bst r23,3
	bld r0,0
	bst r3,4
	bld r23,3
	bst r28,1
	bld r3,4
	bst r6,4
	bld r28,1
	bst r12,1
	bld r6,4
	bst r14,6
	bld r12,1
	bst r5,3
	bld r14,6
	bst r7,5
	bld r5,3
	bst r24,5
	bld r7,5
	bst r12,7
	bld r24,5
	bst r25,6
	bld r12,7
	bst r25,3
	bld r25,6
	bst r15,7
	bld r25,3
	bst r9,7
	bld r15,7
	bst r5,6
	bld r9,7
	bst r9,1
	bld r5,6
	bst r2,6
	bld r9,1
	bst r25,0
	bld r2,6
	bst r14,3
	bld r25,0
	bst r3,7
	bld r14,3
	bst r29,5
	bld r3,7
	bst r12,4
	bld r29,5
	bst r24,2
	bld r12,4
	bst r11,3
	bld r24,2
	bst r11,6
	bld r11,3
	bst r13,2
	bld r11,6
	bst r0,0
	bld r13,2
	bst r28,3
	bld r0,0
	bst r7,4
	bld r28,3
	bst r24,1
	bld r7,4
	bst r10,7
	bld r24,1
	bst r9,6
	bld r10,7
	bst r5,2
	bld r9,6
	bst r7,1
	bld r5,2
	bst r14,5
	bld r7,1
	bst r4,7
	bld r14,5
	bst r5,5
	bld r4,7
	bst r8,5
	bld r5,5
	bst r28,6
	bld r8,5
	bst r9,0
	bld r28,6
	bst r2,2
	bld r9,0
	bst r15,0
	bld r2,2
	bst r6,3
	bld r15,0
	bst r11,5
	bld r6,3
	bst r12,6
	bld r11,5
	bst r25,2
	bld r12,6
	bst r15,3
	bld r25,2
	bst r7,7
	bld r15,3
	bst r25,5
	bld r7,7
	bst r24,7
	bld r25,5
	bst r13,7
	bld r24,7
	bst r29,7
	bld r13,7
	bst r13,4
	bld r29,7
	bst r0,0
	bld r13,4
	dec r18
	breq 5389f
	rjmp 25b
5389:
#if defined(RAMPZ)
	pop r0
	out _SFR_IO_ADDR(RAMPZ),r0
#endif
	st X+,r22
	st X+,r23
	st X+,r28
	st X+,r29
	st X+,r2
	st X+,r3
	st X+,r4
	st X+,r5
	st X+,r6
	st X+,r7
	st X+,r8
	st X+,r9
	st X+,r10
	st X+,r11
	st X+,r12
	st X+,r13
	st X+,r14
	st X+,r15
	st X+,r24
	st X+,r25
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
	pop r29
	pop r28
	ret
	.size spongent160_permute, .-spongent160_permute

	.text
.global spongent176_permute
	.type spongent176_permute, @function
spongent176_permute:
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
	push r15
	push r16
	push r17
	movw r30,r24
.L__stack_usage = 18
	ld r22,Z
	ldd r23,Z+1
	ldd r28,Z+2
	ldd r29,Z+3
	ldd r2,Z+4
	ldd r3,Z+5
	ldd r4,Z+6
	ldd r5,Z+7
	ldd r6,Z+8
	ldd r7,Z+9
	ldd r8,Z+10
	ldd r9,Z+11
	ldd r10,Z+12
	ldd r11,Z+13
	ldd r12,Z+14
	ldd r13,Z+15
	ldd r14,Z+16
	ldd r15,Z+17
	ldd r24,Z+18
	ldd r25,Z+19
	ldd r16,Z+20
	ldd r17,Z+21
	movw r26,r30
	ldi r30,lo8(table_0)
	ldi r31,hi8(table_0)
#if defined(RAMPZ)
	ldi r21,hh8(table_0)
	in r0,_SFR_IO_ADDR(RAMPZ)
	push r0
	out _SFR_IO_ADDR(RAMPZ),r21
#endif
	ldi r18,90
	ldi r19,69
	ldi r20,162
27:
	eor r22,r19
	eor r17,r20
	lsl r19
	bst r19,7
	bld r19,0
	mov r0,r1
	bst r19,6
	bld r0,0
	eor r19,r0
	andi r19,127
	lsr r20
	bst r20,0
	bld r20,7
	mov r0,r1
	bst r20,1
	bld r0,7
	eor r20,r0
	andi r20,254
	mov r30,r22
#if defined(RAMPZ)
	elpm r22,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r22,Z
#elif defined(__AVR_TINY__)
	ld r22,Z
#else
	lpm
	mov r22,r0
#endif
	mov r30,r23
#if defined(RAMPZ)
	elpm r23,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r23,Z
#elif defined(__AVR_TINY__)
	ld r23,Z
#else
	lpm
	mov r23,r0
#endif
	mov r30,r28
#if defined(RAMPZ)
	elpm r28,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r28,Z
#elif defined(__AVR_TINY__)
	ld r28,Z
#else
	lpm
	mov r28,r0
#endif
	mov r30,r29
#if defined(RAMPZ)
	elpm r29,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r29,Z
#elif defined(__AVR_TINY__)
	ld r29,Z
#else
	lpm
	mov r29,r0
#endif
	mov r30,r2
#if defined(RAMPZ)
	elpm r2,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r2,Z
#elif defined(__AVR_TINY__)
	ld r2,Z
#else
	lpm
	mov r2,r0
#endif
	mov r30,r3
#if defined(RAMPZ)
	elpm r3,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r3,Z
#elif defined(__AVR_TINY__)
	ld r3,Z
#else
	lpm
	mov r3,r0
#endif
	mov r30,r4
#if defined(RAMPZ)
	elpm r4,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r4,Z
#elif defined(__AVR_TINY__)
	ld r4,Z
#else
	lpm
	mov r4,r0
#endif
	mov r30,r5
#if defined(RAMPZ)
	elpm r5,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r5,Z
#elif defined(__AVR_TINY__)
	ld r5,Z
#else
	lpm
	mov r5,r0
#endif
	mov r30,r6
#if defined(RAMPZ)
	elpm r6,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r6,Z
#elif defined(__AVR_TINY__)
	ld r6,Z
#else
	lpm
	mov r6,r0
#endif
	mov r30,r7
#if defined(RAMPZ)
	elpm r7,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r7,Z
#elif defined(__AVR_TINY__)
	ld r7,Z
#else
	lpm
	mov r7,r0
#endif
	mov r30,r8
#if defined(RAMPZ)
	elpm r8,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r8,Z
#elif defined(__AVR_TINY__)
	ld r8,Z
#else
	lpm
	mov r8,r0
#endif
	mov r30,r9
#if defined(RAMPZ)
	elpm r9,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r9,Z
#elif defined(__AVR_TINY__)
	ld r9,Z
#else
	lpm
	mov r9,r0
#endif
	mov r30,r10
#if defined(RAMPZ)
	elpm r10,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r10,Z
#elif defined(__AVR_TINY__)
	ld r10,Z
#else
	lpm
	mov r10,r0
#endif
	mov r30,r11
#if defined(RAMPZ)
	elpm r11,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r11,Z
#elif defined(__AVR_TINY__)
	ld r11,Z
#else
	lpm
	mov r11,r0
#endif
	mov r30,r12
#if defined(RAMPZ)
	elpm r12,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r12,Z
#elif defined(__AVR_TINY__)
	ld r12,Z
#else
	lpm
	mov r12,r0
#endif
	mov r30,r13
#if defined(RAMPZ)
	elpm r13,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r13,Z
#elif defined(__AVR_TINY__)
	ld r13,Z
#else
	lpm
	mov r13,r0
#endif
	mov r30,r14
#if defined(RAMPZ)
	elpm r14,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r14,Z
#elif defined(__AVR_TINY__)
	ld r14,Z
#else
	lpm
	mov r14,r0
#endif
	mov r30,r15
#if defined(RAMPZ)
	elpm r15,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r15,Z
#elif defined(__AVR_TINY__)
	ld r15,Z
#else
	lpm
	mov r15,r0
#endif
	mov r30,r24
#if defined(RAMPZ)
	elpm r24,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r24,Z
#elif defined(__AVR_TINY__)
	ld r24,Z
#else
	lpm
	mov r24,r0
#endif
	mov r30,r25
#if defined(RAMPZ)
	elpm r25,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r25,Z
#elif defined(__AVR_TINY__)
	ld r25,Z
#else
	lpm
	mov r25,r0
#endif
	mov r30,r16
#if defined(RAMPZ)
	elpm r16,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r16,Z
#elif defined(__AVR_TINY__)
	ld r16,Z
#else
	lpm
	mov r16,r0
#endif
	mov r30,r17
#if defined(RAMPZ)
	elpm r17,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r17,Z
#elif defined(__AVR_TINY__)
	ld r17,Z
#else
	lpm
	mov r17,r0
#endif
	bst r22,1
	bld r0,0
	bst r22,4
	bld r22,1
	bst r28,0
	bld r22,4
	bst r6,0
	bld r28,0
	bst r8,1
	bld r6,0
	bst r24,5
	bld r8,1
	bst r6,7
	bld r24,5
	bst r11,5
	bld r6,7
	bst r8,6
	bld r11,5
	bst r17,1
	bld r8,6
	bst r24,7
	bld r17,1
	bst r7,7
	bld r24,7
	bst r15,5
	bld r7,7
	bst r2,7
	bld r15,5
	bst r25,4
	bld r2,7
	bst r10,3
	bld r25,4
	bst r3,6
	bld r10,3
	bst r23,1
	bld r3,6
	bst r2,4
	bld r23,1
	bst r24,0
	bld r2,4
	bst r4,3
	bld r24,0
	bst r29,5
	bld r4,3
	bst r12,4
	bld r29,5
	bst r12,2
	bld r12,4
	bst r11,2
	bld r12,2
	bst r7,2
	bld r11,2
	bst r13,1
	bld r7,2
	bst r14,6
	bld r13,1
	bst r23,3
	bld r14,6
	bst r3,4
	bld r23,3
	bst r0,0
	bld r3,4
	bst r22,2
	bld r0,0
	bst r23,0
	bld r22,2
	bst r2,0
	bld r23,0
	bst r14,0
	bld r2,0
	bst r16,2
	bld r14,0
	bst r13,3
	bld r16,2
	bst r15,6
	bld r13,3
	bst r3,3
	bld r15,6
	bst r17,4
	bld r3,3
	bst r16,3
	bld r17,4
	bst r13,7
	bld r16,3
	bst r25,6
	bld r13,7
	bst r11,3
	bld r25,6
	bst r7,6
	bld r11,3
	bst r15,1
	bld r7,6
	bst r28,7
	bld r15,1
	bst r9,4
	bld r28,7
	bst r28,2
	bld r9,4
	bst r7,0
	bld r28,2
	bst r12,1
	bld r7,0
	bst r10,6
	bld r12,1
	bst r5,2
	bld r10,6
	bst r5,1
	bld r5,2
	bst r4,5
	bld r5,1
	bst r2,5
	bld r4,5
	bst r24,4
	bld r2,5
	bst r6,3
	bld r24,4
	bst r9,5
	bld r6,3
	bst r28,6
	bld r9,5
	bst r9,0
	bld r28,6
	bst r0,0
	bld r9,0
	bst r22,3
	bld r0,0
	bst r23,4
	bld r22,3
	bst r4,0
	bld r23,4
	bst r28,1
	bld r4,0
	bst r6,4
	bld r28,1
	bst r10,1
	bld r6,4
	bst r2,6
	bld r10,1
	bst r25,0
	bld r2,6
	bst r8,3
	bld r25,0
	bst r25,5
	bld r8,3
	bst r10,7
	bld r25,5
	bst r5,6
	bld r10,7
	bst r7,1
	bld r5,6
	bst r12,5
	bld r7,1
	bst r12,6
	bld r12,5
	bst r13,2
	bld r12,6
	bst r15,2
	bld r13,2
	bst r29,3
	bld r15,2
	bst r11,4
	bld r29,3
	bst r8,2
	bld r11,4
	bst r25,1
	bld r8,2
	bst r8,7
	bld r25,1
	bst r17,5
	bld r8,7
	bst r16,7
	bld r17,5
	bst r15,7
	bld r16,7
	bst r3,7
	bld r15,7
	bst r23,5
	bld r3,7
	bst r4,4
	bld r23,5
	bst r2,1
	bld r4,4
	bst r14,4
	bld r2,1
	bst r0,0
	bld r14,4
	bst r22,5
	bld r0,0
	bst r28,4
	bld r22,5
	bst r8,0
	bld r28,4
	bst r24,1
	bld r8,0
	bst r4,7
	bld r24,1
	bst r3,5
	bld r4,7
	bst r0,0
	bld r3,5
	bst r22,6
	bld r0,0
	bst r29,0
	bld r22,6
	bst r10,0
	bld r29,0
	bst r2,2
	bld r10,0
	bst r15,0
	bld r2,2
	bst r28,3
	bld r15,0
	bst r7,4
	bld r28,3
	bst r14,1
	bld r7,4
	bst r16,6
	bld r14,1
	bst r15,3
	bld r16,6
	bst r29,7
	bld r15,3
	bst r13,4
	bld r29,7
	bst r24,2
	bld r13,4
	bst r5,3
	bld r24,2
	bst r5,5
	bld r5,3
	bst r6,5
	bld r5,5
	bst r10,5
	bld r6,5
	bst r4,6
	bld r10,5
	bst r3,1
	bld r4,6
	bst r16,4
	bld r3,1
	bst r14,3
	bld r16,4
	bst r17,6
	bld r14,3
	bst r17,3
	bld r17,6
	bst r25,7
	bld r17,3
	bst r11,7
	bld r25,7
	bst r9,6
	bld r11,7
	bst r29,2
	bld r9,6
	bst r11,0
	bld r29,2
	bst r6,2
	bld r11,0
	bst r9,1
	bld r6,2
	bst r0,0
	bld r9,1
	bst r22,7
	bld r0,0
	bst r29,4
	bld r22,7
	bst r12,0
	bld r29,4
	bst r10,2
	bld r12,0
	bst r3,2
	bld r10,2
	bst r17,0
	bld r3,2
	bst r24,3
	bld r17,0
	bst r5,7
	bld r24,3
	bst r7,5
	bld r5,7
	bst r14,5
	bld r7,5
	bst r0,0
	bld r14,5
	bst r23,2
	bld r0,0
	bst r3,0
	bld r23,2
	bst r16,0
	bld r3,0
	bst r12,3
	bld r16,0
	bst r11,6
	bld r12,3
	bst r9,2
	bld r11,6
	bst r0,0
	bld r9,2
	bst r23,6
	bld r0,0
	bst r5,0
	bld r23,6
	bst r4,1
	bld r5,0
	bst r28,5
	bld r4,1
	bst r8,4
	bld r28,5
	bst r16,1
	bld r8,4
	bst r12,7
	bld r16,1
	bst r13,6
	bld r12,7
	bst r25,2
	bld r13,6
	bst r9,3
	bld r25,2
	bst r0,0
	bld r9,3
	bst r23,7
	bld r0,0
	bst r5,4
	bld r23,7
	bst r6,1
	bld r5,4
	bst r8,5
	bld r6,1
	bst r16,5
	bld r8,5
	bst r14,7
	bld r16,5
	bst r0,0
	bld r14,7
	bst r29,1
	bld r0,0
	bst r10,4
	bld r29,1
	bst r4,2
	bld r10,4
	bst r0,0
	bld r4,2
	bst r29,6
	bld r0,0
	bst r13,0
	bld r29,6
	bst r14,2
	bld r13,0
	bst r17,2
	bld r14,2
	bst r25,3
	bld r17,2
	bst r9,7
	bld r25,3
	bst r0,0
	bld r9,7
	bst r2,3
	bld r0,0
	bst r15,4
	bld r2,3
	bst r0,0
	bld r15,4
	bst r6,6
	bld r0,0
	bst r11,1
	bld r6,6
	bst r0,0
	bld r11,1
	bst r7,3
	bld r0,0
	bst r13,5
	bld r7,3
	bst r24,6
	bld r13,5
	bst r0,0
	bld r24,6
	dec r18
	breq 5445f
	rjmp 27b
5445:
#if defined(RAMPZ)
	pop r0
	out _SFR_IO_ADDR(RAMPZ),r0
#endif
	st X+,r22
	st X+,r23
	st X+,r28
	st X+,r29
	st X+,r2
	st X+,r3
	st X+,r4
	st X+,r5
	st X+,r6
	st X+,r7
	st X+,r8
	st X+,r9
	st X+,r10
	st X+,r11
	st X+,r12
	st X+,r13
	st X+,r14
	st X+,r15
	st X+,r24
	st X+,r25
	st X+,r16
	st X+,r17
	pop r17
	pop r16
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
	pop r29
	pop r28
	ret
	.size spongent176_permute, .-spongent176_permute

#endif
