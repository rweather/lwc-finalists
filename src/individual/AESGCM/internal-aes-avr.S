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
	.byte	99
	.byte	124
	.byte	119
	.byte	123
	.byte	242
	.byte	107
	.byte	111
	.byte	197
	.byte	48
	.byte	1
	.byte	103
	.byte	43
	.byte	254
	.byte	215
	.byte	171
	.byte	118
	.byte	202
	.byte	130
	.byte	201
	.byte	125
	.byte	250
	.byte	89
	.byte	71
	.byte	240
	.byte	173
	.byte	212
	.byte	162
	.byte	175
	.byte	156
	.byte	164
	.byte	114
	.byte	192
	.byte	183
	.byte	253
	.byte	147
	.byte	38
	.byte	54
	.byte	63
	.byte	247
	.byte	204
	.byte	52
	.byte	165
	.byte	229
	.byte	241
	.byte	113
	.byte	216
	.byte	49
	.byte	21
	.byte	4
	.byte	199
	.byte	35
	.byte	195
	.byte	24
	.byte	150
	.byte	5
	.byte	154
	.byte	7
	.byte	18
	.byte	128
	.byte	226
	.byte	235
	.byte	39
	.byte	178
	.byte	117
	.byte	9
	.byte	131
	.byte	44
	.byte	26
	.byte	27
	.byte	110
	.byte	90
	.byte	160
	.byte	82
	.byte	59
	.byte	214
	.byte	179
	.byte	41
	.byte	227
	.byte	47
	.byte	132
	.byte	83
	.byte	209
	.byte	0
	.byte	237
	.byte	32
	.byte	252
	.byte	177
	.byte	91
	.byte	106
	.byte	203
	.byte	190
	.byte	57
	.byte	74
	.byte	76
	.byte	88
	.byte	207
	.byte	208
	.byte	239
	.byte	170
	.byte	251
	.byte	67
	.byte	77
	.byte	51
	.byte	133
	.byte	69
	.byte	249
	.byte	2
	.byte	127
	.byte	80
	.byte	60
	.byte	159
	.byte	168
	.byte	81
	.byte	163
	.byte	64
	.byte	143
	.byte	146
	.byte	157
	.byte	56
	.byte	245
	.byte	188
	.byte	182
	.byte	218
	.byte	33
	.byte	16
	.byte	255
	.byte	243
	.byte	210
	.byte	205
	.byte	12
	.byte	19
	.byte	236
	.byte	95
	.byte	151
	.byte	68
	.byte	23
	.byte	196
	.byte	167
	.byte	126
	.byte	61
	.byte	100
	.byte	93
	.byte	25
	.byte	115
	.byte	96
	.byte	129
	.byte	79
	.byte	220
	.byte	34
	.byte	42
	.byte	144
	.byte	136
	.byte	70
	.byte	238
	.byte	184
	.byte	20
	.byte	222
	.byte	94
	.byte	11
	.byte	219
	.byte	224
	.byte	50
	.byte	58
	.byte	10
	.byte	73
	.byte	6
	.byte	36
	.byte	92
	.byte	194
	.byte	211
	.byte	172
	.byte	98
	.byte	145
	.byte	149
	.byte	228
	.byte	121
	.byte	231
	.byte	200
	.byte	55
	.byte	109
	.byte	141
	.byte	213
	.byte	78
	.byte	169
	.byte	108
	.byte	86
	.byte	244
	.byte	234
	.byte	101
	.byte	122
	.byte	174
	.byte	8
	.byte	186
	.byte	120
	.byte	37
	.byte	46
	.byte	28
	.byte	166
	.byte	180
	.byte	198
	.byte	232
	.byte	221
	.byte	116
	.byte	31
	.byte	75
	.byte	189
	.byte	139
	.byte	138
	.byte	112
	.byte	62
	.byte	181
	.byte	102
	.byte	72
	.byte	3
	.byte	246
	.byte	14
	.byte	97
	.byte	53
	.byte	87
	.byte	185
	.byte	134
	.byte	193
	.byte	29
	.byte	158
	.byte	225
	.byte	248
	.byte	152
	.byte	17
	.byte	105
	.byte	217
	.byte	142
	.byte	148
	.byte	155
	.byte	30
	.byte	135
	.byte	233
	.byte	206
	.byte	85
	.byte	40
	.byte	223
	.byte	140
	.byte	161
	.byte	137
	.byte	13
	.byte	191
	.byte	230
	.byte	66
	.byte	104
	.byte	65
	.byte	153
	.byte	45
	.byte	15
	.byte	176
	.byte	84
	.byte	187
	.byte	22

	.text
.global aes_128_init
	.type aes_128_init, @function
aes_128_init:
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
	movw r30,r24
	movw r26,r22
	in r28,0x3d
	in r29,0x3e
.L__stack_usage = 12
	ld r18,X+
	ld r19,X+
	ld r20,X+
	ld r21,X+
	ld r22,X+
	ld r23,X+
	ld r2,X+
	ld r3,X+
	ld r4,X+
	ld r5,X+
	ld r6,X+
	ld r7,X+
	ld r8,X+
	ld r9,X+
	ld r10,X+
	ld r11,X+
	st Z,r18
	std Z+1,r19
	std Z+2,r20
	std Z+3,r21
	std Z+4,r22
	std Z+5,r23
	std Z+6,r2
	std Z+7,r3
	std Z+8,r4
	std Z+9,r5
	std Z+10,r6
	std Z+11,r7
	std Z+12,r8
	std Z+13,r9
	std Z+14,r10
	std Z+15,r11
	movw r28,r30
	ldi r30,lo8(table_0)
	ldi r31,hi8(table_0)
#if defined(RAMPZ)
	ldi r26,hh8(table_0)
	in r0,_SFR_IO_ADDR(RAMPZ)
	push r0
	out _SFR_IO_ADDR(RAMPZ),r26
#endif
	mov r30,r8
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r9
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,1
	eor r18,r26
	mov r30,r10
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r11
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+16,r18
	std Y+17,r19
	std Y+18,r20
	std Y+19,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+16,r22
	std Y+17,r23
	std Y+18,r2
	std Y+19,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+16,r4
	std Y+17,r5
	std Y+18,r6
	std Y+19,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+16,r8
	std Y+17,r9
	std Y+18,r10
	std Y+19,r11
	adiw r28,4
	mov r30,r8
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r9
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,2
	eor r18,r26
	mov r30,r10
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r11
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+16,r18
	std Y+17,r19
	std Y+18,r20
	std Y+19,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+16,r22
	std Y+17,r23
	std Y+18,r2
	std Y+19,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+16,r4
	std Y+17,r5
	std Y+18,r6
	std Y+19,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+16,r8
	std Y+17,r9
	std Y+18,r10
	std Y+19,r11
	adiw r28,4
	mov r30,r8
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r9
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,4
	eor r18,r26
	mov r30,r10
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r11
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+16,r18
	std Y+17,r19
	std Y+18,r20
	std Y+19,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+16,r22
	std Y+17,r23
	std Y+18,r2
	std Y+19,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+16,r4
	std Y+17,r5
	std Y+18,r6
	std Y+19,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+16,r8
	std Y+17,r9
	std Y+18,r10
	std Y+19,r11
	adiw r28,4
	mov r30,r8
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r9
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,8
	eor r18,r26
	mov r30,r10
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r11
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+16,r18
	std Y+17,r19
	std Y+18,r20
	std Y+19,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+16,r22
	std Y+17,r23
	std Y+18,r2
	std Y+19,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+16,r4
	std Y+17,r5
	std Y+18,r6
	std Y+19,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+16,r8
	std Y+17,r9
	std Y+18,r10
	std Y+19,r11
	adiw r28,4
	mov r30,r8
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r9
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,16
	eor r18,r26
	mov r30,r10
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r11
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+16,r18
	std Y+17,r19
	std Y+18,r20
	std Y+19,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+16,r22
	std Y+17,r23
	std Y+18,r2
	std Y+19,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+16,r4
	std Y+17,r5
	std Y+18,r6
	std Y+19,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+16,r8
	std Y+17,r9
	std Y+18,r10
	std Y+19,r11
	adiw r28,4
	mov r30,r8
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r9
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,32
	eor r18,r26
	mov r30,r10
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r11
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+16,r18
	std Y+17,r19
	std Y+18,r20
	std Y+19,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+16,r22
	std Y+17,r23
	std Y+18,r2
	std Y+19,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+16,r4
	std Y+17,r5
	std Y+18,r6
	std Y+19,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+16,r8
	std Y+17,r9
	std Y+18,r10
	std Y+19,r11
	adiw r28,4
	mov r30,r8
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r9
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,64
	eor r18,r26
	mov r30,r10
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r11
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+16,r18
	std Y+17,r19
	std Y+18,r20
	std Y+19,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+16,r22
	std Y+17,r23
	std Y+18,r2
	std Y+19,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+16,r4
	std Y+17,r5
	std Y+18,r6
	std Y+19,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+16,r8
	std Y+17,r9
	std Y+18,r10
	std Y+19,r11
	adiw r28,4
	mov r30,r8
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r9
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,128
	eor r18,r26
	mov r30,r10
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r11
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+16,r18
	std Y+17,r19
	std Y+18,r20
	std Y+19,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+16,r22
	std Y+17,r23
	std Y+18,r2
	std Y+19,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+16,r4
	std Y+17,r5
	std Y+18,r6
	std Y+19,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+16,r8
	std Y+17,r9
	std Y+18,r10
	std Y+19,r11
	adiw r28,4
	mov r30,r8
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r9
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,27
	eor r18,r26
	mov r30,r10
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r11
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+16,r18
	std Y+17,r19
	std Y+18,r20
	std Y+19,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+16,r22
	std Y+17,r23
	std Y+18,r2
	std Y+19,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+16,r4
	std Y+17,r5
	std Y+18,r6
	std Y+19,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+16,r8
	std Y+17,r9
	std Y+18,r10
	std Y+19,r11
	adiw r28,4
	mov r30,r8
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r9
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,54
	eor r18,r26
	mov r30,r10
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r11
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+16,r18
	std Y+17,r19
	std Y+18,r20
	std Y+19,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+16,r22
	std Y+17,r23
	std Y+18,r2
	std Y+19,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+16,r4
	std Y+17,r5
	std Y+18,r6
	std Y+19,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+16,r8
	std Y+17,r9
	std Y+18,r10
	std Y+19,r11
	ldi r18,10
	mov r19,r1
	mov r20,r1
	mov r21,r1
	subi r28,172
	sbci r29,255
	st Y,r18
	std Y+1,r19
	std Y+2,r20
	std Y+3,r21
#if defined(RAMPZ)
	pop r0
	out _SFR_IO_ADDR(RAMPZ),r0
#endif
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
	.size aes_128_init, .-aes_128_init

	.text
.global aes_192_init
	.type aes_192_init, @function
aes_192_init:
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
	movw r26,r22
	in r28,0x3d
	in r29,0x3e
.L__stack_usage = 18
	ld r18,X+
	ld r19,X+
	ld r20,X+
	ld r21,X+
	ld r22,X+
	ld r23,X+
	ld r2,X+
	ld r3,X+
	ld r4,X+
	ld r5,X+
	ld r6,X+
	ld r7,X+
	ld r8,X+
	ld r9,X+
	ld r10,X+
	ld r11,X+
	ld r12,X+
	ld r13,X+
	ld r14,X+
	ld r15,X+
	ld r24,X+
	ld r25,X+
	ld r16,X+
	ld r17,X+
	st Z,r18
	std Z+1,r19
	std Z+2,r20
	std Z+3,r21
	std Z+4,r22
	std Z+5,r23
	std Z+6,r2
	std Z+7,r3
	std Z+8,r4
	std Z+9,r5
	std Z+10,r6
	std Z+11,r7
	std Z+12,r8
	std Z+13,r9
	std Z+14,r10
	std Z+15,r11
	std Z+16,r12
	std Z+17,r13
	std Z+18,r14
	std Z+19,r15
	std Z+20,r24
	std Z+21,r25
	std Z+22,r16
	std Z+23,r17
	movw r28,r30
	ldi r30,lo8(table_0)
	ldi r31,hi8(table_0)
#if defined(RAMPZ)
	ldi r26,hh8(table_0)
	in r0,_SFR_IO_ADDR(RAMPZ)
	push r0
	out _SFR_IO_ADDR(RAMPZ),r26
#endif
	mov r30,r24
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r25
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,1
	eor r18,r26
	mov r30,r16
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r17
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+24,r18
	std Y+25,r19
	std Y+26,r20
	std Y+27,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+24,r22
	std Y+25,r23
	std Y+26,r2
	std Y+27,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+24,r4
	std Y+25,r5
	std Y+26,r6
	std Y+27,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+24,r8
	std Y+25,r9
	std Y+26,r10
	std Y+27,r11
	adiw r28,4
	eor r12,r8
	eor r13,r9
	eor r14,r10
	eor r15,r11
	std Y+24,r12
	std Y+25,r13
	std Y+26,r14
	std Y+27,r15
	adiw r28,4
	eor r24,r12
	eor r25,r13
	eor r16,r14
	eor r17,r15
	std Y+24,r24
	std Y+25,r25
	std Y+26,r16
	std Y+27,r17
	adiw r28,4
	mov r30,r24
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r25
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,2
	eor r18,r26
	mov r30,r16
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r17
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+24,r18
	std Y+25,r19
	std Y+26,r20
	std Y+27,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+24,r22
	std Y+25,r23
	std Y+26,r2
	std Y+27,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+24,r4
	std Y+25,r5
	std Y+26,r6
	std Y+27,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+24,r8
	std Y+25,r9
	std Y+26,r10
	std Y+27,r11
	adiw r28,4
	eor r12,r8
	eor r13,r9
	eor r14,r10
	eor r15,r11
	std Y+24,r12
	std Y+25,r13
	std Y+26,r14
	std Y+27,r15
	adiw r28,4
	eor r24,r12
	eor r25,r13
	eor r16,r14
	eor r17,r15
	std Y+24,r24
	std Y+25,r25
	std Y+26,r16
	std Y+27,r17
	adiw r28,4
	mov r30,r24
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r25
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,4
	eor r18,r26
	mov r30,r16
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r17
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+24,r18
	std Y+25,r19
	std Y+26,r20
	std Y+27,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+24,r22
	std Y+25,r23
	std Y+26,r2
	std Y+27,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+24,r4
	std Y+25,r5
	std Y+26,r6
	std Y+27,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+24,r8
	std Y+25,r9
	std Y+26,r10
	std Y+27,r11
	adiw r28,4
	eor r12,r8
	eor r13,r9
	eor r14,r10
	eor r15,r11
	std Y+24,r12
	std Y+25,r13
	std Y+26,r14
	std Y+27,r15
	adiw r28,4
	eor r24,r12
	eor r25,r13
	eor r16,r14
	eor r17,r15
	std Y+24,r24
	std Y+25,r25
	std Y+26,r16
	std Y+27,r17
	adiw r28,4
	mov r30,r24
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r25
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,8
	eor r18,r26
	mov r30,r16
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r17
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+24,r18
	std Y+25,r19
	std Y+26,r20
	std Y+27,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+24,r22
	std Y+25,r23
	std Y+26,r2
	std Y+27,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+24,r4
	std Y+25,r5
	std Y+26,r6
	std Y+27,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+24,r8
	std Y+25,r9
	std Y+26,r10
	std Y+27,r11
	adiw r28,4
	eor r12,r8
	eor r13,r9
	eor r14,r10
	eor r15,r11
	std Y+24,r12
	std Y+25,r13
	std Y+26,r14
	std Y+27,r15
	adiw r28,4
	eor r24,r12
	eor r25,r13
	eor r16,r14
	eor r17,r15
	std Y+24,r24
	std Y+25,r25
	std Y+26,r16
	std Y+27,r17
	adiw r28,4
	mov r30,r24
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r25
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,16
	eor r18,r26
	mov r30,r16
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r17
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+24,r18
	std Y+25,r19
	std Y+26,r20
	std Y+27,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+24,r22
	std Y+25,r23
	std Y+26,r2
	std Y+27,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+24,r4
	std Y+25,r5
	std Y+26,r6
	std Y+27,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+24,r8
	std Y+25,r9
	std Y+26,r10
	std Y+27,r11
	adiw r28,4
	eor r12,r8
	eor r13,r9
	eor r14,r10
	eor r15,r11
	std Y+24,r12
	std Y+25,r13
	std Y+26,r14
	std Y+27,r15
	adiw r28,4
	eor r24,r12
	eor r25,r13
	eor r16,r14
	eor r17,r15
	std Y+24,r24
	std Y+25,r25
	std Y+26,r16
	std Y+27,r17
	adiw r28,4
	mov r30,r24
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r25
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,32
	eor r18,r26
	mov r30,r16
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r17
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+24,r18
	std Y+25,r19
	std Y+26,r20
	std Y+27,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+24,r22
	std Y+25,r23
	std Y+26,r2
	std Y+27,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+24,r4
	std Y+25,r5
	std Y+26,r6
	std Y+27,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+24,r8
	std Y+25,r9
	std Y+26,r10
	std Y+27,r11
	adiw r28,4
	eor r12,r8
	eor r13,r9
	eor r14,r10
	eor r15,r11
	std Y+24,r12
	std Y+25,r13
	std Y+26,r14
	std Y+27,r15
	adiw r28,4
	eor r24,r12
	eor r25,r13
	eor r16,r14
	eor r17,r15
	std Y+24,r24
	std Y+25,r25
	std Y+26,r16
	std Y+27,r17
	adiw r28,4
	mov r30,r24
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r25
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,64
	eor r18,r26
	mov r30,r16
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r17
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+24,r18
	std Y+25,r19
	std Y+26,r20
	std Y+27,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+24,r22
	std Y+25,r23
	std Y+26,r2
	std Y+27,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+24,r4
	std Y+25,r5
	std Y+26,r6
	std Y+27,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+24,r8
	std Y+25,r9
	std Y+26,r10
	std Y+27,r11
	adiw r28,4
	eor r12,r8
	eor r13,r9
	eor r14,r10
	eor r15,r11
	std Y+24,r12
	std Y+25,r13
	std Y+26,r14
	std Y+27,r15
	adiw r28,4
	eor r24,r12
	eor r25,r13
	eor r16,r14
	eor r17,r15
	std Y+24,r24
	std Y+25,r25
	std Y+26,r16
	std Y+27,r17
	adiw r28,4
	mov r30,r24
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r25
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,128
	eor r18,r26
	mov r30,r16
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r17
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+24,r18
	std Y+25,r19
	std Y+26,r20
	std Y+27,r21
	adiw r28,4
	eor r22,r18
	eor r23,r19
	eor r2,r20
	eor r3,r21
	std Y+24,r22
	std Y+25,r23
	std Y+26,r2
	std Y+27,r3
	adiw r28,4
	eor r4,r22
	eor r5,r23
	eor r6,r2
	eor r7,r3
	std Y+24,r4
	std Y+25,r5
	std Y+26,r6
	std Y+27,r7
	adiw r28,4
	eor r8,r4
	eor r9,r5
	eor r10,r6
	eor r11,r7
	std Y+24,r8
	std Y+25,r9
	std Y+26,r10
	std Y+27,r11
	ldi r27,12
	mov r12,r27
	mov r13,r1
	mov r14,r1
	mov r15,r1
	adiw r28,60
	st Y,r12
	std Y+1,r13
	std Y+2,r14
	std Y+3,r15
#if defined(RAMPZ)
	pop r0
	out _SFR_IO_ADDR(RAMPZ),r0
#endif
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
	.size aes_192_init, .-aes_192_init

	.text
.global aes_256_init
	.type aes_256_init, @function
aes_256_init:
	push r28
	push r29
	push r2
	push r3
	movw r30,r24
	movw r26,r22
	in r28,0x3d
	in r29,0x3e
.L__stack_usage = 4
	ld r18,X+
	ld r19,X+
	ld r20,X+
	ld r21,X+
	st Z,r18
	std Z+1,r19
	std Z+2,r20
	std Z+3,r21
	ld r22,X+
	ld r23,X+
	ld r2,X+
	ld r3,X+
	std Z+4,r22
	std Z+5,r23
	std Z+6,r2
	std Z+7,r3
	ld r22,X+
	ld r23,X+
	ld r2,X+
	ld r3,X+
	std Z+8,r22
	std Z+9,r23
	std Z+10,r2
	std Z+11,r3
	ld r22,X+
	ld r23,X+
	ld r2,X+
	ld r3,X+
	std Z+12,r22
	std Z+13,r23
	std Z+14,r2
	std Z+15,r3
	ld r22,X+
	ld r23,X+
	ld r2,X+
	ld r3,X+
	std Z+16,r22
	std Z+17,r23
	std Z+18,r2
	std Z+19,r3
	ld r22,X+
	ld r23,X+
	ld r2,X+
	ld r3,X+
	std Z+20,r22
	std Z+21,r23
	std Z+22,r2
	std Z+23,r3
	ld r22,X+
	ld r23,X+
	ld r2,X+
	ld r3,X+
	std Z+24,r22
	std Z+25,r23
	std Z+26,r2
	std Z+27,r3
	ld r22,X+
	ld r23,X+
	ld r2,X+
	ld r3,X+
	std Z+28,r22
	std Z+29,r23
	std Z+30,r2
	std Z+31,r3
	movw r28,r30
	ldi r30,lo8(table_0)
	ldi r31,hi8(table_0)
#if defined(RAMPZ)
	ldi r26,hh8(table_0)
	in r0,_SFR_IO_ADDR(RAMPZ)
	push r0
	out _SFR_IO_ADDR(RAMPZ),r26
#endif
	mov r30,r22
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r23
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,1
	eor r18,r26
	mov r30,r2
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r3
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	mov r30,r22
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	mov r30,r23
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r2
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	mov r30,r3
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	mov r30,r22
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r23
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,2
	eor r18,r26
	mov r30,r2
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r3
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	mov r30,r22
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	mov r30,r23
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r2
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	mov r30,r3
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	mov r30,r22
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r23
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,4
	eor r18,r26
	mov r30,r2
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r3
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	mov r30,r22
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	mov r30,r23
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r2
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	mov r30,r3
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	mov r30,r22
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r23
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,8
	eor r18,r26
	mov r30,r2
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r3
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	mov r30,r22
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	mov r30,r23
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r2
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	mov r30,r3
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	mov r30,r22
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r23
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,16
	eor r18,r26
	mov r30,r2
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r3
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	mov r30,r22
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	mov r30,r23
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r2
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	mov r30,r3
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	mov r30,r22
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r23
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,32
	eor r18,r26
	mov r30,r2
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r3
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	mov r30,r22
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	mov r30,r23
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r2
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	mov r30,r3
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	mov r30,r22
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r21,r26
	mov r30,r23
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r18,r26
	ldi r26,64
	eor r18,r26
	mov r30,r2
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r19,r26
	mov r30,r3
#if defined(RAMPZ)
	elpm r26,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r26,Z
#elif defined(__AVR_TINY__)
	ld r26,Z
#else
	lpm
	mov r26,r0
#endif
	eor r20,r26
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	adiw r28,4
	ld r18,Y
	ldd r19,Y+1
	ldd r20,Y+2
	ldd r21,Y+3
	ldd r22,Y+28
	ldd r23,Y+29
	ldd r2,Y+30
	ldd r3,Y+31
	eor r18,r22
	eor r19,r23
	eor r20,r2
	eor r21,r3
	std Y+32,r18
	std Y+33,r19
	std Y+34,r20
	std Y+35,r21
	ldi r18,14
	mov r19,r1
	mov r20,r1
	mov r21,r1
	std Y+36,r18
	std Y+37,r19
	std Y+38,r20
	std Y+39,r21
#if defined(RAMPZ)
	pop r0
	out _SFR_IO_ADDR(RAMPZ),r0
#endif
	pop r3
	pop r2
	pop r29
	pop r28
	ret
	.size aes_256_init, .-aes_256_init

	.text
.global aes_ecb_encrypt
	.type aes_ecb_encrypt, @function
aes_ecb_encrypt:
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
	push r23
	push r22
	movw r30,r24
	movw r26,r20
	in r28,0x3d
	in r29,0x3e
.L__stack_usage = 18
	ld r20,X+
	ld r21,X+
	ld r22,X+
	ld r23,X+
	ld r2,X+
	ld r3,X+
	ld r4,X+
	ld r5,X+
	ld r6,X+
	ld r7,X+
	ld r8,X+
	ld r9,X+
	ld r10,X+
	ld r11,X+
	ld r12,X+
	ld r13,X+
	movw r26,r30
	subi r30,16
	sbci r31,255
	ld r18,Z
	ldi r30,lo8(table_0)
	ldi r31,hi8(table_0)
#if defined(RAMPZ)
	ldi r19,hh8(table_0)
	in r0,_SFR_IO_ADDR(RAMPZ)
	push r0
	out _SFR_IO_ADDR(RAMPZ),r19
#endif
	ld r19,X+
	eor r20,r19
	ld r19,X+
	eor r21,r19
	ld r19,X+
	eor r22,r19
	ld r19,X+
	eor r23,r19
	ld r19,X+
	eor r2,r19
	ld r19,X+
	eor r3,r19
	ld r19,X+
	eor r4,r19
	ld r19,X+
	eor r5,r19
	ld r19,X+
	eor r6,r19
	ld r19,X+
	eor r7,r19
	ld r19,X+
	eor r8,r19
	ld r19,X+
	eor r9,r19
	ld r19,X+
	eor r10,r19
	ld r19,X+
	eor r11,r19
	ld r19,X+
	eor r12,r19
	ld r19,X+
	eor r13,r19
	cpi r18,10
	breq 62f
	cpi r18,12
	breq 59f
	rcall 125f
	rcall 125f
59:
	rcall 125f
	rcall 125f
62:
	rcall 125f
	rcall 125f
	rcall 125f
	rcall 125f
	rcall 125f
	rcall 125f
	rcall 125f
	rcall 125f
	rcall 125f
	mov r30,r20
#if defined(RAMPZ)
	elpm r20,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r20,Z
#elif defined(__AVR_TINY__)
	ld r20,Z
#else
	lpm
	mov r20,r0
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
	mov r30,r21
#if defined(RAMPZ)
	elpm r18,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r18,Z
#elif defined(__AVR_TINY__)
	ld r18,Z
#else
	lpm
	mov r18,r0
#endif
	mov r30,r3
#if defined(RAMPZ)
	elpm r21,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r21,Z
#elif defined(__AVR_TINY__)
	ld r21,Z
#else
	lpm
	mov r21,r0
#endif
	mov r30,r7
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
	mov r30,r11
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
	mov r11,r18
	mov r30,r22
#if defined(RAMPZ)
	elpm r18,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r18,Z
#elif defined(__AVR_TINY__)
	ld r18,Z
#else
	lpm
	mov r18,r0
#endif
	mov r30,r8
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
	mov r8,r18
	mov r30,r4
#if defined(RAMPZ)
	elpm r18,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r18,Z
#elif defined(__AVR_TINY__)
	ld r18,Z
#else
	lpm
	mov r18,r0
#endif
	mov r30,r12
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
	mov r12,r18
	mov r30,r23
#if defined(RAMPZ)
	elpm r18,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r18,Z
#elif defined(__AVR_TINY__)
	ld r18,Z
#else
	lpm
	mov r18,r0
#endif
	mov r30,r13
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
	mov r30,r9
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
	mov r30,r5
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
	mov r5,r18
	ld r18,X+
	eor r20,r18
	ld r18,X+
	eor r21,r18
	ld r18,X+
	eor r22,r18
	ld r18,X+
	eor r23,r18
	ld r18,X+
	eor r2,r18
	ld r18,X+
	eor r3,r18
	ld r18,X+
	eor r4,r18
	ld r18,X+
	eor r5,r18
	ld r18,X+
	eor r6,r18
	ld r18,X+
	eor r7,r18
	ld r18,X+
	eor r8,r18
	ld r18,X+
	eor r9,r18
	ld r18,X+
	eor r10,r18
	ld r18,X+
	eor r11,r18
	ld r18,X+
	eor r12,r18
	ld r18,X+
	eor r13,r18
	rjmp 367f
125:
	mov r30,r20
#if defined(RAMPZ)
	elpm r20,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r20,Z
#elif defined(__AVR_TINY__)
	ld r20,Z
#else
	lpm
	mov r20,r0
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
	mov r30,r21
#if defined(RAMPZ)
	elpm r18,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r18,Z
#elif defined(__AVR_TINY__)
	ld r18,Z
#else
	lpm
	mov r18,r0
#endif
	mov r30,r3
#if defined(RAMPZ)
	elpm r21,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r21,Z
#elif defined(__AVR_TINY__)
	ld r21,Z
#else
	lpm
	mov r21,r0
#endif
	mov r30,r7
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
	mov r30,r11
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
	mov r11,r18
	mov r30,r22
#if defined(RAMPZ)
	elpm r18,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r18,Z
#elif defined(__AVR_TINY__)
	ld r18,Z
#else
	lpm
	mov r18,r0
#endif
	mov r30,r8
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
	mov r8,r18
	mov r30,r4
#if defined(RAMPZ)
	elpm r18,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r18,Z
#elif defined(__AVR_TINY__)
	ld r18,Z
#else
	lpm
	mov r18,r0
#endif
	mov r30,r12
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
	mov r12,r18
	mov r30,r23
#if defined(RAMPZ)
	elpm r18,Z
#elif defined(__AVR_HAVE_LPMX__)
	lpm r18,Z
#elif defined(__AVR_TINY__)
	ld r18,Z
#else
	lpm
	mov r18,r0
#endif
	mov r30,r13
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
	mov r30,r9
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
	mov r30,r5
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
	mov r5,r18
	mov r19,r20
	mov r18,r1
	lsl r19
	sbc r18,r1
	andi r18,27
	eor r19,r18
	mov r14,r21
	mov r18,r1
	lsl r14
	sbc r18,r1
	andi r18,27
	eor r14,r18
	mov r15,r22
	mov r18,r1
	lsl r15
	sbc r18,r1
	andi r18,27
	eor r15,r18
	mov r24,r19
	eor r24,r14
	eor r24,r21
	eor r24,r22
	eor r24,r23
	mov r25,r20
	eor r25,r14
	eor r25,r15
	eor r25,r22
	eor r25,r23
	mov r14,r23
	mov r18,r1
	lsl r14
	sbc r18,r1
	andi r18,27
	eor r14,r18
	mov r18,r20
	eor r18,r21
	eor r18,r15
	eor r18,r14
	eor r18,r23
	mov r23,r19
	eor r23,r20
	eor r23,r21
	eor r23,r22
	eor r23,r14
	mov r20,r24
	mov r21,r25
	mov r22,r18
	mov r19,r2
	mov r18,r1
	lsl r19
	sbc r18,r1
	andi r18,27
	eor r19,r18
	mov r14,r3
	mov r18,r1
	lsl r14
	sbc r18,r1
	andi r18,27
	eor r14,r18
	mov r15,r4
	mov r18,r1
	lsl r15
	sbc r18,r1
	andi r18,27
	eor r15,r18
	mov r24,r19
	eor r24,r14
	eor r24,r3
	eor r24,r4
	eor r24,r5
	mov r25,r2
	eor r25,r14
	eor r25,r15
	eor r25,r4
	eor r25,r5
	mov r14,r5
	mov r18,r1
	lsl r14
	sbc r18,r1
	andi r18,27
	eor r14,r18
	mov r18,r2
	eor r18,r3
	eor r18,r15
	eor r18,r14
	eor r18,r5
	mov r5,r19
	eor r5,r2
	eor r5,r3
	eor r5,r4
	eor r5,r14
	mov r2,r24
	mov r3,r25
	mov r4,r18
	mov r19,r6
	mov r18,r1
	lsl r19
	sbc r18,r1
	andi r18,27
	eor r19,r18
	mov r14,r7
	mov r18,r1
	lsl r14
	sbc r18,r1
	andi r18,27
	eor r14,r18
	mov r15,r8
	mov r18,r1
	lsl r15
	sbc r18,r1
	andi r18,27
	eor r15,r18
	mov r24,r19
	eor r24,r14
	eor r24,r7
	eor r24,r8
	eor r24,r9
	mov r25,r6
	eor r25,r14
	eor r25,r15
	eor r25,r8
	eor r25,r9
	mov r14,r9
	mov r18,r1
	lsl r14
	sbc r18,r1
	andi r18,27
	eor r14,r18
	mov r18,r6
	eor r18,r7
	eor r18,r15
	eor r18,r14
	eor r18,r9
	mov r9,r19
	eor r9,r6
	eor r9,r7
	eor r9,r8
	eor r9,r14
	mov r6,r24
	mov r7,r25
	mov r8,r18
	mov r19,r10
	mov r18,r1
	lsl r19
	sbc r18,r1
	andi r18,27
	eor r19,r18
	mov r14,r11
	mov r18,r1
	lsl r14
	sbc r18,r1
	andi r18,27
	eor r14,r18
	mov r15,r12
	mov r18,r1
	lsl r15
	sbc r18,r1
	andi r18,27
	eor r15,r18
	mov r24,r19
	eor r24,r14
	eor r24,r11
	eor r24,r12
	eor r24,r13
	mov r25,r10
	eor r25,r14
	eor r25,r15
	eor r25,r12
	eor r25,r13
	mov r14,r13
	mov r18,r1
	lsl r14
	sbc r18,r1
	andi r18,27
	eor r14,r18
	mov r18,r10
	eor r18,r11
	eor r18,r15
	eor r18,r14
	eor r18,r13
	mov r13,r19
	eor r13,r10
	eor r13,r11
	eor r13,r12
	eor r13,r14
	mov r10,r24
	mov r11,r25
	mov r12,r18
	ld r18,X+
	eor r20,r18
	ld r18,X+
	eor r21,r18
	ld r18,X+
	eor r22,r18
	ld r18,X+
	eor r23,r18
	ld r18,X+
	eor r2,r18
	ld r18,X+
	eor r3,r18
	ld r18,X+
	eor r4,r18
	ld r18,X+
	eor r5,r18
	ld r18,X+
	eor r6,r18
	ld r18,X+
	eor r7,r18
	ld r18,X+
	eor r8,r18
	ld r18,X+
	eor r9,r18
	ld r18,X+
	eor r10,r18
	ld r18,X+
	eor r11,r18
	ld r18,X+
	eor r12,r18
	ld r18,X+
	eor r13,r18
	ret 
367:
#if defined(RAMPZ)
	pop r0
	out _SFR_IO_ADDR(RAMPZ),r0
#endif
	ldd r26,Y+1
	ldd r27,Y+2
	st X+,r20
	st X+,r21
	st X+,r22
	st X+,r23
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
	pop r0
	pop r0
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
	.size aes_ecb_encrypt, .-aes_ecb_encrypt

#endif
