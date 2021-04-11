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

	.align	4
	.type	rconst160, %object
rconst160:
	.byte	117
	.byte	174
	.byte	106
	.byte	86
	.byte	84
	.byte	42
	.byte	41
	.byte	148
	.byte	83
	.byte	202
	.byte	39
	.byte	228
	.byte	79
	.byte	242
	.byte	31
	.byte	248
	.byte	62
	.byte	124
	.byte	125
	.byte	190
	.byte	122
	.byte	94
	.byte	116
	.byte	46
	.byte	104
	.byte	22
	.byte	80
	.byte	10
	.byte	33
	.byte	132
	.byte	67
	.byte	194
	.byte	7
	.byte	224
	.byte	14
	.byte	112
	.byte	28
	.byte	56
	.byte	56
	.byte	28
	.byte	113
	.byte	142
	.byte	98
	.byte	70
	.byte	68
	.byte	34
	.byte	9
	.byte	144
	.byte	18
	.byte	72
	.byte	36
	.byte	36
	.byte	73
	.byte	146
	.byte	19
	.byte	200
	.byte	38
	.byte	100
	.byte	77
	.byte	178
	.byte	27
	.byte	216
	.byte	54
	.byte	108
	.byte	109
	.byte	182
	.byte	90
	.byte	90
	.byte	53
	.byte	172
	.byte	107
	.byte	214
	.byte	86
	.byte	106
	.byte	45
	.byte	180
	.byte	91
	.byte	218
	.byte	55
	.byte	236
	.byte	111
	.byte	246
	.byte	94
	.byte	122
	.byte	61
	.byte	188
	.byte	123
	.byte	222
	.byte	118
	.byte	110
	.byte	108
	.byte	54
	.byte	88
	.byte	26
	.byte	49
	.byte	140
	.byte	99
	.byte	198
	.byte	70
	.byte	98
	.byte	13
	.byte	176
	.byte	26
	.byte	88
	.byte	52
	.byte	44
	.byte	105
	.byte	150
	.byte	82
	.byte	74
	.byte	37
	.byte	164
	.byte	75
	.byte	210
	.byte	23
	.byte	232
	.byte	46
	.byte	116
	.byte	93
	.byte	186
	.byte	59
	.byte	220
	.byte	119
	.byte	238
	.byte	110
	.byte	118
	.byte	92
	.byte	58
	.byte	57
	.byte	156
	.byte	115
	.byte	206
	.byte	102
	.byte	102
	.byte	76
	.byte	50
	.byte	25
	.byte	152
	.byte	50
	.byte	76
	.byte	101
	.byte	166
	.byte	74
	.byte	82
	.byte	21
	.byte	168
	.byte	42
	.byte	84
	.byte	85
	.byte	170
	.byte	43
	.byte	212
	.byte	87
	.byte	234
	.byte	47
	.byte	244
	.byte	95
	.byte	250
	.byte	63
	.byte	252
	.size	rconst160, .-rconst160

	.align	4
	.type	rconst176, %object
rconst176:
	.byte	69
	.byte	162
	.byte	11
	.byte	208
	.byte	22
	.byte	104
	.byte	44
	.byte	52
	.byte	89
	.byte	154
	.byte	51
	.byte	204
	.byte	103
	.byte	230
	.byte	78
	.byte	114
	.byte	29
	.byte	184
	.byte	58
	.byte	92
	.byte	117
	.byte	174
	.byte	106
	.byte	86
	.byte	84
	.byte	42
	.byte	41
	.byte	148
	.byte	83
	.byte	202
	.byte	39
	.byte	228
	.byte	79
	.byte	242
	.byte	31
	.byte	248
	.byte	62
	.byte	124
	.byte	125
	.byte	190
	.byte	122
	.byte	94
	.byte	116
	.byte	46
	.byte	104
	.byte	22
	.byte	80
	.byte	10
	.byte	33
	.byte	132
	.byte	67
	.byte	194
	.byte	7
	.byte	224
	.byte	14
	.byte	112
	.byte	28
	.byte	56
	.byte	56
	.byte	28
	.byte	113
	.byte	142
	.byte	98
	.byte	70
	.byte	68
	.byte	34
	.byte	9
	.byte	144
	.byte	18
	.byte	72
	.byte	36
	.byte	36
	.byte	73
	.byte	146
	.byte	19
	.byte	200
	.byte	38
	.byte	100
	.byte	77
	.byte	178
	.byte	27
	.byte	216
	.byte	54
	.byte	108
	.byte	109
	.byte	182
	.byte	90
	.byte	90
	.byte	53
	.byte	172
	.byte	107
	.byte	214
	.byte	86
	.byte	106
	.byte	45
	.byte	180
	.byte	91
	.byte	218
	.byte	55
	.byte	236
	.byte	111
	.byte	246
	.byte	94
	.byte	122
	.byte	61
	.byte	188
	.byte	123
	.byte	222
	.byte	118
	.byte	110
	.byte	108
	.byte	54
	.byte	88
	.byte	26
	.byte	49
	.byte	140
	.byte	99
	.byte	198
	.byte	70
	.byte	98
	.byte	13
	.byte	176
	.byte	26
	.byte	88
	.byte	52
	.byte	44
	.byte	105
	.byte	150
	.byte	82
	.byte	74
	.byte	37
	.byte	164
	.byte	75
	.byte	210
	.byte	23
	.byte	232
	.byte	46
	.byte	116
	.byte	93
	.byte	186
	.byte	59
	.byte	220
	.byte	119
	.byte	238
	.byte	110
	.byte	118
	.byte	92
	.byte	58
	.byte	57
	.byte	156
	.byte	115
	.byte	206
	.byte	102
	.byte	102
	.byte	76
	.byte	50
	.byte	25
	.byte	152
	.byte	50
	.byte	76
	.byte	101
	.byte	166
	.byte	74
	.byte	82
	.byte	21
	.byte	168
	.byte	42
	.byte	84
	.byte	85
	.byte	170
	.byte	43
	.byte	212
	.byte	87
	.byte	234
	.byte	47
	.byte	244
	.byte	95
	.byte	250
	.byte	63
	.byte	252
	.size	rconst176, .-rconst176

	.align	2
	.global	spongent160_permute
	.thumb
	.thumb_func
	.type	spongent160_permute, %function
spongent160_permute:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	ldr	r2, [r0, #0]
	ldr	r3, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
	ldr	r6, [r0, #16]
	adr	r10, rconst160
	movs	r1, #80
.L1:
	ldrb	r7, [r10], #1
	ldrb	r8, [r10], #1
	eors	r2, r7
	eor	r6, r6, r8, lsl #24
	lsr	r7, r2, #3
	eor	r7, r7, r2, lsr #1
	lsr	r8, r2, #2
	eor	r8, r8, r2, lsr #1
	and	r7, r8
	lsr	r8, r2, #3
	eor	r8, r8, r2, lsr #2
	eor	r8, r2
	eor	r8, r7
	mvn	r8, r8
	lsr	r9, r2, #3
	mvn	r9, r9
	and	r8, r9
	lsr	r9, r2, #2
	eor	r9, r8
	lsr	lr, r2, #1
	eor	lr, r2
	eor	lr, r9
	eor	lr, r7
	and	r9, lr
	lsr	lr, r2, #1
	eor	lr, r7
	lsr	ip, r2, #2
	eor	ip, r7
	mvn	ip, ip
	and	lr, ip
	eor	r9, r9, r2, lsr #2
	eor	r9, r9, r2, lsr #1
	eor	r9, r2
	and	r9, r9, #0x11111111
	eor	ip, r2, r2, lsr #3
	eor	ip, ip, r2, lsr #1
	eor	ip, r7
	eor	ip, r8
	and	ip, ip, #0x11111111
	eor	r8, r8, r2, lsr #3
	eor	r8, r8, r2, lsr #2
	eor	r8, r8, r2, lsr #1
	and	r8, r8, #0x11111111
	eor	r2, r2, r2, lsr #3
	eors	r2, r7
	eor	r2, lr
	and	r2, r2, #0x11111111
	orr	r2, r2, r8, lsl #1
	orr	r2, r2, ip, lsl #2
	orr	r2, r2, r9, lsl #3
	lsr	r7, r3, #3
	eor	r7, r7, r3, lsr #1
	lsr	r8, r3, #2
	eor	r8, r8, r3, lsr #1
	and	r7, r8
	lsr	r8, r3, #3
	eor	r8, r8, r3, lsr #2
	eor	r8, r3
	eor	r8, r7
	mvn	r8, r8
	lsr	r9, r3, #3
	mvn	r9, r9
	and	r8, r9
	lsr	r9, r3, #2
	eor	r9, r8
	lsr	lr, r3, #1
	eor	lr, r3
	eor	lr, r9
	eor	lr, r7
	and	r9, lr
	lsr	lr, r3, #1
	eor	lr, r7
	lsr	ip, r3, #2
	eor	ip, r7
	mvn	ip, ip
	and	lr, ip
	eor	r9, r9, r3, lsr #2
	eor	r9, r9, r3, lsr #1
	eor	r9, r3
	and	r9, r9, #0x11111111
	eor	ip, r3, r3, lsr #3
	eor	ip, ip, r3, lsr #1
	eor	ip, r7
	eor	ip, r8
	and	ip, ip, #0x11111111
	eor	r8, r8, r3, lsr #3
	eor	r8, r8, r3, lsr #2
	eor	r8, r8, r3, lsr #1
	and	r8, r8, #0x11111111
	eor	r3, r3, r3, lsr #3
	eors	r3, r7
	eor	r3, lr
	and	r3, r3, #0x11111111
	orr	r3, r3, r8, lsl #1
	orr	r3, r3, ip, lsl #2
	orr	r3, r3, r9, lsl #3
	lsr	r7, r4, #3
	eor	r7, r7, r4, lsr #1
	lsr	r8, r4, #2
	eor	r8, r8, r4, lsr #1
	and	r7, r8
	lsr	r8, r4, #3
	eor	r8, r8, r4, lsr #2
	eor	r8, r4
	eor	r8, r7
	mvn	r8, r8
	lsr	r9, r4, #3
	mvn	r9, r9
	and	r8, r9
	lsr	r9, r4, #2
	eor	r9, r8
	lsr	lr, r4, #1
	eor	lr, r4
	eor	lr, r9
	eor	lr, r7
	and	r9, lr
	lsr	lr, r4, #1
	eor	lr, r7
	lsr	ip, r4, #2
	eor	ip, r7
	mvn	ip, ip
	and	lr, ip
	eor	r9, r9, r4, lsr #2
	eor	r9, r9, r4, lsr #1
	eor	r9, r4
	and	r9, r9, #0x11111111
	eor	ip, r4, r4, lsr #3
	eor	ip, ip, r4, lsr #1
	eor	ip, r7
	eor	ip, r8
	and	ip, ip, #0x11111111
	eor	r8, r8, r4, lsr #3
	eor	r8, r8, r4, lsr #2
	eor	r8, r8, r4, lsr #1
	and	r8, r8, #0x11111111
	eor	r4, r4, r4, lsr #3
	eors	r4, r7
	eor	r4, lr
	and	r4, r4, #0x11111111
	orr	r4, r4, r8, lsl #1
	orr	r4, r4, ip, lsl #2
	orr	r4, r4, r9, lsl #3
	lsr	r7, r5, #3
	eor	r7, r7, r5, lsr #1
	lsr	r8, r5, #2
	eor	r8, r8, r5, lsr #1
	and	r7, r8
	lsr	r8, r5, #3
	eor	r8, r8, r5, lsr #2
	eor	r8, r5
	eor	r8, r7
	mvn	r8, r8
	lsr	r9, r5, #3
	mvn	r9, r9
	and	r8, r9
	lsr	r9, r5, #2
	eor	r9, r8
	lsr	lr, r5, #1
	eor	lr, r5
	eor	lr, r9
	eor	lr, r7
	and	r9, lr
	lsr	lr, r5, #1
	eor	lr, r7
	lsr	ip, r5, #2
	eor	ip, r7
	mvn	ip, ip
	and	lr, ip
	eor	r9, r9, r5, lsr #2
	eor	r9, r9, r5, lsr #1
	eor	r9, r5
	and	r9, r9, #0x11111111
	eor	ip, r5, r5, lsr #3
	eor	ip, ip, r5, lsr #1
	eor	ip, r7
	eor	ip, r8
	and	ip, ip, #0x11111111
	eor	r8, r8, r5, lsr #3
	eor	r8, r8, r5, lsr #2
	eor	r8, r8, r5, lsr #1
	and	r8, r8, #0x11111111
	eor	r5, r5, r5, lsr #3
	eors	r5, r7
	eor	r5, lr
	and	r5, r5, #0x11111111
	orr	r5, r5, r8, lsl #1
	orr	r5, r5, ip, lsl #2
	orr	r5, r5, r9, lsl #3
	lsr	r7, r6, #3
	eor	r7, r7, r6, lsr #1
	lsr	r8, r6, #2
	eor	r8, r8, r6, lsr #1
	and	r7, r8
	lsr	r8, r6, #3
	eor	r8, r8, r6, lsr #2
	eor	r8, r6
	eor	r8, r7
	mvn	r8, r8
	lsr	r9, r6, #3
	mvn	r9, r9
	and	r8, r9
	lsr	r9, r6, #2
	eor	r9, r8
	lsr	lr, r6, #1
	eor	lr, r6
	eor	lr, r9
	eor	lr, r7
	and	r9, lr
	lsr	lr, r6, #1
	eor	lr, r7
	lsr	ip, r6, #2
	eor	ip, r7
	mvn	ip, ip
	and	lr, ip
	eor	r9, r9, r6, lsr #2
	eor	r9, r9, r6, lsr #1
	eor	r9, r6
	and	r9, r9, #0x11111111
	eor	ip, r6, r6, lsr #3
	eor	ip, ip, r6, lsr #1
	eor	ip, r7
	eor	ip, r8
	and	ip, ip, #0x11111111
	eor	r8, r8, r6, lsr #3
	eor	r8, r8, r6, lsr #2
	eor	r8, r8, r6, lsr #1
	and	r8, r8, #0x11111111
	eor	r6, r6, r6, lsr #3
	eors	r6, r7
	eor	r6, lr
	and	r6, r6, #0x11111111
	orr	r6, r6, r8, lsl #1
	orr	r6, r6, ip, lsl #2
	orr	r6, r6, r9, lsl #3
	lsr	r7, r2, #1
	lsr	r8, r2, #4
	bfi	r2, r8, #1, #1
	lsr	r8, r2, #16
	bfi	r2, r8, #4, #1
	bfi	r2, r4, #16, #1
	lsr	r8, r5, #1
	bfi	r4, r8, #0, #1
	lsr	r8, r4, #6
	bfi	r5, r8, #1, #1
	lsr	r8, r5, #25
	bfi	r4, r8, #6, #1
	lsr	r8, r2, #7
	bfi	r5, r8, #25, #1
	lsr	r8, r2, #28
	bfi	r2, r8, #7, #1
	lsr	r8, r5, #16
	bfi	r2, r8, #28, #1
	lsr	r8, r6, #2
	bfi	r5, r8, #16, #1
	lsr	r8, r3, #11
	bfi	r6, r8, #2, #1
	lsr	r8, r2, #13
	bfi	r3, r8, #11, #1
	lsr	r8, r3, #20
	bfi	r2, r8, #13, #1
	lsr	r8, r3, #17
	bfi	r3, r8, #20, #1
	lsr	r8, r3, #5
	bfi	r3, r8, #17, #1
	lsr	r8, r6, #20
	bfi	r3, r8, #5, #1
	lsr	r8, r5, #19
	bfi	r6, r8, #20, #1
	lsr	r8, r6, #14
	bfi	r5, r8, #19, #1
	lsr	r8, r4, #27
	bfi	r6, r8, #14, #1
	lsr	r8, r3, #14
	bfi	r4, r8, #27, #1
	lsr	r8, r2, #25
	bfi	r3, r8, #14, #1
	lsr	r8, r5, #4
	bfi	r2, r8, #25, #1
	lsr	r8, r4, #18
	bfi	r5, r8, #4, #1
	lsr	r8, r2, #10
	bfi	r4, r8, #18, #1
	lsr	r8, r3, #8
	bfi	r2, r8, #10, #1
	bfi	r3, r7, #8, #1
	lsr	r7, r2, #2
	lsr	r8, r2, #8
	bfi	r2, r8, #2, #1
	bfi	r2, r3, #8, #1
	bfi	r3, r6, #0, #1
	lsr	r8, r3, #3
	bfi	r6, r8, #0, #1
	lsr	r8, r6, #12
	bfi	r3, r8, #3, #1
	lsr	r8, r4, #19
	bfi	r6, r8, #12, #1
	lsr	r8, r2, #14
	bfi	r4, r8, #19, #1
	lsr	r8, r3, #24
	bfi	r2, r8, #14, #1
	lsr	r8, r4, #1
	bfi	r3, r8, #24, #1
	lsr	r8, r5, #5
	bfi	r4, r8, #1, #1
	lsr	r8, r4, #22
	bfi	r5, r8, #5, #1
	lsr	r8, r2, #26
	bfi	r4, r8, #22, #1
	lsr	r8, r5, #8
	bfi	r2, r8, #26, #1
	lsr	r8, r5, #2
	bfi	r5, r8, #8, #1
	lsr	r8, r4, #10
	bfi	r5, r8, #2, #1
	lsr	r8, r6, #9
	bfi	r4, r8, #10, #1
	lsr	r8, r4, #7
	bfi	r6, r8, #9, #1
	lsr	r8, r5, #29
	bfi	r4, r8, #7, #1
	lsr	r8, r2, #23
	bfi	r5, r8, #29, #1
	lsr	r8, r4, #28
	bfi	r2, r8, #23, #1
	lsr	r8, r3, #18
	bfi	r4, r8, #28, #1
	lsr	r8, r3, #9
	bfi	r3, r8, #18, #1
	lsr	r8, r2, #5
	bfi	r3, r8, #9, #1
	lsr	r8, r2, #20
	bfi	r2, r8, #5, #1
	lsr	r8, r4, #16
	bfi	r2, r8, #20, #1
	bfi	r4, r7, #16, #1
	lsr	r7, r2, #3
	lsr	r8, r2, #12
	bfi	r2, r8, #3, #1
	lsr	r8, r3, #16
	bfi	r2, r8, #12, #1
	lsr	r8, r3, #1
	bfi	r3, r8, #16, #1
	lsr	r8, r6, #4
	bfi	r3, r8, #1, #1
	lsr	r8, r3, #19
	bfi	r6, r8, #4, #1
	lsr	r8, r3, #13
	bfi	r3, r8, #19, #1
	lsr	r8, r2, #21
	bfi	r3, r8, #13, #1
	lsr	r8, r4, #20
	bfi	r2, r8, #21, #1
	lsr	r8, r2, #18
	bfi	r4, r8, #20, #1
	lsr	r8, r4, #8
	bfi	r2, r8, #18, #1
	lsr	r8, r6, #1
	bfi	r4, r8, #8, #1
	lsr	r8, r3, #7
	bfi	r6, r8, #1, #1
	lsr	r8, r6, #28
	bfi	r3, r8, #7, #1
	lsr	r8, r6, #19
	bfi	r6, r8, #28, #1
	lsr	r8, r5, #15
	bfi	r6, r8, #19, #1
	lsr	r8, r5, #30
	bfi	r5, r8, #15, #1
	lsr	r8, r2, #27
	bfi	r5, r8, #30, #1
	lsr	r8, r5, #12
	bfi	r2, r8, #27, #1
	lsr	r8, r5, #18
	bfi	r5, r8, #12, #1
	lsr	r8, r6, #10
	bfi	r5, r8, #18, #1
	lsr	r8, r4, #11
	bfi	r6, r8, #10, #1
	lsr	r8, r6, #13
	bfi	r4, r8, #11, #1
	lsr	r8, r4, #23
	bfi	r6, r8, #13, #1
	lsr	r8, r2, #30
	bfi	r4, r8, #23, #1
	lsr	r8, r5, #24
	bfi	r2, r8, #30, #1
	bfi	r5, r7, #24, #1
	lsr	r7, r2, #6
	lsr	r8, r2, #24
	bfi	r2, r8, #6, #1
	bfi	r2, r5, #24, #1
	lsr	r8, r4, #2
	bfi	r5, r8, #0, #1
	lsr	r8, r5, #9
	bfi	r4, r8, #2, #1
	lsr	r8, r5, #6
	bfi	r5, r8, #9, #1
	lsr	r8, r4, #26
	bfi	r5, r8, #6, #1
	lsr	r8, r3, #10
	bfi	r4, r8, #26, #1
	lsr	r8, r2, #9
	bfi	r3, r8, #10, #1
	lsr	r8, r3, #4
	bfi	r2, r8, #9, #1
	lsr	r8, r6, #16
	bfi	r3, r8, #4, #1
	lsr	r8, r5, #3
	bfi	r6, r8, #16, #1
	lsr	r8, r4, #14
	bfi	r5, r8, #3, #1
	lsr	r8, r6, #25
	bfi	r4, r8, #14, #1
	lsr	r8, r6, #7
	bfi	r6, r8, #25, #1
	lsr	r8, r3, #31
	bfi	r6, r8, #7, #1
	lsr	r8, r4, #29
	bfi	r3, r8, #31, #1
	lsr	r8, r3, #22
	bfi	r4, r8, #29, #1
	lsr	r8, r3, #25
	bfi	r3, r8, #22, #1
	lsr	r8, r4, #5
	bfi	r3, r8, #25, #1
	lsr	r8, r5, #21
	bfi	r4, r8, #5, #1
	lsr	r8, r6, #22
	bfi	r5, r8, #21, #1
	lsr	r8, r5, #27
	bfi	r6, r8, #22, #1
	lsr	r8, r2, #15
	bfi	r5, r8, #27, #1
	lsr	r8, r3, #28
	bfi	r2, r8, #15, #1
	lsr	r8, r4, #17
	bfi	r3, r8, #28, #1
	bfi	r4, r7, #17, #1
	lsr	r7, r2, #11
	lsr	r8, r3, #12
	bfi	r2, r8, #11, #1
	lsr	r8, r2, #17
	bfi	r3, r8, #12, #1
	lsr	r8, r4, #4
	bfi	r2, r8, #17, #1
	lsr	r8, r5, #17
	bfi	r4, r8, #4, #1
	lsr	r8, r6, #6
	bfi	r5, r8, #17, #1
	lsr	r8, r3, #27
	bfi	r6, r8, #6, #1
	lsr	r8, r4, #13
	bfi	r3, r8, #27, #1
	lsr	r8, r6, #21
	bfi	r4, r8, #13, #1
	lsr	r8, r5, #23
	bfi	r6, r8, #21, #1
	lsr	r8, r6, #30
	bfi	r5, r8, #23, #1
	lsr	r8, r6, #27
	bfi	r6, r8, #30, #1
	lsr	r8, r6, #15
	bfi	r6, r8, #27, #1
	lsr	r8, r4, #31
	bfi	r6, r8, #15, #1
	lsr	r8, r3, #30
	bfi	r4, r8, #31, #1
	lsr	r8, r4, #25
	bfi	r3, r8, #30, #1
	lsr	r8, r3, #6
	bfi	r4, r8, #25, #1
	lsr	r8, r6, #24
	bfi	r3, r8, #6, #1
	lsr	r8, r6, #3
	bfi	r6, r8, #24, #1
	lsr	r8, r3, #15
	bfi	r6, r8, #3, #1
	lsr	r8, r2, #29
	bfi	r3, r8, #15, #1
	lsr	r8, r5, #20
	bfi	r2, r8, #29, #1
	lsr	r8, r6, #18
	bfi	r5, r8, #20, #1
	lsr	r8, r5, #11
	bfi	r6, r8, #18, #1
	lsr	r8, r5, #14
	bfi	r5, r8, #11, #1
	lsr	r8, r5, #26
	bfi	r5, r8, #14, #1
	bfi	r5, r7, #26, #1
	lsr	r7, r2, #19
	lsr	r8, r4, #12
	bfi	r2, r8, #19, #1
	lsr	r8, r6, #17
	bfi	r4, r8, #12, #1
	lsr	r8, r5, #7
	bfi	r6, r8, #17, #1
	lsr	r8, r4, #30
	bfi	r5, r8, #7, #1
	lsr	r8, r3, #26
	bfi	r4, r8, #30, #1
	lsr	r8, r4, #9
	bfi	r3, r8, #26, #1
	lsr	r8, r6, #5
	bfi	r4, r8, #9, #1
	lsr	r8, r3, #23
	bfi	r6, r8, #5, #1
	lsr	r8, r3, #29
	bfi	r3, r8, #23, #1
	lsr	r8, r4, #21
	bfi	r3, r8, #29, #1
	lsr	r8, r2, #22
	bfi	r4, r8, #21, #1
	lsr	r8, r4, #24
	bfi	r2, r8, #22, #1
	lsr	r8, r3, #2
	bfi	r4, r8, #24, #1
	lsr	r8, r6, #8
	bfi	r3, r8, #2, #1
	lsr	r8, r4, #3
	bfi	r6, r8, #8, #1
	lsr	r8, r5, #13
	bfi	r4, r8, #3, #1
	lsr	r8, r5, #22
	bfi	r5, r8, #13, #1
	lsr	r8, r6, #26
	bfi	r5, r8, #22, #1
	lsr	r8, r6, #11
	bfi	r6, r8, #26, #1
	lsr	r8, r4, #15
	bfi	r6, r8, #11, #1
	lsr	r8, r6, #29
	bfi	r4, r8, #15, #1
	lsr	r8, r6, #23
	bfi	r6, r8, #29, #1
	lsr	r8, r5, #31
	bfi	r6, r8, #23, #1
	lsr	r8, r2, #31
	bfi	r5, r8, #31, #1
	lsr	r8, r5, #28
	bfi	r2, r8, #31, #1
	bfi	r5, r7, #28, #1
	subs	r1, r1, #1
	bne	.L1
	str	r2, [r0, #0]
	str	r3, [r0, #4]
	str	r4, [r0, #8]
	str	r5, [r0, #12]
	str	r6, [r0, #16]
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	spongent160_permute, .-spongent160_permute

	.align	2
	.global	spongent176_permute
	.thumb
	.thumb_func
	.type	spongent176_permute, %function
spongent176_permute:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r2, [r0, #0]
	ldr	r3, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
	ldr	r6, [r0, #16]
	ldrh	r7, [r0, #20]
	adr	r10, rconst176
	movs	r1, #90
.L2:
	ldrb	r8, [r10], #1
	ldrb	r9, [r10], #1
	eor	r2, r8
	eor	r7, r7, r9, lsl #8
	lsr	r8, r2, #3
	eor	r8, r8, r2, lsr #1
	lsr	r9, r2, #2
	eor	r9, r9, r2, lsr #1
	and	r8, r9
	lsr	r9, r2, #3
	eor	r9, r9, r2, lsr #2
	eor	r9, r2
	eor	r9, r8
	mvn	r9, r9
	lsr	lr, r2, #3
	mvn	lr, lr
	and	r9, lr
	lsr	lr, r2, #2
	eor	lr, r9
	lsr	fp, r2, #1
	eor	fp, r2
	eor	fp, lr
	eor	fp, r8
	and	lr, fp
	lsr	fp, r2, #1
	eor	fp, r8
	lsr	ip, r2, #2
	eor	ip, r8
	mvn	ip, ip
	and	fp, ip
	eor	lr, lr, r2, lsr #2
	eor	lr, lr, r2, lsr #1
	eor	lr, r2
	and	lr, lr, #0x11111111
	eor	ip, r2, r2, lsr #3
	eor	ip, ip, r2, lsr #1
	eor	ip, r8
	eor	ip, r9
	and	ip, ip, #0x11111111
	eor	r9, r9, r2, lsr #3
	eor	r9, r9, r2, lsr #2
	eor	r9, r9, r2, lsr #1
	and	r9, r9, #0x11111111
	eor	r2, r2, r2, lsr #3
	eor	r2, r8
	eor	r2, fp
	and	r2, r2, #0x11111111
	orr	r2, r2, r9, lsl #1
	orr	r2, r2, ip, lsl #2
	orr	r2, r2, lr, lsl #3
	lsr	r8, r3, #3
	eor	r8, r8, r3, lsr #1
	lsr	r9, r3, #2
	eor	r9, r9, r3, lsr #1
	and	r8, r9
	lsr	r9, r3, #3
	eor	r9, r9, r3, lsr #2
	eor	r9, r3
	eor	r9, r8
	mvn	r9, r9
	lsr	lr, r3, #3
	mvn	lr, lr
	and	r9, lr
	lsr	lr, r3, #2
	eor	lr, r9
	lsr	fp, r3, #1
	eor	fp, r3
	eor	fp, lr
	eor	fp, r8
	and	lr, fp
	lsr	fp, r3, #1
	eor	fp, r8
	lsr	ip, r3, #2
	eor	ip, r8
	mvn	ip, ip
	and	fp, ip
	eor	lr, lr, r3, lsr #2
	eor	lr, lr, r3, lsr #1
	eor	lr, r3
	and	lr, lr, #0x11111111
	eor	ip, r3, r3, lsr #3
	eor	ip, ip, r3, lsr #1
	eor	ip, r8
	eor	ip, r9
	and	ip, ip, #0x11111111
	eor	r9, r9, r3, lsr #3
	eor	r9, r9, r3, lsr #2
	eor	r9, r9, r3, lsr #1
	and	r9, r9, #0x11111111
	eor	r3, r3, r3, lsr #3
	eor	r3, r8
	eor	r3, fp
	and	r3, r3, #0x11111111
	orr	r3, r3, r9, lsl #1
	orr	r3, r3, ip, lsl #2
	orr	r3, r3, lr, lsl #3
	lsr	r8, r4, #3
	eor	r8, r8, r4, lsr #1
	lsr	r9, r4, #2
	eor	r9, r9, r4, lsr #1
	and	r8, r9
	lsr	r9, r4, #3
	eor	r9, r9, r4, lsr #2
	eor	r9, r4
	eor	r9, r8
	mvn	r9, r9
	lsr	lr, r4, #3
	mvn	lr, lr
	and	r9, lr
	lsr	lr, r4, #2
	eor	lr, r9
	lsr	fp, r4, #1
	eor	fp, r4
	eor	fp, lr
	eor	fp, r8
	and	lr, fp
	lsr	fp, r4, #1
	eor	fp, r8
	lsr	ip, r4, #2
	eor	ip, r8
	mvn	ip, ip
	and	fp, ip
	eor	lr, lr, r4, lsr #2
	eor	lr, lr, r4, lsr #1
	eor	lr, r4
	and	lr, lr, #0x11111111
	eor	ip, r4, r4, lsr #3
	eor	ip, ip, r4, lsr #1
	eor	ip, r8
	eor	ip, r9
	and	ip, ip, #0x11111111
	eor	r9, r9, r4, lsr #3
	eor	r9, r9, r4, lsr #2
	eor	r9, r9, r4, lsr #1
	and	r9, r9, #0x11111111
	eor	r4, r4, r4, lsr #3
	eor	r4, r8
	eor	r4, fp
	and	r4, r4, #0x11111111
	orr	r4, r4, r9, lsl #1
	orr	r4, r4, ip, lsl #2
	orr	r4, r4, lr, lsl #3
	lsr	r8, r5, #3
	eor	r8, r8, r5, lsr #1
	lsr	r9, r5, #2
	eor	r9, r9, r5, lsr #1
	and	r8, r9
	lsr	r9, r5, #3
	eor	r9, r9, r5, lsr #2
	eor	r9, r5
	eor	r9, r8
	mvn	r9, r9
	lsr	lr, r5, #3
	mvn	lr, lr
	and	r9, lr
	lsr	lr, r5, #2
	eor	lr, r9
	lsr	fp, r5, #1
	eor	fp, r5
	eor	fp, lr
	eor	fp, r8
	and	lr, fp
	lsr	fp, r5, #1
	eor	fp, r8
	lsr	ip, r5, #2
	eor	ip, r8
	mvn	ip, ip
	and	fp, ip
	eor	lr, lr, r5, lsr #2
	eor	lr, lr, r5, lsr #1
	eor	lr, r5
	and	lr, lr, #0x11111111
	eor	ip, r5, r5, lsr #3
	eor	ip, ip, r5, lsr #1
	eor	ip, r8
	eor	ip, r9
	and	ip, ip, #0x11111111
	eor	r9, r9, r5, lsr #3
	eor	r9, r9, r5, lsr #2
	eor	r9, r9, r5, lsr #1
	and	r9, r9, #0x11111111
	eor	r5, r5, r5, lsr #3
	eor	r5, r8
	eor	r5, fp
	and	r5, r5, #0x11111111
	orr	r5, r5, r9, lsl #1
	orr	r5, r5, ip, lsl #2
	orr	r5, r5, lr, lsl #3
	lsr	r8, r6, #3
	eor	r8, r8, r6, lsr #1
	lsr	r9, r6, #2
	eor	r9, r9, r6, lsr #1
	and	r8, r9
	lsr	r9, r6, #3
	eor	r9, r9, r6, lsr #2
	eor	r9, r6
	eor	r9, r8
	mvn	r9, r9
	lsr	lr, r6, #3
	mvn	lr, lr
	and	r9, lr
	lsr	lr, r6, #2
	eor	lr, r9
	lsr	fp, r6, #1
	eor	fp, r6
	eor	fp, lr
	eor	fp, r8
	and	lr, fp
	lsr	fp, r6, #1
	eor	fp, r8
	lsr	ip, r6, #2
	eor	ip, r8
	mvn	ip, ip
	and	fp, ip
	eor	lr, lr, r6, lsr #2
	eor	lr, lr, r6, lsr #1
	eor	lr, r6
	and	lr, lr, #0x11111111
	eor	ip, r6, r6, lsr #3
	eor	ip, ip, r6, lsr #1
	eor	ip, r8
	eor	ip, r9
	and	ip, ip, #0x11111111
	eor	r9, r9, r6, lsr #3
	eor	r9, r9, r6, lsr #2
	eor	r9, r9, r6, lsr #1
	and	r9, r9, #0x11111111
	eor	r6, r6, r6, lsr #3
	eor	r6, r8
	eor	r6, fp
	and	r6, r6, #0x11111111
	orr	r6, r6, r9, lsl #1
	orr	r6, r6, ip, lsl #2
	orr	r6, r6, lr, lsl #3
	lsr	r8, r7, #3
	eor	r8, r8, r7, lsr #1
	lsr	r9, r7, #2
	eor	r9, r9, r7, lsr #1
	and	r8, r9
	lsr	r9, r7, #3
	eor	r9, r9, r7, lsr #2
	eor	r9, r7
	eor	r9, r8
	mvn	r9, r9
	lsr	lr, r7, #3
	mvn	lr, lr
	and	r9, lr
	lsr	lr, r7, #2
	eor	lr, r9
	lsr	fp, r7, #1
	eor	fp, r7
	eor	fp, lr
	eor	fp, r8
	and	lr, fp
	lsr	fp, r7, #1
	eor	fp, r8
	lsr	ip, r7, #2
	eor	ip, r8
	mvn	ip, ip
	and	fp, ip
	eor	lr, lr, r7, lsr #2
	eor	lr, lr, r7, lsr #1
	eor	lr, r7
	and	lr, lr, #0x11111111
	eor	ip, r7, r7, lsr #3
	eor	ip, ip, r7, lsr #1
	eor	ip, r8
	eor	ip, r9
	and	ip, ip, #0x11111111
	eor	r9, r9, r7, lsr #3
	eor	r9, r9, r7, lsr #2
	eor	r9, r9, r7, lsr #1
	and	r9, r9, #0x11111111
	eor	r7, r7, r7, lsr #3
	eor	r7, r8
	eor	r7, fp
	and	r7, r7, #0x11111111
	orr	r7, r7, r9, lsl #1
	orr	r7, r7, ip, lsl #2
	orr	r7, r7, lr, lsl #3
	lsr	r8, r2, #1
	lsr	r9, r2, #4
	bfi	r2, r9, #1, #1
	lsr	r9, r2, #16
	bfi	r2, r9, #4, #1
	bfi	r2, r4, #16, #1
	lsr	r9, r4, #17
	bfi	r4, r9, #0, #1
	lsr	r9, r6, #21
	bfi	r4, r9, #17, #1
	lsr	r9, r4, #7
	bfi	r6, r9, #21, #1
	lsr	r9, r5, #13
	bfi	r4, r9, #7, #1
	lsr	r9, r4, #22
	bfi	r5, r9, #13, #1
	lsr	r9, r7, #9
	bfi	r4, r9, #22, #1
	lsr	r9, r6, #23
	bfi	r7, r9, #9, #1
	lsr	r9, r4, #15
	bfi	r6, r9, #23, #1
	lsr	r9, r6, #13
	bfi	r4, r9, #15, #1
	lsr	r9, r3, #7
	bfi	r6, r9, #13, #1
	lsr	r9, r6, #28
	bfi	r3, r9, #7, #1
	lsr	r9, r5, #3
	bfi	r6, r9, #28, #1
	lsr	r9, r3, #14
	bfi	r5, r9, #3, #1
	lsr	r9, r2, #9
	bfi	r3, r9, #14, #1
	lsr	r9, r3, #4
	bfi	r2, r9, #9, #1
	lsr	r9, r6, #16
	bfi	r3, r9, #4, #1
	lsr	r9, r3, #19
	bfi	r6, r9, #16, #1
	lsr	r9, r2, #29
	bfi	r3, r9, #19, #1
	lsr	r9, r5, #20
	bfi	r2, r9, #29, #1
	lsr	r9, r5, #18
	bfi	r5, r9, #20, #1
	lsr	r9, r5, #10
	bfi	r5, r9, #18, #1
	lsr	r9, r4, #10
	bfi	r5, r9, #10, #1
	lsr	r9, r5, #25
	bfi	r4, r9, #10, #1
	lsr	r9, r6, #6
	bfi	r5, r9, #25, #1
	lsr	r9, r2, #11
	bfi	r6, r9, #6, #1
	lsr	r9, r3, #12
	bfi	r2, r9, #11, #1
	bfi	r3, r8, #12, #1
	lsr	r8, r2, #2
	lsr	r9, r2, #8
	bfi	r2, r9, #2, #1
	bfi	r2, r3, #8, #1
	bfi	r3, r6, #0, #1
	lsr	r9, r7, #2
	bfi	r6, r9, #0, #1
	lsr	r9, r5, #27
	bfi	r7, r9, #2, #1
	lsr	r9, r6, #14
	bfi	r5, r9, #27, #1
	lsr	r9, r3, #11
	bfi	r6, r9, #14, #1
	lsr	r9, r7, #12
	bfi	r3, r9, #11, #1
	lsr	r9, r7, #3
	bfi	r7, r9, #12, #1
	lsr	r9, r5, #31
	bfi	r7, r9, #3, #1
	lsr	r9, r6, #30
	bfi	r5, r9, #31, #1
	lsr	r9, r5, #11
	bfi	r6, r9, #30, #1
	lsr	r9, r4, #14
	bfi	r5, r9, #11, #1
	lsr	r9, r6, #9
	bfi	r4, r9, #14, #1
	lsr	r9, r2, #23
	bfi	r6, r9, #9, #1
	lsr	r9, r4, #28
	bfi	r2, r9, #23, #1
	lsr	r9, r2, #18
	bfi	r4, r9, #28, #1
	lsr	r9, r4, #8
	bfi	r2, r9, #18, #1
	lsr	r9, r5, #17
	bfi	r4, r9, #8, #1
	lsr	r9, r5, #6
	bfi	r5, r9, #17, #1
	lsr	r9, r3, #26
	bfi	r5, r9, #6, #1
	lsr	r9, r3, #25
	bfi	r3, r9, #26, #1
	lsr	r9, r3, #21
	bfi	r3, r9, #25, #1
	lsr	r9, r3, #5
	bfi	r3, r9, #21, #1
	lsr	r9, r6, #20
	bfi	r3, r9, #5, #1
	lsr	r9, r4, #3
	bfi	r6, r9, #20, #1
	lsr	r9, r4, #29
	bfi	r4, r9, #3, #1
	lsr	r9, r2, #22
	bfi	r4, r9, #29, #1
	lsr	r9, r4, #24
	bfi	r2, r9, #22, #1
	bfi	r4, r8, #24, #1
	lsr	r8, r2, #3
	lsr	r9, r2, #12
	bfi	r2, r9, #3, #1
	lsr	r9, r3, #16
	bfi	r2, r9, #12, #1
	lsr	r9, r2, #17
	bfi	r3, r9, #16, #1
	lsr	r9, r4, #4
	bfi	r2, r9, #17, #1
	lsr	r9, r5, #1
	bfi	r4, r9, #4, #1
	lsr	r9, r3, #6
	bfi	r5, r9, #1, #1
	lsr	r9, r6, #24
	bfi	r3, r9, #6, #1
	lsr	r9, r4, #19
	bfi	r6, r9, #24, #1
	lsr	r9, r6, #29
	bfi	r4, r9, #19, #1
	lsr	r9, r5, #7
	bfi	r6, r9, #29, #1
	lsr	r9, r3, #30
	bfi	r5, r9, #7, #1
	lsr	r9, r4, #9
	bfi	r3, r9, #30, #1
	lsr	r9, r5, #21
	bfi	r4, r9, #9, #1
	lsr	r9, r5, #22
	bfi	r5, r9, #21, #1
	lsr	r9, r5, #26
	bfi	r5, r9, #22, #1
	lsr	r9, r6, #10
	bfi	r5, r9, #26, #1
	lsr	r9, r2, #27
	bfi	r6, r9, #10, #1
	lsr	r9, r5, #12
	bfi	r2, r9, #27, #1
	lsr	r9, r4, #18
	bfi	r5, r9, #12, #1
	lsr	r9, r6, #25
	bfi	r4, r9, #18, #1
	lsr	r9, r4, #23
	bfi	r6, r9, #25, #1
	lsr	r9, r7, #13
	bfi	r4, r9, #23, #1
	lsr	r9, r7, #7
	bfi	r7, r9, #13, #1
	lsr	r9, r6, #15
	bfi	r7, r9, #7, #1
	lsr	r9, r3, #15
	bfi	r6, r9, #15, #1
	lsr	r9, r2, #13
	bfi	r3, r9, #15, #1
	lsr	r9, r3, #20
	bfi	r2, r9, #13, #1
	lsr	r9, r3, #1
	bfi	r3, r9, #20, #1
	lsr	r9, r6, #4
	bfi	r3, r9, #1, #1
	bfi	r6, r8, #4, #1
	lsr	r8, r2, #5
	lsr	r9, r2, #20
	bfi	r2, r9, #5, #1
	lsr	r9, r4, #16
	bfi	r2, r9, #20, #1
	lsr	r9, r6, #17
	bfi	r4, r9, #16, #1
	lsr	r9, r3, #23
	bfi	r6, r9, #17, #1
	lsr	r9, r3, #13
	bfi	r3, r9, #23, #1
	bfi	r3, r8, #13, #1
	lsr	r8, r2, #6
	lsr	r9, r2, #24
	bfi	r2, r9, #6, #1
	bfi	r2, r5, #24, #1
	lsr	r9, r3, #2
	bfi	r5, r9, #0, #1
	lsr	r9, r6, #8
	bfi	r3, r9, #2, #1
	lsr	r9, r2, #19
	bfi	r6, r9, #8, #1
	lsr	r9, r4, #12
	bfi	r2, r9, #19, #1
	lsr	r9, r6, #1
	bfi	r4, r9, #12, #1
	lsr	r9, r7, #6
	bfi	r6, r9, #1, #1
	lsr	r9, r6, #11
	bfi	r7, r9, #6, #1
	lsr	r9, r2, #31
	bfi	r6, r9, #11, #1
	lsr	r9, r5, #28
	bfi	r2, r9, #31, #1
	lsr	r9, r6, #18
	bfi	r5, r9, #28, #1
	lsr	r9, r3, #27
	bfi	r6, r9, #18, #1
	lsr	r9, r3, #29
	bfi	r3, r9, #27, #1
	lsr	r9, r4, #5
	bfi	r3, r9, #29, #1
	lsr	r9, r5, #5
	bfi	r4, r9, #5, #1
	lsr	r9, r3, #22
	bfi	r5, r9, #5, #1
	lsr	r9, r3, #9
	bfi	r3, r9, #22, #1
	lsr	r9, r7, #4
	bfi	r3, r9, #9, #1
	lsr	r9, r6, #3
	bfi	r7, r9, #4, #1
	lsr	r9, r7, #14
	bfi	r6, r9, #3, #1
	lsr	r9, r7, #11
	bfi	r7, r9, #14, #1
	lsr	r9, r6, #31
	bfi	r7, r9, #11, #1
	lsr	r9, r5, #15
	bfi	r6, r9, #31, #1
	lsr	r9, r4, #30
	bfi	r5, r9, #15, #1
	lsr	r9, r2, #26
	bfi	r4, r9, #30, #1
	lsr	r9, r5, #8
	bfi	r2, r9, #26, #1
	lsr	r9, r4, #2
	bfi	r5, r9, #8, #1
	lsr	r9, r4, #25
	bfi	r4, r9, #2, #1
	bfi	r4, r8, #25, #1
	lsr	r8, r2, #7
	lsr	r9, r2, #28
	bfi	r2, r9, #7, #1
	lsr	r9, r5, #16
	bfi	r2, r9, #28, #1
	lsr	r9, r5, #2
	bfi	r5, r9, #16, #1
	lsr	r9, r3, #10
	bfi	r5, r9, #2, #1
	lsr	r9, r7, #8
	bfi	r3, r9, #10, #1
	lsr	r9, r6, #19
	bfi	r7, r9, #8, #1
	lsr	r9, r3, #31
	bfi	r6, r9, #19, #1
	lsr	r9, r4, #13
	bfi	r3, r9, #31, #1
	lsr	r9, r6, #5
	bfi	r4, r9, #13, #1
	bfi	r6, r8, #5, #1
	lsr	r8, r2, #10
	lsr	r9, r3, #8
	bfi	r2, r9, #10, #1
	bfi	r3, r7, #8, #1
	lsr	r9, r5, #19
	bfi	r7, r9, #0, #1
	lsr	r9, r5, #14
	bfi	r5, r9, #19, #1
	lsr	r9, r4, #26
	bfi	r5, r9, #14, #1
	bfi	r4, r8, #26, #1
	lsr	r8, r2, #14
	lsr	r9, r3, #24
	bfi	r2, r9, #14, #1
	lsr	r9, r3, #17
	bfi	r3, r9, #24, #1
	lsr	r9, r2, #21
	bfi	r3, r9, #17, #1
	lsr	r9, r4, #20
	bfi	r2, r9, #21, #1
	lsr	r9, r7, #1
	bfi	r4, r9, #20, #1
	lsr	r9, r5, #23
	bfi	r7, r9, #1, #1
	lsr	r9, r5, #30
	bfi	r5, r9, #23, #1
	lsr	r9, r6, #26
	bfi	r5, r9, #30, #1
	lsr	r9, r4, #27
	bfi	r6, r9, #26, #1
	bfi	r4, r8, #27, #1
	lsr	r8, r2, #15
	lsr	r9, r3, #28
	bfi	r2, r9, #15, #1
	lsr	r9, r4, #1
	bfi	r3, r9, #28, #1
	lsr	r9, r4, #21
	bfi	r4, r9, #1, #1
	lsr	r9, r7, #5
	bfi	r4, r9, #21, #1
	lsr	r9, r6, #7
	bfi	r7, r9, #5, #1
	bfi	r6, r8, #7, #1
	lsr	r8, r2, #25
	lsr	r9, r5, #4
	bfi	r2, r9, #25, #1
	lsr	r9, r3, #18
	bfi	r5, r9, #4, #1
	bfi	r3, r8, #18, #1
	lsr	r8, r2, #30
	lsr	r9, r5, #24
	bfi	r2, r9, #30, #1
	lsr	r9, r6, #2
	bfi	r5, r9, #24, #1
	lsr	r9, r7, #10
	bfi	r6, r9, #2, #1
	lsr	r9, r6, #27
	bfi	r7, r9, #10, #1
	lsr	r9, r4, #31
	bfi	r6, r9, #27, #1
	bfi	r4, r8, #31, #1
	lsr	r8, r3, #3
	lsr	r9, r6, #12
	bfi	r3, r9, #3, #1
	bfi	r6, r8, #12, #1
	lsr	r8, r4, #6
	lsr	r9, r5, #9
	bfi	r4, r9, #6, #1
	bfi	r5, r8, #9, #1
	lsr	r8, r4, #11
	lsr	r9, r5, #29
	bfi	r4, r9, #11, #1
	lsr	r9, r6, #22
	bfi	r5, r9, #29, #1
	bfi	r6, r8, #22, #1
	subs	r1, r1, #1
	bne	.L2
	str	r2, [r0, #0]
	str	r3, [r0, #4]
	str	r4, [r0, #8]
	str	r5, [r0, #12]
	str	r6, [r0, #16]
	strh	r7, [r0, #20]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	spongent176_permute, .-spongent176_permute

#endif
