/* twofish-armv7-neon.S  -  ARM/NEON assembly implementation of Twofish cipher
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/linkage.h>
#include <asm/assembler.h>

#include "glue_helper-asm-neon.S"

.text
.align 4
.fpu neon

/* Structure of twofish_ctx */
#define s0 0
#define s1 ((s0) + 4 * 256)
#define s2 ((s1) + 4 * 256)
#define s3 ((s2) + 4 * 256)
#define w  ((s3) + 4 * 256)
#define k  ((w) + 4 * 8)

/* ARM registers */
#define CTX    r0
#define CTXs0  r0
#define CTXs1  r1
#define CTXs2  r2
#define CTXs3  r3

#define RROUND r12

/* NEON vector registers */
#define RA0 q0
#define RA1 q1
#define RA2 q2
#define RA3 q3

#define RB0 q4
#define RB1 q5
#define RB2 q6
#define RB3 q7

#define RX  q8
#define RY  q9

#define RT0 q10
#define RT1 q11
#define RT2 q12
#define RT3 q13
#define RT4 q14

#define RA0d0 d0
#define RA0d1 d1
#define RA1d0 d2
#define RA1d1 d3
#define RA2d0 d4
#define RA2d1 d5
#define RA3d0 d6
#define RA3d1 d7
#define RB0d0 d8
#define RB0d1 d9
#define RB1d0 d10
#define RB1d1 d11
#define RB2d0 d12
#define RB2d1 d13
#define RB3d0 d14
#define RB3d1 d15
#define RXd0  d16
#define RXd1  d17
#define RYd0  d18
#define RYd1  d19
#define RT0d0 d20
#define RT0d1 d21
#define RT1d0 d22
#define RT1d1 d23
#define RT2d0 d24
#define RT2d1 d25
#define RT3d0 d26
#define RT3d1 d27
#define RT4d0 d28
#define RT4d1 d29

/**********************************************************************
  helper macros
 **********************************************************************/

#define transpose_4x4(_q0, _q1, _q2, _q3) \
	vtrn.32 _q0, _q1;	\
	vtrn.32 _q2, _q3;	\
	vswp _q0##d1, _q2##d0;	\
	vswp _q1##d1, _q3##d0;

/**********************************************************************
  8-way twofish
 **********************************************************************/

/* XOR round key into block state in a0,a1,a2,a3. */
#define BLOCK_XOR_KEY(a0, a1, a2, a3, b0, b1, b2, b3, t0, t1, t2, t3) \
	vdup.32 t3, t0##d0[0]; \
	vdup.32 t1, t0##d0[1]; \
	vdup.32 t2, t0##d1[0]; \
	vdup.32 t0, t0##d1[1]; \
	veor a0, a0, t3;	veor b0, b0, t3; \
	veor a1, a1, t1;	veor b1, b1, t1; \
	veor a2, a2, t2;	veor b2, b2, t2; \
	veor a3, a3, t0;	veor b3, b3, t0;

#define T_TABLE_LOOKUP(rt, a, b, x, y, na, t0, t1, t2, t3) \
	/* Store b */ \
	vst1.8 {b}, [rt]; \
	/* Load a */ \
	ldrb r4, [rt, #16]; \
	ldrb r5, [rt, #20]; \
	ldrb r6, [rt, #17]; \
	ldrb r7, [rt, #21];		add r4, CTXs0, r4, lsl #2; \
	ldrb r8, [rt, #18];		add r5, CTXs0, r5, lsl #2; \
	ldrb r9, [rt, #22];		add r6, CTXs1, r6, lsl #2; \
	ldrb r10, [rt, #19];		add r7, CTXs1, r7, lsl #2; \
	ldrb r11, [rt, #23];		add r8, CTXs2, r8, lsl #2; \
	vld1.32 {t0##d0[0]}, [r4];	add r9, CTXs2, r9, lsl #2; \
	vld1.32 {t0##d0[1]}, [r5];	add r10, CTXs3, r10, lsl #2; \
	vld1.32 {t1##d0[0]}, [r6];	add r11, CTXs3, r11, lsl #2; \
	vld1.32 {t1##d0[1]}, [r7]; \
	vld1.32 {t2##d0[0]}, [r8]; \
	vld1.32 {t2##d0[1]}, [r9]; \
	vld1.32 {t3##d0[0]}, [r10]; \
	vld1.32 {t3##d0[1]}, [r11]; \
	\
	ldrb r4, [rt, #24]; \
	ldrb r5, [rt, #28]; \
	ldrb r6, [rt, #25]; \
	ldrb r7, [rt, #29];		add r4, CTXs0, r4, lsl #2; \
	ldrb r8, [rt, #26];		add r5, CTXs0, r5, lsl #2; \
	ldrb r9, [rt, #30];		add r6, CTXs1, r6, lsl #2; \
	ldrb r10, [rt, #27];		add r7, CTXs1, r7, lsl #2; \
	ldrb r11, [rt, #31];		add r8, CTXs2, r8, lsl #2; \
	vld1.32 {t0##d1[0]}, [r4];	add r9, CTXs2, r9, lsl #2; \
	vld1.32 {t0##d1[1]}, [r5];	add r10, CTXs3, r10, lsl #2; \
	vld1.32 {t1##d1[0]}, [r6];	add r11, CTXs3, r11, lsl #2; \
	vld1.32 {t1##d1[1]}, [r7]; \
	vld1.32 {t2##d1[0]}, [r8]; \
	vld1.32 {t2##d1[1]}, [r9];	veor x, t0, t1; \
	vld1.32 {t3##d1[0]}, [r10];	veor x,  x, t2; \
	vld1.32 {t3##d1[1]}, [r11];	veor x,  x, t3; \
	\
	/* Store next a */ \
	add r4, rt, #16; \
	vst1.8 {na}, [r4]; \
	\
	/* Load b */ \
	ldrb r4, [rt, #0]; \
	ldrb r5, [rt, #4]; \
	ldrb r6, [rt, #1]; \
	ldrb r7, [rt, #5];		add r4, CTXs1, r4, lsl #2; \
	ldrb r8, [rt, #2];		add r5, CTXs1, r5, lsl #2; \
	ldrb r9, [rt, #6];		add r6, CTXs2, r6, lsl #2; \
	ldrb r10, [rt, #3];		add r7, CTXs2, r7, lsl #2; \
	ldrb r11, [rt, #7];		add r8, CTXs3, r8, lsl #2; \
	vld1.32 {t0##d0[0]}, [r4];	add r9, CTXs3, r9, lsl #2; \
	vld1.32 {t0##d0[1]}, [r5];	add r10, CTXs0, r10, lsl #2; \
	vld1.32 {t1##d0[0]}, [r6];	add r11, CTXs0, r11, lsl #2; \
	vld1.32 {t1##d0[1]}, [r7]; \
	vld1.32 {t2##d0[0]}, [r8]; \
	vld1.32 {t2##d0[1]}, [r9]; \
	vld1.32 {t3##d0[0]}, [r10]; \
	vld1.32 {t3##d0[1]}, [r11]; \
	\
	ldrb r4, [rt, #8]; \
	ldrb r5, [rt, #12]; \
	ldrb r6, [rt, #9]; \
	ldrb r7, [rt, #13];		add r4, CTXs1, r4, lsl #2; \
	ldrb r8, [rt, #10];		add r5, CTXs1, r5, lsl #2; \
	ldrb r9, [rt, #14];		add r6, CTXs2, r6, lsl #2; \
	ldrb r10, [rt, #11];		add r7, CTXs2, r7, lsl #2; \
	ldrb r11, [rt, #15];		add r8, CTXs3, r8, lsl #2; \
	vld1.32 {t0##d1[0]}, [r4];	add r9, CTXs3, r9, lsl #2; \
	vld1.32 {t0##d1[1]}, [r5];	add r10, CTXs0, r10, lsl #2; \
	vld1.32 {t1##d1[0]}, [r6];	add r11, CTXs0, r11, lsl #2; \
	vld1.32 {t1##d1[1]}, [r7]; \
	vld1.32 {t2##d1[0]}, [r8]; \
	vld1.32 {t2##d1[1]}, [r9];	veor y, t0, t1; \
	vld1.32 {t3##d1[0]}, [r10];	veor y,  y, t2; \
	vld1.32 {t3##d1[1]}, [r11];	veor y,  y, t3;

/* Apply a Twofish round to eight parallel blocks */
#define ENCRYPT_ROUND(n, x, y, c, d, rk, t0, t1, t2, t3) \
	/* Left rotate d */ \
	vshr.u32 t1, d, #(32 - 1); \
	vshl.u32 d, d, #1; \
	/* x += y */ \
	vadd.u32 x, x, y; \
	/* k[2*n] */ \
	vdup.32 t2, rk[0]; \
	/* k[2*n + 1] */ \
	vdup.32 t3, rk[1]; \
	/* x + k[2*n] */ \
	vadd.u32 t2, t2, x; \
	/* x + k[2*n + 1] */ \
	vadd.u32 t3, t3, x; \
	/* c ^= x + k[2*n] */ \
	veor c, c, t2; \
	veor d, d, t1; \
	/* y += x + k[2*n + 1] */ \
	vadd.u32 y, y, t3; \
	/* Right rotate c */ \
	vshl.u32 t0, c, #(32 - 1); \
	vshr.u32 c, c, #1; \
	/* d ^= y */ \
	veor d, d, y; \
	veor c, c, t0;

/* Apply an inverse Twofish round to eight parallel blocks */
#define DECRYPT_ROUND(n, x, y, c, d, rk, t0, t1, t2, t3) \
	/* Left rotate c */ \
	vshr.u32 t1, c, #(32 - 1); \
	vshl.u32 c, c, #1; \
	/* x += y */ \
	vadd.u32 x, x, y; \
	/* k[2*n] */ \
	vdup.32 t2, rk[0]; \
	/* k[2*n + 1] */ \
	vdup.32 t3, rk[1]; \
	/* y += x */ \
	vadd.u32 y, y, x; \
	/* x + k[2*n] */ \
	vadd.u32 t2, t2, x; \
	/* y + k[2*n + 1] */ \
	vadd.u32 t3, t3, y; \
	/* d ^= y + k[2*n + 1] */ \
	veor d, d, t3; \
	veor c, c, t1; \
	/* Right rotate d */ \
	vshl.u32 t0, d, #(32 - 1); \
	vshr.u32 d, d, #1; \
	/* c ^= x + k[2*n] */ \
	veor c, c, t2; \
	veor d, d, t0;

.type __twofish_enc_blk8_neon,%function
.align 4
__twofish_enc_blk8_neon:
	/* input:
	 *	r0: twofish_ctx pointer
	 *	RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3: eight parallel plaintext
	 *						blocks
	 * output:
	 *	RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1: eight parallel
	 * 						ciphertext blocks
	 */

	/* Allocate space for a and b */
	sub	sp, sp, #2*4*4;

	/* Calculate table pointers */
	add	CTXs3, CTXs0, #(s3 - s0);
	add	CTXs1, CTXs0, #(s1 - s0);
	add	CTXs2, CTXs0, #(s2 - s0);

	transpose_4x4(RA0, RA1, RA2, RA3);
	transpose_4x4(RB0, RB1, RB2, RB3);

	add	r10, CTXs3, #(w - s3);
	add	r11, sp, #16;
	add	RROUND, CTXs3, #(k - s3);

	/* Load whitening key */
	vld1.32 {RT0}, [r10];

	/* Input whitening */
	vdup.32 RT3, RT0d0[0];
	veor RA0, RA0, RT3;	veor RB0, RB0, RT3;

	/* Store a */
	vst1.8 {RA0}, [r11];

	vdup.32 RT1, RT0d0[1];
	vdup.32 RT2, RT0d1[0];
	vdup.32 RT0, RT0d1[1];

	veor RA1, RA1, RT1;	veor RB1, RB1, RT1;
	veor RA2, RA2, RT2;	veor RB2, RB2, RT2;
	veor RA3, RA3, RT0;	veor RB3, RB3, RT0;

	/* Rounds */
	vld1.32 {RT4}, [RROUND]!;

	T_TABLE_LOOKUP(sp, RA0, RA1, RX, RY, RB0, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(0, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RX, RY, RA2, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(0, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	T_TABLE_LOOKUP(sp, RA2, RA3, RX, RY, RB2, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(1, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RX, RY, RA0, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(1, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND]!;

	T_TABLE_LOOKUP(sp, RA0, RA1, RX, RY, RB0, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(2, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RX, RY, RA2, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(2, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	T_TABLE_LOOKUP(sp, RA2, RA3, RX, RY, RB2, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(3, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RX, RY, RA0, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(3, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND]!;

	T_TABLE_LOOKUP(sp, RA0, RA1, RX, RY, RB0, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(4, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RX, RY, RA2, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(4, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	T_TABLE_LOOKUP(sp, RA2, RA3, RX, RY, RB2, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(5, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RX, RY, RA0, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(5, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND]!;

	T_TABLE_LOOKUP(sp, RA0, RA1, RX, RY, RB0, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(6, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RX, RY, RA2, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(6, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	T_TABLE_LOOKUP(sp, RA2, RA3, RX, RY, RB2, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(7, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RX, RY, RA0, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(7, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND]!;

	T_TABLE_LOOKUP(sp, RA0, RA1, RX, RY, RB0, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(8, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RX, RY, RA2, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(8, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	T_TABLE_LOOKUP(sp, RA2, RA3, RX, RY, RB2, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(9, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RX, RY, RA0, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(9, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND]!;

	T_TABLE_LOOKUP(sp, RA0, RA1, RX, RY, RB0, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(10, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RX, RY, RA2, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(10, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	T_TABLE_LOOKUP(sp, RA2, RA3, RX, RY, RB2, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(11, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RX, RY, RA0, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(11, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND]!;

	T_TABLE_LOOKUP(sp, RA0, RA1, RX, RY, RB0, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(12, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RX, RY, RA2, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(12, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	T_TABLE_LOOKUP(sp, RA2, RA3, RX, RY, RB2, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(13, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RX, RY, RA0, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(13, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND];

	T_TABLE_LOOKUP(sp, RA0, RA1, RX, RY, RB0, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(14, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RX, RY, RA2, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(14, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	T_TABLE_LOOKUP(sp, RA2, RA3, RX, RY, RB2, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(15, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RX, RY, RA0, RT0, RT1, RT2, RT3);
	ENCRYPT_ROUND(15, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	/* Load whitening key */
	add	r4, CTXs3, #(w + 4*4 - s3);
	vld1.32 {RT0}, [r4];

	/* Clear data on stack */
	veor RX, RA0, RA0;
	veor RY, RA1, RA1;
	vst1.8 {RX}, [sp]!;
	vst1.8 {RY}, [sp]!;

	/* Output whitening */
	BLOCK_XOR_KEY(RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1, RT0, RT1, RT2, RT3);

	transpose_4x4(RA2, RA3, RA0, RA1);
	transpose_4x4(RB2, RB3, RB0, RB1);

	bx lr;
.size __twofish_enc_blk8_neon,.-__twofish_enc_blk8_neon

.type __twofish_dec_blk8_neon,%function
.align 4
__twofish_dec_blk8_neon:
	/* input:
	 *	r0: twofish_ctx pointer
	 *	RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1: eight parallel
	 * 						ciphertext blocks
	 * output:
	 *	RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3: eight parallel plaintext
	 *						blocks
	 */

	/* Allocate space for a and b */
	sub	sp, sp, #2*4*4;

	/* Calculate table pointers */
	add	CTXs3, CTXs0, #(s3 - s0);
	add	CTXs1, CTXs0, #(s1 - s0);
	add	CTXs2, CTXs0, #(s2 - s0);

	transpose_4x4(RA2, RA3, RA0, RA1);
	transpose_4x4(RB2, RB3, RB0, RB1);

	add	r10, CTXs3, #(w + 4*4 - s3);
	add	r11, sp, #16;
	add	r12, CTXs3, #(k - s3 + 8 * 14);

	/* Load whitening key */
	vld1.32 {RT0}, [r10];

	vdup.32 RT3, RT0d0[0];
	veor RA2, RA2, RT3;	veor RB2, RB2, RT3;

	/* Store a */
	vst1.8 {RA2}, [r11];

	vdup.32 RT1, RT0d0[1];
	vdup.32 RT2, RT0d1[0];
	vdup.32 RT0, RT0d1[1];
	veor RA3, RA3, RT1;	veor RB3, RB3, RT1;
	veor RA0, RA0, RT2;	veor RB0, RB0, RT2;
	veor RA1, RA1, RT0;	veor RB1, RB1, RT0;

	/* Rounds */
	vld1.32 {RT4}, [RROUND];

	T_TABLE_LOOKUP(sp, RA2, RA3, RX, RY, RB2, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(15, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RX, RY, RA0, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(15, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	sub RROUND, RROUND, #16;

	T_TABLE_LOOKUP(sp, RA0, RA1, RX, RY, RB0, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(14, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RX, RY, RA2, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(14, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND];

	T_TABLE_LOOKUP(sp, RA2, RA3, RX, RY, RB2, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(13, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RX, RY, RA0, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(13, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	sub RROUND, RROUND, #16;

	T_TABLE_LOOKUP(sp, RA0, RA1, RX, RY, RB0, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(12, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RX, RY, RA2, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(12, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND];

	T_TABLE_LOOKUP(sp, RA2, RA3, RX, RY, RB2, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(11, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RX, RY, RA0, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(11, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	sub RROUND, RROUND, #16;

	T_TABLE_LOOKUP(sp, RA0, RA1, RX, RY, RB0, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(10, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RX, RY, RA2, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(10, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND];

	T_TABLE_LOOKUP(sp, RA2, RA3, RX, RY, RB2, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(9, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RX, RY, RA0, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(9, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	sub RROUND, RROUND, #16;

	T_TABLE_LOOKUP(sp, RA0, RA1, RX, RY, RB0, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(8, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RX, RY, RA2, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(8, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND];

	T_TABLE_LOOKUP(sp, RA2, RA3, RX, RY, RB2, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(7, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RX, RY, RA0, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(7, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	sub RROUND, RROUND, #16;

	T_TABLE_LOOKUP(sp, RA0, RA1, RX, RY, RB0, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(6, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RX, RY, RA2, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(6, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND];

	T_TABLE_LOOKUP(sp, RA2, RA3, RX, RY, RB2, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(5, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RX, RY, RA0, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(5, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	sub RROUND, RROUND, #16;

	T_TABLE_LOOKUP(sp, RA0, RA1, RX, RY, RB0, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(4, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RX, RY, RA2, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(4, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND];

	T_TABLE_LOOKUP(sp, RA2, RA3, RX, RY, RB2, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(3, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RX, RY, RA0, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(3, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	sub RROUND, RROUND, #16;

	T_TABLE_LOOKUP(sp, RA0, RA1, RX, RY, RB0, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(2, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RX, RY, RA2, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(2, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	vld1.32 {RT4}, [RROUND];

	T_TABLE_LOOKUP(sp, RA2, RA3, RX, RY, RB2, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(1, RX, RY, RA0, RA1, RT4d1, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB2, RB3, RX, RY, RA0, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(1, RX, RY, RB0, RB1, RT4d1, RT0, RT1, RT2, RT3);

	T_TABLE_LOOKUP(sp, RA0, RA1, RX, RY, RB0, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(0, RX, RY, RA2, RA3, RT4d0, RT0, RT1, RT2, RT3);
	T_TABLE_LOOKUP(sp, RB0, RB1, RX, RY, RA2, RT0, RT1, RT2, RT3);
	DECRYPT_ROUND(0, RX, RY, RB2, RB3, RT4d0, RT0, RT1, RT2, RT3);

	/* Load whitening key */
	add	r4, CTXs3, #(w - s3);
	vld1.32 {RT0}, [r4];

	/* Clear data on stack */
	veor RX, RA2, RA2;
	veor RY, RA3, RA3;
	vst1.8 {RX}, [sp]!;
	vst1.8 {RY}, [sp]!;

	/* Output whitening */
	BLOCK_XOR_KEY(RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3, RT0, RT1, RT2, RT3);

	transpose_4x4(RA0, RA1, RA2, RA3);
	transpose_4x4(RB0, RB1, RB2, RB3);

	bx lr;
.size __twofish_dec_blk8_neon,.-__twofish_dec_blk8_neon

ENTRY(twofish_ecb_enc_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 */

	stmdb sp!, {r1, r4-r12, lr};

	load_8way(%r2, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3);

	bl __twofish_enc_blk8_neon;

	pop {r1};

	store_8way(%r1, RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1);

	pop {r4-r12, pc};
ENDPROC(twofish_ecb_enc_8way_neon)

ENTRY(twofish_ecb_dec_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 */

	stmdb sp!, {r1, r4-r12, lr};

	load_8way(%r2, RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1);

	bl __twofish_dec_blk8_neon;

	pop {r1};

	store_8way(%r1, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3);

	pop {r4-r12, pc};
ENDPROC(twofish_ecb_dec_8way_neon)

ENTRY(twofish_cbc_dec_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 */

	stmdb sp!, {r1, r2, r4-r12, lr};

	load_8way(%r2, RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1);

	bl __twofish_dec_blk8_neon;

	pop {r1, r2};

	store_cbc_8way(%r2, %r1, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3, RT0, RT1, RT2, RT3);

	pop {r4-r12, pc};
ENDPROC(twofish_cbc_dec_8way_neon)

ENTRY(twofish_ctr_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 *	%r3: iv (little endian, 128bit)
	 */

	stmdb sp!, {r1, r2, r4-r12, lr};

	load_ctr_8way(%r3, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3,
		      RT0, RT1, RT2);

	bl __twofish_enc_blk8_neon;

	pop {r1, r2};

	store_ctr_8way(%r2, %r1, RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1,
		       RT0, RT1, RT2, RT3);

	pop {r4-r12, pc};
ENDPROC(twofish_ctr_8way_neon)

ENTRY(twofish_xts_enc_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 *	%r3: iv
	 */

	stmdb sp!, {r1, r4-r12, lr};

	/* regs <= src, dst <= IVs, regs <= regs xor IVs */
	load_xts_8way(%r3, %r4, %r2, %r1, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3,
		      RX, RY,
		      RT0, RT1, RT2, .Lxts_gf128mul_and_shl1_mask);

	bl __twofish_enc_blk8_neon;

	pop {r1};

	/* dst <= regs xor IVs(in dst) */
	store_xts_8way(%r1, RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1,
		       RT0, RT1, RT2, RT3);

	pop {r4-r12, pc};
ENDPROC(twofish_xts_enc_8way_neon)

ENTRY(twofish_xts_dec_8way_neon)
	/* input:
	 *	%r0: ctx, CTX
	 *	%r1: dst
	 *	%r2: src
	 *	%r3: iv
	 */

	stmdb sp!, {r1, r4-r12, lr};

	/* regs <= src, dst <= IVs, regs <= regs xor IVs */
	load_xts_8way(%r3, %r4, %r2, %r1, RA2, RA3, RA0, RA1, RB2, RB3, RB0, RB1,
		      RX, RY,
		      RT0, RT1, RT2, .Lxts_gf128mul_and_shl1_mask);

	bl __twofish_dec_blk8_neon;

	pop {r1};

	/* dst <= regs xor IVs(in dst) */
	store_xts_8way(%r1, RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3,
		       RT0, RT1, RT2, RT3);

	pop {r4-r12, pc};
ENDPROC(twofish_xts_dec_8way_neon)

.align 6

.Lxts_gf128mul_and_shl1_mask:
	.byte 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
