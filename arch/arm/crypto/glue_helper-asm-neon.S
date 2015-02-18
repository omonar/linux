/*
 * Shared glue code for 128bit block ciphers, NEON assembler macros
 *
 * Shared glue code based on glue_helper-asm-avx.c by:
 *  Copyright (C) 2012-2013 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define load_8way(src, x0, x1, x2, x3, x4, x5, x6, x7) \
	vld1.8 {x0, x1}, [src]!; \
	vld1.8 {x2, x3}, [src]!; \
	vld1.8 {x4, x5}, [src]!; \
	vld1.8 {x6, x7}, [src]!; \
	sub src, src, #(8*16);

#define store_8way(dst, x0, x1, x2, x3, x4, x5, x6, x7) \
	vst1.8 {x0}, [dst]!; \
	veor x0, x0; \
	vst1.8 {x1}, [dst]!; \
	veor x1, x1; \
	vst1.8 {x2}, [dst]!; \
	veor x2, x2; \
	vst1.8 {x3}, [dst]!; \
	veor x3, x3; \
	vst1.8 {x4}, [dst]!; \
	veor x4, x4; \
	vst1.8 {x5}, [dst]!; \
	veor x5, x5; \
	vst1.8 {x6}, [dst]!; \
	veor x6, x6; \
	vst1.8 {x7}, [dst]!; \
	veor x7, x7;

#define store_cbc_8way(src, dst, x0, x1, x2, x3, x4, x5, x6, x7, t0, t1, t2, t3) \
	vld1.8 {t0, t1}, [src]!; \
	vld1.8 {t2, t3}, [src]!; \
	veor x1, x1, t0; \
	veor x2, x2, t1; \
	vld1.8 {t0, t1}, [src]!; \
	veor x3, x3, t2; \
	veor x4, x4, t3; \
	vld1.8 {t2}, [src]!; \
	veor x5, x5, t0; \
	veor t0, t0; \
	veor x6, x6, t1; \
	veor t1, t1; \
	veor x7, x7, t2; \
	veor t2, t2; \
	store_8way(dst, x0, x1, x2, x3, x4, x5, x6, x7);

#define inc_le128(x, minus_one, tmp, tmp_d1, tmp_d0) \
	vceq.i32 tmp, x, minus_one; \
	vsub.i64 x, x, minus_one; \
	vrev64.32 tmp_d1, tmp_d0; \
	vand tmp_d1, tmp_d1, tmp_d0; \
	veor tmp_d0, tmp_d0, tmp_d0; \
	vsub.i64 x, x, tmp;

#define load_ctr_8way(iv, x0, x1, x2, x3, x4, x5, x6, x7, t0, t1, t2) \
	vceq.i32 t0, t0, t0; /* u128: - 1 */ \
	\
	/* load IV and byteswap */ \
	vld1.8 {x7}, [iv]; \
	veor t0##d1, t0##d1, t0##d1; /* u64_high: 0 u64_low: -1 */ \
	vrev64.u8 x0, x7; \
	\
	/* construct IVs */ \
	inc_le128(x7, t0, t2, t2##d1, t2##d0); \
	vswp x0##d1, x0##d0; \
	vrev64.u8 x1, x7; \
	\
	inc_le128(x7, t0, t2, t2##d1, t2##d0); \
	vswp x1##d1, x1##d0; \
	vrev64.u8 x2, x7; \
	\
	inc_le128(x7, t0, t2, t2##d1, t2##d0); \
	vswp x2##d1, x2##d0; \
	vrev64.u8 x3, x7; \
	\
	inc_le128(x7, t0, t2, t2##d1, t2##d0); \
	vswp x3##d1, x3##d0; \
	vrev64.u8 x4, x7; \
	\
	inc_le128(x7, t0, t2, t2##d1, t2##d0); \
	vswp x4##d1, x4##d0; \
	vrev64.u8 x5, x7; \
	\
	inc_le128(x7, t0, t2, t2##d1, t2##d0); \
	vswp x5##d1, x5##d0; \
	vrev64.u8 x6, x7; \
	\
	inc_le128(x7, t0, t2, t2##d1, t2##d0); \
	vswp x6##d1, x6##d0; \
	vmov t2, x7; \
	vrev64.u8 x7, x7; \
	\
	inc_le128(t2, t0, t1, t1##d1, t1##d0); \
	vswp x7##d1, x7##d0; \
	/* store new IVs */ \
	vst1.8 {t2}, [iv];

#define store_ctr_8way(src, dst, x0, x1, x2, x3, x4, x5, x6, x7, t0, t1, t2, t3) \
	vld1.8 {t0, t1}, [src]!; \
	vld1.8 {t2, t3}, [src]!; \
	veor x0, x0, t0; \
	veor x1, x1, t1; \
	vld1.8 {t0, t1}, [src]!; \
	veor x2, x2, t2; \
	veor x3, x3, t3; \
	vld1.8 {t2, t3}, [src]!; \
	veor x4, x4, t0; \
	veor t0, t0; \
	veor x5, x5, t1; \
	veor t1, t1; \
	veor x6, x6, t2; \
	veor t2, t2; \
	veor x7, x7, t3; \
	veor t3, t3; \
	store_8way(dst, x0, x1, x2, x3, x4, x5, x6, x7);

#define gf128mul_x_ble(iv, mask, tmp, tmp_d1, tmp_d0) \
	vshr.s64 tmp, iv, #63; \
	vadd.u64 iv, iv, iv; \
	vand tmp, tmp, mask; \
	vswp tmp_d1, tmp_d0; \
	veor iv, iv, tmp;

#define load_xts_8way(iv, arm32, src, dst, x0, x1, x2, x3, x4, x5, x6, x7, \
		      t0, t1, tiv, xts_gf128mul_and_shl1_mask) \
	adr arm32, xts_gf128mul_and_shl1_mask; \
	/* load IV */ \
	vld1.8 {tiv}, [iv]; \
	vld1.8 {x0}, [src]!; \
	\
	veor x0, x0, tiv; \
	vst1.8 {tiv}, [dst]!; \
	\
	vld1.8 {t0}, [arm32]; \
	/* construct and store IVs, also xor with source */ \
	gf128mul_x_ble(tiv, t0, t1, t1##d1, t1##d0); \
	vld1.8 {x1}, [src]!; \
	veor x1, x1, tiv; \
	vst1.8 {tiv}, [dst]!; \
	\
	gf128mul_x_ble(tiv, t0, t1, t1##d1, t1##d0); \
	vld1.8 {x2}, [src]!; \
	veor x2, x2, tiv; \
	vst1.8 {tiv}, [dst]!; \
	\
	gf128mul_x_ble(tiv, t0, t1, t1##d1, t1##d0); \
	vld1.8 {x3}, [src]!; \
	veor x3, x3, tiv; \
	vst1.8 {tiv}, [dst]!; \
	\
	gf128mul_x_ble(tiv, t0, t1, t1##d1, t1##d0); \
	vld1.8 {x4}, [src]!; \
	veor x4, x4, tiv; \
	vst1.8 {tiv}, [dst]!; \
	\
	gf128mul_x_ble(tiv, t0, t1, t1##d1, t1##d0); \
	vld1.8 {x5}, [src]!; \
	veor x5, x5, tiv; \
	vst1.8 {tiv}, [dst]!; \
	\
	gf128mul_x_ble(tiv, t0, t1, t1##d1, t1##d0); \
	vld1.8 {x6}, [src]!; \
	veor x6, x6, tiv; \
	vst1.8 {tiv}, [dst]!; \
	\
	gf128mul_x_ble(tiv, t0, t1, t1##d1, t1##d0); \
	vld1.8 {x7}, [src]!; \
	veor x7, x7, tiv; \
	vst1.8 {tiv}, [dst]!; \
	\
	gf128mul_x_ble(tiv, t0, t1, t1##d1, t1##d0); \
	vst1.8 {tiv}, [iv]; \
	sub dst, dst, #(8*16);

#define store_xts_8way(dst, x0, x1, x2, x3, x4, x5, x6, x7, t0, t1, t2, t3) \
	vld1.8 {t0, t1}, [dst]!; \
	vld1.8 {t2, t3}, [dst]!; \
	veor x0, x0, t0; \
	veor x1, x1, t1; \
	vld1.8 {t0, t1}, [dst]!; \
	veor x2, x2, t2; \
	veor x3, x3, t3; \
	vld1.8 {t2, t3}, [dst]!; \
	veor x4, x4, t0; \
	veor t0, t0; \
	veor x5, x5, t1; \
	veor t1, t1; \
	veor x6, x6, t2; \
	veor t2, t2; \
	veor x7, x7, t3; \
	veor t3, t3; \
	sub dst, dst, #(8*16); \
	store_8way(dst, x0, x1, x2, x3, x4, x5, x6, x7);
