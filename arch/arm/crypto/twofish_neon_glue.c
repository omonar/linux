/*
 * Glue Code for NEON assembler versions of Twofish Cipher
 *
 * Glue code based on twofish_glue_avx.c by:
 *  Copyright (C) 2012 Johannes Goetzfried
 *     <Johannes.Goetzfried@informatik.stud.uni-erlangen.de>
 *
 * Copyright (C) 2011-2013 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 * USA
 *
 */

#include <linux/module.h>
#include <linux/hardirq.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <crypto/ablk_helper.h>
#include <crypto/algapi.h>
#include <crypto/twofish.h>
#include <crypto/cryptd.h>
#include <crypto/b128ops.h>
#include <crypto/ctr.h>
#include <crypto/lrw.h>
#include <crypto/xts.h>

#include "twofish_glue.h"
#include "glue_helper.h"

#define TWOFISH_PARALLEL_BLOCKS 8
#define TWOFISH_NEON_ALIGN      8

struct twofish_lrw_ctx {
	struct lrw_table_ctx lrw_table;
	u8 raw_tf_ctx[sizeof(struct twofish_ctx) + TWOFISH_NEON_ALIGN - 1];
};

struct twofish_xts_ctx {
	u8 raw_tweak_ctx[sizeof(struct twofish_ctx) + TWOFISH_NEON_ALIGN - 1];
	u8 raw_crypt_ctx[sizeof(struct twofish_ctx) + TWOFISH_NEON_ALIGN - 1];
};

/* 8-way parallel cipher functions */
asmlinkage void twofish_ecb_enc_8way_neon(struct twofish_ctx *ctx, u8 *dst,
					 const u8 *src);
EXPORT_SYMBOL_GPL(twofish_ecb_enc_8way_neon);

asmlinkage void twofish_ecb_dec_8way_neon(struct twofish_ctx *ctx, u8 *dst,
					 const u8 *src);
EXPORT_SYMBOL_GPL(twofish_ecb_dec_8way_neon);

asmlinkage void twofish_cbc_dec_8way_neon(struct twofish_ctx *ctx, u8 *dst,
					 const u8 *src);
EXPORT_SYMBOL_GPL(twofish_cbc_dec_8way_neon);

asmlinkage void twofish_ctr_8way_neon(struct twofish_ctx *ctx, u8 *dst,
				     const u8 *src, le128 *iv);
EXPORT_SYMBOL_GPL(twofish_ctr_8way_neon);

asmlinkage void twofish_xts_enc_8way_neon(struct twofish_ctx *ctx, u8 *dst,
					 const u8 *src, le128 *iv);
EXPORT_SYMBOL_GPL(twofish_xts_enc_8way_neon);

asmlinkage void twofish_xts_dec_8way_neon(struct twofish_ctx *ctx, u8 *dst,
					 const u8 *src, le128 *iv);
EXPORT_SYMBOL_GPL(twofish_xts_dec_8way_neon);

static inline struct twofish_ctx *tf_ctx_aligned(void *raw_ctx)
{
	unsigned long addr = (unsigned long)raw_ctx;
	unsigned long align = TWOFISH_NEON_ALIGN;

	return (struct twofish_ctx *)ALIGN(addr, align);
}

static int __twofish_setkey_neon(struct crypto_tfm *tfm, void *raw_ctx,
				  const u8 *key, unsigned int keylen)
{
	struct twofish_ctx *ctx = tf_ctx_aligned(raw_ctx);
	u32 *flags = &tfm->crt_flags;

	if (keylen % 8)
	{
		*flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
		return -EINVAL;
	}

	return __twofish_setkey(ctx, key, keylen, flags);
}

static int twofish_setkey_neon(struct crypto_tfm *tfm, const u8 *key,
			       unsigned int keylen)
{
	return __twofish_setkey_neon(tfm, crypto_tfm_ctx(tfm), key, keylen);
}

void __twofish_crypt_ctr(void *ctx, u128 *dst, const u128 *src, le128 *iv)
{
	be128 ctrblk;

	le128_to_be128(&ctrblk, iv);
	le128_inc(iv);

	twofish_enc_blk(ctx, (u8 *)&ctrblk, (u8 *)&ctrblk);
	u128_xor(dst, src, (u128 *)&ctrblk);
}
EXPORT_SYMBOL_GPL(__twofish_crypt_ctr);

void twofish_xts_enc(void *ctx, u128 *dst, const u128 *src, le128 *iv)
{
	glue_xts_crypt_128bit_one(ctx, dst, src, iv,
				  GLUE_FUNC_CAST(twofish_enc_blk));
}
EXPORT_SYMBOL_GPL(twofish_xts_enc);

void twofish_xts_dec(void *ctx, u128 *dst, const u128 *src, le128 *iv)
{
	glue_xts_crypt_128bit_one(ctx, dst, src, iv,
				  GLUE_FUNC_CAST(twofish_dec_blk));
}
EXPORT_SYMBOL_GPL(twofish_xts_dec);


static const struct common_glue_ctx twofish_enc = {
	.num_funcs = 2,
	.fpu_blocks_limit = TWOFISH_PARALLEL_BLOCKS,

	.funcs = { {
		.num_blocks = TWOFISH_PARALLEL_BLOCKS,
		.fn_u = { .ecb = GLUE_FUNC_CAST(twofish_ecb_enc_8way_neon) }
	}, {
		.num_blocks = 1,
		.fn_u = { .ecb = GLUE_FUNC_CAST(twofish_enc_blk) }
	} }
};

static const struct common_glue_ctx twofish_ctr = {
	.num_funcs = 2,
	.fpu_blocks_limit = TWOFISH_PARALLEL_BLOCKS,

	.funcs = { {
		.num_blocks = TWOFISH_PARALLEL_BLOCKS,
		.fn_u = { .ctr = GLUE_CTR_FUNC_CAST(twofish_ctr_8way_neon) }
	}, {
		.num_blocks = 1,
		.fn_u = { .ctr = GLUE_CTR_FUNC_CAST(__twofish_crypt_ctr) }
	} }
};

static const struct common_glue_ctx twofish_enc_xts = {
	.num_funcs = 2,
	.fpu_blocks_limit = TWOFISH_PARALLEL_BLOCKS,

	.funcs = { {
		.num_blocks = TWOFISH_PARALLEL_BLOCKS,
		.fn_u = { .xts = GLUE_XTS_FUNC_CAST(twofish_xts_enc_8way_neon) }
	}, {
		.num_blocks = 1,
		.fn_u = { .xts = GLUE_XTS_FUNC_CAST(twofish_xts_enc) }
	} }
};

static const struct common_glue_ctx twofish_dec = {
	.num_funcs = 2,
	.fpu_blocks_limit = TWOFISH_PARALLEL_BLOCKS,

	.funcs = { {
		.num_blocks = TWOFISH_PARALLEL_BLOCKS,
		.fn_u = { .ecb = GLUE_FUNC_CAST(twofish_ecb_dec_8way_neon) }
	}, {
		.num_blocks = 1,
		.fn_u = { .ecb = GLUE_FUNC_CAST(twofish_dec_blk) }
	} }
};

static const struct common_glue_ctx twofish_dec_cbc = {
	.num_funcs = 2,
	.fpu_blocks_limit = TWOFISH_PARALLEL_BLOCKS,

	.funcs = { {
		.num_blocks = TWOFISH_PARALLEL_BLOCKS,
		.fn_u = { .cbc = GLUE_CBC_FUNC_CAST(twofish_cbc_dec_8way_neon) }
	}, {
		.num_blocks = 1,
		.fn_u = { .cbc = GLUE_CBC_FUNC_CAST(twofish_dec_blk) }
	} }
};

static const struct common_glue_ctx twofish_dec_xts = {
	.num_funcs = 2,
	.fpu_blocks_limit = TWOFISH_PARALLEL_BLOCKS,

	.funcs = { {
		.num_blocks = TWOFISH_PARALLEL_BLOCKS,
		.fn_u = { .xts = GLUE_XTS_FUNC_CAST(twofish_xts_dec_8way_neon) }
	}, {
		.num_blocks = 1,
		.fn_u = { .xts = GLUE_XTS_FUNC_CAST(twofish_xts_dec) }
	} }
};

static int ecb_encrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		       struct scatterlist *src, unsigned int nbytes)
{
	return glue_ecb_crypt_128bit_aligned(&twofish_enc, desc, dst, src, nbytes);
}

static int ecb_decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		       struct scatterlist *src, unsigned int nbytes)
{
	return glue_ecb_crypt_128bit_aligned(&twofish_dec, desc, dst, src, nbytes);
}

static int cbc_encrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		       struct scatterlist *src, unsigned int nbytes)
{
	return glue_cbc_encrypt_128bit_aligned(GLUE_FUNC_CAST(twofish_enc_blk), desc,
				     dst, src, nbytes);
}

static int cbc_decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		       struct scatterlist *src, unsigned int nbytes)
{
	return glue_cbc_decrypt_128bit_aligned(&twofish_dec_cbc, desc, dst, src,
				       nbytes);
}

static int ctr_crypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		     struct scatterlist *src, unsigned int nbytes)
{
	return glue_ctr_crypt_128bit_aligned(&twofish_ctr, desc, dst, src, nbytes);
}

static inline bool twofish_fpu_begin(bool fpu_enabled, unsigned int nbytes)
{
	return glue_fpu_begin(TF_BLOCK_SIZE, TWOFISH_PARALLEL_BLOCKS,
			      NULL, fpu_enabled, nbytes);
}

static inline void twofish_fpu_end(bool fpu_enabled)
{
	glue_fpu_end(fpu_enabled);
}

struct crypt_priv {
	struct twofish_ctx *ctx;
	bool fpu_enabled;
};

static void encrypt_callback(void *priv, u8 *srcdst, unsigned int nbytes)
{
	const unsigned int bsize = TF_BLOCK_SIZE;
	struct crypt_priv *ctx = priv;
	int i;

	ctx->fpu_enabled = twofish_fpu_begin(ctx->fpu_enabled, nbytes);

	if (nbytes == bsize * TWOFISH_PARALLEL_BLOCKS) {
		twofish_ecb_enc_8way_neon(ctx->ctx, srcdst, srcdst);
		return;
	}

	for (i = 0; i < nbytes / bsize; i++, srcdst += bsize)
		twofish_enc_blk(ctx->ctx, srcdst, srcdst);
}

static void decrypt_callback(void *priv, u8 *srcdst, unsigned int nbytes)
{
	const unsigned int bsize = TF_BLOCK_SIZE;
	struct crypt_priv *ctx = priv;
	int i;

	ctx->fpu_enabled = twofish_fpu_begin(ctx->fpu_enabled, nbytes);

	if (nbytes == bsize * TWOFISH_PARALLEL_BLOCKS) {
		twofish_ecb_dec_8way_neon(ctx->ctx, srcdst, srcdst);
		return;
	}

	for (i = 0; i < nbytes / bsize; i++, srcdst += bsize)
		twofish_dec_blk(ctx->ctx, srcdst, srcdst);
}

int lrw_twofish_setkey(struct crypto_tfm *tfm, const u8 *key,
		       unsigned int keylen)
{
	struct twofish_lrw_ctx *ctx = crypto_tfm_ctx(tfm);
	int err;

	err = __twofish_setkey_neon(tfm, ctx->raw_tf_ctx, key,
				     keylen - TF_BLOCK_SIZE);
	if (err)
		return err;

	return lrw_init_table(&ctx->lrw_table, key + keylen -
						TF_BLOCK_SIZE);
}
EXPORT_SYMBOL_GPL(lrw_twofish_setkey);

static int lrw_encrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		       struct scatterlist *src, unsigned int nbytes)
{
	struct twofish_lrw_ctx *ctx = crypto_blkcipher_ctx(desc->tfm);
	be128 buf[TWOFISH_PARALLEL_BLOCKS];
	struct crypt_priv crypt_ctx = {
		.ctx = tf_ctx_aligned(ctx->raw_tf_ctx),
		.fpu_enabled = false,
	};
	struct lrw_crypt_req req = {
		.tbuf = buf,
		.tbuflen = sizeof(buf),

		.table_ctx = &ctx->lrw_table,
		.crypt_ctx = &crypt_ctx,
		.crypt_fn = encrypt_callback,
	};
	int ret;

	desc->flags &= ~CRYPTO_TFM_REQ_MAY_SLEEP;
	ret = lrw_crypt(desc, dst, src, nbytes, &req);
	twofish_fpu_end(crypt_ctx.fpu_enabled);

	return ret;
}

static int lrw_decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		       struct scatterlist *src, unsigned int nbytes)
{
	struct twofish_lrw_ctx *ctx = crypto_blkcipher_ctx(desc->tfm);
	be128 buf[TWOFISH_PARALLEL_BLOCKS];
	struct crypt_priv crypt_ctx = {
		.ctx = tf_ctx_aligned(ctx->raw_tf_ctx),
		.fpu_enabled = false,
	};
	struct lrw_crypt_req req = {
		.tbuf = buf,
		.tbuflen = sizeof(buf),

		.table_ctx = &ctx->lrw_table,
		.crypt_ctx = &crypt_ctx,
		.crypt_fn = decrypt_callback,
	};
	int ret;

	desc->flags &= ~CRYPTO_TFM_REQ_MAY_SLEEP;
	ret = lrw_crypt(desc, dst, src, nbytes, &req);
	twofish_fpu_end(crypt_ctx.fpu_enabled);

	return ret;
}

void lrw_twofish_exit_tfm(struct crypto_tfm *tfm)
{
	struct twofish_lrw_ctx *ctx = crypto_tfm_ctx(tfm);

	lrw_free_table(&ctx->lrw_table);
}
EXPORT_SYMBOL_GPL(lrw_twofish_exit_tfm);

int xts_twofish_setkey(struct crypto_tfm *tfm, const u8 *key,
		       unsigned int keylen)
{
	struct twofish_xts_ctx *ctx = crypto_tfm_ctx(tfm);
	u32 *flags = &tfm->crt_flags;
	int err;

	/* key consists of keys of equal size concatenated, therefore
	 * the length must be even
	 */
	if (keylen % 2) {
		*flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
		return -EINVAL;
	}

	/* first half of xts-key is for crypt */
	err = __twofish_setkey_neon(tfm, ctx->raw_crypt_ctx, key, keylen / 2);
	if (err)
		return err;

	/* second half of xts-key is for tweak */
	return __twofish_setkey_neon(tfm, ctx->raw_tweak_ctx, key + keylen / 2,
				     keylen / 2);
}
EXPORT_SYMBOL_GPL(xts_twofish_setkey);

static int xts_encrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		       struct scatterlist *src, unsigned int nbytes)
{
	struct twofish_xts_ctx *ctx = crypto_blkcipher_ctx(desc->tfm);

	return glue_xts_crypt_128bit(&twofish_enc_xts, desc, dst, src, nbytes,
				     XTS_TWEAK_CAST(twofish_enc_blk),
				     tf_ctx_aligned(ctx->raw_tweak_ctx),
				     tf_ctx_aligned(ctx->raw_crypt_ctx));
}

static int xts_decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		       struct scatterlist *src, unsigned int nbytes)
{
	struct twofish_xts_ctx *ctx = crypto_blkcipher_ctx(desc->tfm);

	return glue_xts_crypt_128bit(&twofish_dec_xts, desc, dst, src, nbytes,
				     XTS_TWEAK_CAST(twofish_enc_blk),
				     tf_ctx_aligned(ctx->raw_tweak_ctx),
				     tf_ctx_aligned(ctx->raw_crypt_ctx));
}

static struct crypto_alg twofish_algs[10] = { {
	.cra_name		= "__ecb-twofish-neon",
	.cra_driver_name	= "__driver-ecb-twofish-neon",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER |
				  CRYPTO_ALG_INTERNAL,
	.cra_blocksize		= TF_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct twofish_ctx) +
				  TWOFISH_NEON_ALIGN - 1,
	.cra_alignmask		= TWOFISH_NEON_ALIGN - 1,
	.cra_type		= &crypto_blkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_u = {
		.blkcipher = {
			.min_keysize	= TF_MIN_KEY_SIZE,
			.max_keysize	= TF_MAX_KEY_SIZE,
			.setkey		= twofish_setkey_neon,
			.encrypt	= ecb_encrypt,
			.decrypt	= ecb_decrypt,
		},
	},
}, {
	.cra_name		= "__cbc-twofish-neon",
	.cra_driver_name	= "__driver-cbc-twofish-neon",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER |
				  CRYPTO_ALG_INTERNAL,
	.cra_blocksize		= TF_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct twofish_ctx) +
				  TWOFISH_NEON_ALIGN - 1,
	.cra_alignmask		= TWOFISH_NEON_ALIGN - 1,
	.cra_type		= &crypto_blkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_u = {
		.blkcipher = {
			.min_keysize	= TF_MIN_KEY_SIZE,
			.max_keysize	= TF_MAX_KEY_SIZE,
			.setkey		= twofish_setkey_neon,
			.encrypt	= cbc_encrypt,
			.decrypt	= cbc_decrypt,
		},
	},
}, {
	.cra_name		= "__ctr-twofish-neon",
	.cra_driver_name	= "__driver-ctr-twofish-neon",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER |
				  CRYPTO_ALG_INTERNAL,
	.cra_blocksize		= 1,
	.cra_ctxsize		= sizeof(struct twofish_ctx) +
				  TWOFISH_NEON_ALIGN - 1,
	.cra_alignmask		= TWOFISH_NEON_ALIGN - 1,
	.cra_type		= &crypto_blkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_u = {
		.blkcipher = {
			.min_keysize	= TF_MIN_KEY_SIZE,
			.max_keysize	= TF_MAX_KEY_SIZE,
			.ivsize		= TF_BLOCK_SIZE,
			.setkey		= twofish_setkey_neon,
			.encrypt	= ctr_crypt,
			.decrypt	= ctr_crypt,
		},
	},
}, {
	.cra_name		= "__lrw-twofish-neon",
	.cra_driver_name	= "__driver-lrw-twofish-neon",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER |
				  CRYPTO_ALG_INTERNAL,
	.cra_blocksize		= TF_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct twofish_lrw_ctx),
	.cra_alignmask		= TWOFISH_NEON_ALIGN - 1,
	.cra_type		= &crypto_blkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_exit		= lrw_twofish_exit_tfm,
	.cra_u = {
		.blkcipher = {
			.min_keysize	= TF_MIN_KEY_SIZE +
					  TF_BLOCK_SIZE,
			.max_keysize	= TF_MAX_KEY_SIZE +
					  TF_BLOCK_SIZE,
			.ivsize		= TF_BLOCK_SIZE,
			.setkey		= lrw_twofish_setkey,
			.encrypt	= lrw_encrypt,
			.decrypt	= lrw_decrypt,
		},
	},
}, {
	.cra_name		= "__xts-twofish-neon",
	.cra_driver_name	= "__driver-xts-twofish-neon",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER |
				  CRYPTO_ALG_INTERNAL,
	.cra_blocksize		= TF_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct twofish_xts_ctx),
	.cra_alignmask		= TWOFISH_NEON_ALIGN - 1,
	.cra_type		= &crypto_blkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_u = {
		.blkcipher = {
			.min_keysize	= TF_MIN_KEY_SIZE * 2,
			.max_keysize	= TF_MAX_KEY_SIZE * 2,
			.ivsize		= TF_BLOCK_SIZE,
			.setkey		= xts_twofish_setkey,
			.encrypt	= xts_encrypt,
			.decrypt	= xts_decrypt,
		},
	},
}, {
	.cra_name		= "ecb(twofish)",
	.cra_driver_name	= "ecb-twofish-neon",
	.cra_priority		= 300,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= TF_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct async_helper_ctx),
	.cra_alignmask		= TWOFISH_NEON_ALIGN - 1,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= ablk_init,
	.cra_exit		= ablk_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= TF_MIN_KEY_SIZE,
			.max_keysize	= TF_MAX_KEY_SIZE,
			.setkey		= ablk_set_key,
			.encrypt	= ablk_encrypt,
			.decrypt	= ablk_decrypt,
		},
	},
}, {
	.cra_name		= "cbc(twofish)",
	.cra_driver_name	= "cbc-twofish-neon",
	.cra_priority		= 300,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= TF_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct async_helper_ctx),
	.cra_alignmask		= TWOFISH_NEON_ALIGN - 1,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= ablk_init,
	.cra_exit		= ablk_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= TF_MIN_KEY_SIZE,
			.max_keysize	= TF_MAX_KEY_SIZE,
			.ivsize		= TF_BLOCK_SIZE,
			.setkey		= ablk_set_key,
			.encrypt	= __ablk_encrypt,
			.decrypt	= ablk_decrypt,
		},
	},
}, {
	.cra_name		= "ctr(twofish)",
	.cra_driver_name	= "ctr-twofish-neon",
	.cra_priority		= 300,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= 1,
	.cra_ctxsize		= sizeof(struct async_helper_ctx),
	.cra_alignmask		= TWOFISH_NEON_ALIGN - 1,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= ablk_init,
	.cra_exit		= ablk_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= TF_MIN_KEY_SIZE,
			.max_keysize	= TF_MAX_KEY_SIZE,
			.ivsize		= TF_BLOCK_SIZE,
			.setkey		= ablk_set_key,
			.encrypt	= ablk_encrypt,
			.decrypt	= ablk_encrypt,
			.geniv		= "chainiv",
		},
	},
}, {
	.cra_name		= "lrw(twofish)",
	.cra_driver_name	= "lrw-twofish-neon",
	.cra_priority		= 300,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= TF_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct async_helper_ctx),
	.cra_alignmask		= TWOFISH_NEON_ALIGN - 1,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= ablk_init,
	.cra_exit		= ablk_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= TF_MIN_KEY_SIZE +
					  TF_BLOCK_SIZE,
			.max_keysize	= TF_MAX_KEY_SIZE +
					  TF_BLOCK_SIZE,
			.ivsize		= TF_BLOCK_SIZE,
			.setkey		= ablk_set_key,
			.encrypt	= ablk_encrypt,
			.decrypt	= ablk_decrypt,
		},
	},
}, {
	.cra_name		= "xts(twofish)",
	.cra_driver_name	= "xts-twofish-neon",
	.cra_priority		= 300,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= TF_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct async_helper_ctx),
	.cra_alignmask		= TWOFISH_NEON_ALIGN - 1,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= ablk_init,
	.cra_exit		= ablk_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= TF_MIN_KEY_SIZE * 2,
			.max_keysize	= TF_MAX_KEY_SIZE * 2,
			.ivsize		= TF_BLOCK_SIZE,
			.setkey		= ablk_set_key,
			.encrypt	= ablk_encrypt,
			.decrypt	= ablk_decrypt,
		},
	},
} };

static int __init twofish_init(void)
{
	if (!cpu_has_neon()) {
		printk(KERN_INFO "NEON instructions are not detected.\n");
		return -ENODEV;
	}

	return crypto_register_algs(twofish_algs, ARRAY_SIZE(twofish_algs));
}

static void __exit twofish_exit(void)
{
	crypto_unregister_algs(twofish_algs, ARRAY_SIZE(twofish_algs));
}

module_init(twofish_init);
module_exit(twofish_exit);

MODULE_DESCRIPTION("Twofish Cipher Algorithm, NEON optimized");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("twofish");
