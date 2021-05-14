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

#include "gen.h"
#include <iostream>
#include <cstring>

enum Mode
{
    Generate,
    Test
};

static char const copyright_message[] =
"/*\n"
" * Copyright (C) 2021 Southern Storm Software, Pty Ltd.\n"
" *\n"
" * Permission is hereby granted, free of charge, to any person obtaining a\n"
" * copy of this software and associated documentation files (the \"Software\"),\n"
" * to deal in the Software without restriction, including without limitation\n"
" * the rights to use, copy, modify, merge, publish, distribute, sublicense,\n"
" * and/or sell copies of the Software, and to permit persons to whom the\n"
" * Software is furnished to do so, subject to the following conditions:\n"
" *\n"
" * The above copyright notice and this permission notice shall be included\n"
" * in all copies or substantial portions of the Software.\n"
" *\n"
" * THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS\n"
" * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"
" * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n"
" * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n"
" * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING\n"
" * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER\n"
" * DEALINGS IN THE SOFTWARE.\n"
" */\n\n";

static void header(std::ostream &ostream)
{
    ostream << "#if defined(__AVR__)" << std::endl;
    ostream << copyright_message;
    ostream << "#include <avr/io.h>" << std::endl;
    ostream << "/* Automatically generated - do not edit */" << std::endl;
}

static void footer(std::ostream &ostream)
{
    ostream << std::endl;
    ostream << "#endif" << std::endl;
}

static bool aes128_setup_key(enum Mode mode)
{
    Code code;
    gen_aes128_setup_key(code);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_aes_sbox());
        code.write(std::cout);
    } else {
        if (!test_aes128_setup_key(code)) {
            std::cout << "AES-128 key setup tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "AES-128 key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool aes192_setup_key(enum Mode mode)
{
    Code code;
    gen_aes192_setup_key(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_aes192_setup_key(code)) {
            std::cout << "AES-192 key setup tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "AES-192 key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool aes256_setup_key(enum Mode mode)
{
    Code code;
    gen_aes256_setup_key(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_aes256_setup_key(code)) {
            std::cout << "AES-256 key setup tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "AES-256 key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool aes_ecb_encrypt(enum Mode mode)
{
    Code code;
    gen_aes_ecb_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_aes_ecb_encrypt(code)) {
            std::cout << "AES encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "AES encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool aes(enum Mode mode)
{
    bool ok = true;
    if (!aes128_setup_key(mode))
        ok = false;
    if (!aes192_setup_key(mode))
        ok = false;
    if (!aes256_setup_key(mode))
        ok = false;
    if (!aes_ecb_encrypt(mode))
        ok = false;
    return ok;
}

static bool ascon(enum Mode mode)
{
    Code code;
    gen_ascon_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_ascon_permutation(code)) {
            std::cout << "ASCON tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "ASCON tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool ghash_init(enum Mode mode)
{
    Code code;
    gen_ghash_init(code);
    if (mode == Generate) {
        code.write(std::cout);
    }
    return true;
}

static bool ghash_mul(enum Mode mode)
{
    Code code;
    gen_ghash_mul(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_ghash_mul(code)) {
            std::cout << "GHASH tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GHASH tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool ghash(enum Mode mode)
{
    bool ok = true;
    if (!ghash_init(mode))
        ok = false;
    if (!ghash_mul(mode))
        ok = false;
    return ok;
}

static bool gift128b_setup_key(enum Mode mode)
{
    Code code;
    gen_gift128b_setup_key(code);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_gift128_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128b_setup_key(code)) {
            std::cout << "GIFT-128b key setup tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_encrypt_block(enum Mode mode)
{
    Code code;
    gen_gift128b_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128b_encrypt(code)) {
            std::cout << "GIFT-128b encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_encrypt_block_preloaded(enum Mode mode)
{
    Code code;
    gen_gift128b_encrypt_preloaded(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128b_encrypt_preloaded(code)) {
            std::cout << "GIFT-128b preloaded encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b preloaded encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_decrypt_block(enum Mode mode)
{
    Code code;
    gen_gift128b_decrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128b_decrypt(code)) {
            std::cout << "GIFT-128b decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b(enum Mode mode)
{
    bool ok = true;
    if (!gift128b_setup_key(mode))
        ok = false;
    if (!gift128b_encrypt_block(mode))
        ok = false;
    if (!gift128b_encrypt_block_preloaded(mode))
        ok = false;
    if (!gift128b_decrypt_block(mode))
        ok = false;
    return ok;
}

static bool gift128b_cofb_only(enum Mode mode)
{
    bool ok = true;
    if (!gift128b_setup_key(mode))
        ok = false;
    if (!gift128b_encrypt_block_preloaded(mode))
        ok = false;
    return ok;
}

static bool gift128b_setup_key_alt(enum Mode mode)
{
    Code code;
    gen_gift128b_setup_key_alt(code);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_gift128_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128b_setup_key(code)) {
            std::cout << "GIFT-128b-alt key setup tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-alt key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_encrypt_block_alt(enum Mode mode)
{
    Code code;
    gen_gift128b_encrypt_alt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128b_encrypt(code)) {
            std::cout << "GIFT-128b-alt encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-alt encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_decrypt_block_alt(enum Mode mode)
{
    Code code;
    gen_gift128b_decrypt_alt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128b_decrypt(code)) {
            std::cout << "GIFT-128b-alt decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-alt decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_encrypt_block_alt(enum Mode mode)
{
    Code code;
    gen_gift128n_encrypt_alt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128n_encrypt_alt(code)) {
            std::cout << "GIFT-128n-alt encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n-alt encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_decrypt_block_alt(enum Mode mode)
{
    Code code;
    gen_gift128n_decrypt_alt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128n_decrypt_alt(code)) {
            std::cout << "GIFT-128n-alt decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n-alt decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128_alt(enum Mode mode)
{
    bool ok = true;
    if (!gift128b_setup_key_alt(mode))
        ok = false;
    if (!gift128b_encrypt_block_alt(mode))
        ok = false;
    if (!gift128b_decrypt_block_alt(mode))
        ok = false;
    if (!gift128n_encrypt_block_alt(mode))
        ok = false;
    if (!gift128n_decrypt_block_alt(mode))
        ok = false;
    return ok;
}

static bool gift128n_setup_key(enum Mode mode)
{
    Code code;
    gen_gift128n_setup_key(code);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_gift128_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128n_setup_key(code)) {
            std::cout << "GIFT-128n key setup tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_encrypt_block(enum Mode mode)
{
    Code code;
    gen_gift128n_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128n_encrypt(code)) {
            std::cout << "GIFT-128n encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_decrypt_block(enum Mode mode)
{
    Code code;
    gen_gift128n_decrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128n_decrypt(code)) {
            std::cout << "GIFT-128n decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128t_encrypt_block(enum Mode mode)
{
    Code code;
    gen_gift128t_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128t_encrypt(code)) {
            std::cout << "TweGIFT-128 encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "TweGIFT-128 encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128t_decrypt_block(enum Mode mode)
{
    Code code;
    gen_gift128t_decrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128t_decrypt(code)) {
            std::cout << "TweGIFT-128 decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "TweGIFT-128 decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n(enum Mode mode)
{
    bool ok = true;
    if (!gift128n_setup_key(mode))
        ok = false;
    if (!gift128n_encrypt_block(mode))
        ok = false;
    if (!gift128n_decrypt_block(mode))
        ok = false;
    if (!gift128t_encrypt_block(mode))
        ok = false;
    if (!gift128t_decrypt_block(mode))
        ok = false;
    return ok;
}

static bool gift128b_fs_setup_key(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128b_fs_setup_key(code, num_keys);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_gift128_fs_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128b_fs_setup_key(code, num_keys)) {
            std::cout << "GIFT-128b-fs-" << num_keys << " key setup tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-fs-" << num_keys << " key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_fs_encrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128b_fs_encrypt(code, num_keys);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128b_fs_encrypt(code, num_keys)) {
            std::cout << "GIFT-128b-fs-" << num_keys << " encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-fs-" << num_keys << " encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_fs_encrypt_block_preloaded(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128b_fs_encrypt_preloaded(code, num_keys);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128b_fs_encrypt_preloaded(code, num_keys)) {
            std::cout << "GIFT-128b-fs-" << num_keys << " preloaded encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-fs-" << num_keys << " preloaded encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_fs_decrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128b_fs_decrypt(code, num_keys);
    if (mode == Generate) {
        if (num_keys != 80)
            code.sbox_write(std::cout, 1, get_gift128_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128b_fs_decrypt(code, num_keys)) {
            std::cout << "GIFT-128b-fs-" << num_keys << " decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-fs-" << num_keys << " decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_fs(enum Mode mode, int num_keys, bool cofb_only)
{
    bool ok = true;
    if (mode == Generate) {
        std::cout << std::endl;
        std::cout << "#include \"internal-gift128-config.h\"" << std::endl;
        std::cout << std::endl;
        std::cout << "#if GIFT128_VARIANT == ";
        if (num_keys == 4)
            std::cout << "GIFT128_VARIANT_TINY" << std::endl;
        else if (num_keys == 20)
            std::cout << "GIFT128_VARIANT_SMALL" << std::endl;
        else
            std::cout << "GIFT128_VARIANT_FULL" << std::endl;
    }
    if (!gift128b_fs_setup_key(mode, num_keys))
        ok = false;
    if (!cofb_only && !gift128b_fs_encrypt_block(mode, num_keys))
        ok = false;
    if (!gift128b_fs_encrypt_block_preloaded(mode, num_keys))
        ok = false;
    if (!cofb_only && !gift128b_fs_decrypt_block(mode, num_keys))
        ok = false;
    if (mode == Generate) {
        std::cout << std::endl;
        std::cout << "#endif" << std::endl;
    }
    return ok;
}

static bool gift128b_fs_4(enum Mode mode)
{
    return gift128b_fs(mode, 4, false);
}

static bool gift128b_fs_4_cofb_only(enum Mode mode)
{
    return gift128b_fs(mode, 4, true);
}

static bool gift128b_fs_20(enum Mode mode)
{
    return gift128b_fs(mode, 20, false);
}

static bool gift128b_fs_20_cofb_only(enum Mode mode)
{
    return gift128b_fs(mode, 20, true);
}

static bool gift128b_fs_80(enum Mode mode)
{
    return gift128b_fs(mode, 80, false);
}

static bool gift128b_fs_80_cofb_only(enum Mode mode)
{
    return gift128b_fs(mode, 80, true);
}

static bool gift128n_fs_setup_key(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128n_fs_setup_key(code, num_keys);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_gift128_fs_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128n_fs_setup_key(code, num_keys)) {
            std::cout << "GIFT-128n-fs-" << num_keys << " key setup tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n-fs-" << num_keys << " key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_fs_encrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128n_fs_encrypt(code, num_keys);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128n_fs_encrypt(code, num_keys)) {
            std::cout << "GIFT-128n-fs-" << num_keys << " encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n-fs-" << num_keys << " encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_fs_decrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128n_fs_decrypt(code, num_keys);
    if (mode == Generate) {
        if (num_keys != 80)
            code.sbox_write(std::cout, 1, get_gift128_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128n_fs_decrypt(code, num_keys)) {
            std::cout << "GIFT-128n-fs-" << num_keys << " decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n-fs-" << num_keys << " decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128t_fs_encrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128t_fs_encrypt(code, num_keys);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128t_fs_encrypt(code, num_keys)) {
            std::cout << "GIFT-128t-fs-" << num_keys << " encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128t-fs-" << num_keys << " encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128t_fs_decrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128t_fs_decrypt(code, num_keys);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128t_fs_decrypt(code, num_keys)) {
            std::cout << "GIFT-128t-fs-" << num_keys << " decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128t-fs-" << num_keys << " decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_fs(enum Mode mode, int num_keys)
{
    bool ok = true;
    if (mode == Generate) {
        std::cout << std::endl;
        std::cout << "#include \"internal-gift128-config.h\"" << std::endl;
        std::cout << std::endl;
        std::cout << "#if GIFT128_VARIANT == ";
        if (num_keys == 4)
            std::cout << "GIFT128_VARIANT_TINY" << std::endl;
        else if (num_keys == 20)
            std::cout << "GIFT128_VARIANT_SMALL" << std::endl;
        else
            std::cout << "GIFT128_VARIANT_FULL" << std::endl;
    }
    if (!gift128n_fs_setup_key(mode, num_keys))
        ok = false;
    if (!gift128n_fs_encrypt_block(mode, num_keys))
        ok = false;
    if (!gift128n_fs_decrypt_block(mode, num_keys))
        ok = false;
    if (!gift128t_fs_encrypt_block(mode, num_keys))
        ok = false;
    if (!gift128t_fs_decrypt_block(mode, num_keys))
        ok = false;
    if (mode == Generate) {
        std::cout << std::endl;
        std::cout << "#endif" << std::endl;
    }
    return ok;
}

static bool gift128n_fs_4(enum Mode mode)
{
    return gift128n_fs(mode, 4);
}

static bool gift128n_fs_20(enum Mode mode)
{
    return gift128n_fs(mode, 20);
}

static bool gift128n_fs_80(enum Mode mode)
{
    return gift128n_fs(mode, 80);
}

static bool gift128b_alt_fs_setup_key(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128b_fs_setup_key_alt(code, num_keys);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_gift128_fs_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128b_fs_setup_key(code, num_keys)) {
            std::cout << "GIFT-128b-alt-fs-" << num_keys << " key setup tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-alt-fs-" << num_keys << " key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_alt_fs_encrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128b_fs_encrypt_alt(code, num_keys);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128b_fs_encrypt(code, num_keys)) {
            std::cout << "GIFT-128b-alt-fs-" << num_keys << " encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-alt-fs-" << num_keys << " encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_alt_fs_decrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128b_fs_decrypt_alt(code, num_keys);
    if (mode == Generate) {
        if (num_keys != 80)
            code.sbox_write(std::cout, 1, get_gift128_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128b_fs_decrypt(code, num_keys)) {
            std::cout << "GIFT-128b-alt-fs-" << num_keys << " decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-alt-fs-" << num_keys << " decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_alt_fs_encrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128n_fs_encrypt_alt(code, num_keys);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128n_fs_encrypt_alt(code, num_keys)) {
            std::cout << "GIFT-128n-alt-fs-" << num_keys << " encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n-alt-fs-" << num_keys << " encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_alt_fs_decrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128n_fs_decrypt_alt(code, num_keys);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128n_fs_decrypt_alt(code, num_keys)) {
            std::cout << "GIFT-128n-alt-fs-" << num_keys << " decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n-alt-fs-" << num_keys << " decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128_alt_fs(enum Mode mode, int num_keys)
{
    bool ok = true;
    if (!gift128b_alt_fs_setup_key(mode, num_keys))
        ok = false;
    if (!gift128b_alt_fs_encrypt_block(mode, num_keys))
        ok = false;
    if (!gift128b_alt_fs_decrypt_block(mode, num_keys))
        ok = false;
    if (!gift128n_alt_fs_encrypt_block(mode, num_keys))
        ok = false;
    if (!gift128n_alt_fs_decrypt_block(mode, num_keys))
        ok = false;
    return ok;
}

static bool gift128_alt_fs_4(enum Mode mode)
{
    return gift128_alt_fs(mode, 4);
}

static bool gift128_alt_fs_20(enum Mode mode)
{
    return gift128_alt_fs(mode, 20);
}

static bool gift128_alt_fs_80(enum Mode mode)
{
    return gift128_alt_fs(mode, 80);
}

static bool grain128_core(enum Mode mode)
{
    Code code;
    gen_grain128_core(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_grain128_core(code)) {
            std::cout << "Grain-128 core tests FAILED" << std::endl;
            return false;
        } else {
                std::cout << "Grain-128 core tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool grain128_preoutput(enum Mode mode)
{
    Code code;
    gen_grain128_preoutput(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_grain128_preoutput(code)) {
            std::cout << "Grain-128 preoutput tests FAILED" << std::endl;
            return false;
        } else {
                std::cout << "Grain-128 preoutput tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool grain128_swap_word32(enum Mode mode)
{
    Code code;
    gen_grain128_swap_word32(code);
    if (mode == Generate)
        code.write(std::cout);
    return true;
}

static bool grain128_compute_tag(enum Mode mode)
{
    Code code;
    gen_grain128_compute_tag(code);
    if (mode == Generate)
        code.write(std::cout);
    return true;
}

static bool grain128_interleave(enum Mode mode)
{
    Code code;
    gen_grain128_interleave(code);
    if (mode == Generate)
        code.write(std::cout);
    return true;
}

static bool grain128(enum Mode mode)
{
    bool ok = true;
    if (!grain128_core(mode))
        ok = false;
    if (!grain128_preoutput(mode))
        ok = false;
    if (!grain128_swap_word32(mode))
        ok = false;
    if (!grain128_compute_tag(mode))
        ok = false;
    if (!grain128_interleave(mode))
        ok = false;
    return ok;
}

static bool keccakp_200(enum Mode mode)
{
    Code code;
    gen_keccakp_200_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_keccakp_200_permutation(code)) {
            std::cout << "Keccak-p[200] tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "Keccak-p[200] tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool keccakp_400(enum Mode mode)
{
    Code code;
    gen_keccakp_400_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_keccakp_400_permutation(code)) {
            std::cout << "Keccak-p[400] tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "Keccak-p[400] tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool photon256(enum Mode mode)
{
    Code code;
    gen_photon256_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_photon256_permutation(code)) {
            std::cout << "PHOTON-256 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "PHOTON-256 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool sha256(enum Mode mode)
{
    Code code;
    gen_sha256_transform(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_sha256_transform(code)) {
            std::cout << "SHA256 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "SHA256 tests succeeded" << std::endl;
        }
    }
    return true;
}

static void skinny128_sboxes(enum Mode mode)
{
    if (mode == Generate) {
        Code code;
        for (int index = 0; index < SKINNY128_SBOX_COUNT; ++index)
            code.sbox_write(std::cout, index, get_skinny128_sbox(index));
    }
}

static bool skinny128_384_setup_key(enum Mode mode, int rounds = 56)
{
    Code code;
    gen_skinny128_384_setup_key(code, rounds);
    if (mode == Generate)
        code.write(std::cout);
    return true;
}

static bool skinny128_384_encrypt(enum Mode mode, int rounds = 56)
{
    Code code;
    gen_skinny128_384_encrypt(code, rounds);
    if (mode == Generate) {
        code.write(std::cout);
        code.write_alias(std::cout, "skinny_plus_encrypt_tk_full");
    } else {
        if (!test_skinny128_384_encrypt(code)) {
            std::cout << "SKINNY-128-384 encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "SKINNY-128-384 encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool skinny128_384_decrypt(enum Mode mode, int rounds = 56)
{
    Code code;
    gen_skinny128_384_decrypt(code, rounds);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_skinny128_384_decrypt(code)) {
            std::cout << "SKINNY-128-384 decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "SKINNY-128-384 decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool skinny128_256_setup_key(enum Mode mode)
{
    Code code;
    gen_skinny128_256_setup_key(code);
    if (mode == Generate)
        code.write(std::cout);
    return true;
}

static bool skinny128_256_encrypt(enum Mode mode)
{
    Code code;
    gen_skinny128_256_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
        code.write_alias(std::cout, "skinny_128_256_encrypt_tk_full");
    } else {
        if (!test_skinny128_256_encrypt(code)) {
            std::cout << "SKINNY-128-256 encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "SKINNY-128-256 encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool skinny128_256_decrypt(enum Mode mode)
{
    Code code;
    gen_skinny128_256_decrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_skinny128_256_decrypt(code)) {
            std::cout << "SKINNY-128-256 decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "SKINNY-128-256 decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool skinny128(enum Mode mode)
{
    bool ok = true;
    skinny128_sboxes(mode);
    if (!skinny128_384_setup_key(mode))
        ok = false;
    if (!skinny128_384_encrypt(mode))
        ok = false;
    if (!skinny128_384_decrypt(mode))
        ok = false;
    if (!skinny128_256_setup_key(mode))
        ok = false;
    if (!skinny128_256_encrypt(mode))
        ok = false;
    if (!skinny128_256_decrypt(mode))
        ok = false;
    return ok;
}

static bool skinny128_enc_only(enum Mode mode)
{
    bool ok = true;
    skinny128_sboxes(mode);
    if (!skinny128_384_setup_key(mode))
        ok = false;
    if (!skinny128_384_encrypt(mode))
        ok = false;
    if (!skinny128_256_setup_key(mode))
        ok = false;
    if (!skinny128_256_encrypt(mode))
        ok = false;
    return ok;
}

static bool skinny_plus(enum Mode mode)
{
    bool ok = true;
    skinny128_sboxes(mode);
    if (!skinny128_384_setup_key(mode, 40))
        ok = false;
    if (!skinny128_384_encrypt(mode, 40))
        ok = false;
    return ok;
}

static bool sparkle256(enum Mode mode)
{
    Code code;
    gen_sparkle256_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_sparkle256_permutation(code)) {
            std::cout << "SPARKLE-256 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "SPARKLE-256 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool sparkle384(enum Mode mode)
{
    Code code;
    gen_sparkle384_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_sparkle384_permutation(code)) {
            std::cout << "SPARKLE-384 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "SPARKLE-384 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool sparkle512(enum Mode mode)
{
    Code code;
    gen_sparkle512_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_sparkle512_permutation(code)) {
            std::cout << "SPARKLE-512 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "SPARKLE-512 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool spongent160(enum Mode mode)
{
    Code code;
    gen_spongent160_permutation(code);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_spongent_sbox());
        code.write(std::cout);
    } else {
        if (!test_spongent160_permutation(code)) {
            std::cout << "Spongent-pi[160] tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "Spongent-pi[160] tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool spongent176(enum Mode mode)
{
    Code code;
    gen_spongent176_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_spongent176_permutation(code)) {
            std::cout << "Spongent-pi[176] tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "Spongent-pi[176] tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool tinyjambu128(enum Mode mode)
{
    Code code;
    gen_tinyjambu128_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_tinyjambu128_permutation(code)) {
            std::cout << "TinyJAMBU-128 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "TinyJAMBU-128 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool tinyjambu192(enum Mode mode)
{
    Code code;
    gen_tinyjambu192_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_tinyjambu192_permutation(code)) {
            std::cout << "TinyJAMBU-192 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "TinyJAMBU-192 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool tinyjambu256(enum Mode mode)
{
    Code code;
    gen_tinyjambu256_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_tinyjambu256_permutation(code)) {
            std::cout << "TinyJAMBU-256 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "TinyJAMBU-256 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool xoodoo(enum Mode mode)
{
    Code code;
    gen_xoodoo_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_xoodoo_permutation(code)) {
            std::cout << "Xoodoo tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "Xoodoo tests succeeded" << std::endl;
        }
    }
    return true;
}

typedef bool (*gen_code)(enum Mode mode);

int main(int argc, char *argv[])
{
    bool generate = true;
    int exit_val = 0;
    gen_code gen1 = 0;
    gen_code gen2 = 0;
    gen_code gen3 = 0;

    if (argc > 1 && !strcmp(argv[1], "--test")) {
        generate = false;
    } else {
        if (argc <= 1) {
            fprintf(stderr, "Usage: %s algorithm-name\n", argv[0]);
            return 1;
        }
        if (!strcmp(argv[1], "AES")) {
            gen1 = aes;
        } else if (!strcmp(argv[1], "ASCON")) {
            gen1 = ascon;
        } else if (!strcmp(argv[1], "GHASH")) {
            gen1 = ghash;
        } else if (!strcmp(argv[1], "GIFT-128b")) {
            gen1 = gift128b;
        } else if (!strcmp(argv[1], "GIFT-COFB-128b")) {
            gen1 = gift128b_cofb_only;
        } else if (!strcmp(argv[1], "GIFT-128n")) {
            gen1 = gift128n;
        } else if (!strcmp(argv[1], "GIFT-128-alt")) {
            gen1 = gift128_alt;
        } else if (!strcmp(argv[1], "GIFT-128b-fs-4")) {
            gen1 = gift128b_fs_4;
        } else if (!strcmp(argv[1], "GIFT-128b-fs-20")) {
            gen1 = gift128b_fs_20;
        } else if (!strcmp(argv[1], "GIFT-128b-fs-80")) {
            gen1 = gift128b_fs_80;
        } else if (!strcmp(argv[1], "GIFT-COFB-128b-fs-4")) {
            gen1 = gift128b_fs_4_cofb_only;
        } else if (!strcmp(argv[1], "GIFT-COFB-128b-fs-20")) {
            gen1 = gift128b_fs_20_cofb_only;
        } else if (!strcmp(argv[1], "GIFT-COFB-128b-fs-80")) {
            gen1 = gift128b_fs_80_cofb_only;
        } else if (!strcmp(argv[1], "GIFT-128n-fs-4")) {
            gen1 = gift128n_fs_4;
        } else if (!strcmp(argv[1], "GIFT-128n-fs-20")) {
            gen1 = gift128n_fs_20;
        } else if (!strcmp(argv[1], "GIFT-128n-fs-80")) {
            gen1 = gift128n_fs_80;
        } else if (!strcmp(argv[1], "GIFT-128-alt-fs-4")) {
            gen1 = gift128_alt_fs_4;
        } else if (!strcmp(argv[1], "GIFT-128-alt-fs-20")) {
            gen1 = gift128_alt_fs_20;
        } else if (!strcmp(argv[1], "GIFT-128-alt-fs-80")) {
            gen1 = gift128_alt_fs_80;
        } else if (!strcmp(argv[1], "Grain-128")) {
            gen1 = grain128;
        } else if (!strcmp(argv[1], "Keccak")) {
            gen1 = keccakp_200;
            gen2 = keccakp_400;
        } else if (!strcmp(argv[1], "Keccakp-200")) {
            gen1 = keccakp_200;
        } else if (!strcmp(argv[1], "Keccakp-400")) {
            gen1 = keccakp_400;
        } else if (!strcmp(argv[1], "PHOTON-256")) {
            gen1 = photon256;
        } else if (!strcmp(argv[1], "SHA256")) {
            gen1 = sha256;
        } else if (!strcmp(argv[1], "SKINNY-128")) {
            gen1 = skinny128;
        } else if (!strcmp(argv[1], "SKINNY-128-Enc-Only")) {
            gen1 = skinny128_enc_only;
        } else if (!strcmp(argv[1], "SKINNY-128-384-Plus")) {
            gen1 = skinny_plus;
        } else if (!strcmp(argv[1], "SPARKLE")) {
            gen1 = sparkle256;
            gen2 = sparkle384;
            gen3 = sparkle512;
        } else if (!strcmp(argv[1], "Spongent-pi")) {
            gen1 = spongent160;
            gen2 = spongent176;
        } else if (!strcmp(argv[1], "TinyJAMBU")) {
            gen1 = tinyjambu128;
            gen2 = tinyjambu192;
            gen3 = tinyjambu256;
        } else if (!strcmp(argv[1], "Xoodoo")) {
            gen1 = xoodoo;
        }
    }

    if (generate) {
        header(std::cout);
        if (gen1)
            gen1(Generate);
        if (gen2)
            gen2(Generate);
        if (gen3)
            gen3(Generate);
        footer(std::cout);
    } else {
        if (!aes(Test))
            exit_val = 1;
        if (!ascon(Test))
            exit_val = 1;
        if (!ghash(Test))
            exit_val = 1;
        if (!gift128b(Test))
            exit_val = 1;
        if (!gift128_alt(Test))
            exit_val = 1;
        if (!gift128n(Test))
            exit_val = 1;
        if (!gift128b_fs_4(Test))
            exit_val = 1;
        if (!gift128b_fs_20(Test))
            exit_val = 1;
        if (!gift128b_fs_80(Test))
            exit_val = 1;
        if (!gift128n_fs_4(Test))
            exit_val = 1;
        if (!gift128n_fs_20(Test))
            exit_val = 1;
        if (!gift128n_fs_80(Test))
            exit_val = 1;
        if (!gift128_alt_fs_4(Test))
            exit_val = 1;
        if (!gift128_alt_fs_20(Test))
            exit_val = 1;
        if (!gift128_alt_fs_80(Test))
            exit_val = 1;
        if (!grain128(Test))
            exit_val = 1;
        if (!keccakp_200(Test))
            exit_val = 1;
        if (!keccakp_400(Test))
            exit_val = 1;
        if (!photon256(Test))
            exit_val = 1;
        if (!sha256(Test))
            exit_val = 1;
        if (!skinny128(Test))
            exit_val = 1;
        if (!sparkle256(Test))
            exit_val = 1;
        if (!sparkle384(Test))
            exit_val = 1;
        if (!sparkle512(Test))
            exit_val = 1;
        if (!spongent160(Test))
            exit_val = 1;
        if (!spongent176(Test))
            exit_val = 1;
        if (!tinyjambu128(Test))
            exit_val = 1;
        if (!tinyjambu192(Test))
            exit_val = 1;
        if (!tinyjambu256(Test))
            exit_val = 1;
        if (!xoodoo(Test))
            exit_val = 1;
    }

    return exit_val;
}
