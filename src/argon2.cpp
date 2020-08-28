inline namespace {

    using uint8_t = __UINT8_TYPE__;
    using uint32_t = __UINT32_TYPE__;
    using uint64_t = __UINT64_TYPE__;
    using uintptr_t = __UINTPTR_TYPE__;
    using size_t = __SIZE_TYPE__;

}

#ifndef UINT64_C
#   define UINT_C2(n, suf) n ## suf
#   define UINT_C1(n, suf) UINT_C2(n, suf)
#   define UINT64_C(n) UINT_C1(n, __UINT64_C_SUFFIX__)
#endif


namespace std {

    template <class E>
    class initializer_list {
    public:
        typedef E value_type;
        typedef const E& reference;
        typedef const E& const_reference;
        typedef size_t size_type;
        typedef const E* iterator;
        typedef const E* const_iterator;

    private:
        iterator m_array;
        size_type m_len;

        // The compiler can call a private constructor.
        constexpr initializer_list(const_iterator a, size_type l) : m_array(a), m_len(l) { }

    public:
        constexpr initializer_list() noexcept : m_array(0), m_len(0) { }

        // Number of elements.
        constexpr size_type size() const noexcept { return m_len; }

        // First element.
        constexpr const_iterator begin() const noexcept { return m_array; }

        // One past the last element.
        constexpr const_iterator end() const noexcept { return begin() + size(); }

        // First element.
        constexpr friend iterator begin(initializer_list<E> l) { return l.begin(); }

        // One past the last element.
        constexpr friend iterator end(initializer_list<E> l) { return l.end(); }
    };

}  // namespace std


inline namespace {

#ifdef GENKAT
    extern "C" int printf(const char *format, ...);

    void print_hex(const char *what, const void *out, uint32_t outlen) {
        if (!out) {
            return;
        }

        const uint8_t *c = reinterpret_cast<const uint8_t *>(out);
        ::printf("%s[%u]: ", what, (unsigned) outlen);
        while (outlen--) {
            ::printf("%2.2x ", *(c++));
        }
        ::printf("\n");
    }
#endif


    enum class Argon2_type : uint32_t {
        d = 0,
        i = 1,
        id = 2
    };


    // values can be tweaked:

    static inline constexpr uint32_t memory_size_kb = 64 * 1024;
    static inline constexpr uint32_t iterations = 4;
    static inline constexpr uint32_t tag_length = 32;

    // other values aren't implemented:

    static inline constexpr uint32_t parallelism = 1;
    static inline constexpr uint32_t version = 0x13;
    static inline constexpr uint32_t hash_type = static_cast<uint32_t>(Argon2_type::d);
    static inline constexpr uint32_t sync_points = 4;
    static inline constexpr uint32_t lanes = 1;
    static inline constexpr uint32_t memory_blocks = memory_size_kb;
    static inline constexpr uint32_t segment_length = memory_blocks / (lanes * sync_points);
    static inline constexpr uint32_t lane_length = segment_length * lanes * sync_points;


    class Endian {
    private:
        static constexpr uint32_t v32 = 0x01020304;
        static constexpr uint8_t v8 = (const uint8_t&) v32;
        Endian() = delete;

    public:
        static constexpr bool little = v8 == 0x04;
        static constexpr bool big = v8 == 0x01;
        static_assert(little || big, "Cannot determine endianness!");
    };

    static_assert(Endian::little, "Big endian is not implemented!");


    union alignas(512 / 8) Block {
        uint8_t bytes[1024];
        uint64_t u64[1024 / 8];
        uint64_t u128[64][2];
    };

    using Blocks = Block[memory_blocks];


    size_t minZ(size_t a, size_t b) {
        return a <= b ? a : b;
    }


    template <class I>
    void memcpy_round(void *&dst, const void *&src, size_t &cnt, size_t n) {
        if (!n) {
            return;
        }

        I *&dI = reinterpret_cast<I*&>(dst);
        const I *&sI = reinterpret_cast<const I*&>(src);

        if (n >= 8) {
            n = 8;
            dI[0] = sI[0]; dI[1] = sI[1]; dI[2] = sI[2]; dI[3] = sI[3];
            dI[4] = sI[4]; dI[5] = sI[5]; dI[6] = sI[6]; dI[7] = sI[7];
        } else if (n >= 4) {
            n = 4;
            dI[0] = sI[0]; dI[1] = sI[1]; dI[2] = sI[2]; dI[3] = sI[3];
        } else {
            n = 1;
            dI[0] = sI[0];
        }

        dI += n;
        sI += n;
        cnt -= n * sizeof(I);
    }

    template <class I>
    void memset0_round(void *&d, size_t &cnt, size_t n) {
        if (!n) {
            return;
        }

        I *&dI = reinterpret_cast<I*&>(d);

        if (n >= 8) {
            n = 8;
            dI[0] = 0; dI[1] = 0; dI[2] = 0; dI[3] = 0;
            dI[4] = 0; dI[5] = 0; dI[6] = 0; dI[7] = 0;
        } else if (n >= 4) {
            n = 4;
            dI[0] = 0; dI[1] = 0; dI[2] = 0; dI[3] = 0;
        } else {
            n = 1;
            dI[0] = 0;
        }

        dI += n;
        cnt -= n * sizeof(I);
    }

    extern "C" void *memcpy(void *dst, const void* src, size_t cnt) {
        using I = uint64_t;

        if (cnt == 0 || dst == src) {
            return reinterpret_cast<uintptr_t*>(dst) + cnt;
        }

        if (auto missalign = reinterpret_cast<uintptr_t>(dst) % sizeof(I)) {
            memcpy_round<uint8_t>(dst, src, cnt, minZ(cnt, sizeof(I) - missalign));
        }
        while (auto r = cnt / sizeof(uint64_t)) {
            memcpy_round<uint64_t>(dst, src, cnt, r);
        }
        memcpy_round<uint8_t>(dst, src, cnt, cnt);

        return dst;
    }

    extern "C" void *memset(void *d, int c, size_t cnt) {
        if (!c) {
            using I = uint64_t;

            if (auto missalign = reinterpret_cast<uintptr_t>(d) % sizeof(I)) {
                memset0_round<uint8_t>(d, cnt, minZ(cnt, sizeof(I) - missalign));
            }
            while (auto r = cnt / sizeof(I)) {
                memset0_round<I>(d, cnt, r);
            }
            memset0_round<uint8_t>(d, cnt, cnt);

            return d;
        } else {
            uint8_t *d1 = reinterpret_cast<uint8_t*>(d);
            while (cnt--) {
                *(d1) = static_cast<unsigned>(c) & 0xffu;
            }
            return d1;
        }
    }

#   define memcpy(D, S, N) __builtin_memcpy((D), (S), (N))
#   define memset(S, C, N) __builtin_memset((S), (C), (N))


    uint64_t ror(uint64_t a, unsigned amount) {
        return (a >> amount) | (a << (64 - amount));
    }


    uint32_t min32(uint32_t a, uint32_t b) {
        return a <= b ? a : b;
    }


    struct SrcLen {
        const void *src;
        size_t src_len;
    };


    class Blake2b {
    private:
        struct {
            uint64_t h[8];
            uint64_t t;  // RFC: uint128_t
            uint8_t buffer_length; // 0..128
            union {
                uint8_t bytes[128];
                uint64_t words[16];
            } buffer;
        } S;

        static constexpr const uint8_t SIGMA[12][16] = {
            {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
            { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
            { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
            {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
            {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
            {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
            { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
            { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
            {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
            { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },

            {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
            { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
        };

        static constexpr const uint64_t IV[8] = {
            UINT64_C(0x6a09e667f3bcc908),
            UINT64_C(0xbb67ae8584caa73b),
            UINT64_C(0x3c6ef372fe94f82b),
            UINT64_C(0xa54ff53a5f1d36f1),
            UINT64_C(0x510e527fade682d1),
            UINT64_C(0x9b05688c2b3e6c1f),
            UINT64_C(0x1f83d9abfb41bd6b),
            UINT64_C(0x5be0cd19137e2179),
        };

        static void mix(uint64_t &a, uint64_t &b, uint64_t &c, uint64_t &d, uint64_t x, uint64_t y) {
            a = a + b + x;
            d = ror(d ^ a, 32);
            c = c + d;
            b = ror(b ^ c, 24);
            a = a + b + y;
            d = ror(d ^ a, 16);
            c = c + d;
            b = ror(b ^ c, 63);
        }

        void compress(bool is_last_block) {
            alignas(512 / 8) uint64_t V[16];
            for (unsigned i = 0; i < 8; ++i) {
                V[i] = S.h[i];
            }
            for (unsigned i = 0; i < 8; ++i) {
                V[8 + i] = IV[i];
            }

            V[12] ^= S.t;
            if (is_last_block) {
                V[14] = ~V[14];
            }

            const auto &m = S.buffer.words;

            // Twelve rounds of cryptographic message mixing
            for (unsigned i = 0; i < 12; ++i) {
                auto &sigma = SIGMA[i];

                mix(V[0], V[4], V[ 8], V[12], m[sigma[ 0]], m[sigma[ 1]]);
                mix(V[1], V[5], V[ 9], V[13], m[sigma[ 2]], m[sigma[ 3]]);
                mix(V[2], V[6], V[10], V[14], m[sigma[ 4]], m[sigma[ 5]]);
                mix(V[3], V[7], V[11], V[15], m[sigma[ 6]], m[sigma[ 7]]);

                mix(V[0], V[5], V[10], V[15], m[sigma[ 8]], m[sigma[ 9]]);
                mix(V[1], V[6], V[11], V[12], m[sigma[10]], m[sigma[11]]);
                mix(V[2], V[7], V[ 8], V[13], m[sigma[12]], m[sigma[13]]);
                mix(V[3], V[4], V[ 9], V[14], m[sigma[14]], m[sigma[15]]);
            }

            // Mix the upper and lower halves of V into ongoing state vector h
            for (unsigned i = 0; i < 8; ++i) {
                S.h[i] ^= V[i];
            }
            for (unsigned i = 0; i < 8; ++i) {
                S.h[i] ^= V[i + 8];
            }
        }

    public:
        explicit Blake2b(uint32_t outlen) {
            memcpy(S.h, IV, sizeof(S.h));
            S.h[0] ^= UINT64_C(0x01010000) | outlen;
            S.t = 0;
            S.buffer_length = 0;
        }

        void update(const void *in, uint32_t inlen) {
            const uint8_t *c = reinterpret_cast<const uint8_t*>(in);
            while (inlen) {
                uint32_t cnt = min32(sizeof(S.buffer) - S.buffer_length, inlen);
                memcpy(S.buffer.bytes + S.buffer_length, c, cnt);

                S.buffer_length += cnt;
                S.t += cnt;
                inlen -= cnt;
                c += cnt;

                if (S.buffer_length == sizeof(S.buffer)) {
                    S.buffer_length = 0;
                    compress(false);
                }
            }
        }

        void finalize(void *out, uint32_t outlen) {
            memset(S.buffer.bytes + S.buffer_length, 0, sizeof(S.buffer) - S.buffer_length);
            compress(true);
            memcpy(out, S.h, outlen);
        }

        static void hash(void *dest, uint32_t dest_len, std::initializer_list<SrcLen> src_lens) {
            auto S = Blake2b{dest_len};
            for (auto [src, src_len] : src_lens) {
                S.update(src, src_len);
            }
            S.finalize(dest, dest_len);
        }
    };


    void hash(
        void *digest_, uint32_t digest_length,
        const void *message_, uint32_t message_length
    ) {
        uint8_t *digest = reinterpret_cast<uint8_t*>(digest_);
        const uint8_t *message = reinterpret_cast<const uint8_t*>(message_);

        if (digest_length <= 64) {
            Blake2b::hash(digest_, digest_length, {
                { &digest_length, sizeof(digest_length) },
                { message, message_length },
            });
        } else {
            alignas(512 / 8) uint8_t V1[64];
            Blake2b::hash(V1, sizeof(V1), {
                { &digest_length, sizeof(digest_length) },
                { message, message_length },
            });

            while (true) {
                memcpy(digest, V1, 32);
                digest += 32;
                digest_length -= 32;
                if (digest_length <= 64) {
                    break;
                }
                Blake2b::hash(V1, sizeof(V1), {
                    { V1, sizeof(V1) },
                });
            }

            Blake2b::hash(digest, digest_length, {
                { V1, sizeof(V1) },
            });
        }
    }
    
    uint64_t fBlaMka(uint64_t x, uint64_t y) {
        constexpr uint64_t m = UINT64_C(0xFFFFFFFF);
        uint64_t xy = (x & m) * (y & m);
        return x + y + 2 * xy;
    }


    void argon2_G(uint64_t &a, uint64_t &b, uint64_t &c, uint64_t &d) {
        a = fBlaMka(a, b);
        d = ror(d ^ a, 32);
        c = fBlaMka(c, d);
        b = ror(b ^ c, 24);
        a = fBlaMka(a, b);
        d = ror(d ^ a, 16);
        c = fBlaMka(c, d);
        b = ror(b ^ c, 63);
    }


    void argon2_P(
        uint64_t &v0, uint64_t &v1, uint64_t & v2, uint64_t & v3, uint64_t & v4, uint64_t & v5, uint64_t & v6, uint64_t & v7,
        uint64_t &v8, uint64_t &v9, uint64_t &v10, uint64_t &v11, uint64_t &v12, uint64_t &v13, uint64_t &v14, uint64_t &v15
    ) {
        argon2_G(v0, v4,  v8, v12);
        argon2_G(v1, v5,  v9, v13);
        argon2_G(v2, v6, v10, v14);
        argon2_G(v3, v7, v11, v15);

        argon2_G(v0, v5, v10, v15);
        argon2_G(v1, v6, v11, v12);
        argon2_G(v2, v7,  v8, v13);
        argon2_G(v3, v4,  v9, v14);
    }


    void argon2_fill_block(Block &N, const Block &X, const Block &Y, bool with_xor) {
        Block R;
        for (unsigned i = 0; i < 128; ++i) {
            R.u64[i] = X.u64[i] ^ Y.u64[i];
        }

        Block T;
        if (with_xor) {
            for (unsigned i = 0; i < 128; ++i) {
                T.u64[i] = R.u64[i] ^ N.u64[i];
            }
        } else {
            T = R;
        }

        auto &r = R.u64;

        for (unsigned i = 0; i < 8; ++i) {
            argon2_P(
                r[(16 * i) +  0], r[(16 * i) +  1], r[(16 * i) +  2], r[(16 * i) +  3],
                r[(16 * i) +  4], r[(16 * i) +  5], r[(16 * i) +  6], r[(16 * i) +  7],
                r[(16 * i) +  8], r[(16 * i) +  9], r[(16 * i) + 10], r[(16 * i) + 11],
                r[(16 * i) + 12], r[(16 * i) + 13], r[(16 * i) + 14], r[(16 * i) + 15]
            );
        }

        for (unsigned i = 0; i < 8; ++i) {
            argon2_P(
                r[(2 * i) +  0], r[(2 * i) +  1], r[(2 * i) +  16], r[(2 * i) +  17],
                r[(2 * i) + 32], r[(2 * i) + 33], r[(2 * i) +  48], r[(2 * i) +  49],
                r[(2 * i) + 64], r[(2 * i) + 65], r[(2 * i) +  80], r[(2 * i) +  81],
                r[(2 * i) + 96], r[(2 * i) + 97], r[(2 * i) + 112], r[(2 * i) + 113]
            );
        }

        for (unsigned i = 0; i < 128; ++i) {
            N.u64[i] = T.u64[i] ^ R.u64[i];
        }
    }


    uint32_t index_alpha(uint32_t pass_r, uint32_t slice_s, uint32_t index, uint32_t pseudo_rand) {
        uint32_t reference_area_size;
        if (pass_r > 0) {
            reference_area_size = lane_length - segment_length + index - 1;
        } else if (slice_s == 0) {
            // First pass, first slice
            reference_area_size = index - 1;
        } else {
            // First pass
            reference_area_size = slice_s * segment_length + index - 1;
        }

        uint64_t relative_position = pseudo_rand;
        relative_position = (relative_position * relative_position) >> 32;
        relative_position = reference_area_size - 1 - ((reference_area_size * relative_position) >> 32);

        uint32_t start_position = 0;
        if (pass_r > 0 && slice_s != sync_points - 1) {
            start_position = (slice_s + 1) * segment_length;
        }

        uint32_t absolute_position = (start_position + relative_position) % lane_length;
        return absolute_position;
    }


    __attribute__((visibility("default")))
    extern "C" Blocks B = {};

    class Argon2 {
    private:
        static void initialize(std::initializer_list<SrcLen> src_lens) {
            alignas(512 / 8) struct __attribute__((packed)) {
                uint8_t H0[64];
                uint32_t block_no;
                uint32_t lane_no;
            } data;

            // Generate initial 64-byte block H0.
            Blake2b::hash(data.H0, sizeof(data.H0), src_lens);

#ifdef GENKAT
            print_hex("Pre-hashing digest", data.H0, sizeof(data.H0));
#endif

            // Compute the first and second block (i.e. column zero and one)

            data.block_no = 0;
            data.lane_no = 0;
            hash(B[0].bytes, sizeof(B[0]), &data, sizeof(data));

            data.block_no = 1;
            data.lane_no = 0;
            hash(B[1].bytes, sizeof(B[1]), &data, sizeof(data));
        }

        static void fill_segment(uint32_t pass_r, uint32_t slice_s) {
            uint32_t starting_index = 0;
            if (pass_r == 0 && slice_s == 0) {
                starting_index = 2;
            }

            uint32_t curr_offset = slice_s * segment_length + starting_index;

            uint32_t prev_offset;
            if (curr_offset % lane_length == 0) {
                prev_offset = curr_offset + lane_length - 1;
            } else {
                prev_offset = curr_offset - 1;
            }

            for (uint32_t i = starting_index; i < segment_length; ++i, ++curr_offset, ++prev_offset) {
                if (curr_offset % lane_length == 1) {
                    prev_offset = curr_offset - 1;
                }

                uint32_t ref_index = index_alpha(pass_r, slice_s, i, static_cast<uint32_t>(B[prev_offset].u64[0]));
                Block &curr_block = B[curr_offset];
                Block &prev_block = B[prev_offset];
                Block &ref_block = B[ref_index];
                argon2_fill_block(curr_block, prev_block, ref_block, (pass_r > 0));
            }
        }

        static void run() {
            for (uint32_t pass_r = 0; pass_r < iterations; ++pass_r) {
                for (uint32_t slice_s = 0; slice_s < sync_points; ++slice_s) {
                    fill_segment(pass_r, slice_s);
                }
#if GENKAT
#   if 0
                ::printf("\n After pass %d:\n", pass_r);
                for (uint32_t block_no = 0; block_no < memory_blocks; ++block_no) {
                    for (uint32_t int_no = 0; int_no < 128; ++int_no) {
                        ::printf(
                            "Block %04d [%3d]: %016llx\n",
                            (unsigned) block_no,
                            (unsigned) int_no,
                            (unsigned long long) B[block_no].u64[int_no]
                        );
                    }
                }
#   endif
#endif
            }
        }

        static void finalize() {
            hash(&B, tag_length, B[memory_blocks - 1].bytes, sizeof(Block));
        }

    public:
        [[gnu::unused]]
        static bool argon2_hash(uint32_t buffer_length) {
            const uint32_t min_buffer_length = (
                sizeof(uint32_t) +  // parallelism
                sizeof(uint32_t) +  // tag_length
                sizeof(uint32_t) +  // memory_size_kb
                sizeof(uint32_t) +  // iterations
                sizeof(uint32_t) +  // version
                sizeof(uint32_t) +  // hash_type
                sizeof(uint32_t) +  // hash_type
                0                +  // password
                sizeof(uint32_t) +  // salt_length
                8                +  // salt
                sizeof(uint32_t) +  // key_length
                0                +  // key
                sizeof(uint32_t) +  // associated_data_length
                0                   // associated_data
            );
            if (buffer_length < min_buffer_length) {
                return false;
            }

            const uint8_t *buffer = reinterpret_cast<const uint8_t*>(&B);
            uint32_t buffer_pos = 0;

            auto buffer_incrementable = [&](uint32_t count) -> bool {
                return (
                    (buffer_pos + count >= buffer_pos) &&
                    (buffer_pos + count >= count) &&
                    (buffer_pos + count <= buffer_length)
                );
            };

            auto buffer_increment = [&](uint32_t count) -> bool {
                if (!buffer_incrementable(count)) {
                    return false;
                }

                buffer_pos += count;
                return true;
            };

            auto buffer_read_u32 = [&](uint32_t &out) -> bool {
                if (!buffer_incrementable(sizeof(uint32_t))) {
                    return false;
                }

                memcpy(&out, buffer + buffer_pos, sizeof(uint32_t));
                buffer_pos += sizeof(sizeof(uint32_t));
                return true;
            };

            auto buffer_read_u32_exact = [&](uint32_t expected) -> bool {
                uint32_t actual;
                return buffer_read_u32(actual) && expected == actual;
            };

            auto buffer_read_str = [&](uint32_t min_length) -> bool {
                uint32_t count;
                return buffer_read_u32(count) && (count >= min_length) && buffer_increment(count);
            };

            if (
                !buffer_read_u32_exact(parallelism) ||
                !buffer_read_u32_exact(tag_length) ||
                !buffer_read_u32_exact(memory_size_kb) ||
                !buffer_read_u32_exact(iterations) ||
                !buffer_read_u32_exact(version) ||
                !buffer_read_u32_exact(hash_type) ||
                !buffer_read_str(0) ||  // password
                !buffer_read_str(8) ||  // salt
                !buffer_read_str(0) ||  // key
                !buffer_read_str(0) ||  // associated_data
                !(buffer_pos == buffer_length) ||
                false
            ) {
                return false;
            }

            initialize({
                { buffer, buffer_length },
            });
            run();
            finalize();

            return true;
        }

        [[gnu::unused]]
        static bool argon2_hash(
            const void *password, uint32_t password_length,
            const void *salt, uint32_t salt_length,
            const void *key, uint32_t key_length,
            const void *associated_data, uint32_t associated_data_length
        ) {
            if (
                (!password && password_length > 0) ||
                (!salt || salt_length < 8) ||
                (!key && key_length > 0) ||
                (!associated_data && associated_data_length > 0)
            ) {
                return false;
            }

            initialize({
                { &parallelism, sizeof(parallelism) },
                { &tag_length, sizeof(tag_length) },
                { &memory_size_kb, sizeof(memory_size_kb) },
                { &iterations, sizeof(iterations) },
                { &version, sizeof(version) },
                { &hash_type, sizeof(hash_type) },

                { &password_length, sizeof(password_length) },
                { password, password_length },

                { &salt_length, sizeof(salt_length) },
                { salt, salt_length },

                { &key_length, sizeof(key_length) },
                { key, key_length },

                { &associated_data_length, sizeof(associated_data_length) },
                { associated_data, associated_data_length },
            });
            run();
            finalize();

            return true;
        }
    };

}  // anonymous inline namespace


extern "C" {

    __attribute__((visibility("default")))
    bool argon2(uint32_t buffer_length) {
        return Argon2::argon2_hash(buffer_length);
    }

}  // extern "C"



#ifdef GENKAT
int main(void) {
#if 0
    constexpr uint32_t TEST_PWDLEN = 32;
    constexpr uint32_t TEST_SALTLEN = 16;
    constexpr uint32_t TEST_SECRETLEN = 8;
    constexpr uint32_t TEST_ADLEN = 12;

    unsigned char pwd[TEST_PWDLEN];
    unsigned char salt[TEST_SALTLEN];
    unsigned char secret[TEST_SECRETLEN];
    unsigned char ad[TEST_ADLEN];

    memset(pwd, 1, TEST_PWDLEN);
    memset(salt, 2, TEST_SALTLEN);
    memset(secret, 3, TEST_SECRETLEN);
    memset(ad, 4, TEST_ADLEN);

    Argon2::argon2_hash(
        pwd, sizeof(pwd),
        salt, sizeof(salt),
        secret, sizeof(secret),
        ad, sizeof(ad)
    );
    print_hex("Tag", &B, tag_length);
#else
    unsigned char pwd[] = "test1234";
    unsigned char salt[] = "salt1234";

    Argon2::argon2_hash(
        pwd, 8,
        salt, 8,
        nullptr, 0,
        nullptr, 0
    );
    print_hex("Tag", &B, tag_length);
#endif

    return 0;
}
#endif
