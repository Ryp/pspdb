// Native default-output PSAR pipeline, adapted from pinned pspdecrypt/newpsardumper.
// Original algorithms: PspPet, Nem, Dark_AleX, Noobz, Team C+D, M33,
// bbtgp, Proxima, some1; PC port and IPL stages by pspdecrypt contributors.
// Input is immutable; only bounded records enter reusable per-call scratch.
#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <iterator>
#include <new>
#include <string>
#include <utility>
#include <vector>
#include <zlib.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include "CommonTypes.h"
#include "PrxDecrypter.h"
extern "C" {
#include "libkirk/kirk_engine.h"
#include "syscon_ipl_keys.h"
int decompress_kle_bounded_member(u8 *, int, const u8 *, int, int, size_t *);
int pspdb_psar_lzr(const u8 *, size_t, u8 *, size_t, size_t *);
void pspdb_psar_hash(int, const u8 *, size_t, const u8 *, size_t, u8 *);
}

namespace {
constexpr size_t data_size = 3000000;
struct psar_error {};
struct sink_error {};
struct crypto_error {};
// DES-CBC belongs to OpenSSL's legacy provider. Keep its provider and cipher
// state private to this walk; no global provider changes or per-table setup.
class des_context {
    OSSL_LIB_CTX *library = nullptr;
    OSSL_PROVIDER *provider = nullptr;
    EVP_CIPHER *cipher = nullptr;
    EVP_CIPHER_CTX *context = nullptr;
public:
    des_context() = default;
    des_context(const des_context &) = delete;
    des_context &operator=(const des_context &) = delete;
    ~des_context() {
        EVP_CIPHER_CTX_free(context);
        EVP_CIPHER_free(cipher);
        if (provider) OSSL_PROVIDER_unload(provider);
        OSSL_LIB_CTX_free(library);
    }
    void decrypt(u8 *bytes, int size, const u8 *key, const u8 *iv) {
        if (!context) {
            library = OSSL_LIB_CTX_new();
            if (!library) throw std::bad_alloc{};
            provider = OSSL_PROVIDER_load(library, "legacy");
            if (!provider) throw crypto_error{};
            cipher = EVP_CIPHER_fetch(library, "DES-CBC", nullptr);
            if (!cipher) throw crypto_error{};
            context = EVP_CIPHER_CTX_new();
            if (!context) throw std::bad_alloc{};
        }
        int written = 0, final_size = 0;
        u8 final_block[8];
        if (EVP_DecryptInit_ex2(context, cipher, key, iv, nullptr) != 1 ||
            EVP_CIPHER_CTX_set_padding(context, 0) != 1 ||
            EVP_DecryptUpdate(context, bytes, &written, bytes, size) != 1 ||
            written != size ||
            EVP_DecryptFinal_ex(context, final_block, &final_size) != 1 ||
            final_size != 0) throw crypto_error{};
    }
};
using emit_fn = int (*)(void *, const char *, size_t, const u8 *, size_t, int);
struct psar_sink {
    void *context;
    emit_fn emit;
    bool file(const char *name, const u8 *bytes, size_t size) {
        if (emit(context, name, strlen(name), bytes, size, 0)) throw sink_error{};
        return true;
    }
    void directory(const std::string &name) {
        if (emit(context, name.data(), name.size(), nullptr, 0, 1)) throw sink_error{};
    }
    void parents(const std::string &name) {
        for (size_t i = 0; i < name.size(); ++i)
            if (name[i] == '/') directory(name.substr(0, i));
    }
};
u32 read_le32(const u8 *p) {
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}
bool address_range(u32 address, u32 base, size_t size, size_t length) {
    return address >= base && size_t(address - base) <= size && length <= size - (address - base);
}
// Upstream uses zlib framing for PSAR records and gzip framing for payloads.
// Never let zlib inspect a synthetic 0xE0000 span or an unbounded scratch tail.
int gunzip(u8 *input, u32 size, u8 *out, u32 capacity, u32 *consumed = nullptr, bool raw = false) {
    if (size < 2) return -1;
    z_stream stream{};
    if (inflateInit2(&stream, raw ? 15 : 31) != Z_OK) return -1;
    stream.next_in = input;
    stream.avail_in = size;
    stream.next_out = out;
    stream.avail_out = capacity;
    const int status = inflate(&stream, Z_FINISH);
    const auto written = stream.total_out;
    const auto used = stream.total_in;
    inflateEnd(&stream);
    if (status != Z_STREAM_END || written > INT_MAX) return -1;
    if (consumed) *consumed = static_cast<u32>(used);
    return static_cast<int>(written);
}
// The memory patch retains only bounded IPL1/linearization/table primitives.
#include "pspdecrypt_lib.cpp"
// The memory patch places all IPL state and its sink in ipl_context.
#include "ipl_decrypt.cpp"

bool compressed(const u8 *p, size_t n) {
    return (n >= 2 && p[0] == 0x1f && p[1] == 0x8b) ||
        (n >= 4 && (!memcmp(p, "2RLZ", 4) || !memcmp(p, "KL4E", 4) || !memcmp(p, "KL3E", 4)));
}
int expand(u8 *input, size_t size, u8 *output, size_t capacity, size_t &used) {
    used = 0;
    if (size > INT_MAX || capacity > INT_MAX) throw psar_error{};
    int result = -1;
    if (size >= 2 && input[0] == 0x1f && input[1] == 0x8b) {
        u32 count = 0;
        result = gunzip(input, size, output, capacity, &count);
        used = count;
    } else if (size >= 4 && !memcmp(input, "2RLZ", 4)) {
        result = pspdb_psar_lzr(input + 4, size - 4, output, capacity, &used);
        used += 4;
    } else if (size >= 4 && (!memcmp(input, "KL4E", 4) || !memcmp(input, "KL3E", 4))) {
        result = decompress_kle_bounded_member(output, capacity, input + 4, size - 4, input[2] == '4', &used);
        used += 4;
    }
    if (result <= 0 || size_t(result) > capacity || used == 0 || used > size) throw psar_error{};
    return result;
}
int decrypt_prx(const u8 *input, u8 *output, size_t size) {
    if (size < 0x150 || size > data_size) throw psar_error{};
    const int result = pspDecryptPRX(input, output, static_cast<u32>(size));
    if (result <= 0 || size_t(result) > size) throw psar_error{};
    return result;
}

struct psar_context {
    const u8 *input;
    size_t size;
    psar_sink &sink;
    des_context des;
    std::vector<u8> first = std::vector<u8>(data_size);
    std::vector<u8> second = std::vector<u8>(data_size);
    std::array<std::vector<char>, 13> tables;
    size_t cursor = 0;
    size_t overhead = 0;
    int psar_version = 0;
    int firmware = 0;
    int table_mode = 0;
    bool plaintext = false;

    void range(size_t offset, size_t length) const {
        if (offset > size || length > size - offset) throw psar_error{};
    }
    int block(size_t offset, size_t length, u8 *out) {
        if (length > data_size) throw psar_error{};
        const size_t aligned = plaintext ? length : (length + 15) & ~size_t(15);
        if (aligned > data_size) throw psar_error{};
        range(offset, aligned);
        if (plaintext) {
            memcpy(out, input + offset, length);
            return static_cast<int>(length);
        }
        if (aligned < 0x150) return -1;
        memcpy(out, input + offset, aligned);
        if (psar_version != 1) {
            alignas(16) u8 buffer[20 + 0x130]{};
            static constexpr u8 k1[16] = {0xD8,0x69,0xB8,0x95,0x33,0x6B,0x63,0x34,0x98,0xB9,0xFC,0x3C,0xB7,0x26,0x2B,0xD7};
            static constexpr u8 k2[16] = {0x0D,0xA0,0x90,0x84,0xAF,0x9E,0xB6,0xE2,0xD2,0x94,0xF2,0xAA,0xEF,0x99,0x68,0x71};
            memcpy(buffer + 20, input + offset + 0x20, 0x130);
            if (psar_version == 5) for (size_t i = 0; i < 0x130; ++i) buffer[20+i] ^= k1[i & 15];
            auto *header = reinterpret_cast<u32 *>(buffer);
            header[0] = 5; header[3] = 0x55; header[4] = 0x130;
            if (sceUtilsBufferCopyWithRange(buffer, sizeof(buffer), buffer, sizeof(buffer), 7)) return -1;
            if (psar_version == 5) for (size_t i = 0; i < 0x130; ++i) buffer[i] ^= k2[i & 15];
            memcpy(out + 0x20, buffer, 0x130);
        }
        return pspDecryptPRX(out, out, aligned);
    }
    void init() {
        range(0, 0x30);
        if (memcmp(input, "PSAR", 4)) throw psar_error{};
        plaintext = read_le32(input + 0x20) == 0x2c333333;
        overhead = plaintext ? 0 : 0x150;
        psar_version = input[4];
        if (block(0x10, overhead + 0x110, first.data()) != 0x110) throw psar_error{};
        cursor = 0x10 + overhead + 0x110;
        int decoded = 0;
        if (plaintext) {
            decoded = block(cursor, read_le32(first.data() + 0x90), second.data());
            if (decoded <= 0) throw psar_error{};
            range(cursor, decoded);
            cursor += decoded;
        } else if (psar_version != 1) {
            decoded = block(cursor, overhead + 100, second.data());
            if (decoded <= 0) decoded = block(cursor, overhead + 144, second.data());
            if (decoded <= 0) decoded = block(cursor, overhead + first[0x90] + (size_t(first[0x91]) << 8), second.data());
            if (decoded <= 0 || size_t(decoded) > data_size - 15) throw psar_error{};
            const size_t advance = overhead + ((size_t(decoded) + 15) & ~size_t(15));
            range(cursor, advance);
            cursor += advance;
        }
        const char *begin = reinterpret_cast<char *>(first.data() + 0x10);
        const char *end = reinterpret_cast<const char *>(memchr(begin, 0, 0x100));
        if (!end) throw psar_error{};
        std::string version(begin, end);
        const auto comma = version.rfind(',');
        version = comma == std::string::npos ? "1.00" : version.substr(comma + 1);
        if (version.size() != 4 || version[1] != '.' || version[0] < '0' || version[0] > '9' || version[2] < '0' || version[2] > '9' || version[3] < '0' || version[3] > '9') throw psar_error{};
        firmware = (version[0]-'0')*100 + (version[2]-'0')*10 + version[3]-'0';
        if (firmware >= 380 && firmware < 400) table_mode = 1;
        else if (firmware >= 400 && firmware < 500) table_mode = 2;
        else if (firmware >= 500 && firmware < 600) table_mode = 3;
        else if (firmware >= 610 && firmware < 630 && psar_version == 5) table_mode = 5;
        else if (firmware >= 600 && firmware < 700) table_mode = 4;
    }
    bool next(std::string &name, size_t &expanded) {
        range(cursor, 0);
        if (size - cursor <= overhead) return false;
        if (block(cursor, overhead + 0x110, first.data()) != 0x110) throw psar_error{};
        const char *start = reinterpret_cast<char *>(first.data() + 4);
        const char *end = reinterpret_cast<const char *>(memchr(start, 0, 0xfc));
        if (!end || end == start || end - start >= 128) throw psar_error{};
        name.assign(start, end);
        if (read_le32(first.data() + 0x100)) throw psar_error{};
        const size_t chunk = read_le32(first.data() + 0x104);
        expanded = read_le32(first.data() + 0x108);
        if (expanded > data_size) throw psar_error{};
        cursor += overhead + 0x110;
        range(cursor, chunk);
        if (expanded) {
            const int packed = block(cursor, chunk, first.data());
            if (packed <= 10 || size_t(packed) > data_size || first[0] != 0x78 || first[1] != 0x9c) throw psar_error{};
            if (gunzip(first.data(), packed, second.data(), expanded, nullptr, true) != int(expanded)) throw psar_error{};
        }
        cursor += chunk;
        return true;
    }
    bool table_path(const std::vector<char> &table, const std::string &number, std::string &name) {
        if (number.size() < 5) throw psar_error{};
        for (size_t i = 0; i + 5 < table.size(); ++i) {
            if (memcmp(table.data() + i, number.data(), 5)) continue;
            const size_t start = i + 6;
            size_t end = start;
            while (end < table.size() && static_cast<unsigned char>(table[end]) >= 0x20) ++end;
            if (end == table.size() || end == start || end - start >= 128) throw psar_error{};
            std::string path(table.data() + start, end - start);
            if (table[i + 5] == '|') {
                if (path.compare(0, 5, "flash") == 0) {
                    if (path.size() < 7) throw psar_error{};
                    path.replace(6, 1, ":/");
                } else if (path.compare(0, 3, "ipl") == 0) {
                    if (path.size() < 4) throw psar_error{};
                    path.replace(3, 1, ":/");
                }
            }
            if (path.size() >= 128) throw psar_error{};
            name = std::move(path);
            return true;
        }
        return false;
    }
    void resolve_name(std::string &name) {
        const bool numeric = name.size() == 5 && std::all_of(name.begin(), name.end(), [](char c) { return c >= '0' && c <= '9'; });
        if (numeric && (std::stoi(name) >= 100 || (std::stoi(name) >= 10 && firmware < 660))) {
            for (const auto &table : tables) if (!table.empty() && table_path(table, name, name)) return;
            throw psar_error{};
        }
        static constexpr const char *prefixes[] = {"com:", "01g:", "02g:"};
        for (size_t i = 0; i < 3; ++i) {
            if (name.compare(0, 4, prefixes[i]) == 0 && !tables[i].empty()) {
                if (!table_path(tables[i], name.substr(4), name)) throw psar_error{};
                return;
            }
        }
    }
    std::string output_path(const std::string &name, size_t &expanded) {
        if (name.compare(0, 8, "flash0:/") == 0) return "F0/" + name.substr(8);
        if (name.compare(0, 8, "flash1:/") == 0) return "F1/" + name.substr(8);
        static constexpr std::pair<const char *, int> filenames[] = {
            {"com:00000",0},{"01g:00000",1},{"02g:00000",2},{"00001",1},{"00002",2},
            {"00003",3},{"00004",4},{"00005",5},{"00006",6},{"00007",7},{"00008",8},
            {"00009",9},{"00011",11},{"00012",12}};
        for (const auto &entry : filenames) {
            if (name.compare(0, strlen(entry.first), entry.first)) continue;
            const int length = pspDecryptTable(des, second.data(), first.data(), expanded, psar_version, table_mode);
            if (length <= 0 || size_t(length) > expanded) throw psar_error{};
            expanded = length;
            tables[entry.second].assign(reinterpret_cast<char *>(second.data()), reinterpret_cast<char *>(second.data()) + length);
            char model[6];
            snprintf(model, sizeof(model), "%05d", entry.second);
            return "PSARDUMPER/" + std::string(entry.second ? model : "common") + "_files_table.bin";
        }
        const auto slash = name.rfind('/');
        if (slash == std::string::npos || slash + 1 == name.size()) throw psar_error{};
        return "PSARDUMPER/" + name.substr(slash + 1);
    }
    void reboot(const std::string &name, const u8 *bytes, size_t length) {
        std::string path;
        if (name == "flash0:/kd/loadexec.prx") path = "PSARDUMPER/reboot.bin";
        else if (name.compare(0, strlen("flash0:/kd/loadexec_"), "flash0:/kd/loadexec_") == 0) {
            if (name.size() != strlen("flash0:/kd/loadexec_00g.prx")) throw psar_error{};
            path = "PSARDUMPER/reboot_" + name.substr(strlen("flash0:/kd/loadexec_"), 2) + "g.bin";
        } else return;
        for (size_t i = 0; i + 0x30 < length; ++i) {
            if (memcmp(bytes + i, "~PSP", 4)) continue;
            const size_t embedded = read_le32(bytes + i + 0x2c);
            if (embedded > length - i || embedded > data_size) throw psar_error{};
            std::vector<u8> decrypted(data_size), output(data_size);
            const int n = decrypt_prx(bytes + i, decrypted.data(), embedded);
            size_t consumed;
            const int actual = expand(decrypted.data(), n, output.data(), output.size(), consumed);
            sink.file(path.c_str(), output.data(), actual);
            return;
        }
        throw psar_error{};
    }
    void run() {
        init();
        sink.directory("F0"); sink.directory("F1"); sink.directory("PSARDUMPER");
        std::string name;
        size_t expanded;
        while (next(name, expanded)) {
            resolve_name(name);
            std::string path = output_path(name, expanded);
            const bool flash = name.compare(0, 8, "flash0:/") == 0 || name.compare(0, 8, "flash1:/") == 0;
            if (flash && !expanded) while (!path.empty() && path.back() == '/') path.pop_back();
            if (flash) {
                sink.parents(path);
                if (!expanded) sink.directory(path);
            }
            if (!expanded) continue;
            const bool ipl = name.compare(0, 4, "ipl:") == 0;
            bool prx = expanded >= 4 && !memcmp(second.data(), "~PSP", 4);
            if (ipl && !prx) {
                if (expanded < 0x64) throw psar_error{};
                const u32 mode = read_le32(second.data() + 0x60);
                if (mode != 1 && mode != 0x10001) {
                    expanded = decrypt_prx(second.data(), first.data(), expanded);
                    memcpy(second.data(), first.data(), expanded);
                }
                prx = expanded >= 4 && !memcmp(second.data(), "~PSP", 4);
            }
            if (prx || name.compare(0, strlen("flash0:/kd/resource/me"), "flash0:/kd/resource/me") == 0) {
                const size_t decrypted = decrypt_prx(second.data(), first.data(), expanded);
                u8 *final_bytes = first.data();
                size_t final_size = decrypted, used = decrypted;
                if (compressed(first.data(), decrypted)) {
                    final_size = expand(first.data(), decrypted, second.data(), second.size(), used);
                    final_bytes = second.data();
                }
                sink.file(path.c_str(), final_bytes, final_size);
                reboot(name, final_bytes, final_size);
                if (used < decrypted) {
                    size_t used_second;
                    const int length = expand(first.data() + used, decrypted - used, second.data(), second.size(), used_second);
                    if (used_second != decrypted - used) throw psar_error{};
                    sink.file((path + ".2").c_str(), second.data(), length);
                }
            } else {
                sink.file(path.c_str(), second.data(), expanded);
                reboot(name, second.data(), expanded);
                if (ipl) {
                    const int blocks = pspDecryptIPL1(second.data(), first.data(), expanded);
                    if (blocks <= 0 || size_t(blocks) != expanded) throw psar_error{};
                    u32 address = 0;
                    const int linear = pspLinearizeIPL2(first.data(), second.data(), blocks, &address);
                    if (linear <= 0) throw psar_error{};
                    const std::string base = name.substr(name.rfind('/') + 1);
                    sink.file(("PSARDUMPER/stage1_" + base).c_str(), second.data(), linear);
                    ipl_context stages(sink);
                    if (stages.extractIPLStages(second.data(), linear, firmware, address, base.c_str(), "PSARDUMPER", nullptr, 0)) throw psar_error{};
                }
            }
        }
    }
};
} // namespace

// 0 success; -1 malformed/transform; -2 allocation; -3 sink; -4 crypto provider.
extern "C" int pspdb_psar_walk(const u8 *input, size_t size, void *context, emit_fn emit) noexcept {
    if (!input || !emit || size < 0x30 || memcmp(input, "PSAR", 4)) return -1;
    try {
        kirk_init_prx();
        psar_sink sink{context, emit};
        psar_context state{input, size, sink};
        state.run();
        return 0;
    } catch (const std::bad_alloc &) {
        return -2;
    } catch (const sink_error &) {
        return -3;
    } catch (const crypto_error &) {
        return -4;
    } catch (...) {
        return -1;
    }
}
