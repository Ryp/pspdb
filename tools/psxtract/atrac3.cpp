// Native ATRAC3 transport for PSXtract-2 (GPL-3.0-or-later).
// The upstream unscrambler, track lengths and pregap reconstruction are unchanged.
#include "native.h"

#include <array>
#include <memory>
#include <cfenv>
#include <cfloat>

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/mem.h>
#include <libavutil/cpu.h>
}

namespace {
uint32_t little32(const unsigned char* p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}

void put32(unsigned char* p, uint32_t value) {
    for (int i = 0; i < 4; ++i) p[i] = value >> (8 * i);
}

struct Decoder {
    AVCodecContext* codec = nullptr;
    AVFrame* frame = av_frame_alloc();
    AVPacket* packet = av_packet_alloc();
    ~Decoder() {
        av_packet_free(&packet);
        av_frame_free(&frame);
        avcodec_free_context(&codec);
    }
};
}

int decode_atrac3(const char* input, const char* output) {
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__GNUC__) || defined(__FAST_MATH__)
#error "Exact ATRAC3 requires native Linux x86_64 GCC-compatible arithmetic without fast-math"
#endif
    static_assert(FLT_MANT_DIG == 24 && DBL_MANT_DIG == 53 && LDBL_MANT_DIG == 64,
                  "Exact ATRAC3 requires IEEE float/double and x87 long double");
    unsigned short control;
    __asm__ __volatile__("fnstcw %0" : "=m" (control));
    if ((control & 0x0f00) != 0x0300 || std::fegetround() != FE_TONEAREST) {
        fprintf(stderr, "ERROR: Exact ATRAC3 requires x87 extended precision and round-to-nearest\n");
        return -1;
    }
    // Set dispatch here, before allocating/opening any decoder DSP context.
    av_force_cpu_flags(0);
    std::unique_ptr<FILE, decltype(&fclose)> source(fopen(input, "rb"), fclose);
    if (!source) return -1;
    std::array<unsigned char, 76> header;
    if (fread(header.data(), 1, header.size(), source.get()) != header.size() ||
        memcmp(header.data(), "RIFF", 4) || memcmp(header.data() + 8, "WAVEfmt ", 8) ||
        little32(header.data() + 16) != 32 || header[20] != 0x70 || header[21] != 2 ||
        header[22] != 2 || header[23] || little32(header.data() + 24) != 44100 ||
        little32(header.data() + 32) != 384 || memcmp(header.data() + 68, "data", 4)) {
        fprintf(stderr, "ERROR: Invalid PSX ATRAC3 header: %s\n", input);
        return -1;
    }
    const uint32_t data_size = little32(header.data() + 72);
    if (!data_size || data_size % 384 || little32(header.data() + 4) != data_size + 68) return -1;
    const AVCodec* codec = avcodec_find_decoder(AV_CODEC_ID_ATRAC3);
    if (!codec) {
        fprintf(stderr, "ERROR: Linked libavcodec lacks ATRAC3 decoding\n");
        return -1;
    }
    Decoder decoder;
    decoder.codec = avcodec_alloc_context3(codec);
    if (!decoder.codec || !decoder.frame || !decoder.packet) return -1;
    decoder.codec->sample_rate = 44100;
    decoder.codec->block_align = 384;
    decoder.codec->bit_rate = 132300;
    decoder.codec->flags |= AV_CODEC_FLAG_BITEXACT;
    decoder.codec->err_recognition = AV_EF_EXPLODE;
    av_channel_layout_default(&decoder.codec->ch_layout, 2);
    decoder.codec->extradata_size = 14;
    decoder.codec->extradata = static_cast<unsigned char*>(av_mallocz(14 + AV_INPUT_BUFFER_PADDING_SIZE));
    if (!decoder.codec->extradata) return -1;
    memcpy(decoder.codec->extradata, header.data() + 38, 14);
    if (avcodec_open2(decoder.codec, codec, nullptr) < 0 || av_new_packet(decoder.packet, 384) < 0) return -1;

    std::unique_ptr<FILE, decltype(&fclose)> destination(fopen(output, "wb"), fclose);
    if (!destination) return -1;
    // Keep the ACM transport's 18-byte PCM fmt chunk. Upstream reconstruction
    // consumes this WAV using its existing offset convention; changing it is
    // a separate output-semantic change, not a platform port.
    std::array<unsigned char, 46> wave{};
    memcpy(wave.data(), "RIFF", 4);
    memcpy(wave.data() + 8, "WAVEfmt ", 8);
    put32(wave.data() + 16, 18);
    wave[20] = 1;
    wave[22] = 2;
    put32(wave.data() + 24, 44100);
    put32(wave.data() + 28, 176400);
    wave[32] = 4;
    wave[34] = 16;
    memcpy(wave.data() + 38, "data", 4);
    if (fwrite(wave.data(), 1, wave.size(), destination.get()) != wave.size()) return -1;
    uint64_t pcm_size = 0;
    int skip_frames = 1165;
    std::array<unsigned char, 4096> pcm;
    auto receive = [&]() -> int {
        for (;;) {
            int status = avcodec_receive_frame(decoder.codec, decoder.frame);
            if (status == AVERROR(EAGAIN) || status == AVERROR_EOF) return 0;
            if (status < 0 || decoder.frame->nb_samples != 1024 ||
                decoder.frame->sample_rate != 44100 || decoder.frame->ch_layout.nb_channels != 2) return -1;
            if (decoder.frame->format != AV_SAMPLE_FMT_FLTP) return -1;
            int frames = 0;
            const float* left = reinterpret_cast<const float*>(decoder.frame->extended_data[0]);
            const float* right = reinterpret_cast<const float*>(decoder.frame->extended_data[1]);
            for (int i = 0; i < 1024; ++i) {
                if (skip_frames > 0) { --skip_frames; continue; }
                const float values[] = {left[i], right[i]};
                for (int ch = 0; ch < 2; ++ch) {
                    float value = -values[ch] * 32768.0f;
                    int sample = value < -32768 ? -32768 : value > 32767 ? 32767 : static_cast<int>(value);
                    pcm[frames * 4 + ch * 2] = sample & 255;
                    pcm[frames * 4 + ch * 2 + 1] = (sample >> 8) & 255;
                }
                ++frames;
            }
            if (fwrite(pcm.data(), 1, frames * 4, destination.get()) != static_cast<size_t>(frames * 4)) return -1;
            pcm_size += frames * 4;
            av_frame_unref(decoder.frame);
        }
    };
    for (uint32_t consumed = 0; consumed < data_size; consumed += 384) {
        if (fread(decoder.packet->data, 1, 384, source.get()) != 384 ||
            avcodec_send_packet(decoder.codec, decoder.packet) < 0 || receive() < 0) return -1;
    }
    if (fgetc(source.get()) != EOF || ferror(source.get()) ||
        avcodec_send_packet(decoder.codec, nullptr) < 0 || receive() < 0 ||
        pcm_size + 4660 != uint64_t(data_size / 384) * 4096 || pcm_size > UINT32_MAX - 46) return -1;
    // Match upstream's transport header, including its noncanonical RIFF size.
    put32(wave.data() + 4, static_cast<uint32_t>(pcm_size + 46));
    put32(wave.data() + 42, static_cast<uint32_t>(pcm_size));
    if (fseek(destination.get(), 0, SEEK_SET) ||
        fwrite(wave.data(), 1, wave.size(), destination.get()) != wave.size() ||
        fflush(destination.get())) return -1;
    return fclose(destination.release()) == 0 ? 0 : -1;
}
