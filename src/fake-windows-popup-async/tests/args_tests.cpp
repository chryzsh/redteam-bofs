#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>

#include "args.h"

namespace {

// OC2 out_arguments for `fake-windows-popup-async` with no options, as sent by
// the teamserver: JAAAAAIAAAAAAAIAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAA
const unsigned char kOc2Defaults[] = {
    0x24, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// The same OC2 layout for --caption Hi --message Yo --timeout 30
// --attempts 2 --validate --include-password --persistent
const unsigned char kOc2AllSet[] = {
    0x2c, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x48, 0x00, 0x69, 0x00,
    0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x59, 0x00, 0x6f, 0x00, 0x00, 0x00,
    0x1e, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
};

void put_u32(std::string* out, unsigned int value, bool big_endian) {
    for (int index = 0; index < 4; ++index) {
        const int shift = big_endian ? (3 - index) * 8 : index * 8;
        out->push_back(static_cast<char>((value >> shift) & 0xff));
    }
}

void put_utf16(std::string* out, const char* ascii, bool big_endian) {
    std::string data;
    for (const char* c = ascii; *c != '\0'; ++c) {
        data.push_back(*c);
        data.push_back('\0');
    }
    data.append(2, '\0');
    put_u32(out, static_cast<unsigned int>(data.size()), big_endian);
    out->append(data);
}

// BOF-PE standalone layout, as loader.exe and BEACON_MAIN pack ZZiiiii
std::string pack_big_endian(const char* caption, const char* message, const int* ints, int count) {
    std::string out;
    put_utf16(&out, caption, true);
    put_utf16(&out, message, true);
    for (int index = 0; index < count; ++index) {
        put_u32(&out, static_cast<unsigned int>(ints[index]), true);
    }
    return out;
}

bool parse(const void* data, std::size_t len, PackedArguments* out) {
    return parse_packed_arguments(
        static_cast<const char*>(data), static_cast<int>(len), out);
}

bool utf16_equals(const char* value, int bytes, const char* ascii) {
    const int chars = static_cast<int>(std::strlen(ascii));
    if (bytes != (chars + 1) * 2) {
        return false;
    }
    for (int index = 0; index < chars; ++index) {
        if (value[index * 2] != ascii[index] || value[index * 2 + 1] != '\0') {
            return false;
        }
    }
    return value[chars * 2] == '\0' && value[chars * 2 + 1] == '\0';
}

void check_all_set(const PackedArguments& args) {
    assert(utf16_equals(args.caption, args.caption_bytes, "Hi"));
    assert(utf16_equals(args.message, args.message_bytes, "Yo"));
    assert(args.int_count == 5);
    assert(args.ints[0] == 30);
    assert(args.ints[1] == 2);
    assert(args.ints[2] == 1);
    assert(args.ints[3] == 1);
    assert(args.ints[4] == 1);
}

}  // namespace

int main() {
    PackedArguments args{};

    // OC2 defaults: two empty strings and timeout 0, attempts 1, flags 0
    assert(parse(kOc2Defaults, sizeof(kOc2Defaults), &args));
    assert(args.layout == PackedLayout::little_endian_prefixed);
    assert(utf16_equals(args.caption, args.caption_bytes, ""));
    assert(utf16_equals(args.message, args.message_bytes, ""));
    assert(args.int_count == 5);
    assert(args.ints[0] == 0 && args.ints[1] == 1);
    assert(args.ints[2] == 0 && args.ints[3] == 0 && args.ints[4] == 0);

    // OC2 with caption, message and every flag set
    assert(parse(kOc2AllSet, sizeof(kOc2AllSet), &args));
    assert(args.layout == PackedLayout::little_endian_prefixed);
    check_all_set(args);

    // The same buffer with the total-length prefix stripped
    assert(parse(kOc2AllSet + 4, sizeof(kOc2AllSet) - 4, &args));
    assert(args.layout == PackedLayout::little_endian);
    check_all_set(args);

    // BOF-PE standalone big-endian layout
    const int all_set[] = {30, 2, 1, 1, 1};
    const std::string standalone = pack_big_endian("Hi", "Yo", all_set, 5);
    assert(parse(standalone.data(), standalone.size(), &args));
    assert(args.layout == PackedLayout::big_endian);
    check_all_set(args);

    // Fewer ints are allowed, the rest keep their defaults
    const std::string two_ints = pack_big_endian("", "", all_set, 2);
    assert(parse(two_ints.data(), two_ints.size(), &args));
    assert(args.int_count == 2);

    // A prefix that does not match the buffer length is not the OC2 layout
    unsigned char wrong_prefix[sizeof(kOc2Defaults)];
    std::memcpy(wrong_prefix, kOc2Defaults, sizeof(wrong_prefix));
    wrong_prefix[0] = 0x23;
    assert(!parse(wrong_prefix, sizeof(wrong_prefix), &args));

    // Truncated buffer: prefix no longer matches and the body is incomplete
    assert(!parse(kOc2AllSet, sizeof(kOc2AllSet) - 1, &args));

    // Six ints is one too many
    const int six[] = {30, 2, 1, 1, 1, 1};
    const std::string too_many = pack_big_endian("", "", six, 6);
    assert(!parse(too_many.data(), too_many.size(), &args));

    // String without its NUL terminator
    std::string no_nul;
    put_u32(&no_nul, 4, true);
    no_nul.append("H\0i\0", 4);
    assert(!parse(no_nul.data(), no_nul.size(), &args));

    // Odd string size
    std::string odd;
    put_u32(&odd, 3, false);
    odd.append("\0\0\0", 3);
    assert(!parse(odd.data(), odd.size(), &args));

    // String longer than the 1024-byte limit
    std::string oversize;
    put_u32(&oversize, 1026, false);
    oversize.append(1026, '\0');
    assert(!parse(oversize.data(), oversize.size(), &args));

    // Raw string arguments for inline-execute-pe are not packed
    const char raw[] = "60 1 0 0 1";
    assert(!parse(raw, sizeof(raw) - 1, &args));

    // Too short, or no buffer at all
    assert(!parse(kOc2Defaults, 3, &args));
    assert(!parse_packed_arguments(nullptr, 0, &args));

    std::puts("args tests passed");
    return 0;
}
