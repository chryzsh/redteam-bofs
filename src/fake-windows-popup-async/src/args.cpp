#include "args.h"

namespace {

unsigned int read_u32(const char* data, bool big_endian) {
    const auto* bytes = reinterpret_cast<const unsigned char*>(data);
    if (big_endian) {
        return (static_cast<unsigned int>(bytes[0]) << 24) |
            (static_cast<unsigned int>(bytes[1]) << 16) |
            (static_cast<unsigned int>(bytes[2]) << 8) |
            static_cast<unsigned int>(bytes[3]);
    }
    return static_cast<unsigned int>(bytes[0]) |
        (static_cast<unsigned int>(bytes[1]) << 8) |
        (static_cast<unsigned int>(bytes[2]) << 16) |
        (static_cast<unsigned int>(bytes[3]) << 24);
}

bool read_string(
    const char* data,
    int len,
    int* offset,
    bool big_endian,
    const char** value,
    int* bytes) {
    if (*offset < 0 || *offset > len - 4) {
        return false;
    }
    const unsigned int size = read_u32(data + *offset, big_endian);
    if (size < 2 || size > static_cast<unsigned int>(kMaximumPackedStringBytes) ||
        size % 2 != 0 ||
        size > static_cast<unsigned int>(len - *offset - 4)) {
        return false;
    }
    const int start = *offset + 4;
    const int end = start + static_cast<int>(size);
    if (data[end - 1] != '\0' || data[end - 2] != '\0') {
        return false;
    }
    *value = data + start;
    *bytes = static_cast<int>(size);
    *offset = end;
    return true;
}

bool parse_body(
    const char* data,
    int len,
    int offset,
    bool big_endian,
    PackedArguments* out) {
    PackedArguments result{};
    if (!read_string(
            data, len, &offset, big_endian, &result.caption, &result.caption_bytes)) {
        return false;
    }
    if (offset < len &&
        !read_string(
            data, len, &offset, big_endian, &result.message, &result.message_bytes)) {
        return false;
    }
    const int remaining = len - offset;
    if (remaining < 0 || remaining % 4 != 0 ||
        remaining / 4 > kMaximumPackedInts) {
        return false;
    }
    result.int_count = remaining / 4;
    for (int index = 0; index < result.int_count; ++index) {
        result.ints[index] =
            static_cast<int>(read_u32(data + offset + index * 4, big_endian));
    }
    *out = result;
    return true;
}

}  // namespace

bool parse_packed_arguments(const char* data, int len, PackedArguments* out) {
    if (data == nullptr || out == nullptr || len < 4) {
        return false;
    }
    // A string size is 2 to 1024, so its little-endian and big-endian forms
    // never both pass the size check. The total-length prefix equals len,
    // and a first string size is at most len - 4, so the prefixed layout
    // cannot be mistaken for an unprefixed one either.
    const unsigned int prefix = read_u32(data, false);
    if (prefix == static_cast<unsigned int>(len) &&
        parse_body(data, len, 4, false, out)) {
        out->layout = PackedLayout::little_endian_prefixed;
        return true;
    }
    if (parse_body(data, len, 0, false, out)) {
        out->layout = PackedLayout::little_endian;
        return true;
    }
    if (parse_body(data, len, 0, true, out)) {
        out->layout = PackedLayout::big_endian;
        return true;
    }
    return false;
}
