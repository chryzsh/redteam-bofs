#pragma once

// Packed ZZiiiii argument parsing. Kept free of Windows and Beacon API
// dependencies so the host tests can exercise it.
//
// Two hosts pack arguments differently, and their BeaconData* functions read
// them differently, so go parses the buffer itself:
//
// - Cobalt Strike style (OC2): a 4-byte little-endian total length (the
//   whole buffer, prefix included), then each Z as a little-endian 4-byte
//   size and UTF-16LE data including the NUL, then little-endian ints. The
//   same layout without the prefix is also accepted.
// - BOF-PE standalone (loader.exe, BEACON_MAIN): no total length, sizes and
//   ints big-endian.

constexpr int kMaximumPackedStringBytes = 1024;
constexpr int kMaximumPackedInts = 5;

enum class PackedLayout {
    none,
    little_endian_prefixed,
    little_endian,
    big_endian,
};

struct PackedArguments {
    PackedLayout layout;
    // UTF-16LE strings including the terminating NUL, pointing into the input
    // buffer. nullptr when the string was not supplied.
    const char* caption;
    const char* message;
    int caption_bytes;
    int message_bytes;
    int ints[kMaximumPackedInts];
    int int_count;
};

// Returns true and fills *out when data is a complete packed buffer in one of
// the layouts above: one or two strings (2 to kMaximumPackedStringBytes bytes,
// even, NUL-terminated) followed by 0 to kMaximumPackedInts ints and nothing
// else.
bool parse_packed_arguments(const char* data, int len, PackedArguments* out);
