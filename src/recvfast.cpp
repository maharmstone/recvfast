#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <filesystem>
#include <iostream>
#include <format>
#include "unique_fd.h"

using namespace std;

static const char BTRFS_SEND_STREAM_MAGIC[] = "btrfs-stream";
static const uint32_t BTRFS_SEND_STREAM_VERSION = 3;

struct btrfs_stream_header {
    char magic[sizeof(BTRFS_SEND_STREAM_MAGIC)];
    uint32_t version;
} __attribute__ ((__packed__));

enum class btrfs_send_cmd : uint16_t {
    UNSPEC = 0,
    SUBVOL = 1,
    SNAPSHOT = 2,
    MKFILE = 3,
    MKDIR = 4,
    MKNOD = 5,
    MKFIFO = 6,
    MKSOCK = 7,
    SYMLINK = 8,
    RENAME = 9,
    LINK = 10,
    UNLINK = 11,
    RMDIR = 12,
    SET_XATTR = 13,
    REMOVE_XATTR = 14,
    WRITE = 15,
    CLONE = 16,
    TRUNCATE = 17,
    CHMOD = 18,
    CHOWN = 19,
    UTIMES = 20,
    END = 21,
    UPDATE_EXTENT = 22,
    FALLOCATE = 23,
    FILEATTR = 24,
    ENCODED_WRITE = 25,
    ENABLE_VERITY = 26,
};

struct btrfs_cmd_header {
    uint32_t len;
    enum btrfs_send_cmd cmd;
    uint32_t crc;
} __attribute__ ((__packed__));

enum class btrfs_send_attr : uint16_t {
    UNSPEC = 0,
    UUID = 1,
    CTRANSID = 2,
    INO = 3,
    SIZE = 4,
    MODE = 5,
    UID = 6,
    GID = 7,
    RDEV = 8,
    CTIME = 9,
    MTIME = 10,
    ATIME = 11,
    OTIME = 12,
    XATTR_NAME = 13,
    XATTR_DATA = 14,
    PATH = 15,
    PATH_TO = 16,
    PATH_LINK = 17,
    FILE_OFFSET = 18,
    DATA = 19,
    CLONE_UUID = 20,
    CLONE_CTRANSID = 21,
    CLONE_PATH = 22,
    CLONE_OFFSET = 23,
    CLONE_LEN = 24,
    FALLOCATE_MODE = 25,
    FILEATTR = 26,
    UNENCODED_FILE_LEN = 27,
    UNENCODED_LEN = 28,
    UNENCODED_OFFSET = 29,
    COMPRESSION = 30,
    ENCRYPTION = 31,
    VERITY_ALGORITHM = 32,
    VERITY_BLOCK_SIZE = 33,
    VERITY_SALT_DATA = 34,
    VERITY_SIG_DATA = 35,
};

struct btrfs_tlv_header {
    enum btrfs_send_attr tlv_type;
    uint16_t tlv_len;
} __attribute__ ((__packed__));

class formatted_error : public exception {
public:
    template<typename... Args>
    formatted_error(format_string<Args...> s, Args&&... args) : msg(format(s, forward<Args>(args)...)) {
    }

    const char* what() const noexcept {
        return msg.c_str();
    }

private:
    string msg;
};

template<>
struct std::formatter<enum btrfs_send_cmd> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(enum btrfs_send_cmd c, format_context& ctx) const {
        switch (c) {
            case btrfs_send_cmd::UNSPEC:
                return std::format_to(ctx.out(), "UNSPEC");
            case btrfs_send_cmd::SUBVOL:
                return std::format_to(ctx.out(), "SUBVOL");
            case btrfs_send_cmd::SNAPSHOT:
                return std::format_to(ctx.out(), "SNAPSHOT");
            case btrfs_send_cmd::MKFILE:
                return std::format_to(ctx.out(), "MKFILE");
            case btrfs_send_cmd::MKDIR:
                return std::format_to(ctx.out(), "MKDIR");
            case btrfs_send_cmd::MKNOD:
                return std::format_to(ctx.out(), "MKNOD");
            case btrfs_send_cmd::MKFIFO:
                return std::format_to(ctx.out(), "MKFIFO");
            case btrfs_send_cmd::MKSOCK:
                return std::format_to(ctx.out(), "MKSOCK");
            case btrfs_send_cmd::SYMLINK:
                return std::format_to(ctx.out(), "SYMLINK");
            case btrfs_send_cmd::RENAME:
                return std::format_to(ctx.out(), "RENAME");
            case btrfs_send_cmd::LINK:
                return std::format_to(ctx.out(), "LINK");
            case btrfs_send_cmd::UNLINK:
                return std::format_to(ctx.out(), "UNLINK");
            case btrfs_send_cmd::RMDIR:
                return std::format_to(ctx.out(), "RMDIR");
            case btrfs_send_cmd::SET_XATTR:
                return std::format_to(ctx.out(), "SET_XATTR");
            case btrfs_send_cmd::REMOVE_XATTR:
                return std::format_to(ctx.out(), "REMOVE_XATTR");
            case btrfs_send_cmd::WRITE:
                return std::format_to(ctx.out(), "WRITE");
            case btrfs_send_cmd::CLONE:
                return std::format_to(ctx.out(), "CLONE");
            case btrfs_send_cmd::TRUNCATE:
                return std::format_to(ctx.out(), "TRUNCATE");
            case btrfs_send_cmd::CHMOD:
                return std::format_to(ctx.out(), "CHMOD");
            case btrfs_send_cmd::CHOWN:
                return std::format_to(ctx.out(), "CHOWN");
            case btrfs_send_cmd::UTIMES:
                return std::format_to(ctx.out(), "UTIMES");
            case btrfs_send_cmd::END:
                return std::format_to(ctx.out(), "END");
            case btrfs_send_cmd::UPDATE_EXTENT:
                return std::format_to(ctx.out(), "UPDATE_EXTENT");
            case btrfs_send_cmd::FALLOCATE:
                return std::format_to(ctx.out(), "FALLOCATE");
            case btrfs_send_cmd::FILEATTR:
                return std::format_to(ctx.out(), "FILEATTR");
            case btrfs_send_cmd::ENCODED_WRITE:
                return std::format_to(ctx.out(), "ENCODED_WRITE");
            case btrfs_send_cmd::ENABLE_VERITY:
                return std::format_to(ctx.out(), "ENABLE_VERITY");
            default:
                return std::format_to(ctx.out(), "{:x}", (uint16_t)c);
        }
    }
};

static void parse(span<const uint8_t> sp) {
    const auto& h = *(btrfs_stream_header*)sp.data();

    if (strcmp(h.magic, BTRFS_SEND_STREAM_MAGIC))
        throw runtime_error("Not a stream file.");

    if (h.version > BTRFS_SEND_STREAM_VERSION)
        throw formatted_error("Stream was version {}, only streams up to version {} supported.",
                              h.version, BTRFS_SEND_STREAM_VERSION);

    sp = sp.subspan(sizeof(btrfs_stream_header));

    while (true) {
        if (sp.size() < sizeof(btrfs_cmd_header))
            break;

        const auto& cmd = *(btrfs_cmd_header*)sp.data();

        cout << format("{}, {:x}, crc = {:08x}\n",
                       cmd.cmd, cmd.len, cmd.crc);

        // FIXME - attributes

        if (sp.size() < cmd.len + sizeof(btrfs_cmd_header))
            break;

        sp = sp.subspan(cmd.len + sizeof(btrfs_cmd_header));
    }

    // FIXME - loop through cmds
}

static void process(const filesystem::path& fn) {
    int ret;

    ret = open(fn.string().c_str(), O_RDONLY);
    if (ret < 0)
        throw formatted_error("open failed: {}", ret);

    unique_fd f{ret};
    struct stat st;

    if (fstat(f.get(), &st))
        throw formatted_error("fstat failed: {}", errno);

    if (st.st_size < sizeof(btrfs_cmd_header))
        throw formatted_error("file was too short ({} bytes, expected at least {})", st.st_size, sizeof(btrfs_cmd_header));

    auto ptr = (uint8_t*)mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, f.get(), 0);
    if (!ptr)
        throw formatted_error("mmap failed: {}", errno);

    auto sp = span(ptr, st.st_size);

    try {
        parse(sp);
    } catch (...) {
        munmap(sp.data(), sp.size());
        throw;
    }

    munmap(sp.data(), sp.size());
}

int main() {
    try {
        process("/home/hellas/Desktop/work/stream/stream");
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
    }

    return 0;
}
