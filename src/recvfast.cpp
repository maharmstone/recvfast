#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <getopt.h>
#include <filesystem>
#include <iostream>
#include <format>
#include <chrono>
#include <array>
#include <liburing.h>
#include "unique_fd.h"

using namespace std;

static const char BTRFS_SEND_STREAM_MAGIC[] = "btrfs-stream";
static const uint32_t BTRFS_SEND_STREAM_VERSION = 3;

static const unsigned int QUEUE_DEPTH = 256; // FIXME?

static unsigned int items_pending;

static array<int, 256> files;
static unsigned int next_file_index = 0;
static unsigned int sqes_left = QUEUE_DEPTH;

static bool verbose = false;

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

struct btrfs_timespec {
    uint64_t sec;
    uint32_t nsec;
} __attribute__ ((__packed__));

struct sqe_ctx {
    uint64_t offset;
    string path, path2;
};

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
                return format_to(ctx.out(), "unspec");
            case btrfs_send_cmd::SUBVOL:
                return format_to(ctx.out(), "subvol");
            case btrfs_send_cmd::SNAPSHOT:
                return format_to(ctx.out(), "snapshot");
            case btrfs_send_cmd::MKFILE:
                return format_to(ctx.out(), "mkfile");
            case btrfs_send_cmd::MKDIR:
                return format_to(ctx.out(), "mkdir");
            case btrfs_send_cmd::MKNOD:
                return format_to(ctx.out(), "mknod");
            case btrfs_send_cmd::MKFIFO:
                return format_to(ctx.out(), "mkfifo");
            case btrfs_send_cmd::MKSOCK:
                return format_to(ctx.out(), "mksock");
            case btrfs_send_cmd::SYMLINK:
                return format_to(ctx.out(), "symlink");
            case btrfs_send_cmd::RENAME:
                return format_to(ctx.out(), "rename");
            case btrfs_send_cmd::LINK:
                return format_to(ctx.out(), "link");
            case btrfs_send_cmd::UNLINK:
                return format_to(ctx.out(), "unlink");
            case btrfs_send_cmd::RMDIR:
                return format_to(ctx.out(), "rmdir");
            case btrfs_send_cmd::SET_XATTR:
                return format_to(ctx.out(), "set_xattr");
            case btrfs_send_cmd::REMOVE_XATTR:
                return format_to(ctx.out(), "remove_xattr");
            case btrfs_send_cmd::WRITE:
                return format_to(ctx.out(), "write");
            case btrfs_send_cmd::CLONE:
                return format_to(ctx.out(), "clone");
            case btrfs_send_cmd::TRUNCATE:
                return format_to(ctx.out(), "truncate");
            case btrfs_send_cmd::CHMOD:
                return format_to(ctx.out(), "chmod");
            case btrfs_send_cmd::CHOWN:
                return format_to(ctx.out(), "chown");
            case btrfs_send_cmd::UTIMES:
                return format_to(ctx.out(), "utimes");
            case btrfs_send_cmd::END:
                return format_to(ctx.out(), "end");
            case btrfs_send_cmd::UPDATE_EXTENT:
                return format_to(ctx.out(), "update_extent");
            case btrfs_send_cmd::FALLOCATE:
                return format_to(ctx.out(), "fallocate");
            case btrfs_send_cmd::FILEATTR:
                return format_to(ctx.out(), "fileattr");
            case btrfs_send_cmd::ENCODED_WRITE:
                return format_to(ctx.out(), "encoded_write");
            case btrfs_send_cmd::ENABLE_VERITY:
                return format_to(ctx.out(), "enable_verity");
            default:
                return format_to(ctx.out(), "{:x}", (uint16_t)c);
        }
    }
};

template<>
struct std::formatter<enum btrfs_send_attr> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(enum btrfs_send_attr a, format_context& ctx) const {
        switch (a) {
            case btrfs_send_attr::UNSPEC:
                return format_to(ctx.out(), "unspec");
            case btrfs_send_attr::UUID:
                return format_to(ctx.out(), "uuid");
            case btrfs_send_attr::CTRANSID:
                return format_to(ctx.out(), "ctransid");
            case btrfs_send_attr::INO:
                return format_to(ctx.out(), "ino");
            case btrfs_send_attr::SIZE:
                return format_to(ctx.out(), "size");
            case btrfs_send_attr::MODE:
                return format_to(ctx.out(), "mode");
            case btrfs_send_attr::UID:
                return format_to(ctx.out(), "uid");
            case btrfs_send_attr::GID:
                return format_to(ctx.out(), "gid");
            case btrfs_send_attr::RDEV:
                return format_to(ctx.out(), "rdev");
            case btrfs_send_attr::CTIME:
                return format_to(ctx.out(), "ctime");
            case btrfs_send_attr::MTIME:
                return format_to(ctx.out(), "mtime");
            case btrfs_send_attr::ATIME:
                return format_to(ctx.out(), "atime");
            case btrfs_send_attr::OTIME:
                return format_to(ctx.out(), "otime");
            case btrfs_send_attr::XATTR_NAME:
                return format_to(ctx.out(), "xattr_name");
            case btrfs_send_attr::XATTR_DATA:
                return format_to(ctx.out(), "xattr_data");
            case btrfs_send_attr::PATH:
                return format_to(ctx.out(), "path");
            case btrfs_send_attr::PATH_TO:
                return format_to(ctx.out(), "path_to");
            case btrfs_send_attr::PATH_LINK:
                return format_to(ctx.out(), "path_link");
            case btrfs_send_attr::FILE_OFFSET:
                return format_to(ctx.out(), "file_offset");
            case btrfs_send_attr::DATA:
                return format_to(ctx.out(), "data");
            case btrfs_send_attr::CLONE_UUID:
                return format_to(ctx.out(), "clone_uuid");
            case btrfs_send_attr::CLONE_CTRANSID:
                return format_to(ctx.out(), "clone_ctransid");
            case btrfs_send_attr::CLONE_PATH:
                return format_to(ctx.out(), "clone_path");
            case btrfs_send_attr::CLONE_OFFSET:
                return format_to(ctx.out(), "clone_offset");
            case btrfs_send_attr::CLONE_LEN:
                return format_to(ctx.out(), "clone_len");
            case btrfs_send_attr::FALLOCATE_MODE:
                return format_to(ctx.out(), "fallocate_mode");
            case btrfs_send_attr::FILEATTR:
                return format_to(ctx.out(), "fileattr");
            case btrfs_send_attr::UNENCODED_FILE_LEN:
                return format_to(ctx.out(), "unencoded_file_len");
            case btrfs_send_attr::UNENCODED_LEN:
                return format_to(ctx.out(), "unencoded_len");
            case btrfs_send_attr::UNENCODED_OFFSET:
                return format_to(ctx.out(), "unencoded_offset");
            case btrfs_send_attr::COMPRESSION:
                return format_to(ctx.out(), "compression");
            case btrfs_send_attr::ENCRYPTION:
                return format_to(ctx.out(), "encryption");
            case btrfs_send_attr::VERITY_ALGORITHM:
                return format_to(ctx.out(), "verity_algorithm");
            case btrfs_send_attr::VERITY_BLOCK_SIZE:
                return format_to(ctx.out(), "verity_block_size");
            case btrfs_send_attr::VERITY_SALT_DATA:
                return format_to(ctx.out(), "verity_salt_data");
            case btrfs_send_attr::VERITY_SIG_DATA:
                return format_to(ctx.out(), "verity_sig_data");
            default:
                return format_to(ctx.out(), "{:x}", (uint16_t)a);
        }
    }
};

template<>
struct std::formatter<btrfs_timespec> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const btrfs_timespec& t, format_context& ctx) const {
        auto tp = chrono::system_clock::from_time_t(t.sec);

        tp += chrono::nanoseconds(t.nsec);

        return format_to(ctx.out(), "{}", tp);
    }
};

// FIXME - invocable concept for func
template<typename T>
static void parse_atts(span<const uint8_t> sp, const T& func) {
    while (!sp.empty()) {
        if (sp.size() < sizeof(btrfs_tlv_header))
            throw runtime_error("Attribute overflow");

        const auto& h = *(btrfs_tlv_header*)sp.data();

        if (sp.size() < sizeof(btrfs_tlv_header) + h.tlv_len)
            throw runtime_error("Attribute overflow");

        switch (h.tlv_type) {
            case btrfs_send_attr::CTRANSID:
            case btrfs_send_attr::INO:
            case btrfs_send_attr::SIZE:
            case btrfs_send_attr::MODE:
            case btrfs_send_attr::UID:
            case btrfs_send_attr::GID:
            case btrfs_send_attr::RDEV:
            case btrfs_send_attr::FILE_OFFSET:
            case btrfs_send_attr::CLONE_CTRANSID:
            case btrfs_send_attr::CLONE_OFFSET:
            case btrfs_send_attr::CLONE_LEN:
            case btrfs_send_attr::FILEATTR:
            case btrfs_send_attr::UNENCODED_FILE_LEN:
            case btrfs_send_attr::UNENCODED_LEN:
            case btrfs_send_attr::UNENCODED_OFFSET: {
                if (h.tlv_len != sizeof(uint64_t))
                    throw formatted_error("Length for {} was {}, expected {}", h.tlv_type, h.tlv_len, sizeof(uint64_t));

                auto v = *(uint64_t*)(sp.data() + sizeof(btrfs_tlv_header));

                func(h.tlv_type, v);
                break;
            }

            case btrfs_send_attr::FALLOCATE_MODE:
            case btrfs_send_attr::COMPRESSION:
            case btrfs_send_attr::ENCRYPTION: {
                if (h.tlv_len != sizeof(uint32_t))
                    throw formatted_error("Length for {} was {}, expected {}", h.tlv_type, h.tlv_len, sizeof(uint32_t));

                auto v = *(uint32_t*)(sp.data() + sizeof(btrfs_tlv_header));

                func(h.tlv_type, v);
                break;
            }

            case btrfs_send_attr::XATTR_NAME:
            case btrfs_send_attr::XATTR_DATA:
            case btrfs_send_attr::PATH:
            case btrfs_send_attr::PATH_TO:
            case btrfs_send_attr::PATH_LINK:
            case btrfs_send_attr::CLONE_PATH: {
                auto sv = string_view((char*)sp.data() + sizeof(btrfs_tlv_header), h.tlv_len);

                func(h.tlv_type, sv);
                break;
            }

            case btrfs_send_attr::CTIME:
            case btrfs_send_attr::MTIME:
            case btrfs_send_attr::ATIME:
            case btrfs_send_attr::OTIME: {
                if (h.tlv_len != sizeof(btrfs_timespec))
                    throw formatted_error("Length for {} was {}, expected {}", h.tlv_type, h.tlv_len, sizeof(btrfs_timespec));

                auto& t = *(btrfs_timespec*)(sp.data() + sizeof(btrfs_tlv_header));

                func(h.tlv_type, t);
                break;
            }

            case btrfs_send_attr::DATA: {
                auto sp2 = sp.subspan(sizeof(btrfs_tlv_header), h.tlv_len);

                // FIXME - different for stream version 2

                func(h.tlv_type, sp2);
                break;
            }

            // FIXME - VERITY_ALGORITHM
            // FIXME - VERITY_BLOCK_SIZE
            // FIXME - VERITY_SALT_DATA
            // FIXME - VERITY_SIG_DATA
            // FIXME - UUID
            // FIXME - CLONE_UUID

            default:
                // cout << format("  {}, {}\n", h.tlv_type, h.tlv_len);
                break;
        }

        sp = sp.subspan(sizeof(btrfs_tlv_header) + h.tlv_len);
    }
}

static io_uring_sqe* get_sqe(io_uring& ring) {
    sqes_left--;

    auto sqe = io_uring_get_sqe(&ring);

    if (sqe)
        return sqe;

    io_uring_submit(&ring);
    sqes_left = QUEUE_DEPTH - 1;

    return io_uring_get_sqe(&ring);
}

static void do_mkdir(io_uring& ring, int dirfd, span<const uint8_t> atts, uint64_t offset) {
    optional<string> path;

    parse_atts(atts, [&]<typename T>(enum btrfs_send_attr attr, const T& v) {
        if constexpr (is_same_v<T, string_view>) {
            if (attr == btrfs_send_attr::PATH)
                path = v;
        }
    });

    if (!path.has_value())
        throw formatted_error("mkdir cmd without path");

    auto ctx = new sqe_ctx;

    ctx->offset = offset;
    ctx->path.swap(path.value());

    auto sqe = get_sqe(ring);

    // FIXME - mode
    // FIXME - linking

    io_uring_prep_mkdirat(sqe, dirfd, ctx->path.c_str(), 0755);
    io_uring_sqe_set_data(sqe, ctx);

    items_pending++;
}

static void do_wait(io_uring& ring) {
    io_uring_submit(&ring);

    while (items_pending > 0) {
        io_uring_cqe* cqe;

        auto ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret < 0)
            throw formatted_error("io_uring_wait_cqe failed: {}", ret);

        auto ptr = io_uring_cqe_get_data(cqe);
        auto& ctx = *static_cast<sqe_ctx*>(ptr);

        // if (cqe->res < 0) {
        //     auto off = ctx.offset;
        //     delete &ctx;
        //
        //     throw formatted_error("operation failed: {} (offset {:x})", cqe->res, off);
        // }

        if (cqe->res < 0)
            cerr << format("operation failed: {} (offset {:x})\n", cqe->res, ctx.offset); // TESTING

        delete &ctx;

        items_pending--;
        io_uring_cqe_seen(&ring, cqe);
    }

    sqes_left = QUEUE_DEPTH;
}

static unsigned get_file_index(io_uring& ring) {
    if (next_file_index < files.size()) {
        next_file_index++;
        return next_file_index - 1;
    }

    do_wait(ring);

    next_file_index = 1;
    return 0;
}

static void do_mkfile(io_uring& ring, int dirfd, span<const uint8_t> atts, uint64_t offset) {
    optional<string> path;

    parse_atts(atts, [&]<typename T>(enum btrfs_send_attr attr, const T& v) {
        if constexpr (is_same_v<T, string_view>) {
            if (attr == btrfs_send_attr::PATH)
                path = v;
        }
    });

    if (!path.has_value())
        throw formatted_error("mkfile cmd without path");

    auto file_index = get_file_index(ring);

    auto ctx = new sqe_ctx;

    ctx->offset = offset;
    ctx->path.swap(path.value());

    if (sqes_left < 2)
        do_wait(ring);

    auto sqe = get_sqe(ring);

    // FIXME - mode

    io_uring_prep_openat_direct(sqe, dirfd, ctx->path.c_str(),
                                O_CREAT | O_EXCL, 0644, file_index);
    io_uring_sqe_set_data(sqe, ctx);
    sqe->flags |= IOSQE_IO_LINK;

    sqe = get_sqe(ring);

    ctx = new sqe_ctx;
    ctx->offset = offset;

    io_uring_prep_close_direct(sqe, file_index);
    io_uring_sqe_set_data(sqe, ctx);

    items_pending += 2;
}

static void do_symlink(io_uring& ring, int dirfd, span<const uint8_t> atts, uint64_t offset) {
    optional<string> path, path_link;

    parse_atts(atts, [&]<typename T>(enum btrfs_send_attr attr, const T& v) {
        if constexpr (is_same_v<T, string_view>) {
            if (attr == btrfs_send_attr::PATH)
                path = v;
            else if (attr == btrfs_send_attr::PATH_LINK)
                path_link = v;
        }
    });

    if (!path.has_value())
        throw formatted_error("symlink cmd without path");
    else if (!path.has_value())
        throw formatted_error("symlink cmd without path_link");

    auto sqe = get_sqe(ring);

    auto ctx = new sqe_ctx;

    ctx->offset = offset;
    ctx->path.swap(path.value());
    ctx->path2.swap(path_link.value());

    // FIXME - mode

    io_uring_prep_symlinkat(sqe, ctx->path2.c_str(), dirfd, ctx->path.c_str());
    io_uring_sqe_set_data(sqe, ctx);
    items_pending++;
}

static void create_files(io_uring& ring, int dirfd, span<const uint8_t> sp) {
    auto orig_sp = span(sp.data() - sizeof(btrfs_stream_header),
                        sp.size() + sizeof(btrfs_stream_header));

    while (!sp.empty()) {
        if (sp.size() < sizeof(btrfs_cmd_header))
            throw runtime_error("Command exceeding bounds of file.");

        const auto& cmd = *(btrfs_cmd_header*)sp.data();

        // FIXME - check CRC?

        if (sp.size() < cmd.len + sizeof(btrfs_cmd_header))
            throw runtime_error("Command exceeding bounds of file.");

        auto atts = span(sp.data() + sizeof(btrfs_cmd_header), cmd.len);

        switch (cmd.cmd) {
            case btrfs_send_cmd::MKDIR:
                do_mkdir(ring, dirfd, atts, sp.data() - orig_sp.data());
                break;

            case btrfs_send_cmd::MKFILE:
                do_mkfile(ring, dirfd, atts, sp.data() - orig_sp.data());
                break;

            case btrfs_send_cmd::SYMLINK:
                do_symlink(ring, dirfd, atts, sp.data() - orig_sp.data());
                break;

            case btrfs_send_cmd::RENAME:
                break;

            default:
                if (verbose) {
                    cout << format("{}, {:x}, {:08x}\n", cmd.cmd, cmd.len, cmd.crc);

                    parse_atts(atts, []<typename T>(enum btrfs_send_attr attr, const T& v) {
                        if constexpr (is_same_v<T, string_view>)
                            cout << format("  {}: \"{}\"\n", attr, v);
                        else if constexpr (is_same_v<T, uint64_t>) {
                            if (attr == btrfs_send_attr::MODE)
                                cout << format("  {}: {:o}\n", attr, v);
                            else
                                cout << format("  {}: {}\n", attr, v);
                        } else if constexpr (is_same_v<T, span<const uint8_t>>)
                            cout << format("  {}: ({} bytes)\n", attr, v.size());
                        else
                            cout << format("  {}: {}\n", attr, v);
                    });
                }

                break;
        }

        sp = sp.subspan(cmd.len + sizeof(btrfs_cmd_header));
    }

    do_wait(ring);
}

static unsigned int count_path_to_slashes(span<const uint8_t> atts) {
    unsigned int ret = 0;

    parse_atts(atts, [&]<typename T>(enum btrfs_send_attr attr, const T& v) {
        if constexpr (is_same_v<T, string_view>) {
            if (attr == btrfs_send_attr::PATH_TO) {
                for (auto c : v) {
                    if (c == '/')
                        ret++;
                }
            }
        }
    });

    return ret;
}

static void do_renames(io_uring& ring, int dirfd, span<const uint8_t> sp) {
    auto orig_sp = sp;

    struct rename_entry {
        const uint8_t* ptr;
        unsigned int num_slashes;
    };

    vector<rename_entry> entries;

    while (!sp.empty()) {
        const auto& cmd = *(btrfs_cmd_header*)sp.data();

        auto atts = span(sp.data() + sizeof(btrfs_cmd_header), cmd.len);

        if (cmd.cmd == btrfs_send_cmd::RENAME) {
            auto slashes = count_path_to_slashes(atts);

            entries.emplace_back(sp.data(), slashes);
        }

        sp = sp.subspan(cmd.len + sizeof(btrfs_cmd_header));
    }

    if (entries.empty())
        return;

    sort(entries.begin(), entries.end(), [](const rename_entry& a, const rename_entry& b) {
        return a.num_slashes < b.num_slashes;
    });

    unsigned int last_num_slashes = 0;

    for (const auto& e : entries) {
        const auto& cmd = *(btrfs_cmd_header*)e.ptr;

        if (e.num_slashes > last_num_slashes) {
            do_wait(ring);
            last_num_slashes = e.num_slashes;
        }

        auto atts = span(e.ptr + sizeof(btrfs_cmd_header), cmd.len);

        optional<string> path, path_to;

        parse_atts(atts, [&]<typename T>(enum btrfs_send_attr attr, const T& v) {
            if constexpr (is_same_v<T, string_view>) {
                if (attr == btrfs_send_attr::PATH)
                    path = v;
                else if (attr == btrfs_send_attr::PATH_TO)
                    path_to = v;
            }
        });

        if (!path.has_value())
            throw formatted_error("rename cmd without path");

        if (!path_to.has_value())
            throw formatted_error("rename cmd without path_to");

        auto sqe = get_sqe(ring);

        auto ctx = new sqe_ctx;

        ctx->offset = e.ptr - orig_sp.data() + sizeof(btrfs_cmd_header);
        ctx->path.swap(path.value());
        ctx->path2.swap(path_to.value());

        io_uring_prep_renameat(sqe, dirfd, ctx->path.c_str(), dirfd,
                                ctx->path2.c_str(), 0);
        io_uring_sqe_set_data(sqe, ctx);
        items_pending++;
    }

    do_wait(ring);
}

static void do_write(io_uring& ring, int dirfd, span<const uint8_t> atts,
                     uint64_t offset) {
    optional<string> path;
    optional<uint64_t> file_offset;
    optional<span<const uint8_t>> data;

    parse_atts(atts, [&]<typename T>(enum btrfs_send_attr attr, const T& v) {
        if constexpr (is_same_v<T, string_view>) {
            if (attr == btrfs_send_attr::PATH)
                path = v;
        } else if constexpr (is_same_v<T, uint64_t>) {
            if (attr == btrfs_send_attr::FILE_OFFSET)
                file_offset = v;
        } else if constexpr (is_same_v<T, span<const uint8_t>>) {
            if (attr == btrfs_send_attr::DATA)
                data = v;
        }
    });

    if (!path.has_value())
        throw formatted_error("write cmd without path");

    if (!file_offset.has_value())
        throw formatted_error("write cmd without file_offset");

    if (!data.has_value())
        throw formatted_error("write cmd without data");

    // FIXME - if we've just mkfile'd this, the fd should still be open
    // FIXME - keep fd open if multiple write commands

    auto file_index = get_file_index(ring);

    if (sqes_left < 3)
        do_wait(ring);

    auto sqe = get_sqe(ring);

    auto ctx = new sqe_ctx;

    ctx->offset = offset;
    ctx->path.swap(path.value());

    io_uring_prep_openat_direct(sqe, dirfd, ctx->path.c_str(), O_WRONLY, 0,
                                file_index);
    io_uring_sqe_set_data(sqe, ctx);
    sqe->flags |= IOSQE_IO_LINK;

    sqe = get_sqe(ring);
    ctx = new sqe_ctx;

    ctx->offset = offset;

    io_uring_prep_write(sqe, file_index, data.value().data(), data.value().size(),
                        file_offset.value());
    io_uring_sqe_set_data(sqe, ctx);
    sqe->flags |= IOSQE_IO_LINK | IOSQE_FIXED_FILE;

    sqe = get_sqe(ring);
    ctx = new sqe_ctx;

    ctx->offset = offset;

    io_uring_prep_close_direct(sqe, file_index);
    io_uring_sqe_set_data(sqe, ctx);

    items_pending += 3;
}

static void do_writes(io_uring& ring, int dirfd, span<const uint8_t> sp) {
    auto orig_sp = span(sp.data() - sizeof(btrfs_stream_header),
                        sp.size() + sizeof(btrfs_stream_header));

    while (!sp.empty()) {
        const auto& cmd = *(btrfs_cmd_header*)sp.data();

        auto atts = span(sp.data() + sizeof(btrfs_cmd_header), cmd.len);

        if (cmd.cmd == btrfs_send_cmd::WRITE)
            do_write(ring, dirfd, atts, sp.data() - orig_sp.data());

        sp = sp.subspan(cmd.len + sizeof(btrfs_cmd_header));
    }

    do_wait(ring);
}

static void parse(span<const uint8_t> sp) {
    const auto& h = *(btrfs_stream_header*)sp.data();

    if (strcmp(h.magic, BTRFS_SEND_STREAM_MAGIC))
        throw runtime_error("Not a stream file.");

    if (h.version > BTRFS_SEND_STREAM_VERSION)
        throw formatted_error("Stream was version {}, only streams up to version {} supported.",
                              h.version, BTRFS_SEND_STREAM_VERSION);

    // TESTING
    auto dir = to_string(time(nullptr));
    if (!filesystem::create_directory(dir))
        throw formatted_error("failed to create directory {}", dir);

    unique_fd dirfd;

    if (auto ret = open(dir.c_str(), O_RDONLY); ret < 0)
        throw formatted_error("open failed: {}", ret);
    else
        dirfd.reset(ret);

    sp = sp.subspan(sizeof(btrfs_stream_header));

    io_uring ring;

    if (auto ret = io_uring_queue_init(QUEUE_DEPTH, &ring, 0); ret)
        throw formatted_error("io_uring_queue_init failed: {}", ret);

    try {
        if (auto ret = io_uring_register_files(&ring, files.data(), files.size()); ret)
            throw formatted_error("io_uring_register_files failed: {}", ret);

        create_files(ring, dirfd.get(), sp);
        do_renames(ring, dirfd.get(), sp);
        do_writes(ring, dirfd.get(), sp);
    } catch (...) {
        io_uring_queue_exit(&ring);
        throw;
    }

    io_uring_queue_exit(&ring);
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

    if ((uint64_t)st.st_size < sizeof(btrfs_cmd_header))
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

static void show_usage() {
    cerr << "Usage: recvfast [-v|--verbose] <stream>" << endl;
}

int main(int argc, char** argv) {
    int longindex = 0;

    static const option longopts[] = {
        {"verbose", no_argument, nullptr, 'v'},
        {nullptr, 0, nullptr, 0}
    };

    while (true) {
        auto c = getopt_long(argc, argv, "v", longopts, &longindex);

        if (c == -1)
            break;

        switch (c) {
            case 'v':
                verbose = true;
            break;

            default:
                show_usage();
                return 1;
        }
    }

    if (optind != argc - 1) {
        show_usage();
        return 1;
    }

    const char* fn = argv[optind];

    try {
        process(fn);
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
    }

    return 0;
}
