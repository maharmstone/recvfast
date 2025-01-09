#include <stdint.h>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <format>
#include "unique_fd.h"

using namespace std;

#define BTRFS_SEND_STREAM_MAGIC "btrfs-stream"

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

class formatted_error : public std::exception {
public:
    template<typename... Args>
    formatted_error(format_string<Args...> s, Args&&... args) : msg(format(s, std::forward<Args>(args)...)) {
    }

    const char* what() const noexcept {
        return msg.c_str();
    }

private:
    std::string msg;
};

static void process(const filesystem::path& fn) {
    int ret;

    ret = open(fn.string().c_str(), O_RDONLY);
    if (ret < 0)
        throw formatted_error("open failed: {}", ret);

    unique_fd f{ret};

    // FIXME - mmap file
    // FIXME - check header
    // FIXME - loop through cmds
}

int main() {
    try {
        process("/home/hellas/Desktop/work/stream/stream");
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
    }

    return 0;
}
