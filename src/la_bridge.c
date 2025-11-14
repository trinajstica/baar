#if 0
   Copyright 2025 BArko

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http:

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
#endif
#define _GNU_SOURCE
#include "la_bridge.h"
#define BAAR_HEADER "BAAR v0.28, \xC2\xA9 BArko, 2025"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <limits.h>
#include <ctype.h>
#include <archive.h>
#include <archive_entry.h>


static void fmt_size(uint64_t n, char *out, size_t outlen) {
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    double v = (double)n;
    int ui = 0;
    while (v >= 1000.0 && ui < 4) {
        v /= 1000.0;
        ui++;
    }
    snprintf(out, outlen, "%.2f %s", v, units[ui]);
}

static const char* strip_leading_slashes(const char *s) {
    if (!s) return s;
    while (*s == '/') s++;
    return s;
}

static void sanitize_temp_component(const char *input, char *out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    size_t oi = 0;
    if (!input) input = "archive";
    for (size_t i = 0; input[i] && oi + 1 < out_sz; i++) {
        unsigned char c = (unsigned char)input[i];
        if (c == '/') c = '_';
        if (!isalnum(c) && c != '-' && c != '_' && c != '.') {
            c = '_';
        }
        out[oi++] = (char)c;
    }
    if (oi == 0 && out_sz > 1) {
        out[oi++] = 'a';
    }
    out[oi] = '\0';
}

static int try_temp_file_in_dir(const char *dir, const char *base, const char *tag,
                                char *out, size_t out_sz) {
    if (!dir || !dir[0] || !base || !tag || !out || out_sz == 0) return -1;
    if (access(dir, W_OK | X_OK) != 0) {
        return -1;
    }
    int pid = (int)getpid();
    for (int attempt = 0; attempt < 200; attempt++) {
        if (strcmp(dir, "/") == 0) {
            snprintf(out, out_sz, "/.%s_%s_%d_%02d", tag, base, pid, attempt);
        } else {
            snprintf(out, out_sz, "%s/.%s_%s_%d_%02d", dir, tag, base, pid, attempt);
        }
        if (access(out, F_OK) != 0) {
            return 0;
        }
    }
    return -1;
}

static int make_temp_file_path_near_archive(const char *archive_path, const char *tag,
                                            char *out, size_t out_sz) {
    if (!archive_path || !tag || !out || out_sz == 0) return -1;
    char dir[PATH_MAX];
    const char *slash = strrchr(archive_path, '/');
    if (slash) {
        size_t len = (size_t)(slash - archive_path);
        if (len == 0) {
            strcpy(dir, "/");
        } else {
            if (len >= sizeof(dir)) len = sizeof(dir) - 1;
            memcpy(dir, archive_path, len);
            dir[len] = '\0';
        }
    } else {
        strcpy(dir, ".");
    }

    const char *base = slash ? slash + 1 : archive_path;
    char safe_base[64];
    sanitize_temp_component(base, safe_base, sizeof(safe_base));

    if (try_temp_file_in_dir(dir, safe_base, tag, out, out_sz) == 0) {
        return 0;
    }
    if (try_temp_file_in_dir("/tmp", safe_base, tag, out, out_sz) == 0) {
        return 0;
    }
    return -1;
}


static int mkpath(const char *path, mode_t mode) {
    char *tmp = strdup(path);
    if (!tmp) return -1;

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
                free(tmp);
                return -1;
            }
            *p = '/';
        }
    }

    if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
        free(tmp);
        return -1;
    }

    free(tmp);
    return 0;
}


bool la_is_supported(const char *path) {
    if (!path) return false;

    struct archive *a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    int r = archive_read_open_filename(a, path, 10240);
    bool supported = (r == ARCHIVE_OK);

    archive_read_free(a);
    return supported;
}


const char *la_get_format(const char *archive_path) {
    struct archive *a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    if (archive_read_open_filename(a, archive_path, 10240) != ARCHIVE_OK) {
        archive_read_free(a);
        return NULL;
    }


    struct archive_entry *entry;
    archive_read_next_header(a, &entry);

    const char *format = archive_format_name(a);
    static char format_buf[64];
    if (format && format[0]) {
        snprintf(format_buf, sizeof(format_buf), "%s", format);
    } else {

        const char *ext = strrchr(archive_path, '.');
        if (ext) {
            if (strcmp(ext, ".zip") == 0) {
                snprintf(format_buf, sizeof(format_buf), "ZIP");
            } else if (strcmp(ext, ".tar") == 0) {
                snprintf(format_buf, sizeof(format_buf), "TAR");
            } else if (strcmp(ext, ".7z") == 0) {
                snprintf(format_buf, sizeof(format_buf), "7-Zip");
            } else if (strcmp(ext, ".rar") == 0) {
                snprintf(format_buf, sizeof(format_buf), "RAR");
            } else {
                snprintf(format_buf, sizeof(format_buf), "Unknown");
            }
        } else {
            snprintf(format_buf, sizeof(format_buf), "Unknown");
        }
    }

    archive_read_free(a);
    return format_buf;
}


int la_list(const char *archive_path, bool json_output, bool verbose) {
    struct archive *a = archive_read_new();
    struct archive_entry *entry;

    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    int r = archive_read_open_filename(a, archive_path, 10240);
    if (r != ARCHIVE_OK) {
        fprintf(stderr, "Error opening archive: %s\n", archive_error_string(a));
        archive_read_free(a);
        return 1;
    }


    const char *format = la_get_format(archive_path);

    if (json_output) {
        printf("{\"format\":\"%s\",\"entries\":[\n", format ? format : "Unknown");
    } else {
        printf("Archive: %s\nFormat: %s\n", archive_path, format ? format : "Unknown");
        if (verbose) {
            printf("%-50s %12s %12s %s\n", "Name", "Size", "Compressed", "Mode");
            printf("─────────────────────────────────────────────────────────────────────────────────────\n");
        } else {
            printf("\nContents:\n");
        }
    }

    int entry_count = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        const char *tname = strip_leading_slashes(name);
        int64_t size = archive_entry_size(entry);
        mode_t mode = archive_entry_mode(entry);

        if (json_output) {
            if (entry_count > 0) printf(",\n");
                 printf("  {\"name\":\"%s\",\"size\":%lld,\"mode\":%o}",
                     tname ? tname : "", (long long)size, mode);
        } else if (verbose) {
            char sz[64];
            fmt_size(size, sz, sizeof(sz));
            printf("%-50s %12s %12s %04o\n", tname ? tname : "", sz, "-", mode & 0777);
        } else {
            printf("  %s\n", tname ? tname : "");
        }

        entry_count++;
        archive_read_data_skip(a);
    }

    if (json_output) {
        printf("\n],\"total_entries\":%d}\n", entry_count);
    } else {
        printf("\nTotal entries: %d\n", entry_count);
    }

    r = archive_read_free(a);
    return (r == ARCHIVE_OK) ? 0 : 1;
}


int la_extract(const char *archive_path, const char *dest_dir, const char *password) {
    struct archive *a = archive_read_new();
    struct archive *ext = archive_write_disk_new();
    struct archive_entry *entry;
    int errors = 0;

    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    if (password) {
        archive_read_add_passphrase(a, password);
    }


    int flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM |
                ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS;
    archive_write_disk_set_options(ext, flags);
    archive_write_disk_set_standard_lookup(ext);

    int r = archive_read_open_filename(a, archive_path, 10240);
    if (r != ARCHIVE_OK) {
        fprintf(stderr, "Error opening archive: %s\n", archive_error_string(a));
        archive_read_free(a);
        archive_write_free(ext);
        return 1;
    }


    if (dest_dir && dest_dir[0]) {
        mkpath(dest_dir, 0755);
        if (chdir(dest_dir) != 0) {
            fprintf(stderr, "Error: cannot change to directory %s: %s\n",
                    dest_dir, strerror(errno));
            archive_read_free(a);
            archive_write_free(ext);
            return 1;
        }
    }

    int extracted = 0;
    int rcode;
    while ((rcode = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);

        r = archive_write_header(ext, entry);
        if (r != ARCHIVE_OK) {
            fprintf(stderr, "Warning: %s: %s\n", name, archive_error_string(ext));
            errors++;
        } else {

            const void *buff;
            size_t size;
            int64_t offset;

            int rd;
            while ((rd = archive_read_data_block(a, &buff, &size, &offset)) == ARCHIVE_OK) {
                r = archive_write_data_block(ext, buff, size, offset);
                if (r != ARCHIVE_OK) {
                    fprintf(stderr, "Error writing %s: %s\n", name, archive_error_string(ext));
                    errors++;
                    break;
                }
            }

            if (rd != ARCHIVE_EOF) {
                fprintf(stderr, "Error reading %s: %s\n", name, archive_error_string(a));
                errors++;
            } else {
                printf("  %s\n", strip_leading_slashes(name) ? strip_leading_slashes(name) : "");
                extracted++;
            }
        }

        archive_write_finish_entry(ext);
    }
    if (rcode != ARCHIVE_EOF && rcode != ARCHIVE_OK) {
        fprintf(stderr, "Archive iteration finished with error: %s\n", archive_error_string(a));
        errors++;
    }

    printf("\nExtracted %d files.\n", extracted);

    archive_read_free(a);
    archive_write_free(ext);
    return (errors == 0) ? 0 : 1;
}


int la_extract_single(const char *archive_path, const char *entry_name,
                      const char *dest_dir, const char *password) {
    struct archive *a = archive_read_new();
    struct archive *ext = archive_write_disk_new();
    struct archive_entry *entry;

    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    if (password) {
        archive_read_add_passphrase(a, password);
    }

    int flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM;
    archive_write_disk_set_options(ext, flags);
    archive_write_disk_set_standard_lookup(ext);

    int r = archive_read_open_filename(a, archive_path, 10240);
    if (r != ARCHIVE_OK) {
        fprintf(stderr, "Error opening archive: %s\n", archive_error_string(a));
        archive_read_free(a);
        archive_write_free(ext);
        return 1;
    }

    if (dest_dir && dest_dir[0]) {
        mkpath(dest_dir, 0755);
        if (chdir(dest_dir) != 0) {
            fprintf(stderr, "Error: cannot change to directory %s: %s\n",
                    dest_dir, strerror(errno));
            archive_read_free(a);
            archive_write_free(ext);
            return 1;
        }
    }

    bool found = false;
    int rcode;
    while ((rcode = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        const char *tname = strip_leading_slashes(name);

        if ((tname && strcmp(tname, entry_name) == 0) || strcmp(name, entry_name) == 0) {
            found = true;

            r = archive_write_header(ext, entry);
            if (r != ARCHIVE_OK) {
                fprintf(stderr, "Error: %s\n", archive_error_string(ext));
                archive_read_free(a);
                archive_write_free(ext);
                return 1;
            } else {
                const void *buff;
                size_t size;
                int64_t offset;
                int rd;
                while ((rd = archive_read_data_block(a, &buff, &size, &offset)) == ARCHIVE_OK) {
                    if (archive_write_data_block(ext, buff, size, offset) != ARCHIVE_OK) {
                        fprintf(stderr, "Error writing %s: %s\n", name, archive_error_string(ext));
                        archive_read_free(a);
                        archive_write_free(ext);
                        return 1;
                    }
                }
                if (rd != ARCHIVE_EOF) {
                    fprintf(stderr, "Error reading %s: %s\n", name, archive_error_string(a));
                    archive_read_free(a);
                    archive_write_free(ext);
                    return 1;
                }
                printf("Extracted: %s\n", strip_leading_slashes(name) ? strip_leading_slashes(name) : "");
            }

            archive_write_finish_entry(ext);
            break;
        }

        archive_read_data_skip(a);
    }

    if (!found) {
        fprintf(stderr, "Error: entry '%s' not found in archive\n", entry_name);
        archive_read_free(a);
        archive_write_free(ext);
        return 1;
    }

    archive_read_free(a);
    archive_write_free(ext);
    return 0;
}


int la_extract_to_path(const char *archive_path, const char *entry_name,
                       const char *dest_path, const char *password) {
    struct archive *a = archive_read_new();
    struct archive *ext = archive_write_disk_new();
    struct archive_entry *entry;

    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    if (password) {
        archive_read_add_passphrase(a, password);
    }

    int flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM;
    archive_write_disk_set_options(ext, flags);
    archive_write_disk_set_standard_lookup(ext);

    int r = archive_read_open_filename(a, archive_path, 10240);
    if (r != ARCHIVE_OK) {
        archive_read_free(a);
        archive_write_free(ext);
        return 1;
    }


    char *dest_dir = strdup(dest_path);
    char *last_slash = strrchr(dest_dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        mkpath(dest_dir, 0755);
    }
    free(dest_dir);

    bool found = false;
    int rcode;
    while ((rcode = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        const char *tname = strip_leading_slashes(name);

        if ((tname && strcmp(tname, entry_name) == 0) || strcmp(name, entry_name) == 0) {
            found = true;


            archive_entry_set_pathname(entry, dest_path);

            r = archive_write_header(ext, entry);
            if (r != ARCHIVE_OK) {
                archive_read_free(a);
                archive_write_free(ext);
                return 1;
            }

            const void *buff;
            size_t size;
            int64_t offset;
            int rd;
            while ((rd = archive_read_data_block(a, &buff, &size, &offset)) == ARCHIVE_OK) {
                if (archive_write_data_block(ext, buff, size, offset) != ARCHIVE_OK) {
                    archive_read_free(a);
                    archive_write_free(ext);
                    return 1;
                }
            }

            if (rd != ARCHIVE_EOF) {
                archive_read_free(a);
                archive_write_free(ext);
                return 1;
            }

            archive_write_finish_entry(ext);
            break;
        }

        archive_read_data_skip(a);
    }

    archive_read_free(a);
    archive_write_free(ext);

    return found ? 0 : 1;
}


int la_test(const char *archive_path, const char *password) {
    struct archive *a = archive_read_new();
    struct archive_entry *entry;

    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    if (password) {
        archive_read_add_passphrase(a, password);
    }

    int r = archive_read_open_filename(a, archive_path, 10240);
    if (r != ARCHIVE_OK) {
        fprintf(stderr, "Error opening archive: %s\n", archive_error_string(a));
        archive_read_free(a);
        return 1;
    }

    printf("Testing archive: %s\n", archive_path);

    int tested = 0;
    int errors = 0;

    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        int64_t expected_size = archive_entry_size(entry);
        int64_t actual_size = 0;


        const void *buff;
        size_t size;
        int64_t offset;

        while ((r = archive_read_data_block(a, &buff, &size, &offset)) == ARCHIVE_OK) {
            actual_size += size;
        }

        if (r != ARCHIVE_EOF) {
            fprintf(stderr, "  FAIL: %s - %s\n", strip_leading_slashes(name) ? strip_leading_slashes(name) : "", archive_error_string(a));
            errors++;
        } else if (expected_size >= 0 && actual_size != expected_size) {
                fprintf(stderr, "  FAIL: %s - size mismatch (expected %lld, got %lld)\n",
                    strip_leading_slashes(name) ? strip_leading_slashes(name) : "", (long long)expected_size, (long long)actual_size);
            errors++;
        } else {
            printf("  OK: %s\n", strip_leading_slashes(name) ? strip_leading_slashes(name) : "");
        }

        tested++;
    }

    printf("\nTested %d entries, %d errors.\n", tested, errors);

    archive_read_free(a);
    return (errors == 0) ? 0 : 1;
}


int la_add_files(const char *archive_path, const char **file_paths,
                 int file_count, int compression_level, const char *password, int verbose) {
    if (file_count == 0) {
        fprintf(stderr, "Error: no files to add\n");
        return 1;
    }




    bool archive_exists = false;
    struct stat st;
    if (stat(archive_path, &st) == 0 && st.st_size > 0) {

        if (la_is_supported(archive_path)) {
            archive_exists = true;
        }
    }

    
    char temp_path[PATH_MAX];
    if (make_temp_file_path_near_archive(archive_path, "tmp", temp_path, sizeof(temp_path)) != 0) {
        fprintf(stderr, "Error: unable to create temporary path for archive %s\n", archive_path);
        return 1;
    }

    struct archive *out = archive_write_new();


    const char *ext = strrchr(archive_path, '.');


    int level = compression_level;
    if (level < 0 || level > 9) level = 6;
    if (level >= 1 && level <= 2) level = 6;


    if (ext && strcmp(ext, ".zip") == 0 && password && password[0]) {

        char **argv = malloc(sizeof(char*) * (file_count + 7));
        int ai = 0;
        argv[ai++] = "zip";
        argv[ai++] = "-P";
        argv[ai++] = (char*)password;
        if (!verbose) argv[ai++] = "-q";
        argv[ai++] = "-j";
        argv[ai++] = (char*)archive_path;
        for (int i = 0; i < file_count; i++) argv[ai++] = (char*)file_paths[i];
        argv[ai] = NULL;

        pid_t pid = fork();
        if (pid == 0) {

            execvp("zip", argv);
            _exit(127);
        } else if (pid > 0) {
            int status = 0;
            waitpid(pid, &status, 0);
            free(argv);
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;
            return 1;
        } else {
            free(argv);
            return 1;
        }
    }

    if (ext && strcmp(ext, ".zip") == 0) {
        archive_write_set_format_zip(out);
        archive_write_zip_set_compression_deflate(out);

        char opt[512];
        if (password && password[0]) {
            snprintf(opt, sizeof(opt), "compression-level=%d,encryption=traditional,passphrase=%s", level, password);
        } else {
            snprintf(opt, sizeof(opt), "compression-level=%d", level);
        }
        archive_write_set_options(out, opt);
    } else if (ext && strcmp(ext, ".7z") == 0) {
        archive_write_set_format_7zip(out);
        char opt[128];
        snprintf(opt, sizeof(opt), "compression=lzma2,compression-level=%d", level);
        archive_write_set_options(out, opt);
    } else if (ext && strstr(archive_path, ".tar.gz")) {
        archive_write_set_format_pax_restricted(out);
        archive_write_add_filter_gzip(out);
        char opt[64];
        snprintf(opt, sizeof(opt), "%d", level);
        archive_write_set_filter_option(out, "gzip", "compression-level", opt);
    } else if (ext && strstr(archive_path, ".tar.bz2")) {
        archive_write_set_format_pax_restricted(out);
        archive_write_add_filter_bzip2(out);
        char opt[64];
        int bz2_level = (level == 0) ? 1 : ((level > 6) ? 9 : level);
        snprintf(opt, sizeof(opt), "%d", bz2_level);
        archive_write_set_filter_option(out, "bzip2", "compression-level", opt);
    } else if (ext && strstr(archive_path, ".tar.xz")) {
        archive_write_set_format_pax_restricted(out);
        archive_write_add_filter_xz(out);
        char opt[64];
        snprintf(opt, sizeof(opt), "%d", level);
        archive_write_set_filter_option(out, "xz", "compression-level", opt);
    } else if (ext && (strcmp(ext, ".tar") == 0 || strcmp(ext, ".tar.gz") == 0)) {
        archive_write_set_format_pax_restricted(out);
        if (strstr(archive_path, ".gz")) {
            archive_write_add_filter_gzip(out);
            char opt[64];
            snprintf(opt, sizeof(opt), "%d", level);
            archive_write_set_filter_option(out, "gzip", "compression-level", opt);
        }
    } else {

        archive_write_set_format_zip(out);
        archive_write_zip_set_compression_deflate(out);
        char opt[64];
        snprintf(opt, sizeof(opt), "compression-level=%d", level);
        archive_write_set_options(out, opt);
    }



    int r = archive_write_open_filename(out, temp_path);
    if (r != ARCHIVE_OK) {
        fprintf(stderr, "Error creating archive: %s\n", archive_error_string(out));
        archive_write_free(out);
        unlink(temp_path);
        return 1;
    }


    if (archive_exists) {
        fprintf(stderr, "Archive exists, recreating with new files...\n");

        struct archive *in = archive_read_new();
        archive_read_support_filter_all(in);
        archive_read_support_format_all(in);


        if (password) {
            archive_read_add_passphrase(in, password);
        }

        if (archive_read_open_filename(in, archive_path, 10240) == ARCHIVE_OK) {
            struct archive_entry *entry;

            while (archive_read_next_header(in, &entry) == ARCHIVE_OK) {

                archive_write_header(out, entry);

                const void *buff;
                size_t size;
                int64_t offset;
                int rdcode;


                int copy_failed = 0;
                while ((rdcode = archive_read_data_block(in, &buff, &size, &offset)) == ARCHIVE_OK) {
                    if (archive_write_data(out, buff, size) < 0) {
                        fprintf(stderr, "Warning: error copying data: %s\n", archive_error_string(out));
                        copy_failed = 1;
                        break;
                    }
                }

                if (rdcode != ARCHIVE_EOF || copy_failed) {
                    const char *errstr = archive_error_string(in);
                    if (!errstr) errstr = "Unknown error while reading archive";
                    fprintf(stderr, "Error copying existing archive entry: %s\n", errstr);
                    archive_read_free(in);
                    archive_write_close(out);
                    archive_write_free(out);

                    unlink(temp_path);
                    return 1;
                }

                archive_write_finish_entry(out);
            }

            archive_read_free(in);
        }
    }


    if (!verbose && file_count > 0) {
        fprintf(stderr, "%s\n", BAAR_HEADER);
        fprintf(stderr, "Adding %d files: ", file_count);
        fflush(stderr);
    }

    for (int i = 0; i < file_count; i++) {
        const char *file_path = file_paths[i];

        struct stat st;
        if (stat(file_path, &st) != 0) {
            fprintf(stderr, "Warning: cannot stat %s: %s\n", file_path, strerror(errno));
            continue;
        }

        struct archive_entry *entry = archive_entry_new();
        archive_entry_copy_stat(entry, &st);

        const char *entry_name = strrchr(file_path, '/');
        entry_name = entry_name ? entry_name + 1 : file_path;
        archive_entry_set_pathname(entry, entry_name);

        r = archive_write_header(out, entry);
        if (r != ARCHIVE_OK) {
            fprintf(stderr, "Error writing header for %s: %s\n",
                    file_path, archive_error_string(out));
            archive_entry_free(entry);
            continue;
        }


        if (S_ISREG(st.st_mode)) {
            int fd = open(file_path, O_RDONLY);
            if (fd < 0) {
                fprintf(stderr, "Error opening %s: %s\n", file_path, strerror(errno));
                archive_entry_free(entry);
                continue;
            }

            char buff[8192];
            ssize_t len;
            while ((len = read(fd, buff, sizeof(buff))) > 0) {
                archive_write_data(out, buff, len);
            }

            close(fd);
            if (verbose) fprintf(stderr, "  Added: %s\n", file_path);
            else { fprintf(stderr, "\rAdding %d files: %s", file_count, file_path); fflush(stderr); }
        }

        archive_entry_free(entry);
        archive_write_finish_entry(out);
    }

    archive_write_close(out);
    archive_write_free(out);


    if (rename(temp_path, archive_path) != 0) {
        if (errno == EXDEV) {

            FILE *src = fopen(temp_path, "rb");
            FILE *dst = fopen(archive_path, "wb");
            if (src && dst) {
                char buf[65536];
                size_t n;
                while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
                    if (fwrite(buf, 1, n, dst) != n) break;
                }
                fclose(src); fclose(dst);
                unlink(temp_path);
                fprintf(stderr, "\nArchive updated (copy): %s\n", archive_path);
                return 0;
            } else {
                fprintf(stderr, "Error: cannot copy archive: %s\n", strerror(errno));
                if (src) fclose(src);
                if (dst) fclose(dst);
                unlink(temp_path);
                return 1;
            }
        } else {
            fprintf(stderr, "Error: cannot replace archive: %s\n", strerror(errno));
            unlink(temp_path);
            return 1;
        }
    }

    if (!verbose && file_count > 0) fprintf(stderr, "\n");
    fprintf(stderr, "\nArchive updated: %s\n", archive_path);
    return 0;
}
