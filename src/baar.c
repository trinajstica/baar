#define BAAR_HEADER "BAAR v0.30, \xC2\xA9 BArko, 2025"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <zlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <libgen.h>
#include <pthread.h>
#include <time.h>
#include <utime.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>
#include <signal.h>
#include <gtk/gtk.h>
#include <archive.h>
#include <archive_entry.h>
#include "la_bridge.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/err.h>

static const char *compact_basename(const char *path, char *buf, size_t buflen){
    if(!path){ if(buflen>0) buf[0]='\0'; return buf; }
    size_t n = strlen(path);
    while(n>0 && path[n-1] == '/') n--;
    size_t start = 0;
    for(size_t i=0;i<n;i++) if(path[i] == '/') start = i+1;
    size_t len = n > start ? n - start : 0;
    if(len >= buflen) len = buflen - 1;
    if(len) memcpy(buf, path + start, len);
    buf[len] = '\0';
    return buf;
}

static void fmt_size(uint64_t n, char *out, size_t outlen){
    const char *units[] = {"B","KB","MB","GB","TB"};
    double v = (double)n;
    int ui = 0;

    while(v >= 1000.0 && ui < 4){ v /= 1000.0; ui++; }
    snprintf(out, outlen, "%.2f %s", v, units[ui]);
}

#define MAGIC "BAARv1\0"
#define HEADER_SIZE 32


#define RESPONSE_OPEN_CREATE 100

typedef struct {
    uint32_t id;
    char *name;
    uint8_t flags;
    uint8_t comp_level;
    uint64_t data_offset;
    uint64_t comp_size;
    uint64_t uncomp_size;
    uint32_t crc32;

    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t mtime;

    struct {
        char *key;
        char *value;
    } *meta;
    uint32_t meta_n;
} entry_t;

typedef struct {
    entry_t *entries;
    uint32_t n;
    uint32_t next_id;
} index_t;


static index_t load_index(FILE *f);
static index_t load_libarchive_index(const char *path);
static void free_index(index_t *idx);

static int rebuild_archive(const char *archive, const uint32_t *exclude_ids, uint32_t exclude_count, int quiet);

static void xor_buf(unsigned char *buf, size_t len, const char *pwd);


static int global_quiet = 0;
static int global_verbose = 0;

static void safe_chown_path(const char *path, uint32_t uid, uint32_t gid){
    if(!path) return;
    if(geteuid() != 0) return;
    if(chown(path, (uid_t)uid, (gid_t)gid) != 0){
        if(global_verbose) fprintf(stderr, "Warning: chown %s -> %u:%u failed: %s\n", path, (unsigned)uid, (unsigned)gid, strerror(errno));
    }
}

static void usage(){
    fprintf(stderr,
        BAAR_HEADER
        "\n\n"
        "Usage:\n"
        "  baar a <archive> [files...] [-c 0|1|2|3|4] [-p password] [-v|--verbose]\n"
        "    Add files or directories to <archive> (.baar is appended if missing).\n"
        "    Files may be specified as src:dst to control the archive path or src:level to set per-file compression.\n"
        "    Use --incremental (-i) and/or --mirror (-m) to mirror provided paths: skip unchanged files and remove entries missing on disk.\n"
        "      --incremental, -i     Incremental mode: only add new/changed files.\n"
        "      --mirror, -m         Mirror mode: also mark as deleted files missing from source.\n"
        "      --ignore PATTERN     Skip sources or archive paths matching the glob pattern (can be repeated).\n"
        "\n"
        "  baar x <archive> [dest_dir] [-p password]\n"
        "    Extract all files from <archive> into dest_dir (current dir if omitted).\n"
        "\n"
        "  baar l <archive> [-j|--json]\n"
        "    List archive contents (human or JSON).\n"
        "\n"
        "  baar t <archive> [-p password] [-j|--json]\n"
        "    Test integrity (decompress and CRC-check) of all entries.\n"
        "\n"
        "  baar f <archive>\n"
        "    Repair/rebuild archive (removes deleted/removed entries).\n"
        "\n"
        "  baar search <archive> <pattern> [-j|--json]\n"
        "    Search entries by name using shell wildcards (* and ?).\n"
        "\n"
        "  baar info <archive> <id> [-j|--json]\n"
        "    Show metadata for entry id.\n"
        "\n"
        "  baar cat <archive> <id> [-p password]\n"
        "    Print entry contents to stdout.\n"
        "\n"
        "  baar r <archive> <id>\n"
        "    Remove (mark deleted) entry by id.\n"
        "\n"
        "  baar mkdir <archive> path/to/dir\n"
        "    Create an empty directory entry inside the archive.\n"
        "\n"
        "  baar rename <archive> <id> <new_name>\n"
        "    Rename an entry in the archive.\n"
        "\n"
        "  baar xx <archive> <entry_name> [-p password]\n"
        "    Extract a single file by its archive path (writes to local cwd).\n"
        "\n"
    "  baar compress <archive> -c 0|1|2|3|4 [-p password]\n"
        "    Recompress entries safely using the requested level (0=store,1=fast,2=balanced,3=best,4=ultra).\n"
        "\n"
        ""
    );
}


typedef struct {
    char *src_path;
    char *archive_path;
} filepair_t;

typedef struct {
    char *src_root;
    char *archive_override;
    int clevel;
} add_job_t;

static int add_files_streaming(const char *archive, add_job_t *jobs, int job_count,
                               const char *pwd, int incremental_mode, int mirror_mode,
                               char **ignore_patterns, size_t ignore_count);
static GtkWidget *g_main_window = NULL;
static GtkWidget *g_list_container = NULL;
static GtkWidget *g_welcome_label = NULL;
static GtkWidget *g_plus_btn = NULL;
static GtkWidget *g_add_btn = NULL;
static GtkWidget *g_newfolder_btn = NULL;
static GtkWidget *g_remove_btn = NULL;
static GtkWidget *g_extract_btn = NULL;
static GtkWidget *g_compact_btn = NULL;
static GtkWidget *g_back_btn = NULL;
static GtkWidget *g_close_btn = NULL;

static GtkWidget *g_info_panel = NULL;
static GtkWidget *g_info_name_lbl = NULL;
static GtkWidget *g_info_size_lbl = NULL;
static GtkWidget *g_info_entries_lbl = NULL;


static char *g_current_archive = NULL;
static index_t g_current_index = {0};
static char *g_current_prefix = NULL;
static int g_current_is_libarchive = 0;

static char *g_initial_gui_archive = NULL;

static char *g_archive_password = NULL;

static int g_archive_was_encrypted = 0;

static int g_internal_drag_active = 0;

static GtkWidget *g_progress_dialog = NULL;
static GtkWidget *g_progress_bar = NULL;
static GtkWidget *g_progress_label = NULL;

static GSList *g_temp_dirs_for_cleanup = NULL;
static int g_cleanup_registered = 0;

static void cleanup_registered_temp_dirs(void);
static void register_temp_dir_for_cleanup(const char *path);

static volatile sig_atomic_t g_abort_requested = 0;
static int g_sig_handlers_installed = 0;
static struct sigaction g_prev_sigint;
static struct sigaction g_prev_sigterm;


static void on_row_activated(GtkListBox *box, GtkListBoxRow *row, gpointer user_data);

static void on_chooser_response(GtkDialog *dialog, gint response, gpointer user_data);

static void on_drop_create_response(GtkDialog *dialog, gint response, gpointer user_data);

typedef struct {
    int *response_out;
    GMainLoop *loop;
} drop_encrypt_data_t;
static void on_drop_encrypt_response(GtkDialog *dialog, gint response, gpointer user_data);

static GdkContentProvider* on_drag_prepare(GtkDragSource *source, double x, double y, gpointer user_data);
static void on_drag_begin(GtkDragSource *source, GdkDrag *drag, gpointer user_data);
static void on_drag_end(GtkDragSource *source, GdkDrag *drag, gboolean delete_data, gpointer user_data);
static gboolean g_clear_internal_drag_flag(gpointer user_data);
static gboolean on_internal_drop_accept(GtkDropTarget *target, GdkDrop *drop, gpointer user_data);
static gboolean on_internal_drop(GtkDropTarget *target, const GValue *value, double x, double y, gpointer user_data);

static char **collect_files_recursive(const char *path, int *out_count);
static char *normalize_path_basic(const char *path);
static int make_temp_dir_near_archive(const char *archive_path, const char *tag,
                                      char *out, size_t out_sz);
static int prepare_temp_dir_for_archive(const char *archive_path, const char *tag,
                                         char *out, size_t out_sz, int track_cleanup);
static void install_cli_signal_handlers(void);
static void restore_cli_signal_handlers(void);

static void on_file_overwrite_response(GtkDialog *dialog, gint response, gpointer user_data);


typedef struct {
    uint32_t id;
    char *name;
    uint8_t flags;
    uint8_t comp_level;
    uint64_t comp_size;
    uint64_t uncomp_size;
    uint32_t crc32;
} row_data_t;

typedef struct {
    entry_t *entry;
    char *path;
} folder_view_t;

static int folder_view_exists(folder_view_t *views, int count, const char *path){
    if(!views || !path) return 0;
    for(int i = 0; i < count; i++){
        if(views[i].path && strcmp(views[i].path, path) == 0){
            return 1;
        }
    }
    return 0;
}

static void folder_view_add(folder_view_t **views, int *count, entry_t *entry, const char *path){
    if(!views || !count || !path) return;
    char *dup = strdup(path);
    if(!dup) return;

    folder_view_t *tmp = realloc(*views, sizeof(folder_view_t) * (*count + 1));
    if(!tmp){
        free(dup);
        return;
    }

    *views = tmp;
    (*views)[*count].entry = entry;
    (*views)[*count].path = dup;
    (*count)++;
}


typedef struct {
    char *src_name;
    char *target_name;
    uint32_t src_id;
    char *target_folder;
} file_overwrite_data_t;

static void on_row_selected(GtkListBox *box, GtkListBoxRow *row, gpointer user_data);
static void free_row_data(gpointer data);

static void free_row_data(gpointer data){
    if(!data) return;
    row_data_t *rd = (row_data_t*)data;
    if(rd->name) free(rd->name);
    free(rd);
}

static void on_row_selected(GtkListBox *box, GtkListBoxRow *row, gpointer user_data){
    (void)box; (void)user_data;
    if(!row) return;
    row_data_t *rd = g_object_get_data(G_OBJECT(row), "baar-row-data");
    if(!rd) return;

}


static void populate_list_from_index(void){
    if(!g_list_container) {
        return;
    }


    GtkWidget *child;
    while((child = gtk_widget_get_first_child(g_list_container)) != NULL){
        gtk_list_box_remove(GTK_LIST_BOX(g_list_container), child);
    }
    if(!g_current_index.n) {
        return;
    }
    size_t plen = g_current_prefix ? strlen(g_current_prefix) : 0;

    int added_count = 0;


    if(plen > 0){
    GtkWidget *h = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_set_homogeneous(GTK_BOX(h), FALSE);
    GtkWidget *lbl_name = gtk_label_new("..");
    gtk_label_set_xalign(GTK_LABEL(lbl_name), 0.0);
    gtk_widget_set_hexpand(lbl_name, TRUE);
    gtk_widget_add_css_class(lbl_name, "baar-name-small");

    GtkWidget *lbl_size = gtk_label_new("↑ Parent");
    gtk_label_set_xalign(GTK_LABEL(lbl_size), 1.0);
    gtk_widget_set_halign(lbl_size, GTK_ALIGN_END);


    GtkWidget *lbl_comp = gtk_label_new("-");
    gtk_label_set_xalign(GTK_LABEL(lbl_comp), 1.0);
    gtk_widget_set_margin_start(lbl_comp, 6);
    gtk_widget_set_margin_end(lbl_comp, 6);
    gtk_widget_set_halign(lbl_comp, GTK_ALIGN_END);
    gtk_widget_set_size_request(lbl_comp, 120, -1);

    GtkWidget *lbl_csize = gtk_label_new("-");
    gtk_label_set_xalign(GTK_LABEL(lbl_csize), 1.0);
    gtk_widget_set_margin_start(lbl_csize, 4);
    gtk_widget_set_halign(lbl_csize, GTK_ALIGN_END);
    gtk_widget_set_size_request(lbl_csize, 120, -1);

    gtk_widget_set_size_request(lbl_size, 120, -1);

    gtk_box_append(GTK_BOX(h), lbl_name);
    gtk_box_append(GTK_BOX(h), lbl_comp);
    gtk_box_append(GTK_BOX(h), lbl_size);
    gtk_box_append(GTK_BOX(h), lbl_csize);

        GtkWidget *row = gtk_list_box_row_new();
        gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), h);
        gtk_widget_set_tooltip_text(row, "Navigate to parent folder");


        row_data_t *rd = malloc(sizeof(row_data_t));
        memset(rd, 0, sizeof(row_data_t));
        rd->id = 0;
        rd->name = strdup("..");
        g_object_set_data_full(G_OBJECT(row), "baar-row-data", rd, free_row_data);





        if(!g_current_is_libarchive){

            GtkDropTarget *drop_target = gtk_drop_target_new(G_TYPE_BYTES, GDK_ACTION_MOVE | GDK_ACTION_COPY);
            gtk_drop_target_set_preload(drop_target, TRUE);


            char *parent_path = NULL;
            if(plen > 0){
                char *tmp = strdup(g_current_prefix);
                if(tmp[plen-1] == '/') tmp[plen-1] = '\0';
                char *last_slash = strrchr(tmp, '/');
                if(last_slash){
                    parent_path = strndup(tmp, (last_slash - tmp) + 1);
                } else {
                    parent_path = strdup("");
                }
                free(tmp);
            }

            char *user_data_path = parent_path ? parent_path : strdup("");
            g_signal_connect(drop_target, "accept", G_CALLBACK(on_internal_drop_accept), user_data_path);
            g_signal_connect(drop_target, "drop", G_CALLBACK(on_internal_drop), user_data_path);
            gtk_widget_add_controller(row, GTK_EVENT_CONTROLLER(drop_target));
        }

        gtk_list_box_append(GTK_LIST_BOX(g_list_container), row);
        added_count++;
    }


    folder_view_t *folders_to_show = NULL;
    int folder_count = 0;
    entry_t **files_to_show = NULL;
    int file_count = 0;

    for(uint32_t i=0;i<g_current_index.n;i++){
        entry_t *e = &g_current_index.entries[i];
        if(e->flags & 4) continue;


        if(g_current_is_libarchive){

            if(plen > 0){
                if(strncmp(e->name, g_current_prefix, plen) != 0) continue;
            }

            const char *display_part = plen > 0 ? e->name + plen : e->name;
            size_t display_len = strlen(display_part);


            if(display_len == 0) continue;


            if(display_len > 0 && display_part[display_len - 1] == '/'){
                const char *slash_pos = strchr(display_part, '/');

                if(slash_pos == display_part + display_len - 1){

                    if(!folder_view_exists(folders_to_show, folder_count, e->name)){
                        folder_view_add(&folders_to_show, &folder_count, e, e->name);
                    }
                    continue;
                }
            }


            const char *next_slash = strchr(display_part, '/');

            if(next_slash){

                size_t folder_len = next_slash - display_part;
                char folder_path[4096];
                if(plen > 0){
                    snprintf(folder_path, sizeof(folder_path), "%s%.*s/", g_current_prefix, (int)folder_len, display_part);
                } else {
                    snprintf(folder_path, sizeof(folder_path), "%.*s/", (int)folder_len, display_part);
                }


                if(!folder_view_exists(folders_to_show, folder_count, folder_path)){

                    printf("DEBUG: Adding virtual folder for path '%s' (from entry '%s')\n", folder_path, e->name);
                    folder_view_add(&folders_to_show, &folder_count, e, folder_path);
                }
            } else {

                files_to_show = realloc(files_to_show, sizeof(entry_t*) * (file_count + 1));
                files_to_show[file_count++] = e;
            }
            continue;
        }



        if(plen>0){
            if(strncmp(e->name, g_current_prefix, plen)!=0) continue;
            const char *rest = e->name + plen;
            size_t restlen = strlen(rest);
            if(restlen == 0) continue;

            if(rest[restlen-1] == '/'){
                if(strchr(rest, '/') != rest + restlen - 1) continue;
                if(!folder_view_exists(folders_to_show, folder_count, e->name)){
                    folder_view_add(&folders_to_show, &folder_count, e, e->name);
                }
                continue;
            }

            const char *next_slash = strchr(rest, '/');
            if(next_slash){
                size_t folder_len = next_slash - rest;
                char folder_path[4096];
                if(plen > 0){
                    snprintf(folder_path, sizeof(folder_path), "%s%.*s/", g_current_prefix, (int)folder_len, rest);
                } else {
                    snprintf(folder_path, sizeof(folder_path), "%.*s/", (int)folder_len, rest);
                }
                if(!folder_view_exists(folders_to_show, folder_count, folder_path)){
                    folder_view_add(&folders_to_show, &folder_count, e, folder_path);
                }
                continue;
            }

            files_to_show = realloc(files_to_show, sizeof(entry_t*) * (file_count + 1));
            files_to_show[file_count++] = e;
            continue;
        }

        size_t namelen = strlen(e->name);
        if(namelen == 0) continue;

        if(e->name[namelen-1] == '/'){
            if(strchr(e->name, '/') != e->name + namelen - 1) continue;
            if(!folder_view_exists(folders_to_show, folder_count, e->name)){
                folder_view_add(&folders_to_show, &folder_count, e, e->name);
            }
            continue;
        }

        const char *next_slash = strchr(e->name, '/');
        if(next_slash){
            size_t folder_len = next_slash - e->name;
            char folder_path[4096];
            snprintf(folder_path, sizeof(folder_path), "%.*s/", (int)folder_len, e->name);
            if(!folder_view_exists(folders_to_show, folder_count, folder_path)){
                folder_view_add(&folders_to_show, &folder_count, e, folder_path);
            }
            continue;
        }

        files_to_show = realloc(files_to_show, sizeof(entry_t*) * (file_count + 1));
        files_to_show[file_count++] = e;
    }


    for(int pass = 0; pass < 2; pass++){
        int count = (pass == 0) ? folder_count : file_count;

        for(int idx = 0; idx < count; idx++){
            entry_t *e = (pass == 0) ? folders_to_show[idx].entry : files_to_show[idx];
            if(!e || !e->name) continue;

            size_t ename_len = strlen(e->name);
            const char *effective_path = (pass == 0) ? (folders_to_show[idx].path ? folders_to_show[idx].path : e->name) : e->name;

            const char *display_name = effective_path;
            if(pass == 0 && plen > 0 && strncmp(effective_path, g_current_prefix, plen) == 0){
                display_name = effective_path + plen;
                if(!display_name[0]) display_name = effective_path;
            }
            if(pass == 1){
                display_name = e->name + plen;
                if(!display_name || !display_name[0]) display_name = e->name;
            }


            char usz[64], csz[64];
            fmt_size(e->uncomp_size, usz, sizeof(usz));

            if(g_current_is_libarchive && e->comp_size == 0){
                snprintf(csz, sizeof(csz), " ");
            } else {
                fmt_size(e->comp_size, csz, sizeof(csz));
            }
            GtkWidget *h = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
            gtk_box_set_homogeneous(GTK_BOX(h), FALSE);


            if(!g_current_is_libarchive && (e->flags & 2)){
                GtkWidget *lock_icon = gtk_image_new_from_icon_name("dialog-password");
                gtk_image_set_pixel_size(GTK_IMAGE(lock_icon), 16);
                gtk_widget_set_tooltip_text(lock_icon, "Encrypted");
                gtk_box_append(GTK_BOX(h), lock_icon);
            }

            GtkWidget *lbl_name = gtk_label_new(display_name);
            gtk_label_set_xalign(GTK_LABEL(lbl_name), 0.0);
            gtk_label_set_ellipsize(GTK_LABEL(lbl_name), PANGO_ELLIPSIZE_END);
            gtk_widget_set_hexpand(lbl_name, TRUE);
            gtk_widget_add_css_class(lbl_name, "baar-name-small");

            GtkWidget *lbl_size = NULL;

            int is_folder = (pass == 0) || (ename_len > 0 && e->name[ename_len-1] == '/');
            if(is_folder){

            uint32_t child_count = 0;

            char folder_path_for_count[4096];
            if(pass == 0){
                snprintf(folder_path_for_count, sizeof(folder_path_for_count), "%s", effective_path);
            } else {
                snprintf(folder_path_for_count, sizeof(folder_path_for_count), "%s", e->name);
            }
            size_t prefix_len = strlen(folder_path_for_count);
            for(uint32_t j=0;j<g_current_index.n;j++){
                entry_t *ce = &g_current_index.entries[j];
                if(ce->flags & 4) continue;
                if(strncmp(ce->name, folder_path_for_count, prefix_len) != 0) continue;
                const char *rest2 = ce->name + prefix_len;
                size_t rlen2 = strlen(rest2);
                if(rlen2 == 0) continue;
                if(rlen2 > 0 && rest2[rlen2-1] == '/'){
                    if(strchr(rest2, '/') != rest2 + rlen2 - 1) continue;
                } else {
                    if(strchr(rest2, '/')) continue;
                }
                child_count++;
            }
            char sbuf[64]; snprintf(sbuf, sizeof(sbuf), "%u items", child_count);
            lbl_size = gtk_label_new(sbuf);
        } else {
            lbl_size = gtk_label_new(usz);
        }
        gtk_label_set_xalign(GTK_LABEL(lbl_size), 1.0);

            const char *comp_name = "unknown";
            if(g_current_is_libarchive){

                switch(e->comp_level){
                    case 0: comp_name = "store"; break;
                    default: comp_name = "compressed"; break;
                }
            } else {

                switch(e->comp_level){
                    case 0: comp_name = "store"; break;
                    case 1: comp_name = "fast"; break;
                    case 2: comp_name = "balanced"; break;
                    case 3: comp_name = "best"; break;
                    case 4: comp_name = "ultra"; break;
                    default: comp_name = "unknown"; break;
                }
            }
            GtkWidget *lbl_comp = gtk_label_new(comp_name);
            gtk_label_set_xalign(GTK_LABEL(lbl_comp), 1.0);
            gtk_widget_set_margin_start(lbl_comp, 6);
            gtk_widget_set_margin_end(lbl_comp, 6);
            gtk_widget_set_halign(lbl_comp, GTK_ALIGN_END);

            gtk_widget_set_size_request(lbl_comp, 120, -1);
            gtk_widget_set_size_request(lbl_size, 120, -1);
            gtk_widget_set_halign(lbl_size, GTK_ALIGN_END);


            GtkWidget *lbl_csize = gtk_label_new(csz);
            gtk_label_set_xalign(GTK_LABEL(lbl_csize), 1.0);
            gtk_widget_set_size_request(lbl_csize, 120, -1);
            gtk_widget_set_halign(lbl_csize, GTK_ALIGN_END);

            gtk_box_append(GTK_BOX(h), lbl_name);
            gtk_box_append(GTK_BOX(h), lbl_comp);
            gtk_box_append(GTK_BOX(h), lbl_size);
            gtk_box_append(GTK_BOX(h), lbl_csize);
            char tooltip[512]; snprintf(tooltip, sizeof(tooltip), "id: %u\nflags: 0x%02x\ncomp_level: %u\nuncomp: %s\ncomp: %s", e->id, e->flags, (unsigned)e->comp_level, usz, csz);
        GtkWidget *row = gtk_list_box_row_new();
        gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), h);
        gtk_widget_set_tooltip_text(row, tooltip);
        row_data_t *rd = malloc(sizeof(row_data_t));
        rd->id = e->id;

        if(pass == 0){
            rd->name = strdup(effective_path);
        } else {
            rd->name = strdup(e->name);
        }

        rd->flags = e->flags; rd->comp_level = e->comp_level; rd->comp_size = e->comp_size; rd->uncomp_size = e->uncomp_size; rd->crc32 = e->crc32;
        g_object_set_data_full(G_OBJECT(row), "baar-row-data", rd, free_row_data);


        GtkDragSource *drag_source = gtk_drag_source_new();

        if(g_current_is_libarchive){
            gtk_drag_source_set_actions(drag_source, GDK_ACTION_COPY);
        } else {
            gtk_drag_source_set_actions(drag_source, GDK_ACTION_COPY | GDK_ACTION_MOVE);
        }
        g_signal_connect(drag_source, "prepare", G_CALLBACK(on_drag_prepare), row);
        g_signal_connect(drag_source, "drag-begin", G_CALLBACK(on_drag_begin), row);
        g_signal_connect(drag_source, "drag-end", G_CALLBACK(on_drag_end), row);
        gtk_widget_add_controller(row, GTK_EVENT_CONTROLLER(drag_source));


        if(!g_current_is_libarchive){

            const char *drop_path = (pass == 0) ? effective_path : e->name;
            size_t drop_len = drop_path ? strlen(drop_path) : 0;
            if(drop_path && drop_len > 0 && drop_path[drop_len-1] == '/'){

                GtkDropTarget *drop_target = gtk_drop_target_new(G_TYPE_BYTES, GDK_ACTION_MOVE | GDK_ACTION_COPY);
                gtk_drop_target_set_preload(drop_target, TRUE);
                char *folder_path = strdup(drop_path);
                g_signal_connect(drop_target, "accept", G_CALLBACK(on_internal_drop_accept), folder_path);
                g_signal_connect(drop_target, "drop", G_CALLBACK(on_internal_drop), folder_path);
                gtk_widget_add_controller(row, GTK_EVENT_CONTROLLER(drop_target));
            }
        }


        gtk_list_box_append(GTK_LIST_BOX(g_list_container), row);
        added_count++;
        }
    }


    if(folders_to_show){
        for(int i = 0; i < folder_count; i++){
            if(folders_to_show[i].path) free(folders_to_show[i].path);
        }
        free(folders_to_show);
    }
    if(files_to_show) free(files_to_show);
}


static void update_info_panel(void){
    if(!g_info_panel || !g_info_name_lbl || !g_info_size_lbl || !g_info_entries_lbl) return;
    if(!g_current_archive){
        gtk_widget_set_visible(g_info_panel, FALSE);
        gtk_label_set_text(GTK_LABEL(g_info_name_lbl), "");
        gtk_label_set_text(GTK_LABEL(g_info_size_lbl), "");
        gtk_label_set_text(GTK_LABEL(g_info_entries_lbl), "");
        return;
    }
    char namebuf[4096]; snprintf(namebuf, sizeof(namebuf), "Archive: %s", g_current_archive);
    gtk_label_set_text(GTK_LABEL(g_info_name_lbl), namebuf);
    struct stat st;
    if(stat(g_current_archive, &st)==0){
        char s[64]; fmt_size(st.st_size, s, sizeof(s));
        char sb[128]; snprintf(sb, sizeof(sb), "Size: %s", s);
        gtk_label_set_text(GTK_LABEL(g_info_size_lbl), sb);
    } else {
        gtk_label_set_text(GTK_LABEL(g_info_size_lbl), "Size: <unknown>");
    }

    uint32_t shown = 0, total_active = 0;
    size_t plen = g_current_prefix ? strlen(g_current_prefix) : 0;
    for(uint32_t i=0;i<g_current_index.n;i++){
        entry_t *e = &g_current_index.entries[i];
        if(e->flags & 4) continue;
        total_active++;

        if(plen>0){
            if(strncmp(e->name, g_current_prefix, plen)!=0) continue;
            const char *rest = e->name + plen;
            size_t restlen = strlen(rest);

            if(restlen == 0) continue;
            if(restlen > 0 && rest[restlen-1] == '/'){
                if(strchr(rest, '/') != rest + restlen - 1) continue;
            } else {
                if(strchr(rest, '/')) continue;
            }
            shown++;
        } else {
            size_t namelen = strlen(e->name);
            if(namelen > 0 && e->name[namelen-1] == '/'){
                if(strchr(e->name, '/') != e->name + namelen - 1) continue;
            } else {
                if(strchr(e->name, '/')) continue;
            }
            shown++;
        }
    }
    char eb[128]; snprintf(eb, sizeof(eb), "Entries: %u shown (%u total)", shown, total_active);
    gtk_label_set_text(GTK_LABEL(g_info_entries_lbl), eb);
    gtk_widget_set_visible(g_info_panel, TRUE);
}


typedef struct {
    GtkWidget *entry;
    int *result;
} password_dialog_data_t;

static void on_password_dialog_response(GtkDialog *d, int response, gpointer user_data){
    (void)d;
    password_dialog_data_t *data = (password_dialog_data_t*)user_data;
    if(response == GTK_RESPONSE_ACCEPT){
        const char *pwd = gtk_editable_get_text(GTK_EDITABLE(data->entry));
        if(pwd && pwd[0]){
            if(g_archive_password) free(g_archive_password);
            g_archive_password = strdup(pwd);
            *(data->result) = 1;
        }
    }
}


static int show_password_dialog(const char *message){
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Password Required",
                                                    GTK_WINDOW(g_main_window),
                                                    GTK_DIALOG_MODAL,
                                                    "_Cancel", GTK_RESPONSE_CANCEL,
                                                    "_OK", GTK_RESPONSE_ACCEPT,
                                                    NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 400, -1);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_widget_set_margin_start(content, 20);
    gtk_widget_set_margin_end(content, 20);
    gtk_widget_set_margin_top(content, 20);
    gtk_widget_set_margin_bottom(content, 20);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);

    GtkWidget *info_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *icon = gtk_image_new_from_icon_name("dialog-password");
    gtk_image_set_pixel_size(GTK_IMAGE(icon), 48);
    gtk_box_append(GTK_BOX(info_box), icon);

    GtkWidget *msg_lbl = gtk_label_new(message ? message : "Please enter the password:");
    gtk_label_set_xalign(GTK_LABEL(msg_lbl), 0.0);
    gtk_label_set_wrap(GTK_LABEL(msg_lbl), TRUE);
    gtk_box_append(GTK_BOX(info_box), msg_lbl);
    gtk_box_append(GTK_BOX(box), info_box);

    GtkWidget *entry = gtk_password_entry_new();
    gtk_password_entry_set_show_peek_icon(GTK_PASSWORD_ENTRY(entry), TRUE);
    gtk_widget_set_size_request(entry, 300, -1);
    gtk_box_append(GTK_BOX(box), entry);

    gtk_box_append(GTK_BOX(content), box);


    GtkWidget *action_area = NULL;
    GtkWidget *kid = gtk_widget_get_first_child(GTK_WIDGET(dialog));
    while(kid){
        if(gtk_widget_get_next_sibling(kid) == NULL) action_area = kid;
        kid = gtk_widget_get_next_sibling(kid);
    }
    if(action_area){
        gtk_widget_set_margin_top(action_area, 6);
        gtk_widget_set_margin_bottom(action_area, 6);
        gtk_widget_set_margin_start(action_area, 12);
        gtk_widget_set_margin_end(action_area, 12);
        if(GTK_IS_BOX(action_area)) gtk_box_set_spacing(GTK_BOX(action_area), 8);
        GtkWidget *cancel_btn = gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog), GTK_RESPONSE_CANCEL);
        if(cancel_btn) gtk_widget_set_margin_end(cancel_btn, 5);
    }

    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);


    GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    int result = 0;
    password_dialog_data_t pwd_data = { entry, &result };

    g_signal_connect_swapped(dialog, "response", G_CALLBACK(g_main_loop_quit), loop);
    g_signal_connect(dialog, "response", G_CALLBACK(on_password_dialog_response), &pwd_data);

    gtk_window_present(GTK_WINDOW(dialog));
    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    gtk_window_destroy(GTK_WINDOW(dialog));
    return result;
}


static int open_archive_gui(const char *path){
    if(!path) return 1;


    int is_libarchive = 0;
    const char *ext = strrchr(path, '.');
    if (ext) {

        if (strcmp(ext, ".zip") == 0 || strcmp(ext, ".jar") == 0 ||
            strcmp(ext, ".tar") == 0 || strcmp(ext, ".tgz") == 0 ||
            strcmp(ext, ".tbz") == 0 || strcmp(ext, ".tbz2") == 0 ||
            strcmp(ext, ".txz") == 0 || strcmp(ext, ".tlz") == 0 ||
            strcmp(ext, ".gz") == 0 || strcmp(ext, ".bz2") == 0 ||
            strcmp(ext, ".xz") == 0 || strcmp(ext, ".lzma") == 0 ||
            strcmp(ext, ".7z") == 0 || strcmp(ext, ".rar") == 0 ||
            strcmp(ext, ".iso") == 0 || strcmp(ext, ".cab") == 0 ||
            strcmp(ext, ".lzh") == 0 || strcmp(ext, ".lha") == 0 ||
            strcmp(ext, ".ar") == 0 || strcmp(ext, ".cpio") == 0 ||
            strcmp(ext, ".rpm") == 0 || strcmp(ext, ".deb") == 0) {
            if (la_is_supported(path)) {
                is_libarchive = 1;
            }
        }

        if (!is_libarchive && strlen(path) > 7) {
            if (strstr(path, ".tar.gz") || strstr(path, ".tar.bz2") ||
                strstr(path, ".tar.xz") || strstr(path, ".tar.lzma") ||
                strstr(path, ".tar.Z")) {
                if (la_is_supported(path)) {
                    is_libarchive = 1;
                }
            }
        }
    }


    free_index(&g_current_index);

    if (is_libarchive) {

        g_current_index = load_libarchive_index(path);
        g_current_is_libarchive = 1;
    } else {

        FILE *f = fopen(path, "rb");
        if(!f) {
            return 1;
        }
        g_current_index = load_index(f);
        fclose(f);
        g_current_is_libarchive = 0;
    }

    if(g_current_archive) free(g_current_archive);
    g_current_archive = strdup(path);

    if(g_current_prefix) { free(g_current_prefix); g_current_prefix = NULL; }

    GtkWidget *content_stack = g_object_get_data(G_OBJECT(g_main_window), "content-stack");
    if(content_stack) gtk_stack_set_visible_child_name(GTK_STACK(content_stack), "filelist");

    if(g_plus_btn) gtk_widget_set_visible(g_plus_btn, FALSE);
    if(g_add_btn) gtk_widget_set_visible(g_add_btn, TRUE);
    if(g_newfolder_btn) gtk_widget_set_visible(g_newfolder_btn, g_current_is_libarchive ? FALSE : TRUE);
    if(g_remove_btn) gtk_widget_set_visible(g_remove_btn, g_current_is_libarchive ? FALSE : TRUE);
    if(g_extract_btn) gtk_widget_set_visible(g_extract_btn, TRUE);
    if(g_compact_btn) gtk_widget_set_visible(g_compact_btn, g_current_is_libarchive ? FALSE : TRUE);
    if(g_back_btn) gtk_widget_set_visible(g_back_btn, FALSE);
    if(g_close_btn) gtk_widget_set_visible(g_close_btn, TRUE);

    populate_list_from_index();


    update_info_panel();
    return 0;
}

static void close_archive_gui(void){


    if(g_current_archive && !g_current_is_libarchive){
        int has_deleted = 0;
        for(uint32_t i=0;i<g_current_index.n;i++){
            if(g_current_index.entries[i].flags & 4){ has_deleted = 1; break; }
        }
        if(has_deleted){

            rebuild_archive(g_current_archive, NULL, 0, 1);
        }
    }
    free_index(&g_current_index);
    if(g_current_archive){ free(g_current_archive); g_current_archive = NULL; }
    if(g_current_prefix){ free(g_current_prefix); g_current_prefix = NULL; }

    if(g_archive_password){ free(g_archive_password); g_archive_password = NULL; }
    g_archive_was_encrypted = 0;
    g_current_is_libarchive = 0;

    if(g_list_container){
        GtkWidget *child;
        while((child = gtk_widget_get_first_child(g_list_container)) != NULL){
            gtk_list_box_remove(GTK_LIST_BOX(g_list_container), child);
        }
    }

    if(g_info_panel) gtk_widget_set_visible(g_info_panel, FALSE);
    if(g_info_name_lbl) gtk_label_set_text(GTK_LABEL(g_info_name_lbl), "");
    if(g_info_size_lbl) gtk_label_set_text(GTK_LABEL(g_info_size_lbl), "");
    if(g_info_entries_lbl) gtk_label_set_text(GTK_LABEL(g_info_entries_lbl), "");

    GtkWidget *content_stack = g_object_get_data(G_OBJECT(g_main_window), "content-stack");
    if(content_stack) gtk_stack_set_visible_child_name(GTK_STACK(content_stack), "welcome");

    if(g_plus_btn) gtk_widget_set_visible(g_plus_btn, TRUE);
    if(g_add_btn) gtk_widget_set_visible(g_add_btn, FALSE);
    if(g_newfolder_btn) gtk_widget_set_visible(g_newfolder_btn, FALSE);
    if(g_remove_btn) gtk_widget_set_visible(g_remove_btn, FALSE);
    if(g_extract_btn) gtk_widget_set_visible(g_extract_btn, FALSE);
    if(g_compact_btn) gtk_widget_set_visible(g_compact_btn, FALSE);
    if(g_back_btn) gtk_widget_set_visible(g_back_btn, FALSE);
    if(g_close_btn) gtk_widget_set_visible(g_close_btn, FALSE);
}

static int write_index(FILE *f, index_t *idx);
static int update_header_index_offset(FILE *f, uint64_t index_offset);
static int ensure_header(FILE *f);
static int add_files(const char *archive, filepair_t *filepairs, int *clevels, int nfiles, const char *pwd, int incremental_mode, int mirror_mode);


static void show_progress_dialog(const char *title, const char *message){
    if(g_progress_dialog) return;

    g_progress_dialog = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(g_progress_dialog), title);
    gtk_window_set_transient_for(GTK_WINDOW(g_progress_dialog), GTK_WINDOW(g_main_window));
    gtk_window_set_modal(GTK_WINDOW(g_progress_dialog), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(g_progress_dialog), 400, 150);
    gtk_window_set_resizable(GTK_WINDOW(g_progress_dialog), FALSE);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_start(box, 20);
    gtk_widget_set_margin_end(box, 20);
    gtk_widget_set_margin_top(box, 20);
    gtk_widget_set_margin_bottom(box, 20);

    g_progress_label = gtk_label_new(message);
    gtk_label_set_xalign(GTK_LABEL(g_progress_label), 0.0);
    gtk_box_append(GTK_BOX(box), g_progress_label);

    g_progress_bar = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(g_progress_bar), TRUE);
    gtk_box_append(GTK_BOX(box), g_progress_bar);

    gtk_window_set_child(GTK_WINDOW(g_progress_dialog), box);
    gtk_window_present(GTK_WINDOW(g_progress_dialog));


    while(g_main_context_pending(NULL)) g_main_context_iteration(NULL, FALSE);
}

static void update_progress(double fraction, const char *text){
    if(!g_progress_bar) return;
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(g_progress_bar), fraction);
    if(text) gtk_progress_bar_set_text(GTK_PROGRESS_BAR(g_progress_bar), text);


    while(g_main_context_pending(NULL)) g_main_context_iteration(NULL, FALSE);
}

static void update_progress_label(const char *text){
    if(!g_progress_label) return;
    gtk_label_set_text(GTK_LABEL(g_progress_label), text);
    while(g_main_context_pending(NULL)) g_main_context_iteration(NULL, FALSE);
}


static gboolean destroy_window_cb(gpointer win){
    if(win){
        gtk_window_destroy(GTK_WINDOW(win));
    }
    return G_SOURCE_REMOVE;
}


static int compress_data_level(int level, const unsigned char *in, size_t in_sz, unsigned char **outp, size_t *out_szp){
    if(!in || in_sz==0) return 1;
    *outp = NULL; *out_szp = 0;
    if(level <= 1){
        uLong bound = compressBound(in_sz);
        unsigned char *out = malloc(bound);
        if(!out) return 1;
        uLong outsz = bound;
        int zr = compress2(out, &outsz, in, in_sz, Z_BEST_SPEED);
        if(zr!=Z_OK){ free(out); return 2; }
        *outp = out; *out_szp = outsz; return 0;
    }
    if(level == 2){
        uLong bound = compressBound(in_sz);
        unsigned char *out = malloc(bound);
        if(!out) return 1;
        uLong outsz = bound;
        int zr = compress2(out, &outsz, in, in_sz, Z_DEFAULT_COMPRESSION);
        if(zr!=Z_OK){ free(out); return 2; }
        *outp = out; *out_szp = outsz; return 0;
    }
    if(level == 3 || level == 4){
        int strategies[] = {Z_DEFAULT_STRATEGY, Z_FILTERED, Z_RLE, Z_HUFFMAN_ONLY};
        int windowBitsOpts[] = {15, 15 | 16, -15};
        int memLevels[9];
        size_t memLevelsCount = (level == 4) ? 9u : 2u;
        for(size_t i=0;i<9;i++) memLevels[i]= (int)i + 1;
        if(level == 3) { memLevels[0]=9; memLevels[1]=8; }
        unsigned char *best = NULL; size_t best_sz = 0;
        for(size_t wi=0; wi<(level==4?3:2); wi++){
            for(size_t mi=0; mi<memLevelsCount; mi++){
                for(size_t si=0; si<sizeof(strategies)/sizeof(strategies[0]); si++){
                    int strat = strategies[si];
                    z_stream zs; memset(&zs,0,sizeof(zs));
                    int windowBits = windowBitsOpts[wi]; int memLevel = memLevels[mi];
                    if(deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, windowBits, memLevel, strat) != Z_OK) continue;
                    uLong bound = compressBound(in_sz);
                    unsigned char *out = malloc(bound);
                    if(!out){ deflateEnd(&zs); continue; }
                    zs.next_in = (Bytef*)in; zs.avail_in = (uInt)in_sz;
                    zs.next_out = out; zs.avail_out = (uInt)bound;
                    int res = deflate(&zs, Z_FINISH);
                    if(res == Z_STREAM_END){
                        size_t outsz = zs.total_out;
                        if(best==NULL || outsz < best_sz){
                            if(best) free(best);
                            best = out;
                            best_sz = outsz;
                        } else {
                            free(out);
                        }
                    }
                    else { free(out); }
                    deflateEnd(&zs);
                }
            }
        }
        if(best){ *outp = best; *out_szp = best_sz; return 0; }

        uLong bound = compressBound(in_sz);
        unsigned char *outf = malloc(bound);
        if(!outf) return 1;
        uLong outszf = bound;
        int zr = compress2(outf, &outszf, in, in_sz, Z_BEST_COMPRESSION);
        if(zr!=Z_OK){ free(outf); return 2; }
        *outp = outf; *out_szp = outszf; return 0;
    }
    return 1;
}


static int auto_choose_clevel(const char *path){
    if(!path) return 1;
    struct stat st;
    if(stat(path,&st)!=0) return 1;
    size_t fsize = (size_t)st.st_size;
    if(fsize == 0) return 0;

    const char *ext = strrchr(path, '.');
    if(ext){
        char lower[16]; size_t i=0; ext++; while(*ext && i+1<sizeof(lower)){ lower[i++] = tolower((unsigned char)*ext); ext++; } lower[i]='\0';
        const char *no_compress_exts[] = {"jpg","jpeg","png","gif","zip","gz","bz2","7z","xz","rar","mp3","ogg","mp4","mkv","pdf","woff","woff2","lz4","zst", NULL};
        for(const char **p = no_compress_exts; *p; ++p) if(strcmp(lower, *p)==0) return 0;
    }
    if(fsize < 1024) return 0;
    size_t sample = fsize < 65536 ? fsize : 65536;
    FILE *f = fopen(path, "rb"); if(!f) return 1;
    unsigned char *buf = malloc(sample);
    if(!buf){ fclose(f); return 1; }
    size_t r = fread(buf,1,sample,f); fclose(f);
    if(r==0){ free(buf); return 0; }
    uLong bound = compressBound(r);
    unsigned char *out = malloc(bound);
    if(!out){ free(buf); return 1; }
    uLong outsz = bound;
    int zr = compress2(out, &outsz, buf, r, Z_BEST_SPEED);
    free(buf);
    if(zr != Z_OK){ free(out); return 1; }
    double ratio = (double)outsz / (double)r;
    free(out);
    if(ratio > 0.95) return 0;
    if(ratio > 0.6) return 1;

    return 2;
}



static void on_filter_changed(GtkFileChooser *chooser, GParamSpec *pspec, gpointer user_data){
    (void)pspec; (void)user_data;

    GtkFileFilter *filter = gtk_file_chooser_get_filter(chooser);
    if(!filter) return;

    const char *filter_name = gtk_file_filter_get_name(filter);
    if(!filter_name) return;


    GFile *file = gtk_file_chooser_get_file(chooser);
    char *current_name = NULL;
    if(file){
        current_name = g_file_get_basename(file);
        g_object_unref(file);
    }
    if(!current_name) current_name = g_strdup("new_archive");


    char *dot = strrchr(current_name, '.');
    if(dot) *dot = '\0';


    const char *new_ext = NULL;
    if(strstr(filter_name, "BAAR")) new_ext = ".baar";
    else if(strstr(filter_name, "ZIP")) new_ext = ".zip";
    else if(strstr(filter_name, "TAR.GZ")) new_ext = ".tar.gz";
    else if(strstr(filter_name, "TAR.BZ2")) new_ext = ".tar.bz2";
    else if(strstr(filter_name, "TAR.XZ")) new_ext = ".tar.xz";
    else if(strstr(filter_name, "7-Zip")) new_ext = ".7z";
    else if(strstr(filter_name, "TAR")) new_ext = ".tar";

    if(new_ext){
        char new_name[512];
        snprintf(new_name, sizeof(new_name), "%s%s", current_name, new_ext);
        gtk_file_chooser_set_current_name(chooser, new_name);
    }

    g_free(current_name);
}

static void on_add_files_response(GtkDialog *dialog, int response_id, gpointer data){
    (void)data;
    if(response_id == GTK_RESPONSE_ACCEPT){

        const char *password = g_object_get_data(G_OBJECT(dialog), "add-password");

        GListModel *files_model = gtk_file_chooser_get_files(GTK_FILE_CHOOSER(dialog));
        int nfiles = g_list_model_get_n_items(files_model);
        if(nfiles > 0){

            char msg[256];
            snprintf(msg, sizeof(msg), "Adding %d files...", nfiles);
            show_progress_dialog("Adding files", msg);

            filepair_t *filepairs = malloc(sizeof(filepair_t) * nfiles);
            int *clevels = malloc(sizeof(int) * nfiles);
            for(int i=0; i<nfiles; i++){
                GFile *gf = G_FILE(g_list_model_get_item(files_model, i));
                char *path = g_file_get_path(gf);
                filepairs[i].src_path = path;

                char *bn = strrchr(path, '/');
                bn = bn ? bn+1 : path;
                if(g_current_prefix){
                    char tmp[4096];
                    snprintf(tmp, sizeof(tmp), "%s%s", g_current_prefix, bn);
                    filepairs[i].archive_path = strdup(tmp);
                } else {
                    filepairs[i].archive_path = strdup(bn);
                }

                clevels[i] = auto_choose_clevel(path);
                g_object_unref(gf);


                double frac = (double)(i+1) / (double)nfiles;
                char pbuf[128];
                snprintf(pbuf, sizeof(pbuf), "Preparing %d/%d", i+1, nfiles);
                update_progress(frac * 0.1, pbuf);
            }

            update_progress_label("Adding files to archive...");


            if(g_current_is_libarchive){

                const char **file_paths = malloc(sizeof(char*) * nfiles);
                for(int i=0; i<nfiles; i++){
                    file_paths[i] = filepairs[i].src_path;
                }

                    {
                        const char *usepwd = password ? password : g_archive_password;
                        int lar = la_add_files(g_current_archive, file_paths, nfiles, 2, usepwd, global_verbose);
                        if(lar != 0 && !usepwd && g_main_window){

                            if(show_password_dialog("Adding files failed (archive may be encrypted). Enter password to retry:")){
                                if(g_archive_password && g_archive_password[0]) g_archive_was_encrypted = 1;
                                la_add_files(g_current_archive, file_paths, nfiles, 2, g_archive_password, global_verbose);
                            }
                        }
                    }
                free(file_paths);
            } else {

                add_files(g_current_archive, filepairs, clevels, nfiles, password, 0, 0);
            }

            update_progress(0.9, "Refreshing index...");


            if(g_current_is_libarchive){
                free_index(&g_current_index);
                g_current_index = load_libarchive_index(g_current_archive);
            } else {
                FILE *f = fopen(g_current_archive, "rb");
                if(f){ free_index(&g_current_index); g_current_index = load_index(f); fclose(f); }
            }
            populate_list_from_index();
            update_info_panel();

            update_progress(1.0, "Done!");


            for(int i=0; i<nfiles; i++){
                g_free(filepairs[i].src_path);
                free(filepairs[i].archive_path);
            }
            free(filepairs); free(clevels);


            g_timeout_add(500, destroy_window_cb, g_progress_dialog);
            g_progress_dialog = NULL;
            g_progress_bar = NULL;
            g_progress_label = NULL;
        }
        g_object_unref(files_model);
    }
    gtk_window_destroy(GTK_WINDOW(dialog));
}

static void on_newfolder_response(GtkDialog *d, int response_id, gpointer entry_ptr){
    if(response_id == GTK_RESPONSE_ACCEPT){
        GtkEntry *entry = GTK_ENTRY(entry_ptr);
        const char *name = gtk_editable_get_text(GTK_EDITABLE(entry));
        if(name && name[0]){
            char fullpath[4096];
            if(g_current_prefix){
                snprintf(fullpath, sizeof(fullpath), "%s%s/", g_current_prefix, name);
            } else {
                snprintf(fullpath, sizeof(fullpath), "%s/", name);
            }

            FILE *f = fopen(g_current_archive, "rb");
            int exists = 0;
            if(f){
                ensure_header(f);
                index_t idx = load_index(f);
                for(uint32_t i = 0; i < idx.n; i++){
                    if(idx.entries[i].name && strcmp(idx.entries[i].name, fullpath) == 0 && !(idx.entries[i].flags & 0x04)){
                        exists = 1;
                        break;
                    }
                }
                free_index(&idx);
                fclose(f);
            }
            if(exists){
                GtkWidget *msg = gtk_message_dialog_new(GTK_WINDOW(d),
                    GTK_DIALOG_MODAL,
                    GTK_MESSAGE_WARNING,
                    GTK_BUTTONS_OK,
                    "A folder named '%s' already exists in this location.\n\nPlease choose a different name.", name);
                gtk_window_set_title(GTK_WINDOW(msg), "Folder Already Exists");
                gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(msg),
                    "Each folder in this location must have a unique name.\n\nTip: Try adding a number or a short description to the folder name.");
                gtk_window_set_icon_name(GTK_WINDOW(msg), "dialog-warning");
                g_signal_connect(msg, "response", G_CALLBACK(gtk_window_destroy), NULL);
                gtk_window_present(GTK_WINDOW(msg));
            } else {

                f = fopen(g_current_archive, "r+b");
                if(f){
                    ensure_header(f);
                    index_t idx = load_index(f);
                    idx.entries = realloc(idx.entries, sizeof(entry_t)*(idx.n+1));
                    entry_t *e = &idx.entries[idx.n];
                    memset(e,0,sizeof(*e));
                    e->id = idx.next_id++;
                    e->name = strdup(fullpath);
                    e->flags = 0; e->comp_level = 0; e->data_offset = 0; e->comp_size = 0; e->uncomp_size = 0; e->crc32 = 0;
                    idx.n++;
                    fseek(f,0,SEEK_END);
                    uint64_t index_offset = ftell(f);
                    write_index(f, &idx);
                    update_header_index_offset(f, index_offset);
                    fclose(f);
                    free_index(&idx);

                    f = fopen(g_current_archive, "rb");
                    if(f){ free_index(&g_current_index); g_current_index = load_index(f); fclose(f); }
                    populate_list_from_index();
                    update_info_panel();
                }
            }
        }
    }
    gtk_window_destroy(GTK_WINDOW(d));
}


static void on_file_overwrite_response(GtkDialog *dialog, gint response, gpointer user_data){
    file_overwrite_data_t *data = (file_overwrite_data_t*)user_data;
    if(!data) {
        gtk_window_destroy(GTK_WINDOW(dialog));
        return;
    }

    if(response == GTK_RESPONSE_ACCEPT){

        FILE *f = fopen(g_current_archive, "r+b");
        if(f){
            index_t idx = load_index(f);
            int modified = 0;


            for(uint32_t i = 0; i < idx.n; i++){
                entry_t *e = &idx.entries[i];
                if(e->id == data->src_id){

                    free(e->name);
                    e->name = strdup(data->target_name);
                    modified = 1;


                    for(uint32_t j = 0; j < idx.n; j++){
                        if(j != i && strcmp(idx.entries[j].name, data->target_name) == 0){
                            idx.entries[j].flags |= 4;
                            modified = 1;
                            break;
                        }
                    }
                    break;
                }
            }


            if(modified){
                fseek(f, 0, SEEK_END);
                uint64_t new_index_offset = ftell(f);
                write_index(f, &idx);
                update_header_index_offset(f, new_index_offset);


                free_index(&g_current_index);
                rewind(f);
                g_current_index = load_index(f);
                populate_list_from_index();
                update_info_panel();
            }

            free_index(&idx);
            fclose(f);
        }
    }



    if(data->src_name) free(data->src_name);
    if(data->target_name) free(data->target_name);
    if(data->target_folder) free(data->target_folder);
    free(data);

    gtk_window_destroy(GTK_WINDOW(dialog));
}

static void on_remove_response(GtkDialog *d, int response_id, gpointer user_data){
    (void)user_data;

    if(response_id == GTK_RESPONSE_YES){

        GList *selected_rows = g_object_get_data(G_OBJECT(d), "selected-rows");
        if(!selected_rows){
            gtk_window_destroy(GTK_WINDOW(d));
            return;
        }


        uint32_t *to_exclude = NULL;
        uint32_t ex_count = 0;

        for(GList *l = selected_rows; l != NULL; l = l->next){
            GtkListBoxRow *row = GTK_LIST_BOX_ROW(l->data);
            row_data_t *rd = g_object_get_data(G_OBJECT(row), "baar-row-data");
            if(!rd || !rd->name) continue;

            size_t nlen = strlen(rd->name);

            if(nlen > 0 && rd->name[nlen-1] == '/'){

                for(uint32_t i=0; i<g_current_index.n; i++){
                    entry_t *e = &g_current_index.entries[i];
                    if(e->flags & 4) continue;
                    if(strncmp(e->name, rd->name, nlen) == 0){
                        to_exclude = realloc(to_exclude, sizeof(uint32_t)*(ex_count+1));
                        to_exclude[ex_count++] = e->id;
                    }
                }
            } else {

                to_exclude = realloc(to_exclude, sizeof(uint32_t)*(ex_count+1));
                to_exclude[ex_count++] = rd->id;
            }
        }


        if(ex_count > 0){
            rebuild_archive(g_current_archive, to_exclude, ex_count, 1);
            free(to_exclude);


            FILE *f = fopen(g_current_archive, "rb");
            if(f){
                free_index(&g_current_index);
                g_current_index = load_index(f);
                fclose(f);
            }
            populate_list_from_index();
            update_info_panel();
        }
    }


    GList *selected_rows = g_object_get_data(G_OBJECT(d), "selected-rows");
    if(selected_rows) g_list_free(selected_rows);

    gtk_window_destroy(GTK_WINDOW(d));
}



static void on_encryption_dialog_response(GtkDialog *dlg, int response, gpointer data){
    (void)data;
    if(response == GTK_RESPONSE_ACCEPT){
        GtkWidget *encrypt_check = g_object_get_data(G_OBJECT(dlg), "encrypt-check");
        GtkWidget *pwd_entry = g_object_get_data(G_OBJECT(dlg), "pwd-entry");
        int is_libarchive = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(dlg), "is-libarchive"));

        int encrypt = gtk_check_button_get_active(GTK_CHECK_BUTTON(encrypt_check));
        const char *password = NULL;

        if(encrypt){
            password = gtk_editable_get_text(GTK_EDITABLE(pwd_entry));
            if(!password || !password[0]){

                GtkWidget *err = gtk_message_dialog_new(GTK_WINDOW(g_main_window),
                                                       GTK_DIALOG_MODAL,
                                                       GTK_MESSAGE_ERROR,
                                                       GTK_BUTTONS_OK,
                                                       "Encryption requires a password.");
                gtk_window_present(GTK_WINDOW(err));
                g_signal_connect_swapped(err, "response", G_CALLBACK(gtk_window_destroy), err);
                gtk_window_destroy(GTK_WINDOW(dlg));
                return;
            }
        }


        if(is_libarchive){
            int was_encrypted = (g_archive_password && g_archive_password[0]) || g_archive_was_encrypted;
            if(was_encrypted){

                encrypt = 1;
                if((!password || !password[0]) && g_archive_password){
                    password = g_archive_password;
                }
            }

            if(encrypt && password && password[0]){
                if(!g_archive_password || strcmp(g_archive_password, password) != 0){
                    if(g_archive_password) free(g_archive_password);
                    g_archive_password = strdup(password);
                }
            }

        }


        const char *final_pwd = (encrypt && password && password[0]) ? password : NULL;
        if(!final_pwd && is_libarchive && g_archive_password){

            final_pwd = g_archive_password;
        }
        char *pwd_copy = final_pwd ? strdup(final_pwd) : NULL;

        GtkWidget *chooser = gtk_file_chooser_dialog_new("Add files to archive",
                                                         GTK_WINDOW(g_main_window),
                                                         GTK_FILE_CHOOSER_ACTION_OPEN,
                                                         "_Cancel", GTK_RESPONSE_CANCEL,
                                                         "_Add", GTK_RESPONSE_ACCEPT,
                                                         NULL);
        gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER(chooser), TRUE);


        if(pwd_copy){
            g_object_set_data_full(G_OBJECT(chooser), "add-password", pwd_copy, free);
        }

        gtk_window_present(GTK_WINDOW(chooser));
        g_signal_connect(chooser, "response", G_CALLBACK(on_add_files_response), NULL);
    }

    gtk_window_destroy(GTK_WINDOW(dlg));
}


static void on_encrypt_toggled(GtkCheckButton *btn, gpointer data){
    gtk_widget_set_sensitive(GTK_WIDGET(data), gtk_check_button_get_active(btn));
}

static void on_gui_add_clicked(GtkButton *btn, gpointer user_data){
    (void)btn;(void)user_data;
    if(!g_current_archive) return;


    if(g_current_is_libarchive){
        GtkWidget *enc_dlg = gtk_dialog_new_with_buttons("Encryption Options",
                                                         GTK_WINDOW(g_main_window),
                                                         GTK_DIALOG_MODAL,
                                                         "_Cancel", GTK_RESPONSE_CANCEL,
                                                         "_Continue", GTK_RESPONSE_ACCEPT,
                                                         NULL);
        gtk_window_set_default_size(GTK_WINDOW(enc_dlg), 450, -1);

        GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(enc_dlg));
        gtk_widget_set_margin_start(content, 24);
        gtk_widget_set_margin_end(content, 24);
        gtk_widget_set_margin_top(content, 20);
        gtk_widget_set_margin_bottom(content, 16);

        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 16);

        GtkWidget *encrypt_check = gtk_check_button_new_with_label("Encrypt files with password");

        if(g_archive_password || g_archive_was_encrypted) gtk_check_button_set_active(GTK_CHECK_BUTTON(encrypt_check), TRUE);
        gtk_box_append(GTK_BOX(box), encrypt_check);

        GtkWidget *pwd_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
        gtk_widget_set_margin_start(pwd_box, 28);

        GtkWidget *pwd_label = gtk_label_new("Password:");
        gtk_label_set_xalign(GTK_LABEL(pwd_label), 0.0);
        gtk_widget_set_margin_bottom(pwd_label, 4);
        gtk_box_append(GTK_BOX(pwd_box), pwd_label);

        GtkWidget *pwd_entry = gtk_password_entry_new();
        gtk_password_entry_set_show_peek_icon(GTK_PASSWORD_ENTRY(pwd_entry), TRUE);
        gtk_widget_set_hexpand(pwd_entry, TRUE);

        if(g_archive_password){
            gtk_editable_set_text(GTK_EDITABLE(pwd_entry), g_archive_password);
            gtk_widget_set_sensitive(pwd_entry, TRUE);
        } else if(g_archive_was_encrypted) {
            gtk_widget_set_sensitive(pwd_entry, TRUE);
        } else {
            gtk_widget_set_sensitive(pwd_entry, FALSE);
        }
        gtk_box_append(GTK_BOX(pwd_box), pwd_entry);

        gtk_box_append(GTK_BOX(box), pwd_box);
        gtk_box_append(GTK_BOX(content), box);

        g_signal_connect(encrypt_check, "toggled", G_CALLBACK(on_encrypt_toggled), pwd_entry);


        GtkWidget *action_area = NULL;
        GtkWidget *kid = gtk_widget_get_first_child(GTK_WIDGET(enc_dlg));
        while(kid){
            if(gtk_widget_get_next_sibling(kid) == NULL) action_area = kid;
            kid = gtk_widget_get_next_sibling(kid);
        }
        if(action_area){
            gtk_widget_set_margin_top(action_area, 12);
            gtk_widget_set_margin_bottom(action_area, 12);
            gtk_widget_set_margin_start(action_area, 20);
            gtk_widget_set_margin_end(action_area, 20);
            if(GTK_IS_BOX(action_area)) gtk_box_set_spacing(GTK_BOX(action_area), 12);
        }

        g_object_set_data(G_OBJECT(enc_dlg), "encrypt-check", encrypt_check);
        g_object_set_data(G_OBJECT(enc_dlg), "pwd-entry", pwd_entry);

        g_object_set_data(G_OBJECT(enc_dlg), "is-libarchive", GINT_TO_POINTER(1));

        gtk_dialog_set_default_response(GTK_DIALOG(enc_dlg), GTK_RESPONSE_ACCEPT);
        gtk_window_present(GTK_WINDOW(enc_dlg));

        g_signal_connect(enc_dlg, "response", G_CALLBACK(on_encryption_dialog_response), NULL);
        return;
    }


    GtkWidget *enc_dlg = gtk_dialog_new_with_buttons("Encryption Options",
                                                     GTK_WINDOW(g_main_window),
                                                     GTK_DIALOG_MODAL,
                                                     "_Cancel", GTK_RESPONSE_CANCEL,
                                                     "_Continue", GTK_RESPONSE_ACCEPT,
                                                     NULL);
    gtk_window_set_default_size(GTK_WINDOW(enc_dlg), 450, -1);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(enc_dlg));
    gtk_widget_set_margin_start(content, 24);
    gtk_widget_set_margin_end(content, 24);
    gtk_widget_set_margin_top(content, 20);
    gtk_widget_set_margin_bottom(content, 16);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 16);

    GtkWidget *encrypt_check = gtk_check_button_new_with_label("Encrypt files with password");
    gtk_box_append(GTK_BOX(box), encrypt_check);

    GtkWidget *pwd_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_start(pwd_box, 28);

    GtkWidget *pwd_label = gtk_label_new("Password:");
    gtk_label_set_xalign(GTK_LABEL(pwd_label), 0.0);
    gtk_widget_set_margin_bottom(pwd_label, 4);
    gtk_box_append(GTK_BOX(pwd_box), pwd_label);

    GtkWidget *pwd_entry = gtk_password_entry_new();
    gtk_password_entry_set_show_peek_icon(GTK_PASSWORD_ENTRY(pwd_entry), TRUE);
    gtk_widget_set_hexpand(pwd_entry, TRUE);
    gtk_widget_set_sensitive(pwd_entry, FALSE);
    gtk_box_append(GTK_BOX(pwd_box), pwd_entry);

    gtk_box_append(GTK_BOX(box), pwd_box);
    gtk_box_append(GTK_BOX(content), box);

    g_signal_connect(encrypt_check, "toggled", G_CALLBACK(on_encrypt_toggled), pwd_entry);


    GtkWidget *action_area = NULL;
    GtkWidget *kid = gtk_widget_get_first_child(GTK_WIDGET(enc_dlg));
    while(kid){
        if(gtk_widget_get_next_sibling(kid) == NULL) action_area = kid;
        kid = gtk_widget_get_next_sibling(kid);
    }
    if(action_area){
        gtk_widget_set_margin_top(action_area, 12);
        gtk_widget_set_margin_bottom(action_area, 12);
        gtk_widget_set_margin_start(action_area, 20);
        gtk_widget_set_margin_end(action_area, 20);
        if(GTK_IS_BOX(action_area)) gtk_box_set_spacing(GTK_BOX(action_area), 8);
        GtkWidget *cancel_btn = gtk_dialog_get_widget_for_response(GTK_DIALOG(enc_dlg), GTK_RESPONSE_CANCEL);
        if(cancel_btn) gtk_widget_set_margin_end(cancel_btn, 5);
    }

    g_object_set_data(G_OBJECT(enc_dlg), "encrypt-check", encrypt_check);
    g_object_set_data(G_OBJECT(enc_dlg), "pwd-entry", pwd_entry);

    gtk_dialog_set_default_response(GTK_DIALOG(enc_dlg), GTK_RESPONSE_ACCEPT);
    gtk_window_present(GTK_WINDOW(enc_dlg));

    g_signal_connect(enc_dlg, "response", G_CALLBACK(on_encryption_dialog_response), NULL);
}

static void on_gui_newfolder_clicked(GtkButton *btn, gpointer user_data){
    (void)btn;(void)user_data;
    if(!g_current_archive) return;

    GtkWidget *dialog = gtk_dialog_new_with_buttons("Create Folder",
                                                    GTK_WINDOW(g_main_window),
                                                    GTK_DIALOG_MODAL,
                                                    "_Cancel", GTK_RESPONSE_CANCEL,
                                                    "_Create", GTK_RESPONSE_ACCEPT,
                                                    NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 400, -1);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_widget_set_margin_start(content, 20);
    gtk_widget_set_margin_end(content, 20);
    gtk_widget_set_margin_top(content, 20);
    gtk_widget_set_margin_bottom(content, 20);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *label = gtk_label_new("Enter folder name:");
    gtk_label_set_xalign(GTK_LABEL(label), 0.0);
    gtk_box_append(GTK_BOX(box), label);

    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "New folder");
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    gtk_widget_set_size_request(entry, 300, -1);
    gtk_box_append(GTK_BOX(box), entry);

    gtk_box_append(GTK_BOX(content), box);
    gtk_window_present(GTK_WINDOW(dialog));
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);
    g_signal_connect(dialog, "response", G_CALLBACK(on_newfolder_response), entry);

    GtkWidget *action_area = NULL;
    GtkWidget *kid = gtk_widget_get_first_child(GTK_WIDGET(dialog));
    while(kid){ if(gtk_widget_get_next_sibling(kid) == NULL) action_area = kid; kid = gtk_widget_get_next_sibling(kid); }
    if(action_area){
        gtk_widget_set_margin_top(action_area, 6);
        gtk_widget_set_margin_bottom(action_area, 6);
        gtk_widget_set_margin_start(action_area, 12);
        gtk_widget_set_margin_end(action_area, 12);
        if(GTK_IS_BOX(action_area)) gtk_box_set_spacing(GTK_BOX(action_area), 8);
        GtkWidget *cancel_btn = gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog), GTK_RESPONSE_CANCEL);
        GtkWidget *create_btn = gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);
        if(cancel_btn) {
            gtk_widget_set_margin_end(cancel_btn, 5);
            gtk_widget_set_margin_bottom(cancel_btn, 5);
        }
        if(create_btn) gtk_widget_set_margin_bottom(create_btn, 5);
    }
}

static void on_gui_remove_clicked(GtkButton *btn, gpointer user_data){
    (void)btn;(void)user_data;
    if(!g_current_archive) return;


    GList *selected_rows = NULL;
    GtkWidget *child = gtk_widget_get_first_child(g_list_container);
    while(child){
        if(GTK_IS_LIST_BOX_ROW(child)){
            GtkListBoxRow *row = GTK_LIST_BOX_ROW(child);
            if(gtk_list_box_row_is_selected(row)){
                selected_rows = g_list_append(selected_rows, row);
            }
        }
        child = gtk_widget_get_next_sibling(child);
    }

    if(!selected_rows) return;

    int num_selected = g_list_length(selected_rows);


    GtkWidget *dialog = gtk_dialog_new_with_buttons("Confirm removal",
                                                    GTK_WINDOW(g_main_window),
                                                    GTK_DIALOG_MODAL,
                                                    "_Cancel", GTK_RESPONSE_NO,
                                                    "_Remove", GTK_RESPONSE_YES,
                                                    NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 450, -1);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_widget_set_margin_start(content, 20);
    gtk_widget_set_margin_end(content, 20);
    gtk_widget_set_margin_top(content, 20);
    gtk_widget_set_margin_bottom(content, 20);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);


    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *icon = gtk_image_new_from_icon_name("dialog-warning");
    gtk_image_set_pixel_size(GTK_IMAGE(icon), 48);
    gtk_box_append(GTK_BOX(hbox), icon);

    GtkWidget *msg_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    char title_text[256];
    if(num_selected == 1){
        row_data_t *rd = g_object_get_data(G_OBJECT(selected_rows->data), "baar-row-data");
        snprintf(title_text, sizeof(title_text), "Remove '%s'?", rd->name);
    } else {
        snprintf(title_text, sizeof(title_text), "Remove %d items?", num_selected);
    }
    GtkWidget *title_label = gtk_label_new(NULL);
    char *markup = g_markup_printf_escaped("<span size='large' weight='bold'>%s</span>", title_text);
    gtk_label_set_markup(GTK_LABEL(title_label), markup);
    g_free(markup);
    gtk_label_set_xalign(GTK_LABEL(title_label), 0.0);
    gtk_box_append(GTK_BOX(msg_box), title_label);

    char desc_text[256];
    if(num_selected == 1){
        snprintf(desc_text, sizeof(desc_text), "This item will be permanently removed from the archive.");
    } else {
        snprintf(desc_text, sizeof(desc_text), "Selected items will be permanently removed from the archive.");
    }
    GtkWidget *desc_label = gtk_label_new(desc_text);
    gtk_label_set_xalign(GTK_LABEL(desc_label), 0.0);
    gtk_label_set_wrap(GTK_LABEL(desc_label), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(desc_label), 50);
    gtk_box_append(GTK_BOX(msg_box), desc_label);

    gtk_widget_set_hexpand(msg_box, TRUE);
    gtk_box_append(GTK_BOX(hbox), msg_box);
    gtk_box_append(GTK_BOX(box), hbox);

    gtk_box_append(GTK_BOX(content), box);

    GtkWidget *action_area = NULL;
    GtkWidget *kid = gtk_widget_get_first_child(GTK_WIDGET(dialog));
    while(kid){
        if(gtk_widget_get_next_sibling(kid) == NULL) action_area = kid;
        kid = gtk_widget_get_next_sibling(kid);
    }
    if(action_area){
        gtk_widget_set_margin_top(action_area, 12);
        gtk_widget_set_margin_bottom(action_area, 12);
        gtk_widget_set_margin_start(action_area, 20);
        gtk_widget_set_margin_end(action_area, 20);

        if(GTK_IS_BOX(action_area)){
            gtk_box_set_spacing(GTK_BOX(action_area), 12);
        }

        GtkWidget *cancel_btn = gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog), GTK_RESPONSE_NO);
        if(cancel_btn) gtk_widget_set_margin_end(cancel_btn, 5);
    }


    g_object_set_data(G_OBJECT(dialog), "selected-rows", selected_rows);

    gtk_window_present(GTK_WINDOW(dialog));
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_NO);
    g_signal_connect(dialog, "response", G_CALLBACK(on_remove_response), NULL);
}


static void on_extract_response(GtkDialog *d, int response_id, gpointer user_data){
    (void)user_data;
    if(response_id == GTK_RESPONSE_ACCEPT){
        GFile *folder = gtk_file_chooser_get_file(GTK_FILE_CHOOSER(d));
        if(folder){
            char *dest_path = g_file_get_path(folder);
            if(dest_path){

                GList *selected_rows = g_object_get_data(G_OBJECT(d), "selected-rows");
                int count = g_list_length(selected_rows);

                if(count > 0){

                    int has_encrypted = 0;
                    if(!g_current_is_libarchive){
                        for(GList *l = selected_rows; l != NULL; l = l->next){
                            GtkListBoxRow *row = GTK_LIST_BOX_ROW(l->data);
                            row_data_t *rd = g_object_get_data(G_OBJECT(row), "baar-row-data");
                            if(!rd) continue;

                            for(uint32_t i=0; i<g_current_index.n; i++){
                                entry_t *e = &g_current_index.entries[i];
                                if(e->id == rd->id && (e->flags & 2)){
                                    has_encrypted = 1;
                                    break;
                                }
                            }
                            if(has_encrypted) break;
                        }


                        if(has_encrypted && !g_archive_password){
                            if(!show_password_dialog("Selected files contain encrypted entries.\nPlease enter the password:")){

                                g_free(dest_path);
                                g_object_unref(folder);
                                gtk_window_destroy(GTK_WINDOW(d));
                                return;
                            }
                        }
                    }

                    char msg[256];
                    snprintf(msg, sizeof(msg), "Extracting %d files...", count);
                    show_progress_dialog("Extraction", msg);

                    if(g_current_is_libarchive){

                        int res = la_extract(g_current_archive, dest_path, g_archive_password);
                        if (res != 0 && !g_archive_password && g_main_window) {
                            if (show_password_dialog("Extraction failed or archive may be encrypted. Enter password to retry:")) {

                                if (g_archive_password && g_archive_password[0]) g_archive_was_encrypted = 1;

                                res = la_extract(g_current_archive, dest_path, g_archive_password);
                            }
                        }

                        (void)res;
                        update_progress(1.0, "Done!");
                        g_timeout_add(500, destroy_window_cb, g_progress_dialog);
                        g_progress_dialog = NULL;
                        g_progress_bar = NULL;
                        g_progress_label = NULL;
                    } else {

                        FILE *f = fopen(g_current_archive, "rb");
                        if(f){
                            index_t idx = load_index(f);
                            int extracted = 0;

                        for(GList *l = selected_rows; l != NULL; l = l->next){
                            GtkListBoxRow *row = GTK_LIST_BOX_ROW(l->data);
                            row_data_t *rd = g_object_get_data(G_OBJECT(row), "baar-row-data");
                            if(!rd || !rd->name) continue;


                            size_t nlen = strlen(rd->name);
                            if(nlen > 0 && rd->name[nlen-1] == '/') continue;


                            for(uint32_t i=0; i<idx.n; i++){
                                entry_t *e = &idx.entries[i];
                                if(e->id == rd->id && !(e->flags & 4)){

                                    char out_path[4096];
                                    snprintf(out_path, sizeof(out_path), "%s/%s", dest_path, e->name);


                                    char *dup = strdup(out_path);
                                    char *dir = dirname(dup);
                                    char cmd[8192];
                                    snprintf(cmd, sizeof(cmd), "mkdir -p \"%s\"", dir);
                                    system(cmd);
                                    free(dup);


                                    fseek(f, e->data_offset, SEEK_SET);
                                    unsigned char *enc = malloc(e->comp_size);
                                    fread(enc, 1, e->comp_size, f);


                                    unsigned char *out = NULL;
                                    uLong outsz = e->uncomp_size;
                                    int success = 0;
                                    int attempts = 0;
                                    const int max_attempts = 3;

                                    while(attempts < max_attempts && !success){
                                        attempts++;

                                        unsigned char *enc_copy = malloc(e->comp_size);
                                        if(!enc_copy) break;
                                        memcpy(enc_copy, enc, e->comp_size);

                                        if(e->flags & 2){
                                            const char *pwd = g_archive_password ? g_archive_password : "";
                                            xor_buf(enc_copy, e->comp_size, pwd);
                                        }

                                        out = malloc(e->uncomp_size + 1);
                                        if(!out){ free(enc_copy); break; }

                                        if(e->flags & 1){
                                            int zr = uncompress(out, &outsz, enc_copy, e->comp_size);
                                            if(zr != Z_OK){

                                                free(enc_copy);
                                                free(out);
                                                out = NULL;
                                                if(attempts < max_attempts){
                                                    if(!show_password_dialog("Decryption failed (bad password?).\nPlease enter the password:")){

                                                        break;
                                                    }
                                                    continue;
                                                } else break;
                                            }
                                        } else {
                                            memcpy(out, enc_copy, e->comp_size);
                                            outsz = e->comp_size;
                                        }


                                        if((e->flags & 2) && e->crc32 != 0){
                                            uLong computed_crc = crc32(0L, Z_NULL, 0);
                                            computed_crc = crc32(computed_crc, out, outsz);
                                            if(computed_crc != e->crc32){

                                                free(enc_copy);
                                                free(out);
                                                out = NULL;
                                                if(attempts < max_attempts){
                                                    if(!show_password_dialog("Incorrect password for this file.\nPlease enter the password:")){

                                                        break;
                                                    }
                                                    continue;
                                                } else break;
                                            }
                                        }


                                        free(enc_copy);
                                        success = 1;
                                    }

                                    if(!success){

                                        if(out) free(out);
                                        free(enc);
                                        break;
                                    }


                                    FILE *outf = fopen(out_path, "wb");
                                    if(outf){
                                        fwrite(out, 1, outsz, outf);
                                        fclose(outf);


                                        chmod(out_path, e->mode);
                                        if(geteuid() == 0) safe_chown_path(out_path, e->uid, e->gid);
                                        struct utimbuf times;
                                        times.actime = e->mtime;
                                        times.modtime = e->mtime;
                                        utime(out_path, &times);

                                        extracted++;
                                        double frac = (double)extracted / (double)count;
                                        char pbuf[256];
                                        char bn[PATH_MAX]; compact_basename(e->name, bn, sizeof(bn));
                                        snprintf(pbuf, sizeof(pbuf), "%d/%d: %.200s", extracted, count, bn);
                                        update_progress(frac, pbuf);
                                    }

                                    free(enc);
                                    free(out);
                                    break;
                                }
                            }
                        }

                        update_progress(1.0, "Done!");
                        free_index(&idx);
                        fclose(f);


                        g_timeout_add(500, destroy_window_cb, g_progress_dialog);
                        g_progress_dialog = NULL;
                        g_progress_bar = NULL;
                        g_progress_label = NULL;
                        }
                    }
                }
                g_free(dest_path);
            }
            g_object_unref(folder);
        }
    }


    GList *selected_rows = g_object_get_data(G_OBJECT(d), "selected-rows");
    if(selected_rows) g_list_free(selected_rows);

    gtk_window_destroy(GTK_WINDOW(d));
}

static void on_gui_extract_clicked(GtkButton *btn, gpointer user_data){
    (void)btn;(void)user_data;
    if(!g_current_archive) return;


    GList *selected_rows = NULL;
    GtkWidget *child = gtk_widget_get_first_child(g_list_container);
    while(child){
        if(GTK_IS_LIST_BOX_ROW(child)){
            GtkListBoxRow *row = GTK_LIST_BOX_ROW(child);
            if(gtk_list_box_row_is_selected(row)){
                selected_rows = g_list_append(selected_rows, row);
            }
        }
        child = gtk_widget_get_next_sibling(child);
    }

    if(!selected_rows) return;


    GtkWidget *chooser = gtk_file_chooser_dialog_new("Select folder for extraction",
                                                     GTK_WINDOW(g_main_window),
                                                     GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
                                                     "_Cancel", GTK_RESPONSE_CANCEL,
                                                     "_Extract", GTK_RESPONSE_ACCEPT,
                                                     NULL);


    g_object_set_data(G_OBJECT(chooser), "selected-rows", selected_rows);

    gtk_window_present(GTK_WINDOW(chooser));
    g_signal_connect(chooser, "response", G_CALLBACK(on_extract_response), NULL);
}


static void on_compact_response(GtkDialog *d, int response_id, gpointer user_data){
    (void)user_data;
    if(response_id == GTK_RESPONSE_YES){
        if(g_current_archive){
            (void)rebuild_archive(g_current_archive, NULL, 0, 0);

            FILE *f = fopen(g_current_archive, "rb");
            if(f){ free_index(&g_current_index); g_current_index = load_index(f); fclose(f); }
            populate_list_from_index();
            update_info_panel();
        }
    }
    gtk_window_destroy(GTK_WINDOW(d));
}

static void on_gui_compact_clicked(GtkButton *btn, gpointer user_data){
    (void)btn;(void)user_data;
    if(!g_current_archive) return;
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Compact archive",
                                                    GTK_WINDOW(g_main_window),
                                                    GTK_DIALOG_MODAL,
                                                    "_Cancel", GTK_RESPONSE_NO,
                                                    "_Compact", GTK_RESPONSE_YES,
                                                    NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 420, -1);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_widget_set_margin_start(content, 20);
    gtk_widget_set_margin_end(content, 20);
    gtk_widget_set_margin_top(content, 20);
    gtk_widget_set_margin_bottom(content, 20);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *icon = gtk_image_new_from_icon_name("edit-clear");
    gtk_image_set_pixel_size(GTK_IMAGE(icon), 48);
    gtk_box_append(GTK_BOX(box), icon);
    GtkWidget *lbl = gtk_label_new("This will permanently remove deleted entries and compact the archive. Proceed?");
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_label_set_wrap(GTK_LABEL(lbl), TRUE);
    gtk_box_append(GTK_BOX(box), lbl);
    gtk_box_append(GTK_BOX(content), box);

    GtkWidget *action_area = NULL;
    GtkWidget *kid = gtk_widget_get_first_child(GTK_WIDGET(dialog));
    while(kid){ if(gtk_widget_get_next_sibling(kid) == NULL) action_area = kid; kid = gtk_widget_get_next_sibling(kid); }
    if(action_area){ gtk_widget_set_margin_top(action_area, 12); gtk_widget_set_margin_bottom(action_area, 12); gtk_widget_set_margin_start(action_area, 20); gtk_widget_set_margin_end(action_area, 20); if(GTK_IS_BOX(action_area)) gtk_box_set_spacing(GTK_BOX(action_area), 12); GtkWidget *cancel_btn = gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog), GTK_RESPONSE_NO); if(cancel_btn) gtk_widget_set_margin_end(cancel_btn, 5); }
    gtk_window_present(GTK_WINDOW(dialog));
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_NO);
    g_signal_connect(dialog, "response", G_CALLBACK(on_compact_response), NULL);
}
static void on_gui_close_clicked(GtkButton *btn, gpointer user_data){ (void)btn;(void)user_data; close_archive_gui(); }


static void on_row_activated(GtkListBox *box, GtkListBoxRow *row, gpointer user_data){
    (void)box; (void)user_data;
    if(!row) return;
    row_data_t *rd = g_object_get_data(G_OBJECT(row), "baar-row-data");
    if(!rd) return;


    if(strcmp(rd->name, "..") == 0){
        if(!g_current_prefix) return;

        char *tmp = strdup(g_current_prefix);
        size_t tlen = strlen(tmp);
        if(tlen == 0){ free(tmp); return; }


        if(tmp[tlen-1] == '/') tmp[tlen-1] = '\0';


        char *last = strrchr(tmp, '/');
        if(last){

            size_t newlen = (last - tmp) + 1;
            char *np = strndup(tmp, newlen);
            free(g_current_prefix);
            g_current_prefix = np;
        } else {
            free(g_current_prefix);
            g_current_prefix = NULL;
        }
        free(tmp);

        populate_list_from_index();
        update_info_panel();
        return;
    }


    size_t n = strlen(rd->name);
    if(n>0 && rd->name[n-1]=='/'){

    if(g_current_prefix) free(g_current_prefix);
    g_current_prefix = strdup(rd->name);

    populate_list_from_index();
    update_info_panel();
}
    else {

        if(g_current_archive){

            if(strcmp(rd->name, "..") == 0) return;

            char temp_dir[PATH_MAX];
            if(prepare_temp_dir_for_archive(g_current_archive, "baar_extract",
                                            temp_dir, sizeof(temp_dir), 1) != 0){
                g_warning("Failed to create temporary directory for extraction");
                return;
            }


            const char *base = strrchr(rd->name, '/');
            base = base ? base+1 : rd->name;
            char out_path[PATH_MAX * 2];
            snprintf(out_path, sizeof(out_path), "%s/%s", temp_dir, base);


            int suffix = 1;
            while(access(out_path, F_OK) == 0){
                snprintf(out_path, sizeof(out_path), "%s/%s.%d", temp_dir, base, suffix++);
                if(suffix > 1000) break;
            }

            if(g_current_is_libarchive){

                int extracted_ok = 0;
                for(int attempt = 0; attempt < 2 && !extracted_ok; attempt++){
                    struct archive *a = archive_read_new();
                    archive_read_support_format_all(a);
                    archive_read_support_filter_all(a);
                    if (g_archive_password) archive_read_add_passphrase(a, g_archive_password);

                    int open_r = archive_read_open_filename(a, g_current_archive, 10240);
                    if (open_r != ARCHIVE_OK) {
                        (void)archive_error_string(a);
                        archive_read_free(a);

                        if (attempt == 0 && g_main_window && !g_archive_password) {
                            if (!show_password_dialog("Archive may be encrypted. Enter password to view file or Cancel to abort.")) {
                                break;
                            }

                            if (g_archive_password && g_archive_password[0]) g_archive_was_encrypted = 1;

                            continue;
                        }
                        break;
                    }

                    struct archive_entry *entry;
                    int found = 0;
                    int read_error = 0;
                    while ((archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
                        const char *entry_name = archive_entry_pathname(entry);
                        if(strcmp(entry_name, rd->name) == 0){
                            found = 1;

                            FILE *of = fopen(out_path, "wb");
                            if(of){
                                const void *buff;
                                size_t size;
                                int64_t offset;
                                int rdcode;
                                while ((rdcode = archive_read_data_block(a, &buff, &size, &offset)) == ARCHIVE_OK) {
                                    if (fwrite(buff, 1, size, of) != size) {
                                        read_error = 1;
                                        break;
                                    }
                                }
                                if (rdcode != ARCHIVE_EOF && rdcode != ARCHIVE_OK) {

                                    const char *estr = archive_error_string(a);
                                    (void)estr;
                                    read_error = 1;
                                }
                                fclose(of);

                                if(!read_error){

                                    mode_t mode = archive_entry_mode(entry);
                                    chmod(out_path, mode);
                                    if(geteuid() == 0) safe_chown_path(out_path, (uint32_t)archive_entry_uid(entry), (uint32_t)archive_entry_gid(entry));
                                    time_t mtime = archive_entry_mtime(entry);
                                    struct utimbuf times;
                                    times.actime = mtime;
                                    times.modtime = mtime;
                                    utime(out_path, &times);
                                    extracted_ok = 1;
                                } else {

                                    unlink(out_path);
                                }
                            }
                            break;
                        }
                    }

                    archive_read_free(a);

                    if (!found && !extracted_ok) {

                        break;
                    }

                    if (read_error && attempt == 0 && g_main_window && !g_archive_password) {

                        if (!show_password_dialog("Reading file failed (possibly encrypted). Enter password to retry:")) {
                            break;
                        }

                        if (g_archive_password && g_archive_password[0]) g_archive_was_encrypted = 1;

                    }
                }

                if (extracted_ok) {

                    pid_t pid = fork();
                    if(pid == 0){
                        execlp("xdg-open", "xdg-open", out_path, (char*)NULL);
                        _exit(127);
                    }
                }
            } else {

                FILE *f = fopen(g_current_archive, "rb");
                if(f){
                    index_t idx = load_index(f);
                    for(uint32_t i=0;i<idx.n;i++){
                        entry_t *e = &idx.entries[i];
                        if(e->id == rd->id && !(e->flags & 4)){

                            size_t elen = strlen(e->name);
                            if(elen>0 && e->name[elen-1]=='/') break;


                            if(e->flags & 2){
                                int entered = show_password_dialog("This file is encrypted.\nEnter password to use, or Cancel to use the saved password:");
                                if(!entered){
                                    if(!g_archive_password){

                                        break;
                                    }

                                }
                            }

                            fseek(f, e->data_offset, SEEK_SET);
                            unsigned char *enc = malloc(e->comp_size);
                            if(!enc) break;
                            fread(enc,1,e->comp_size,f);


                            unsigned char *out = NULL;
                            uLong outsz = e->uncomp_size;
                            int success = 0;
                            int attempts = 0;
                            const int max_attempts = 3;

                            while(attempts < max_attempts && !success){
                                attempts++;
                                unsigned char *enc_copy = malloc(e->comp_size);
                                if(!enc_copy) break;
                                memcpy(enc_copy, enc, e->comp_size);

                                if(e->flags & 2){
                                    const char *pwd = g_archive_password ? g_archive_password : "";
                                    xor_buf(enc_copy, e->comp_size, pwd);
                                }

                                out = malloc(e->uncomp_size + 1);
                                if(!out){ free(enc_copy); break; }

                                if(e->flags & 1){
                                    int res = uncompress(out, &outsz, enc_copy, e->comp_size);
                                    if(res != Z_OK){
                                        free(enc_copy);
                                        free(out);
                                        out = NULL;
                                        if(attempts < max_attempts){
                                            if(!show_password_dialog("Decompression failed (bad password?).\nPlease enter the password:")){

                                                break;
                                            }
                                            continue;
                                        } else break;
                                    }
                                } else { memcpy(out, enc_copy, e->comp_size); outsz = e->comp_size; }

                                if((e->flags & 2) && e->crc32 != 0){
                                    uLong computed_crc = crc32(0L, Z_NULL, 0);
                                    computed_crc = crc32(computed_crc, out, outsz);
                                    if(computed_crc != e->crc32){
                                        free(enc_copy);
                                        free(out);
                                        out = NULL;
                                        if(attempts < max_attempts){
                                            if(!show_password_dialog("Incorrect password for this file.\nPlease enter the password:")){
                                                break;
                                            }
                                            continue;
                                        } else break;
                                    }
                                }

                                free(enc_copy);
                                success = 1;
                            }

                            if(!success){ if(out) free(out); free(enc); break; }


                            FILE *of = fopen(out_path, "wb");
                            if(of){ fwrite(out,1,outsz,of); fclose(of);
                                chmod(out_path, e->mode);
                                if(geteuid() == 0) safe_chown_path(out_path, e->uid, e->gid);
                                struct utimbuf times; times.actime = e->mtime; times.modtime = e->mtime; utime(out_path, &times);
                            }

                            free(enc); free(out);


                            pid_t pid = fork();
                            if(pid == 0){

                                execlp("xdg-open", "xdg-open", out_path, (char*)NULL);
                                _exit(127);
                            }
                            break;
                        }
                    }
                    free_index(&idx);
                    fclose(f);
                }
            }
        }
    }
}


static GdkContentProvider* on_drag_prepare(GtkDragSource *source, double x, double y, gpointer user_data){
    (void)source; (void)x; (void)y; (void)user_data;

    if(!g_current_archive || !g_list_container) {
        return NULL;
    }




    GList *selected_rows = NULL;
    GtkWidget *child = gtk_widget_get_first_child(g_list_container);
    while(child){
        if(GTK_IS_LIST_BOX_ROW(child)){
            GtkListBoxRow *row = GTK_LIST_BOX_ROW(child);
            if(gtk_list_box_row_is_selected(row)){
                selected_rows = g_list_append(selected_rows, row);
            }
        }
        child = gtk_widget_get_next_sibling(child);
    }

    if(!selected_rows) {
        return NULL;
    }

    int num_selected = g_list_length(selected_rows);
    if(num_selected == 0){
        g_list_free(selected_rows);
        return NULL;
    }


    char temp_dir[PATH_MAX];
    if(prepare_temp_dir_for_archive(g_current_archive, "baar_drag",
                                    temp_dir, sizeof(temp_dir), 1) != 0){
        g_warning("Failed to create temporary directory for drag export");
        g_list_free(selected_rows);
        return NULL;
    }


    int extracted_capacity = num_selected * 10;
    GFile **extracted_files = malloc(sizeof(GFile*) * extracted_capacity);
    int extracted_count = 0;


    if(g_current_is_libarchive){

        for(GList *l = selected_rows; l != NULL; l = l->next){
            GtkListBoxRow *row = GTK_LIST_BOX_ROW(l->data);
            row_data_t *rd = g_object_get_data(G_OBJECT(row), "baar-row-data");
            if(!rd || !rd->name) continue;


            size_t nlen = strlen(rd->name);
            int is_folder = (nlen > 0 && rd->name[nlen-1] == '/');

            if(is_folder){


                char folder_name[256];
                if(nlen > 1 && nlen - 1 < sizeof(folder_name)){
                    memcpy(folder_name, rd->name, nlen - 1);
                    folder_name[nlen - 1] = '\0';
                } else {
                    continue;
                }


                char *last_slash = strrchr(folder_name, '/');
                const char *base_folder = last_slash ? (last_slash + 1) : folder_name;


                char base_folder_path[PATH_MAX * 2];
                snprintf(base_folder_path, sizeof(base_folder_path), "%s/%s", temp_dir, base_folder);
                mkdir(base_folder_path, 0755);
                /* ownership for libarchive-extracted folders is handled by libarchive (if privileged) */


                for(uint32_t i=0; i<g_current_index.n; i++){
                    entry_t *e = &g_current_index.entries[i];
                    if(e->flags & 4) continue;

                    size_t elen = strlen(e->name);
                    if(strncmp(e->name, rd->name, nlen) == 0 && elen > nlen){

                        const char *relative = e->name + nlen;


                        if(relative[strlen(relative)-1] == '/') continue;


                        char dest_path[2048];
                        snprintf(dest_path, sizeof(dest_path), "%s/%s/%s", temp_dir, base_folder, relative);


                        if(la_extract_to_path(g_current_archive, e->name, dest_path, g_archive_password) != 0){

                            continue;
                        }
                    }
                }


                if(extracted_count >= extracted_capacity){
                    if(extracted_capacity > INT_MAX / 2){
                        continue;
                    }
                    extracted_capacity *= 2;
                    GFile **tmp = realloc(extracted_files, sizeof(GFile*) * extracted_capacity);
                    if(!tmp){
                        continue;
                    }
                    extracted_files = tmp;
                }
                extracted_files[extracted_count++] = g_file_new_for_path(base_folder_path);

            } else {

                char *base = basename(rd->name);
                char temp_path[PATH_MAX * 2];
                snprintf(temp_path, sizeof(temp_path), "%s/%s", temp_dir, base);


                if(la_extract_to_path(g_current_archive, rd->name, temp_path, g_archive_password) == 0){

                    if(extracted_count >= extracted_capacity){
                        if(extracted_capacity > INT_MAX / 2){
                            continue;
                        }
                        extracted_capacity *= 2;
                        GFile **tmp = realloc(extracted_files, sizeof(GFile*) * extracted_capacity);
                        if(!tmp){
                            continue;
                        }
                        extracted_files = tmp;
                    }
                    extracted_files[extracted_count++] = g_file_new_for_path(temp_path);
                }
            }
        }

        g_list_free(selected_rows);


        if(extracted_count > 0){
            GdkFileList *file_list = gdk_file_list_new_from_array(extracted_files, extracted_count);
            GdkContentProvider *provider = gdk_content_provider_new_typed(GDK_TYPE_FILE_LIST, file_list);
            g_object_unref(file_list);
            free(extracted_files);
            return provider;
        }

        free(extracted_files);
        return NULL;

    } else {



        GString *id_list = g_string_new("");
        for(GList *l = selected_rows; l != NULL; l = l->next){
            GtkListBoxRow *row = GTK_LIST_BOX_ROW(l->data);
            row_data_t *rd = g_object_get_data(G_OBJECT(row), "baar-row-data");
            if(!rd) continue;

            if(id_list->len > 0) g_string_append_c(id_list, ',');
            g_string_append_printf(id_list, "%u", rd->id);
        }

        if(id_list->len == 0){
            g_string_free(id_list, TRUE);
            g_list_free(selected_rows);
            free(extracted_files);
            return NULL;
        }


        FILE *f = fopen(g_current_archive, "rb");
        if(!f){
            g_string_free(id_list, TRUE);
            g_list_free(selected_rows);
            free(extracted_files);
            return NULL;
        }

        index_t idx = load_index(f);


        for(GList *l = selected_rows; l != NULL; l = l->next){
        GtkListBoxRow *row = GTK_LIST_BOX_ROW(l->data);
        row_data_t *rd = g_object_get_data(G_OBJECT(row), "baar-row-data");
        if(!rd || !rd->name) continue;


        size_t nlen = strlen(rd->name);
        int is_folder = (nlen > 0 && rd->name[nlen-1] == '/');

        if(is_folder){


            char folder_name[256];
            if(nlen > 1 && nlen - 1 < sizeof(folder_name)){
                memcpy(folder_name, rd->name, nlen - 1);
                folder_name[nlen - 1] = '\0';
            } else {
                continue;
            }


            char *last_slash = strrchr(folder_name, '/');
            const char *base_folder = last_slash ? (last_slash + 1) : folder_name;


            char base_folder_path[PATH_MAX * 2];
            snprintf(base_folder_path, sizeof(base_folder_path), "%s/%s", temp_dir, base_folder);
            mkdir(base_folder_path, 0755);


            for(uint32_t i=0; i<idx.n; i++){
                entry_t *e = &idx.entries[i];
                if(e->flags & 4) continue;


                size_t elen = strlen(e->name);
                if(strncmp(e->name, rd->name, nlen) == 0 && elen > nlen){

                    const char *relative = e->name + nlen;


                    if(relative[strlen(relative)-1] == '/') continue;


                    char temp_path[PATH_MAX * 2];
                    snprintf(temp_path, sizeof(temp_path), "%s/%s/%s", temp_dir, base_folder, relative);


                    char *dir_end = strrchr(temp_path, '/');
                    if(dir_end){
                        *dir_end = '\0';

                        char *create_start = temp_path + strlen(temp_dir) + 1;
                        for(char *c = create_start; *c; c++){
                            if(*c == '/'){
                                *c = '\0';
                                mkdir(temp_path, 0755);
                                if(geteuid() == 0) safe_chown_path(temp_path, e->uid, e->gid);
                                *c = '/';
                            }
                        }
                        mkdir(temp_path, 0755);
                        *dir_end = '/';
                    }


                    fseek(f, e->data_offset, SEEK_SET);
                    unsigned char *enc = malloc(e->comp_size);
                    if(!enc) continue;
                    fread(enc, 1, e->comp_size, f);


                    if(e->flags & 2){
                        xor_buf(enc, e->comp_size, g_archive_password ? g_archive_password : "");
                    }

                    unsigned char *out = malloc(e->uncomp_size + 1);
                    if(!out){
                        free(enc);
                        continue;
                    }
                    uLong outsz = e->uncomp_size;

                    if(e->flags & 1){
                        int res = uncompress(out, &outsz, enc, e->comp_size);
                        if(res != Z_OK){
                            free(enc);
                            free(out);
                            continue;
                        }
                    } else {
                        memcpy(out, enc, e->comp_size);
                    }


                    FILE *outf = fopen(temp_path, "wb");
                    if(outf){
                        fwrite(out, 1, outsz, outf);
                        fclose(outf);


                        chmod(temp_path, e->mode);
                        if(geteuid() == 0) safe_chown_path(temp_path, e->uid, e->gid);
                        struct utimbuf times;
                        times.actime = e->mtime;
                        times.modtime = e->mtime;
                        utime(temp_path, &times);
                    }

                    free(enc);
                    free(out);
                }
            }


            if(extracted_count >= extracted_capacity){
                if(extracted_capacity > INT_MAX / 2){
                    goto skip_folder;
                }
                extracted_capacity *= 2;
                GFile **tmp = realloc(extracted_files, sizeof(GFile*) * extracted_capacity);
                if(!tmp){
                    goto skip_folder;
                }
                extracted_files = tmp;
            }
            extracted_files[extracted_count++] = g_file_new_for_path(base_folder_path);
            skip_folder:

        } else {

            char *base = basename(rd->name);
            char temp_path[PATH_MAX * 2];
            snprintf(temp_path, sizeof(temp_path), "%s/%s", temp_dir, base);


            for(uint32_t i=0; i<idx.n; i++){
                entry_t *e = &idx.entries[i];
                if(e->id == rd->id){

                    fseek(f, e->data_offset, SEEK_SET);
                    unsigned char *enc = malloc(e->comp_size);
                    if(!enc){
                        fclose(f);
                        free_index(&idx);
                        g_list_free(selected_rows);
                        free(extracted_files);
                        return NULL;
                    }
                    fread(enc, 1, e->comp_size, f);


                    if(e->flags & 2){
                        xor_buf(enc, e->comp_size, g_archive_password ? g_archive_password : "");
                    }

                    unsigned char *out = malloc(e->uncomp_size + 1);
                    if(!out){
                        free(enc);
                        fclose(f);
                        free_index(&idx);
                        g_list_free(selected_rows);
                        free(extracted_files);
                        return NULL;
                    }
                    uLong outsz = e->uncomp_size;

                    if(e->flags & 1){
                        int res = uncompress(out, &outsz, enc, e->comp_size);
                        if(res != Z_OK){
                            free(enc);
                            free(out);
                            break;
                        }
                    } else {
                        memcpy(out, enc, e->comp_size);
                    }


                    FILE *outf = fopen(temp_path, "wb");
                    if(outf){
                        fwrite(out, 1, outsz, outf);
                        fclose(outf);


                        chmod(temp_path, e->mode);
                        if(geteuid() == 0) safe_chown_path(temp_path, e->uid, e->gid);
                        struct utimbuf times;
                        times.actime = e->mtime;
                        times.modtime = e->mtime;
                        utime(temp_path, &times);


                        if(extracted_count >= extracted_capacity){

                            if(extracted_capacity > INT_MAX / 2){
                                free(enc);
                                free(out);
                                break;
                            }
                            extracted_capacity *= 2;
                            GFile **tmp = realloc(extracted_files, sizeof(GFile*) * extracted_capacity);
                            if(!tmp){
                                free(enc);
                                free(out);
                                break;
                            }
                            extracted_files = tmp;
                        }
                        extracted_files[extracted_count++] = g_file_new_for_path(temp_path);
                    }

                    free(enc);
                    free(out);
                    break;
                }
            }
        }
    }

        free_index(&idx);
        fclose(f);
        g_string_free(id_list, TRUE);
        g_list_free(selected_rows);


        if(extracted_count > 0){
            GdkFileList *file_list = gdk_file_list_new_from_array(extracted_files, extracted_count);
            GdkContentProvider *provider = gdk_content_provider_new_typed(GDK_TYPE_FILE_LIST, file_list);
            g_object_unref(file_list);
            free(extracted_files);
            return provider;
        }

        free(extracted_files);
        return NULL;
    }
}

static void on_drag_begin(GtkDragSource *source, GdkDrag *drag, gpointer user_data){
    (void)source; (void)drag; (void)user_data;

    g_internal_drag_active = 1;
}

static gboolean g_clear_internal_drag_flag(gpointer user_data){
    (void)user_data;
    g_internal_drag_active = 0;
    return FALSE;
}

static void on_drag_end(GtkDragSource *source, GdkDrag *drag, gboolean delete_data, gpointer user_data){
    (void)source; (void)drag; (void)delete_data; (void)user_data;



    g_timeout_add(500, (GSourceFunc)g_clear_internal_drag_flag, NULL);
}


static gboolean on_internal_drop_accept(GtkDropTarget *target, GdkDrop *drop, gpointer user_data){
    (void)target; (void)drop;
    const char *target_folder = (const char*)user_data;

    (void)target_folder; (void)g_internal_drag_active;


    if(g_current_is_libarchive && g_internal_drag_active){
        return FALSE;
    }


    if(g_internal_drag_active) {
        return TRUE;
    }


    return FALSE;
}


static gboolean on_internal_drop(GtkDropTarget *target, const GValue *value, double x, double y, gpointer user_data){
    (void)target; (void)x; (void)y; (void)value;


    const char *target_folder = (const char*)user_data;

    (void)target_folder; (void)g_internal_drag_active;

    if(!target_folder || !g_current_archive) {
        return FALSE;
    }


    if(g_current_is_libarchive){

        g_internal_drag_active = 0;
        return FALSE;
    }


    if(!g_internal_drag_active){
        return FALSE;
    }


    uint32_t *ids = NULL;
    int id_count = 0;


    GList *selected_rows = NULL;
    GtkWidget *child = gtk_widget_get_first_child(g_list_container);
    while(child){
        if(GTK_IS_LIST_BOX_ROW(child)){
            GtkListBoxRow *row = GTK_LIST_BOX_ROW(child);
            if(gtk_list_box_row_is_selected(row)) selected_rows = g_list_append(selected_rows, row);
        }
        child = gtk_widget_get_next_sibling(child);
    }

    if(selected_rows == NULL){

        g_internal_drag_active = 0;
        return FALSE;
    }

    for(GList *l = selected_rows; l != NULL; l = l->next){
        GtkListBoxRow *row = GTK_LIST_BOX_ROW(l->data);
        row_data_t *rd = g_object_get_data(G_OBJECT(row), "baar-row-data");
        if(!rd) continue;
        ids = realloc(ids, sizeof(uint32_t) * (id_count + 1));
        ids[id_count++] = rd->id;
    }
    g_list_free(selected_rows);

    if(id_count == 0){
        if(ids) free(ids);
        g_internal_drag_active = 0;
        return FALSE;
    }


    size_t target_len = strlen(target_folder);
    int target_is_folder = (target_len == 0) ||
                           (strcmp(target_folder, "..") == 0) ||
                           (target_len > 0 && target_folder[target_len-1] == '/');


    FILE *f = fopen(g_current_archive, "r+b");
    if(!f){
        free(ids);
        g_internal_drag_active = 0;
        return FALSE;
    }

    index_t idx = load_index(f);


    if(!target_is_folder){

        for(int j = 0; j < id_count; j++){
            for(uint32_t i = 0; i < idx.n; i++){
                entry_t *e = &idx.entries[i];
                if(e->id == ids[j] && !(e->flags & 4)){
                    size_t item_len = strlen(e->name);
                    int item_is_file = (item_len > 0 && e->name[item_len-1] != '/');

                    if(item_is_file){

                        free(ids);
                        free_index(&idx);
                        fclose(f);
                        g_internal_drag_active = 0;
                        return FALSE;
                    }
                }
            }
        }
    }

    int modified = 0;


    for(int j = 0; j < id_count; j++){
        uint32_t move_id = ids[j];


        for(uint32_t i = 0; i < idx.n; i++){
            entry_t *e = &idx.entries[i];
            if(e->id == move_id && !(e->flags & 4)){

                char temp_name[4096];
                strncpy(temp_name, e->name, sizeof(temp_name) - 1);
                temp_name[sizeof(temp_name) - 1] = '\0';

                size_t len = strlen(temp_name);
                if (len > 0 && temp_name[len - 1] == '/') {
                    temp_name[len - 1] = '\0';
                }

                const char *basename_part = strrchr(temp_name, '/');
                if(basename_part) basename_part++;
                else basename_part = temp_name;

                int is_dir = (strlen(e->name) > 0 && e->name[strlen(e->name)-1] == '/');


                size_t tflen = strlen(target_folder);


                const char *parent_end = strrchr(e->name, '/');
                if(parent_end && is_dir && parent_end == &e->name[strlen(e->name)-1]){

                    char temp_copy[4096];
                    strncpy(temp_copy, e->name, sizeof(temp_copy) - 1);
                    temp_copy[sizeof(temp_copy) - 1] = '\0';
                    temp_copy[strlen(temp_copy) - 1] = '\0';
                    parent_end = strrchr(temp_copy, '/');
                    if(parent_end){
                        size_t parent_len = (parent_end - temp_copy) + 1;
                        if(tflen == parent_len && strncmp(target_folder, temp_copy, parent_len) == 0){
                            continue;
                        }
                    } else if(tflen == 0){
                        continue;
                    }
                } else if(parent_end){

                    size_t parent_len = (parent_end - e->name) + 1;
                    if(tflen == parent_len && strncmp(target_folder, e->name, parent_len) == 0){
                        continue;
                    }
                } else if(tflen == 0){
                    continue;
                }


                size_t new_len = strlen(target_folder) + strlen(basename_part) + (is_dir ? 2 : 1);
                char *new_name = malloc(new_len);
                snprintf(new_name, new_len, "%s%s%s", target_folder, basename_part, is_dir ? "/" : "");


                int target_exists = 0;
                for(uint32_t j = 0; j < idx.n; j++){
                    if(j != i && strcmp(idx.entries[j].name, new_name) == 0 && !(idx.entries[j].flags & 4)){
                        target_exists = 1;
                        break;
                    }
                }

                if(target_exists){

                    free_index(&idx);
                    fclose(f);
                    free(ids);
                    g_internal_drag_active = 0;


                    file_overwrite_data_t *dialog_data = malloc(sizeof(file_overwrite_data_t));
                    if(dialog_data){
                        dialog_data->src_name = strdup(e->name);
                        dialog_data->target_name = new_name;
                        dialog_data->src_id = e->id;
                        dialog_data->target_folder = strdup(target_folder);


                        GtkWidget *dialog = gtk_dialog_new_with_buttons("File already exists",
                                                                        GTK_WINDOW(g_main_window),
                                                                        GTK_DIALOG_MODAL,
                                                                        "_Cancel", GTK_RESPONSE_CANCEL,
                                                                        "_Overwrite", GTK_RESPONSE_ACCEPT,
                                                                        NULL);
                        gtk_window_set_default_size(GTK_WINDOW(dialog), 450, -1);

                        GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
                        gtk_widget_set_margin_start(content, 20);
                        gtk_widget_set_margin_end(content, 20);
                        gtk_widget_set_margin_top(content, 20);
                        gtk_widget_set_margin_bottom(content, 20);

                        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);


                        GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
                        GtkWidget *icon = gtk_image_new_from_icon_name("dialog-question");
                        gtk_image_set_pixel_size(GTK_IMAGE(icon), 48);
                        gtk_box_append(GTK_BOX(hbox), icon);

                        GtkWidget *msg_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
                        GtkWidget *title_label = gtk_label_new(NULL);
                        char *markup = g_markup_printf_escaped("<span size='large' weight='bold'>%s already exists</span>", basename_part);
                        gtk_label_set_markup(GTK_LABEL(title_label), markup);
                        g_free(markup);
                        gtk_label_set_xalign(GTK_LABEL(title_label), 0.0);
                        gtk_box_append(GTK_BOX(msg_box), title_label);

                        GtkWidget *desc_label = gtk_label_new("Do you want to overwrite the existing file?");
                        gtk_label_set_xalign(GTK_LABEL(desc_label), 0.0);
                        gtk_label_set_wrap(GTK_LABEL(desc_label), TRUE);
                        gtk_label_set_max_width_chars(GTK_LABEL(desc_label), 50);
                        gtk_box_append(GTK_BOX(msg_box), desc_label);

                        gtk_widget_set_hexpand(msg_box, TRUE);
                        gtk_box_append(GTK_BOX(hbox), msg_box);
                        gtk_box_append(GTK_BOX(box), hbox);
                        gtk_box_append(GTK_BOX(content), box);

                        gtk_window_present(GTK_WINDOW(dialog));
                        g_signal_connect(dialog, "response", G_CALLBACK(on_file_overwrite_response), dialog_data);
                    }

                    return TRUE;
                } else {

                    if (is_dir) {

                        size_t old_prefix_len = strlen(e->name);
                        char *old_prefix = strdup(e->name);
                        free(e->name);
                        e->name = new_name;
                        size_t new_prefix_len = strlen(new_name);
                        for (uint32_t k = 0; k < idx.n; k++) {
                            if (k == i) continue;
                            entry_t *sub = &idx.entries[k];
                            if (!(sub->flags & 4) && strncmp(sub->name, old_prefix, old_prefix_len) == 0) {

                                const char *suffix = sub->name + old_prefix_len;
                                size_t newlen = new_prefix_len + strlen(suffix) + 1;
                                char *newsub = malloc(newlen);
                                snprintf(newsub, newlen, "%s%s", new_name, suffix);
                                free(sub->name);
                                sub->name = newsub;
                            }
                        }
                        free(old_prefix);
                    } else {
                        free(e->name);
                        e->name = new_name;
                    }
                    modified = 1;
                }
                break;
            }
        }
    }


    if(modified){
        fseek(f, 0, SEEK_END);
        uint64_t new_index_offset = ftell(f);
        write_index(f, &idx);
        update_header_index_offset(f, new_index_offset);


        free_index(&g_current_index);
        rewind(f);
        g_current_index = load_index(f);
        populate_list_from_index();
        update_info_panel();
    }

    free_index(&idx);
    fclose(f);
    free(ids);
    g_internal_drag_active = 0;

    return modified ? TRUE : FALSE;
}


static void on_drop_encrypt_response(GtkDialog *dialog, gint response, gpointer user_data){
    (void)dialog;
    drop_encrypt_data_t *data = (drop_encrypt_data_t*)user_data;
    if(data->response_out) *(data->response_out) = response;
    if(data->loop) g_main_loop_quit(data->loop);
}


static gboolean on_drop(GtkDropTarget *target, const GValue *value, double x, double y, gpointer user_data){
    (void)target; (void)x; (void)y; (void)user_data;



    if(g_internal_drag_active){
        return FALSE;
    }

    if(!G_VALUE_HOLDS(value, GDK_TYPE_FILE_LIST)) return FALSE;

    GdkFileList *file_list = g_value_get_boxed(value);
    if(!file_list) return FALSE;

    GSList *files = gdk_file_list_get_files(file_list);
    if(!files) return FALSE;


    int nfiles = 0;
    char **paths = NULL;
    for(GSList *l = files; l != NULL; l = l->next){
        GFile *file = G_FILE(l->data);
        char *path = g_file_get_path(file);
        if(path){
            paths = realloc(paths, sizeof(char*) * (nfiles + 1));
            paths[nfiles++] = path;
        }
    }

    if(nfiles == 0){
        free(paths);
        return FALSE;
    }


    if(nfiles == 1 && !g_current_archive){
        size_t plen = strlen(paths[0]);
        int is_archive = 0;
        if(plen >= 5 && strcmp(paths[0] + plen - 5, ".baar") == 0){
            is_archive = 1;
        } else if(plen >= 4 && strcmp(paths[0] + plen - 4, ".zip") == 0){
            is_archive = 1;
        } else if(plen >= 4 && strcmp(paths[0] + plen - 4, ".tar") == 0){
            is_archive = 1;
        } else if(plen >= 7 && strcmp(paths[0] + plen - 7, ".tar.gz") == 0){
            is_archive = 1;
        } else if(plen >= 3 && strcmp(paths[0] + plen - 3, ".7z") == 0){
            is_archive = 1;
        }

        if(is_archive){
            if(open_archive_gui(paths[0]) != 0){
                fprintf(stderr, "Failed to open dropped archive: %s\n", paths[0]);
            }
            for(int i=0; i<nfiles; i++) g_free(paths[i]);
            free(paths);
            return TRUE;
        }
    }


    if(g_current_archive){

        if(g_current_is_libarchive){

            typedef struct {
                char *full_path;
                char *base_dir;
            } file_with_base_t;

            file_with_base_t *all_files = NULL;
            int total_files = 0;

            for(int i=0; i<nfiles; i++){
                struct stat st;
                if(stat(paths[i], &st) == 0){
                    if(S_ISDIR(st.st_mode)){
                        int dir_count = 0;
                        char **dir_files = collect_files_recursive(paths[i], &dir_count);
                        if(dir_files){
                            for(int j=0; j<dir_count; j++){
                                all_files = realloc(all_files, sizeof(file_with_base_t) * (total_files + 1));
                                all_files[total_files].full_path = dir_files[j];
                                all_files[total_files].base_dir = strdup(paths[i]);
                                total_files++;
                            }
                            free(dir_files);
                        }
                    } else {
                        all_files = realloc(all_files, sizeof(file_with_base_t) * (total_files + 1));
                        all_files[total_files].full_path = strdup(paths[i]);
                        char *parent = strdup(paths[i]);
                        char *last_slash = strrchr(parent, '/');
                        if(last_slash) *last_slash = '\0';
                        all_files[total_files].base_dir = parent;
                        total_files++;
                    }
                }
            }

            if(total_files > 0){
                char msg[256];
                snprintf(msg, sizeof(msg), "Adding %d files...", total_files);
                show_progress_dialog("Adding files", msg);


                if(g_archive_was_encrypted && !g_archive_password && g_main_window){
                    if(!show_password_dialog("Archive appears to be password-protected. Enter password to add files or Cancel to abort.")){

                        for(int i=0;i<nfiles;i++) { g_free(paths[i]); }
                        free(paths);
                        for(int i=0;i<total_files;i++){ free(all_files[i].full_path); if(all_files[i].base_dir) free(all_files[i].base_dir); }
                        free(all_files);
                        return TRUE;
                    }
                    if(g_archive_password && g_archive_password[0]) g_archive_was_encrypted = 1;
                }

                const char **file_paths = malloc(sizeof(char*) * total_files);
                for(int i=0; i<total_files; i++){
                    file_paths[i] = all_files[i].full_path;
                }


                int avg_clevel = 6;

                int lar = la_add_files(g_current_archive, file_paths, total_files, avg_clevel, g_archive_password, global_verbose);
                if(lar != 0 && !g_archive_password && g_main_window){
                    if(show_password_dialog("Adding files failed (archive may be encrypted). Enter password to retry:")){
                        if(g_archive_password && g_archive_password[0]) g_archive_was_encrypted = 1;
                        lar = la_add_files(g_current_archive, file_paths, total_files, avg_clevel, g_archive_password, global_verbose);
                    }
                }
                if(lar == 0){
                    update_progress(0.9, "Refreshing index...");
                    free_index(&g_current_index);
                    g_current_index = load_libarchive_index(g_current_archive);
                    populate_list_from_index();
                    update_info_panel();
                    update_progress(1.0, "Done!");
                }

                free(file_paths);
                for(int i=0; i<total_files; i++){
                    free(all_files[i].full_path);
                    free(all_files[i].base_dir);
                }
                free(all_files);

                g_timeout_add(500, destroy_window_cb, g_progress_dialog);
                g_progress_dialog = NULL;
                g_progress_bar = NULL;
                g_progress_label = NULL;
            }

            for(int i=0; i<nfiles; i++) g_free(paths[i]);
            free(paths);
            return TRUE;
        }


        GtkWidget *enc_dlg = gtk_dialog_new_with_buttons("Encryption Options",
                                                         GTK_WINDOW(g_main_window),
                                                         GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                         "Cancel", GTK_RESPONSE_CANCEL,
                                                         "Add Files", GTK_RESPONSE_ACCEPT,
                                                         NULL);
        gtk_window_set_default_size(GTK_WINDOW(enc_dlg), 450, -1);

        GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(enc_dlg));
        gtk_widget_set_margin_start(content, 24);
        gtk_widget_set_margin_end(content, 24);
        gtk_widget_set_margin_top(content, 20);
        gtk_widget_set_margin_bottom(content, 16);

        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 16);

        GtkWidget *encrypt_check = gtk_check_button_new_with_label("Encrypt files with password");
        gtk_box_append(GTK_BOX(box), encrypt_check);

        GtkWidget *pwd_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
        gtk_widget_set_margin_start(pwd_box, 28);

        GtkWidget *pwd_label = gtk_label_new("Password:");
        gtk_label_set_xalign(GTK_LABEL(pwd_label), 0.0);
        gtk_widget_set_margin_bottom(pwd_label, 4);
        gtk_box_append(GTK_BOX(pwd_box), pwd_label);

        GtkWidget *pwd_entry = gtk_password_entry_new();
        gtk_password_entry_set_show_peek_icon(GTK_PASSWORD_ENTRY(pwd_entry), TRUE);
        gtk_widget_set_hexpand(pwd_entry, TRUE);
        gtk_widget_set_sensitive(pwd_entry, FALSE);
        gtk_box_append(GTK_BOX(pwd_box), pwd_entry);

        gtk_box_append(GTK_BOX(box), pwd_box);
        gtk_box_append(GTK_BOX(content), box);

        g_signal_connect(encrypt_check, "toggled", G_CALLBACK(on_encrypt_toggled), pwd_entry);


        GtkWidget *action_area = NULL;
        GtkWidget *kid = gtk_widget_get_first_child(GTK_WIDGET(enc_dlg));
        while(kid){
            if(gtk_widget_get_next_sibling(kid) == NULL) action_area = kid;
            kid = gtk_widget_get_next_sibling(kid);
        }
        if(action_area){
            gtk_widget_set_margin_top(action_area, 12);
            gtk_widget_set_margin_bottom(action_area, 12);
            gtk_widget_set_margin_start(action_area, 20);
            gtk_widget_set_margin_end(action_area, 20);
            if(GTK_IS_BOX(action_area)) gtk_box_set_spacing(GTK_BOX(action_area), 12);
        }

        g_object_set_data(G_OBJECT(enc_dlg), "encrypt-check", encrypt_check);
        g_object_set_data(G_OBJECT(enc_dlg), "pwd-entry", pwd_entry);


        g_object_set_data(G_OBJECT(enc_dlg), "dropped-files", paths);
        g_object_set_data(G_OBJECT(enc_dlg), "dropped-count", GINT_TO_POINTER(nfiles));

        gtk_dialog_set_default_response(GTK_DIALOG(enc_dlg), GTK_RESPONSE_ACCEPT);
        gtk_window_present(GTK_WINDOW(enc_dlg));


        GMainLoop *loop = g_main_loop_new(NULL, FALSE);
        int dialog_result = GTK_RESPONSE_CANCEL;
        drop_encrypt_data_t cb_data = { &dialog_result, loop };

        g_signal_connect(enc_dlg, "response", G_CALLBACK(on_drop_encrypt_response), &cb_data);
        g_main_loop_run(loop);
        g_main_loop_unref(loop);


        gboolean should_encrypt = gtk_check_button_get_active(GTK_CHECK_BUTTON(encrypt_check));
        char *password_copy = NULL;
        if(should_encrypt && dialog_result == GTK_RESPONSE_ACCEPT){
            const char *pwd_text = gtk_editable_get_text(GTK_EDITABLE(pwd_entry));
            if(pwd_text && pwd_text[0]) password_copy = strdup(pwd_text);
        }

        gtk_window_destroy(GTK_WINDOW(enc_dlg));


        while(g_main_context_pending(NULL)) g_main_context_iteration(NULL, FALSE);

        if(dialog_result != GTK_RESPONSE_ACCEPT){

            for(int i=0; i<nfiles; i++) g_free(paths[i]);
            free(paths);
            if(password_copy) free(password_copy);
            return FALSE;
        }


        typedef struct {
            char *full_path;
            char *base_dir;
        } file_with_base_t;

        file_with_base_t *all_files = NULL;
        int total_files = 0;

        for(int i=0; i<nfiles; i++){
            struct stat st;
            if(stat(paths[i], &st) == 0){
                if(S_ISDIR(st.st_mode)){

                    int dir_file_count = 0;
                    char **dir_files = collect_files_recursive(paths[i], &dir_file_count);
                    if(dir_files){

                        char *path_copy = strdup(paths[i]);
                        char *last_slash = strrchr(path_copy, '/');
                        char *base = NULL;
                        if(last_slash){
                            *last_slash = '\0';
                            base = strdup(path_copy);
                        } else {
                            base = strdup(".");
                        }
                        free(path_copy);

                        for(int j=0; j<dir_file_count; j++){
                            if(dir_files[j]){
                                all_files = realloc(all_files, sizeof(file_with_base_t) * (total_files + 1));
                                all_files[total_files].full_path = dir_files[j];
                                all_files[total_files].base_dir = strdup(base);
                                total_files++;
                            }
                        }
                        free(base);
                        free(dir_files);
                    }
                } else if(S_ISREG(st.st_mode)){

                    all_files = realloc(all_files, sizeof(file_with_base_t) * (total_files + 1));
                    all_files[total_files].full_path = strdup(paths[i]);
                    all_files[total_files].base_dir = NULL;
                    total_files++;
                }
            }
        }

        if(total_files == 0){

            for(int i=0; i<nfiles; i++) g_free(paths[i]);
            free(paths);
            free(all_files);
            return FALSE;
        }


        char msg[256];
    snprintf(msg, sizeof(msg), "Adding %d files...", total_files);
    show_progress_dialog("Adding files", msg);


        filepair_t *filepairs = malloc(sizeof(filepair_t) * total_files);
        int *clevels = malloc(sizeof(int) * total_files);

        for(int i=0; i<total_files; i++){
            filepairs[i].src_path = all_files[i].full_path;


            char *archive_rel_path = NULL;
            if(all_files[i].base_dir){

                size_t base_len = strlen(all_files[i].base_dir);
                char *full = all_files[i].full_path;


                if(strncmp(full, all_files[i].base_dir, base_len) == 0){
                    char *rel = full + base_len;
                    while(*rel == '/') rel++;
                    archive_rel_path = strdup(rel);
                } else {

                    archive_rel_path = strdup(basename(full));
                }
            } else {

                archive_rel_path = strdup(basename(all_files[i].full_path));
            }


            if(g_current_prefix && g_current_prefix[0]){
                size_t plen = strlen(g_current_prefix);
                size_t rlen = strlen(archive_rel_path);
                char *apath = malloc(plen + rlen + 1);
                memcpy(apath, g_current_prefix, plen);
                memcpy(apath + plen, archive_rel_path, rlen);
                apath[plen + rlen] = '\0';
                free(archive_rel_path);
                filepairs[i].archive_path = apath;
            } else {
                filepairs[i].archive_path = archive_rel_path;
            }


            clevels[i] = auto_choose_clevel(all_files[i].full_path);


            double frac = (double)(i+1) / (double)total_files;
            char pbuf[128];
            snprintf(pbuf, sizeof(pbuf), "Preparing %d/%d", i+1, total_files);
            update_progress(frac * 0.1, pbuf);
        }

    update_progress_label("Adding files to archive...");


        if(g_current_is_libarchive && total_files > 0){

            const char **paths = malloc(sizeof(char*) * (size_t)total_files);
            for(int i=0; i<total_files; i++){
                paths[i] = filepairs[i].src_path;
            }


            int total_level = 0;
            for(int i=0; i<total_files; i++){
                int mapped = clevels[i];
                fprintf(stderr, "DEBUG: File %d, BAAR level=%d", i, mapped);
                if(mapped == 0) mapped = 0;
                else if(mapped == 1) mapped = 3;
                else if(mapped == 2) mapped = 6;
                else mapped = 6;
                fprintf(stderr, " -> libarchive level=%d\n", mapped);
                total_level += mapped;
            }
            int avg_clevel = total_files > 0 ? total_level / total_files : 6;
            fprintf(stderr, "DEBUG: Average compression level for libarchive: %d\n", avg_clevel);


            const char *la_pwd = password_copy ? password_copy : g_archive_password;
            int lar = la_add_files(g_current_archive, paths, total_files, avg_clevel, la_pwd, global_verbose);
            if(lar != 0 && !la_pwd && g_main_window){
                if(show_password_dialog("Adding files failed (archive may be encrypted). Enter password to retry:")){
                    if(g_archive_password && g_archive_password[0]) g_archive_was_encrypted = 1;
                    lar = la_add_files(g_current_archive, paths, total_files, avg_clevel, g_archive_password, global_verbose);
                }
            }
            if(lar == 0){
                update_progress(0.9, "Refreshing index...");


                free_index(&g_current_index);
                g_current_index = load_libarchive_index(g_current_archive);
                populate_list_from_index();
                update_info_panel();

                update_progress(1.0, "Done!");
            }

            free(paths);
        } else {


        char **dir_paths = NULL;
        int dir_count = 0;

        for(int i=0; i<total_files; i++){
            char *path = strdup(filepairs[i].archive_path);
            char *slash = strrchr(path, '/');

            while(slash){
                *slash = '\0';


                int found = 0;
                for(int j=0; j<dir_count; j++){
                    if(strcmp(dir_paths[j], path) == 0){
                        found = 1;
                        break;
                    }
                }

                if(!found){

                    dir_paths = realloc(dir_paths, sizeof(char*) * (dir_count + 1));
                    dir_paths[dir_count++] = strdup(path);
                }


                slash = strrchr(path, '/');
            }
            free(path);
        }


        for(int i=0; i<dir_count-1; i++){
            for(int j=i+1; j<dir_count; j++){
                if(strlen(dir_paths[i]) > strlen(dir_paths[j])){
                    char *tmp = dir_paths[i];
                    dir_paths[i] = dir_paths[j];
                    dir_paths[j] = tmp;
                }
            }
        }


        if(dir_count > 0){
            FILE *f = fopen(g_current_archive, "r+b");
            if(f){
                index_t idx = load_index(f);
                int modified = 0;

                for(int i=0; i<dir_count; i++){
                    char dir_with_slash[4096];
                    snprintf(dir_with_slash, sizeof(dir_with_slash), "%s/", dir_paths[i]);


                    int exists = 0;
                    for(uint32_t j=0; j<idx.n; j++){
                        if(idx.entries[j].name && strcmp(idx.entries[j].name, dir_with_slash) == 0){
                            exists = 1;
                            break;
                        }
                    }

                    if(!exists){

                        idx.entries = realloc(idx.entries, sizeof(entry_t) * (idx.n + 1));
                        entry_t *e = &idx.entries[idx.n];
                        memset(e, 0, sizeof(*e));
                        e->id = idx.next_id++;
                        e->name = strdup(dir_with_slash);
                        e->flags = 0;
                        e->comp_level = 0;
                        e->data_offset = 0;
                        e->comp_size = 0;
                        e->uncomp_size = 0;
                        e->crc32 = 0;
                        e->mode = 0755;
                        e->uid = getuid();
                        e->gid = getgid();
                        e->mtime = time(NULL);
                        e->meta = NULL;
                        e->meta_n = 0;
                        idx.n++;
                        modified = 1;
                    }
                }

                if(modified){

                    fseek(f, 0, SEEK_END);
                    uint64_t index_offset = ftell(f);
                    write_index(f, &idx);
                    update_header_index_offset(f, index_offset);
                }

                free_index(&idx);
                fclose(f);
            }
        }


        for(int i=0; i<dir_count; i++){
            free(dir_paths[i]);
        }
        free(dir_paths);


        if(add_files(g_current_archive, filepairs, clevels, total_files, password_copy, 0, 0) == 0){
            update_progress(0.9, "Refreshing index...");


            FILE *f = fopen(g_current_archive, "rb");
            if(f){
                free_index(&g_current_index);
                g_current_index = load_index(f);
                fclose(f);
            }
            populate_list_from_index();
            update_info_panel();

            update_progress(1.0, "Done!");
        }
        }


        for(int i=0; i<total_files; i++){
            free(filepairs[i].src_path);
            free(filepairs[i].archive_path);
            if(all_files[i].base_dir) free(all_files[i].base_dir);
        }
        free(filepairs);
        free(clevels);
        free(all_files);
        if(password_copy) free(password_copy);


        for(int i=0; i<nfiles; i++) g_free(paths[i]);
        free(paths);


        g_timeout_add(500, destroy_window_cb, g_progress_dialog);
        g_progress_dialog = NULL;
        g_progress_bar = NULL;
        g_progress_label = NULL;

        return TRUE;
    }


    if(!g_current_archive && nfiles > 0){

        GtkWidget *chooser = gtk_file_chooser_dialog_new("Create New Archive",
                                                         GTK_WINDOW(g_main_window),
                                                         GTK_FILE_CHOOSER_ACTION_SAVE,
                                                         "_Cancel", GTK_RESPONSE_CANCEL,
                                                         "_Create", GTK_RESPONSE_ACCEPT,
                                                         NULL);


        GtkFileFilter *filter_baar = gtk_file_filter_new();
        gtk_file_filter_set_name(filter_baar, "BAAR archives (*.baar)");
        gtk_file_filter_add_pattern(filter_baar, "*.baar");
        gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter_baar);

        GtkFileFilter *filter_zip = gtk_file_filter_new();
        gtk_file_filter_set_name(filter_zip, "ZIP archives (*.zip)");
        gtk_file_filter_add_pattern(filter_zip, "*.zip");
        gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter_zip);

        GtkFileFilter *filter_tar = gtk_file_filter_new();
        gtk_file_filter_set_name(filter_tar, "TAR archives (*.tar)");
        gtk_file_filter_add_pattern(filter_tar, "*.tar");
        gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter_tar);

        GtkFileFilter *filter_targz = gtk_file_filter_new();
        gtk_file_filter_set_name(filter_targz, "TAR.GZ archives (*.tar.gz, *.tgz)");
        gtk_file_filter_add_pattern(filter_targz, "*.tar.gz");
        gtk_file_filter_add_pattern(filter_targz, "*.tgz");
        gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter_targz);

        GtkFileFilter *filter_tarbz2 = gtk_file_filter_new();
        gtk_file_filter_set_name(filter_tarbz2, "TAR.BZ2 archives (*.tar.bz2, *.tbz2)");
        gtk_file_filter_add_pattern(filter_tarbz2, "*.tar.bz2");
        gtk_file_filter_add_pattern(filter_tarbz2, "*.tbz2");
        gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter_tarbz2);

        GtkFileFilter *filter_tarxz = gtk_file_filter_new();
        gtk_file_filter_set_name(filter_tarxz, "TAR.XZ archives (*.tar.xz, *.txz)");
        gtk_file_filter_add_pattern(filter_tarxz, "*.tar.xz");
        gtk_file_filter_add_pattern(filter_tarxz, "*.txz");
        gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter_tarxz);

        GtkFileFilter *filter_7z = gtk_file_filter_new();
        gtk_file_filter_set_name(filter_7z, "7-Zip archives (*.7z)");
        gtk_file_filter_add_pattern(filter_7z, "*.7z");
        gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter_7z);

        GtkFileFilter *filter_all = gtk_file_filter_new();
        gtk_file_filter_set_name(filter_all, "All files (*.*)");
        gtk_file_filter_add_pattern(filter_all, "*.*");
        gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter_all);

        gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(chooser), "archive.baar");


        g_signal_connect(chooser, "notify::filter", G_CALLBACK(on_filter_changed), NULL);


        g_object_set_data(G_OBJECT(chooser), "dropped-files", paths);
        g_object_set_data(G_OBJECT(chooser), "dropped-count", GINT_TO_POINTER(nfiles));

        gtk_window_present(GTK_WINDOW(chooser));
        g_signal_connect(chooser, "response", G_CALLBACK(on_drop_create_response), NULL);
        return TRUE;
    }


    for(int i=0; i<nfiles; i++) g_free(paths[i]);
    free(paths);
    return FALSE;
}


static void on_drop_create_response(GtkDialog *dialog, gint response, gpointer user_data){
    (void)user_data;

    char **paths = g_object_get_data(G_OBJECT(dialog), "dropped-files");
    int nfiles = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(dialog), "dropped-count"));


    gtk_window_destroy(GTK_WINDOW(dialog));


    while(g_main_context_pending(NULL)) g_main_context_iteration(NULL, FALSE);

    if(response == GTK_RESPONSE_ACCEPT && paths && nfiles > 0){

        typedef struct {
            char *full_path;
            char *base_dir;
        } file_with_base_t;

        file_with_base_t *all_files = NULL;
        int total_files = 0;

        for(int i=0; i<nfiles; i++){
            struct stat st;
            if(stat(paths[i], &st) == 0){
                if(S_ISDIR(st.st_mode)){

                    int dir_file_count = 0;
                    char **dir_files = collect_files_recursive(paths[i], &dir_file_count);
                    if(dir_files){

                        char *path_copy = strdup(paths[i]);
                        char *last_slash = strrchr(path_copy, '/');
                        char *base = NULL;
                        if(last_slash){
                            *last_slash = '\0';
                            base = strdup(path_copy);
                        } else {
                            base = strdup(".");
                        }
                        free(path_copy);

                        for(int j=0; j<dir_file_count; j++){
                            if(dir_files[j]){
                                all_files = realloc(all_files, sizeof(file_with_base_t) * (total_files + 1));
                                all_files[total_files].full_path = dir_files[j];
                                all_files[total_files].base_dir = strdup(base);
                                total_files++;
                            }
                        }
                        free(base);
                        free(dir_files);
                    }
                } else if(S_ISREG(st.st_mode)){

                    all_files = realloc(all_files, sizeof(file_with_base_t) * (total_files + 1));
                    all_files[total_files].full_path = strdup(paths[i]);
                    all_files[total_files].base_dir = NULL;
                    total_files++;
                }
            }
        }

        if(total_files == 0){

            if(paths){
                for(int i=0; i<nfiles; i++) g_free(paths[i]);
                free(paths);
            }
            free(all_files);
            return;
        }


        char msg[256];
        snprintf(msg, sizeof(msg), "Creating new archive with %d files...", total_files);
        show_progress_dialog("Creating archive", msg);
        update_progress(0.1, "Creating empty archive...");

        GFile *file = gtk_file_chooser_get_file(GTK_FILE_CHOOSER(dialog));
        if(file){
            char *archive_path = g_file_get_path(file);
            if(archive_path){

                char final_path[4096];
                size_t plen = strlen(archive_path);
                int has_archive_ext = 0;
                const char *known_exts[] = {".baar", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar"};
                for(int i = 0; i < 8; i++){
                    size_t elen = strlen(known_exts[i]);
                    if(plen >= elen && strcmp(archive_path + plen - elen, known_exts[i]) == 0){
                        has_archive_ext = 1;
                        break;
                    }
                }
                if(has_archive_ext){
                    strncpy(final_path, archive_path, sizeof(final_path)-1);
                } else {
                    snprintf(final_path, sizeof(final_path), "%s.baar", archive_path);
                }
                final_path[sizeof(final_path)-1] = '\0';


                size_t final_len = strlen(final_path);
                int is_baar = (final_len >= 5 && strcmp(final_path + final_len - 5, ".baar") == 0);

                if(is_baar){

                    FILE *f = fopen(final_path, "w+b");
                    if(f){
                        fwrite(MAGIC, 1, 8, f);
                        uint64_t zero = 0;
                        fwrite(&zero, 8, 1, f);
                        for(int i=0; i<16; i++) fputc(0, f);
                        uint64_t index_offset = 32;
                        uint32_t n = 0;
                        fwrite(&n, 4, 1, f);
                        fseek(f, 8, SEEK_SET);
                        fwrite(&index_offset, 8, 1, f);
                        fclose(f);

                        update_progress(0.2, "Opening archive...");


                        if(open_archive_gui(final_path) == 0){
                        update_progress_label("Adding files to archive...");


                        filepair_t *filepairs = malloc(sizeof(filepair_t) * total_files);
                        int *clevels = malloc(sizeof(int) * total_files);

                        for(int i=0; i<total_files; i++){
                            filepairs[i].src_path = all_files[i].full_path;


                            char *archive_rel_path = NULL;
                            if(all_files[i].base_dir){

                                size_t base_len = strlen(all_files[i].base_dir);
                                char *full = all_files[i].full_path;


                                if(strncmp(full, all_files[i].base_dir, base_len) == 0){
                                    char *rel = full + base_len;
                                    while(*rel == '/') rel++;
                                    archive_rel_path = strdup(rel);
                                } else {

                                    archive_rel_path = strdup(basename(full));
                                }
                            } else {

                                archive_rel_path = strdup(basename(all_files[i].full_path));
                            }

                            filepairs[i].archive_path = archive_rel_path;
                            clevels[i] = auto_choose_clevel(all_files[i].full_path);


                            double frac = 0.2 + ((double)(i+1) / (double)total_files) * 0.1;
                            char pbuf[128];
                            snprintf(pbuf, sizeof(pbuf), "Preparing %d/%d", i+1, total_files);
                            update_progress(frac, pbuf);
                        }


                        char **dir_paths = NULL;
                        int dir_count = 0;

                        for(int i=0; i<total_files; i++){
                            char *path = strdup(filepairs[i].archive_path);
                            char *slash = strrchr(path, '/');

                            while(slash){
                                *slash = '\0';

                                int found = 0;
                                for(int j=0; j<dir_count; j++){
                                    if(strcmp(dir_paths[j], path) == 0){
                                        found = 1;
                                        break;
                                    }
                                }

                                if(!found){
                                    dir_paths = realloc(dir_paths, sizeof(char*) * (dir_count + 1));
                                    dir_paths[dir_count++] = strdup(path);
                                }

                                slash = strrchr(path, '/');
                            }
                            free(path);
                        }


                        for(int i=0; i<dir_count-1; i++){
                            for(int j=i+1; j<dir_count; j++){
                                if(strlen(dir_paths[i]) > strlen(dir_paths[j])){
                                    char *tmp = dir_paths[i];
                                    dir_paths[i] = dir_paths[j];
                                    dir_paths[j] = tmp;
                                }
                            }
                        }


                        if(dir_count > 0){
                            FILE *fa = fopen(final_path, "r+b");
                            if(fa){
                                index_t idx = load_index(fa);

                                for(int i=0; i<dir_count; i++){
                                    char dir_with_slash[4096];
                                    snprintf(dir_with_slash, sizeof(dir_with_slash), "%s/", dir_paths[i]);

                                    idx.entries = realloc(idx.entries, sizeof(entry_t) * (idx.n + 1));
                                    entry_t *e = &idx.entries[idx.n];
                                    memset(e, 0, sizeof(*e));
                                    e->id = idx.next_id++;
                                    e->name = strdup(dir_with_slash);
                                    e->flags = 0;
                                    e->comp_level = 0;
                                    e->data_offset = 0;
                                    e->comp_size = 0;
                                    e->uncomp_size = 0;
                                    e->crc32 = 0;
                                    e->mode = 0755;
                                    e->uid = getuid();
                                    e->gid = getgid();
                                    e->mtime = time(NULL);
                                    e->meta = NULL;
                                    e->meta_n = 0;
                                    idx.n++;
                                }

                                fseek(fa, 0, SEEK_END);
                                uint64_t index_offset = ftell(fa);
                                write_index(fa, &idx);
                                update_header_index_offset(fa, index_offset);
                                free_index(&idx);
                                fclose(fa);
                            }
                        }

                        for(int i=0; i<dir_count; i++){
                            free(dir_paths[i]);
                        }
                        free(dir_paths);

                        if(add_files(final_path, filepairs, clevels, total_files, NULL, 0, 0) == 0){
                            update_progress(0.9, "Refreshing index...");

                            FILE *rf = fopen(final_path, "rb");
                            if(rf){
                                free_index(&g_current_index);
                                g_current_index = load_index(rf);
                                fclose(rf);
                            }
                            populate_list_from_index();
                            update_info_panel();

                            update_progress(1.0, "Done!");
                        }

                        for(int i=0; i<total_files; i++){
                            free(filepairs[i].archive_path);
                            free(filepairs[i].src_path);
                            if(all_files[i].base_dir) free(all_files[i].base_dir);
                        }
                        free(filepairs);
                        free(clevels);
                    }
                    }
                } else {

                    struct archive *a = archive_write_new();
                    if(!a){
                        fprintf(stderr, "Failed to create libarchive writer\n");
                        g_free(archive_path);
                        g_object_unref(file);
                        free(all_files);
                        g_timeout_add(100, destroy_window_cb, g_progress_dialog);
                        g_progress_dialog = NULL;
                        return;
                    }


                    if(strstr(final_path, ".zip")){
                        archive_write_set_format_zip(a);
                        archive_write_zip_set_compression_deflate(a);
                        archive_write_set_options(a, "compression-level=6");
                    } else if(strstr(final_path, ".7z")){
                        archive_write_set_format_7zip(a);
                        archive_write_set_options(a, "compression=lzma2,compression-level=6");
                    } else if(strstr(final_path, ".tar.gz") || strstr(final_path, ".tgz")){
                        archive_write_set_format_pax_restricted(a);
                        archive_write_add_filter_gzip(a);
                        archive_write_set_filter_option(a, "gzip", "compression-level", "6");
                    } else if(strstr(final_path, ".tar.bz2") || strstr(final_path, ".tbz2")){
                        archive_write_set_format_pax_restricted(a);
                        archive_write_add_filter_bzip2(a);
                        archive_write_set_filter_option(a, "bzip2", "compression-level", "9");
                    } else if(strstr(final_path, ".tar.xz") || strstr(final_path, ".txz")){
                        archive_write_set_format_pax_restricted(a);
                        archive_write_add_filter_xz(a);
                        archive_write_set_filter_option(a, "xz", "compression-level", "6");
                    } else if(strstr(final_path, ".tar")){
                        archive_write_set_format_pax_restricted(a);
                    } else {
                        archive_write_set_format_zip(a);
                        archive_write_zip_set_compression_deflate(a);
                        archive_write_set_options(a, "compression-level=6");
                    }

                    if(archive_write_open_filename(a, final_path) != ARCHIVE_OK){
                        fprintf(stderr, "Failed to create archive: %s\n", archive_error_string(a));
                        archive_write_free(a);
                        g_free(archive_path);
                        g_object_unref(file);
                        free(all_files);
                        g_timeout_add(100, destroy_window_cb, g_progress_dialog);
                        g_progress_dialog = NULL;
                        return;
                    }

                    update_progress(0.2, "Adding files...");


                    for(int i = 0; i < total_files; i++){
                        struct stat st;
                        if(stat(all_files[i].full_path, &st) != 0) continue;


                        char *entry_name = NULL;
                        if(all_files[i].base_dir){
                            size_t base_len = strlen(all_files[i].base_dir);
                            char *full = all_files[i].full_path;
                            if(strncmp(full, all_files[i].base_dir, base_len) == 0){
                                char *rel = full + base_len;
                                while(*rel == '/') rel++;
                                entry_name = strdup(rel);
                            } else {
                                entry_name = strdup(basename(full));
                            }
                        } else {
                            entry_name = strdup(basename(all_files[i].full_path));
                        }

                        struct archive_entry *entry = archive_entry_new();
                        archive_entry_set_pathname(entry, entry_name);
                        archive_entry_copy_stat(entry, &st);
                        archive_entry_set_filetype(entry, AE_IFREG);
                        archive_entry_set_perm(entry, st.st_mode & 0777);

                        if(archive_write_header(a, entry) == ARCHIVE_OK){
                            FILE *f = fopen(all_files[i].full_path, "rb");
                            if(f){
                                char buf[8192];
                                size_t len;
                                while((len = fread(buf, 1, sizeof(buf), f)) > 0){
                                    archive_write_data(a, buf, len);
                                }
                                fclose(f);
                            }
                        }

                        archive_entry_free(entry);
                        free(entry_name);

                        double prog = 0.2 + ((double)(i+1) / (double)total_files) * 0.7;
                        char pbuf[128];
                        snprintf(pbuf, sizeof(pbuf), "Adding %d/%d", i+1, total_files);
                        update_progress(prog, pbuf);
                    }

                    archive_write_close(a);
                    archive_write_free(a);

                    update_progress(0.95, "Opening archive...");


                    if(open_archive_gui(final_path) == 0){
                        update_progress(1.0, "Done!");
                    }


                    for(int i=0; i<total_files; i++){
                        free(all_files[i].full_path);
                        if(all_files[i].base_dir) free(all_files[i].base_dir);
                    }
                }
                g_free(archive_path);
            }
            g_object_unref(file);
        }

        free(all_files);


        g_timeout_add(500, destroy_window_cb, g_progress_dialog);
        g_progress_dialog = NULL;
        g_progress_bar = NULL;
        g_progress_label = NULL;
    }


    if(paths){
        for(int i=0; i<nfiles; i++) g_free(paths[i]);
        free(paths);
    }
}

static void on_plus_clicked(GtkButton *button, gpointer user_data){
    (void)button; (void)user_data;


    GtkWidget *chooser = gtk_file_chooser_dialog_new("Open or Create Archive",
                                                      GTK_WINDOW(g_main_window),
                                                      GTK_FILE_CHOOSER_ACTION_SAVE,
                                                      "_Cancel", GTK_RESPONSE_CANCEL,
                                                      "_Open/Create", RESPONSE_OPEN_CREATE,
                                                      NULL);


    GtkFileFilter *filter_baar = gtk_file_filter_new();
    gtk_file_filter_set_name(filter_baar, "BAAR archives (*.baar)");
    gtk_file_filter_add_pattern(filter_baar, "*.baar");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter_baar);

    GtkFileFilter *filter_zip = gtk_file_filter_new();
    gtk_file_filter_set_name(filter_zip, "ZIP archives (*.zip)");
    gtk_file_filter_add_pattern(filter_zip, "*.zip");
    gtk_file_filter_add_pattern(filter_zip, "*.jar");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter_zip);

    GtkFileFilter *filter_tar = gtk_file_filter_new();
    gtk_file_filter_set_name(filter_tar, "TAR archives (*.tar)");
    gtk_file_filter_add_pattern(filter_tar, "*.tar");
    gtk_file_filter_add_pattern(filter_tar, "*.tar.gz");
    gtk_file_filter_add_pattern(filter_tar, "*.tgz");
    gtk_file_filter_add_pattern(filter_tar, "*.tar.bz2");
    gtk_file_filter_add_pattern(filter_tar, "*.tbz");
    gtk_file_filter_add_pattern(filter_tar, "*.tbz2");
    gtk_file_filter_add_pattern(filter_tar, "*.tar.xz");
    gtk_file_filter_add_pattern(filter_tar, "*.txz");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter_tar);

    GtkFileFilter *filter_7z = gtk_file_filter_new();
    gtk_file_filter_set_name(filter_7z, "7-Zip archives (*.7z)");
    gtk_file_filter_add_pattern(filter_7z, "*.7z");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter_7z);

    GtkFileFilter *filter_rar = gtk_file_filter_new();
    gtk_file_filter_set_name(filter_rar, "RAR archives (*.rar)");
    gtk_file_filter_add_pattern(filter_rar, "*.rar");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter_rar);

    GtkFileFilter *filter_comp = gtk_file_filter_new();
    gtk_file_filter_set_name(filter_comp, "Compressed files");
    gtk_file_filter_add_pattern(filter_comp, "*.gz");
    gtk_file_filter_add_pattern(filter_comp, "*.bz2");
    gtk_file_filter_add_pattern(filter_comp, "*.xz");
    gtk_file_filter_add_pattern(filter_comp, "*.lzma");
    gtk_file_filter_add_pattern(filter_comp, "*.Z");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter_comp);

    GtkFileFilter *filter_other = gtk_file_filter_new();
    gtk_file_filter_set_name(filter_other, "Other archives");
    gtk_file_filter_add_pattern(filter_other, "*.iso");
    gtk_file_filter_add_pattern(filter_other, "*.cab");
    gtk_file_filter_add_pattern(filter_other, "*.deb");
    gtk_file_filter_add_pattern(filter_other, "*.rpm");
    gtk_file_filter_add_pattern(filter_other, "*.ar");
    gtk_file_filter_add_pattern(filter_other, "*.cpio");
    gtk_file_filter_add_pattern(filter_other, "*.lzh");
    gtk_file_filter_add_pattern(filter_other, "*.lha");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter_other);

    GtkFileFilter *filter_all = gtk_file_filter_new();
    gtk_file_filter_set_name(filter_all, "All supported archives");
    gtk_file_filter_add_pattern(filter_all, "*.baar");
    gtk_file_filter_add_pattern(filter_all, "*.zip");
    gtk_file_filter_add_pattern(filter_all, "*.jar");
    gtk_file_filter_add_pattern(filter_all, "*.tar");
    gtk_file_filter_add_pattern(filter_all, "*.tar.gz");
    gtk_file_filter_add_pattern(filter_all, "*.tgz");
    gtk_file_filter_add_pattern(filter_all, "*.tar.bz2");
    gtk_file_filter_add_pattern(filter_all, "*.tbz");
    gtk_file_filter_add_pattern(filter_all, "*.tbz2");
    gtk_file_filter_add_pattern(filter_all, "*.tar.xz");
    gtk_file_filter_add_pattern(filter_all, "*.txz");
    gtk_file_filter_add_pattern(filter_all, "*.7z");
    gtk_file_filter_add_pattern(filter_all, "*.rar");
    gtk_file_filter_add_pattern(filter_all, "*.gz");
    gtk_file_filter_add_pattern(filter_all, "*.bz2");
    gtk_file_filter_add_pattern(filter_all, "*.xz");
    gtk_file_filter_add_pattern(filter_all, "*.lzma");
    gtk_file_filter_add_pattern(filter_all, "*.iso");
    gtk_file_filter_add_pattern(filter_all, "*.cab");
    gtk_file_filter_add_pattern(filter_all, "*.deb");
    gtk_file_filter_add_pattern(filter_all, "*.rpm");
    gtk_file_filter_add_pattern(filter_all, "*.ar");
    gtk_file_filter_add_pattern(filter_all, "*.cpio");
    gtk_file_filter_add_pattern(filter_all, "*.lzh");
    gtk_file_filter_add_pattern(filter_all, "*.lha");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter_all);
    gtk_file_chooser_set_filter(GTK_FILE_CHOOSER(chooser), filter_all);


    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(chooser), "new_archive.baar");


    gtk_dialog_set_default_response(GTK_DIALOG(chooser), RESPONSE_OPEN_CREATE);


    g_signal_connect(chooser, "notify::filter", G_CALLBACK(on_filter_changed), NULL);

    g_signal_connect(chooser, "response", G_CALLBACK(on_chooser_response), NULL);
    gtk_window_present(GTK_WINDOW(chooser));
}

static void on_chooser_response(GtkDialog *dialog, gint response, gpointer user_data){
    (void)user_data;


    if(response == RESPONSE_OPEN_CREATE){
        GFile *file = gtk_file_chooser_get_file(GTK_FILE_CHOOSER(dialog));
        if(file){
            char *path = g_file_get_path(file);
            if(path){

                char final_path[4096];
                size_t plen = strlen(path);
                int has_archive_ext = 0;


                if(strstr(path, ".tar.gz") || strstr(path, ".tar.bz2") ||
                   strstr(path, ".tar.xz") || strstr(path, ".tgz") ||
                   strstr(path, ".tbz2") || strstr(path, ".txz")){
                    has_archive_ext = 1;
                }


                if(!has_archive_ext){
                    const char *known_exts[] = {".baar", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar"};
                    for(int i = 0; i < 8; i++){
                        size_t elen = strlen(known_exts[i]);
                        if(plen >= elen && strcmp(path + plen - elen, known_exts[i]) == 0){
                            has_archive_ext = 1;
                            break;
                        }
                    }
                }

                if(has_archive_ext){
                    strncpy(final_path, path, sizeof(final_path)-1);
                    final_path[sizeof(final_path)-1] = 0;
                } else {
                    snprintf(final_path, sizeof(final_path), "%s.baar", path);
                }


                struct stat st;
                int exists = (stat(final_path, &st) == 0);

                if(exists){

                    if(open_archive_gui(final_path)!=0){
                        fprintf(stderr, "Failed to open archive: %s\n", final_path);
                    }
                } else {

                    size_t final_len = strlen(final_path);
                    int is_baar = (final_len >= 5 && strcmp(final_path + final_len - 5, ".baar") == 0);

                    if(is_baar){

                        FILE *f = fopen(final_path, "w+b");
                        if(!f){
                            fprintf(stderr, "Failed to create archive: %s\n", final_path);
                            g_free(path);
                            g_object_unref(file);
                            gtk_window_destroy(GTK_WINDOW(dialog));
                            return;
                        }

                        fwrite(MAGIC, 1, 8, f);
                        uint64_t zero = 0;
                        fwrite(&zero, 8, 1, f);

                        for(int i=0; i<16; i++) fputc(0, f);

                        uint64_t index_offset = 32;
                        uint32_t n = 0;
                        fwrite(&n, 4, 1, f);

                        fseek(f, 8, SEEK_SET);
                        fwrite(&index_offset, 8, 1, f);
                        fclose(f);
                    } else {

                        struct archive *a = archive_write_new();
                        if(!a){
                            fprintf(stderr, "Failed to create libarchive writer\n");
                            g_free(path);
                            g_object_unref(file);
                            gtk_window_destroy(GTK_WINDOW(dialog));
                            return;
                        }


                        if(strstr(final_path, ".zip")){
                            archive_write_set_format_zip(a);
                            archive_write_zip_set_compression_deflate(a);
                            archive_write_set_options(a, "compression-level=6");
                        } else if(strstr(final_path, ".7z")){
                            archive_write_set_format_7zip(a);
                            archive_write_set_options(a, "compression=lzma2,compression-level=6");
                        } else if(strstr(final_path, ".tar.gz") || strstr(final_path, ".tgz")){
                            archive_write_set_format_pax_restricted(a);
                            archive_write_add_filter_gzip(a);
                            archive_write_set_filter_option(a, "gzip", "compression-level", "6");
                        } else if(strstr(final_path, ".tar.bz2") || strstr(final_path, ".tbz2")){
                            archive_write_set_format_pax_restricted(a);
                            archive_write_add_filter_bzip2(a);
                            archive_write_set_filter_option(a, "bzip2", "compression-level", "9");
                        } else if(strstr(final_path, ".tar.xz") || strstr(final_path, ".txz")){
                            archive_write_set_format_pax_restricted(a);
                            archive_write_add_filter_xz(a);
                            archive_write_set_filter_option(a, "xz", "compression-level", "6");
                        } else if(strstr(final_path, ".tar")){
                            archive_write_set_format_pax_restricted(a);
                        } else {

                            archive_write_set_format_zip(a);
                            archive_write_zip_set_compression_deflate(a);
                            archive_write_set_options(a, "compression-level=6");
                        }

                        if(archive_write_open_filename(a, final_path) != ARCHIVE_OK){
                            fprintf(stderr, "Failed to create archive: %s\n", archive_error_string(a));
                            archive_write_free(a);
                            g_free(path);
                            g_object_unref(file);
                            gtk_window_destroy(GTK_WINDOW(dialog));
                            return;
                        }


                        archive_write_close(a);
                        archive_write_free(a);
                    }


                    if(open_archive_gui(final_path)!=0){
                        fprintf(stderr, "Failed to open archive: %s\n", final_path);
                    }
                }

                g_free(path);
            }
            g_object_unref(file);
        }
    }
    gtk_window_destroy(GTK_WINDOW(dialog));
}

static void on_activate(GtkApplication *app, gpointer user_data){
    (void)user_data;
    GtkWidget *win = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(win), BAAR_HEADER);
    gtk_window_set_default_size(GTK_WINDOW(win), 600, 500);
    gtk_widget_set_size_request(GTK_WIDGET(win), 600, 500);

    g_main_window = win;

    gtk_widget_set_name(win, "baar-root");


    GtkDropTarget *drop_target = gtk_drop_target_new(GDK_TYPE_FILE_LIST, GDK_ACTION_COPY);
    g_signal_connect(drop_target, "drop", G_CALLBACK(on_drop), NULL);
    gtk_widget_add_controller(win, GTK_EVENT_CONTROLLER(drop_target));


     GtkCssProvider *css = gtk_css_provider_new();
     gtk_css_provider_load_from_data(css, "#baar-root * , .baar-dialog * { font-size: 16px; } .baar-name-small { font-size: 13px; }", -1);
     gtk_style_context_add_provider_for_display(gdk_display_get_default(), GTK_STYLE_PROVIDER(css), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
     g_object_unref(css);


    GtkWidget *header = gtk_header_bar_new();
    GtkWidget *plus_btn_local = gtk_button_new();
    GtkWidget *plus_label = gtk_label_new("+");
    gtk_button_set_child(GTK_BUTTON(plus_btn_local), plus_label);
    gtk_widget_set_tooltip_text(plus_btn_local, "Open/Create archive");
    g_signal_connect(plus_btn_local, "clicked", G_CALLBACK(on_plus_clicked), NULL);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), plus_btn_local);
    g_plus_btn = plus_btn_local;


    GtkWidget *add_btn = gtk_button_new();
    GtkWidget *add_icon = gtk_image_new_from_icon_name("list-add");
    gtk_button_set_child(GTK_BUTTON(add_btn), add_icon);
    gtk_widget_set_tooltip_text(add_btn, "Add files to archive");
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), add_btn);
    g_add_btn = add_btn;

    GtkWidget *newfolder_btn = gtk_button_new();
    GtkWidget *nf_icon = gtk_image_new_from_icon_name("folder-new");
    gtk_button_set_child(GTK_BUTTON(newfolder_btn), nf_icon);
    gtk_widget_set_tooltip_text(newfolder_btn, "Create new folder in archive");
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), newfolder_btn);
    g_newfolder_btn = newfolder_btn;

    GtkWidget *remove_btn = gtk_button_new();
    GtkWidget *rm_icon = gtk_image_new_from_icon_name("list-remove");
    gtk_button_set_child(GTK_BUTTON(remove_btn), rm_icon);
    gtk_widget_set_tooltip_text(remove_btn, "Remove selected entry from archive");
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), remove_btn);
    g_remove_btn = remove_btn;

    GtkWidget *extract_btn = gtk_button_new();
    GtkWidget *extract_icon = gtk_image_new_from_icon_name("document-save");
    gtk_button_set_child(GTK_BUTTON(extract_btn), extract_icon);
    gtk_widget_set_tooltip_text(extract_btn, "Extract selected files from archive");
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), extract_btn);
    g_extract_btn = extract_btn;


    GtkWidget *compact_btn = gtk_button_new();
    GtkWidget *compact_icon = gtk_image_new_from_icon_name("view-refresh");
    gtk_button_set_child(GTK_BUTTON(compact_btn), compact_icon);
    gtk_widget_set_tooltip_text(compact_btn, "Compact archive: permanently remove deleted entries and shrink file size");
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), compact_btn);
    g_compact_btn = compact_btn;



    g_back_btn = NULL;

    GtkWidget *close_btn = gtk_button_new();
    GtkWidget *close_icon = gtk_image_new_from_icon_name("window-close");
    gtk_button_set_child(GTK_BUTTON(close_btn), close_icon);
    gtk_widget_set_tooltip_text(close_btn, "Close archive");
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), close_btn);
    g_close_btn = close_btn;


    g_signal_connect(g_add_btn, "clicked", G_CALLBACK(on_gui_add_clicked), NULL);
    g_signal_connect(g_newfolder_btn, "clicked", G_CALLBACK(on_gui_newfolder_clicked), NULL);
    g_signal_connect(g_remove_btn, "clicked", G_CALLBACK(on_gui_remove_clicked), NULL);
    g_signal_connect(g_extract_btn, "clicked", G_CALLBACK(on_gui_extract_clicked), NULL);
    g_signal_connect(g_compact_btn, "clicked", G_CALLBACK(on_gui_compact_clicked), NULL);

    g_signal_connect(g_close_btn, "clicked", G_CALLBACK(on_gui_close_clicked), NULL);
    gtk_widget_set_visible(g_add_btn, FALSE);
    gtk_widget_set_visible(g_newfolder_btn, FALSE);
    gtk_widget_set_visible(g_remove_btn, FALSE);
    gtk_widget_set_visible(g_extract_btn, FALSE);
    gtk_widget_set_visible(g_compact_btn, FALSE);

    gtk_widget_set_visible(g_close_btn, FALSE);
    gtk_window_set_titlebar(GTK_WINDOW(win), header);


    g_list_container = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(g_list_container), GTK_SELECTION_MULTIPLE);
    gtk_list_box_set_activate_on_single_click(GTK_LIST_BOX(g_list_container), FALSE);
    gtk_widget_set_vexpand(g_list_container, TRUE);
    gtk_widget_set_hexpand(g_list_container, TRUE);
    gtk_widget_set_margin_start(g_list_container, 5);
    gtk_widget_set_margin_end(g_list_container, 5);
    gtk_widget_set_margin_top(g_list_container, 5);
    gtk_widget_set_margin_bottom(g_list_container, 0);
    g_signal_connect(g_list_container, "row-selected", G_CALLBACK(on_row_selected), NULL);
    g_signal_connect(g_list_container, "row-activated", G_CALLBACK(on_row_activated), NULL);

    GtkWidget *scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), g_list_container);


    g_welcome_label = gtk_label_new(
        BAAR_HEADER
        "\n\n"
        "To get started:\n\n"
        "• Click the '+' button or drag & drop an archive file to open it\n"
        "• Or drag & drop any non-archive file here to create a new archive"
    );
    gtk_label_set_justify(GTK_LABEL(g_welcome_label), GTK_JUSTIFY_CENTER);
    gtk_widget_set_vexpand(g_welcome_label, TRUE);
    gtk_widget_set_hexpand(g_welcome_label, TRUE);
    gtk_widget_set_valign(g_welcome_label, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(g_welcome_label, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_start(g_welcome_label, 40);
    gtk_widget_set_margin_end(g_welcome_label, 40);
    gtk_widget_set_margin_top(g_welcome_label, 40);
    gtk_widget_set_margin_bottom(g_welcome_label, 40);


    g_info_panel = gtk_frame_new(NULL);

    gtk_widget_set_margin_start(g_info_panel, 8);
    gtk_widget_set_margin_end(g_info_panel, 8);
    gtk_widget_set_margin_bottom(g_info_panel, 8);
    gtk_widget_set_margin_top(g_info_panel, 8);
    GtkWidget *info_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_start(info_box, 3);
    gtk_widget_set_margin_end(info_box, 3);
    gtk_widget_set_margin_top(info_box, 3);
    gtk_widget_set_margin_bottom(info_box, 3);
    g_info_name_lbl = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(g_info_name_lbl), 0.0);
    g_info_size_lbl = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(g_info_size_lbl), 0.0);
    g_info_entries_lbl = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(g_info_entries_lbl), 0.0);
    gtk_box_append(GTK_BOX(info_box), g_info_name_lbl);
    gtk_box_append(GTK_BOX(info_box), g_info_size_lbl);
    gtk_box_append(GTK_BOX(info_box), g_info_entries_lbl);
    gtk_frame_set_child(GTK_FRAME(g_info_panel), info_box);
    gtk_widget_set_visible(g_info_panel, FALSE);


    GtkWidget *content_stack = gtk_stack_new();
    gtk_stack_add_named(GTK_STACK(content_stack), g_welcome_label, "welcome");
    gtk_stack_add_named(GTK_STACK(content_stack), scrolled, "filelist");
    gtk_stack_set_visible_child_name(GTK_STACK(content_stack), "welcome");
    gtk_widget_set_vexpand(content_stack, TRUE);
    gtk_widget_set_hexpand(content_stack, TRUE);


    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_append(GTK_BOX(main_box), content_stack);
    gtk_box_append(GTK_BOX(main_box), g_info_panel);
    gtk_window_set_child(GTK_WINDOW(win), main_box);


    g_object_set_data(G_OBJECT(win), "content-stack", content_stack);

    gtk_window_present(GTK_WINDOW(win));


    if(g_initial_gui_archive){

        while(g_main_context_pending(NULL)) g_main_context_iteration(NULL, FALSE);

        if(open_archive_gui(g_initial_gui_archive)!=0){
            fprintf(stderr, "Failed to open initial archive: %s\n", g_initial_gui_archive);
        }


        while(g_main_context_pending(NULL)) g_main_context_iteration(NULL, FALSE);
    }
}

static int run_gui(int argc, char **argv){
    (void)argc;
    GtkApplication *app = gtk_application_new("si.generacija.baar", G_APPLICATION_NON_UNIQUE);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);


    char *app_argv[2];
    app_argv[0] = argv ? argv[0] : "baar";
    app_argv[1] = NULL;
    int status = g_application_run(G_APPLICATION(app), 1, app_argv);
    g_object_unref(app);
    return status;
}

static uint64_t read_u64(FILE *f){ uint64_t v; fread(&v,8,1,f); return v; }
static void write_u64(FILE *f,uint64_t v){ fwrite(&v,8,1,f); }
static uint32_t read_u32(FILE *f){ uint32_t v; fread(&v,4,1,f); return v; }
static void write_u32(FILE *f,uint32_t v){ fwrite(&v,4,1,f); }
static uint16_t read_u16(FILE *f){ uint16_t v; fread(&v,2,1,f); return v; }
static void write_u16(FILE *f,uint16_t v){ fwrite(&v,2,1,f); }


static char *make_name(const char *base, const char *suffix){
    if(!base) return NULL;
    size_t bl = strlen(base);
    size_t sl = strlen(suffix);
    size_t need = bl + sl + 1;
    char *r = malloc(need);
    if(!r) return NULL;
    memcpy(r, base, bl);
    memcpy(r+bl, suffix, sl+1);
    return r;
}


static char *normalize_path_basic(const char *path){
    if(!path) return NULL;
    size_t len = strlen(path);
    if(len == 0) return NULL;
    char *out = malloc(len + 1);
    if(!out) return NULL;
    size_t oi = 0;
    int last_slash = 0;
    for(size_t i=0;i<len;i++){
        unsigned char c = (unsigned char)path[i];
        if(c == '/'){
            if(oi == 0){
                out[oi++] = '/';
            } else if(!last_slash){
                out[oi++] = '/';
            }
            last_slash = 1;
        } else {
            out[oi++] = (char)c;
            last_slash = 0;
        }
    }
    while(oi > 1 && out[oi-1] == '/') oi--;
    out[oi] = '\0';
    if(oi == 0){
        free(out);
        return NULL;
    }
    return out;
}

static void remove_path_recursive(const char *path){
    if(!path || !path[0]) return;
    struct stat st;
    if(lstat(path, &st) != 0){
        return;
    }
    if(S_ISDIR(st.st_mode)){
        DIR *dir = opendir(path);
        if(dir){
            struct dirent *ent;
            while((ent = readdir(dir))){
                if(strcmp(ent->d_name, ".")==0 || strcmp(ent->d_name, "..") == 0) continue;
                char child[PATH_MAX * 2];
                snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
                remove_path_recursive(child);
            }
            closedir(dir);
        }
        rmdir(path);
    } else {
        unlink(path);
    }
}

static void cleanup_registered_temp_dirs(void){
    GSList *iter = g_temp_dirs_for_cleanup;
    while(iter){
        char *dir = iter->data;
        if(dir){
            remove_path_recursive(dir);
            free(dir);
        }
        iter = iter->next;
    }
    g_slist_free(g_temp_dirs_for_cleanup);
    g_temp_dirs_for_cleanup = NULL;
}

static void register_temp_dir_for_cleanup(const char *path){
    if(!path || !path[0]) return;
    char *dup = strdup(path);
    if(!dup) return;
    g_temp_dirs_for_cleanup = g_slist_prepend(g_temp_dirs_for_cleanup, dup);
    if(!g_cleanup_registered){
        atexit(cleanup_registered_temp_dirs);
        g_cleanup_registered = 1;
    }
}

static int make_temp_dir_near_archive(const char *archive_path, const char *tag,
                                      char *out, size_t out_sz){
    if(!archive_path || !tag || !out || out_sz == 0) return -1;
    char base[PATH_MAX];
    const char *slash = strrchr(archive_path, '/');
    if(slash){
        size_t dir_len = (size_t)(slash - archive_path);
        if(dir_len == 0){
            strcpy(base, "/");
        } else {
            if(dir_len >= sizeof(base)) dir_len = sizeof(base) - 1;
            memcpy(base, archive_path, dir_len);
            base[dir_len] = '\0';
        }
    } else {
        strcpy(base, ".");
    }

    int pid = (int)getpid();
    for(int attempt = 0; attempt < 100; attempt++){
        if(strcmp(base, "/") == 0){
            snprintf(out, out_sz, "/.%s_%d_%02d", tag, pid, attempt);
        } else {
            snprintf(out, out_sz, "%s/.%s_%d_%02d", base, tag, pid, attempt);
        }
        if(mkdir(out, 0700) == 0){
            return 0;
        }
        if(errno == EEXIST){
            continue;
        }
        if(errno == EROFS || errno == EACCES || errno == EPERM || errno == ENOENT){
            return 1; // signal fallback to /tmp
        }
    }
    return 1;
}

static int prepare_temp_dir_for_archive(const char *archive_path, const char *tag,
                                         char *out, size_t out_sz, int track_cleanup){
    int res = make_temp_dir_near_archive(archive_path, tag, out, out_sz);
    if(res == 0){
        if(track_cleanup) register_temp_dir_for_cleanup(out);
        return 0;
    }
    int pid = (int)getpid();
    for(int attempt = 0; attempt < 100; attempt++){
        snprintf(out, out_sz, "/tmp/%s_%d_%02d", tag, pid, attempt);
        if(mkdir(out, 0700) == 0){
            if(track_cleanup) register_temp_dir_for_cleanup(out);
            return 0;
        }
        if(errno == EEXIST){
            continue;
        }
    }
    return -1;
}

static void baar_signal_handler(int sig){
    (void)sig;
    g_abort_requested = 1;
}

static void install_cli_signal_handlers(void){
    if(g_sig_handlers_installed) return;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = baar_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    struct sigaction oldint, oldterm;
    if(sigaction(SIGINT, &sa, &oldint) == 0){
        g_prev_sigint = oldint;
    } else {
        memset(&g_prev_sigint, 0, sizeof(g_prev_sigint));
        g_prev_sigint.sa_handler = SIG_DFL;
    }
    if(sigaction(SIGTERM, &sa, &oldterm) == 0){
        g_prev_sigterm = oldterm;
    } else {
        memset(&g_prev_sigterm, 0, sizeof(g_prev_sigterm));
        g_prev_sigterm.sa_handler = SIG_DFL;
    }
    g_sig_handlers_installed = 1;
}

static void restore_cli_signal_handlers(void){
    if(!g_sig_handlers_installed) return;
    sigaction(SIGINT, &g_prev_sigint, NULL);
    sigaction(SIGTERM, &g_prev_sigterm, NULL);
    g_sig_handlers_installed = 0;
    g_abort_requested = 0;
}

static char **collect_files_recursive(const char *path, int *out_count){
    if(out_count) *out_count = 0;
    if(!path || !path[0]) return NULL;

    char *clean = normalize_path_basic(path);
    if(!clean) return NULL;

    char **list = NULL; int count = 0;
    struct stat st;
    if(stat(clean,&st)!=0){ free(clean); return NULL; }
    if(S_ISDIR(st.st_mode)){
        DIR *d = opendir(clean);
        if(!d){ free(clean); return NULL; }
        struct dirent *ent;
        while((ent = readdir(d))){
            if(strcmp(ent->d_name, ".")==0 || strcmp(ent->d_name, "..")==0) continue;
            char child[4096];
            if(clean[0]=='/' && clean[1]=='\0') snprintf(child,sizeof(child),"/%s", ent->d_name);
            else snprintf(child,sizeof(child),"%s/%s", clean, ent->d_name);
            int child_count = 0;
            char **child_list = collect_files_recursive(child, &child_count);
            if(child_list){
                for(int i=0; i<child_count; i++){
                    list = realloc(list, sizeof(char*)*(count+1));
                    list[count++] = child_list[i];
                }
                free(child_list);
            }
        }
        closedir(d);
        free(clean);

        list = realloc(list, sizeof(char*)*(count+1));
        list[count] = NULL;
        if(out_count) *out_count = count;
        return list;
    } else if(S_ISREG(st.st_mode)){
        list = malloc(sizeof(char*)*2);
        if(!list){ free(clean); return NULL; }
        list[0] = clean;
        list[1] = NULL;
        if(out_count) *out_count = 1;
        return list;
    }
    free(clean);
    return NULL;
}

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} path_stack_t;

static void path_stack_free(path_stack_t *stack){
    if(!stack) return;
    for(size_t i=0;i<stack->count;i++){
        free(stack->items[i]);
    }
    free(stack->items);
    stack->items = NULL;
    stack->count = 0;
    stack->capacity = 0;
}

static int path_stack_push(path_stack_t *stack, const char *path){
    if(!stack || !path) return -1;
    char *dup = strdup(path);
    if(!dup) return -1;
    if(stack->count == stack->capacity){
        size_t newcap = stack->capacity ? stack->capacity * 2 : 64;
        char **tmp = realloc(stack->items, sizeof(char*) * newcap);
        if(!tmp){
            free(dup);
            return -1;
        }
        stack->items = tmp;
        stack->capacity = newcap;
    }
    stack->items[stack->count++] = dup;
    return 0;
}

static char *path_stack_pop(path_stack_t *stack){
    if(!stack || stack->count == 0) return NULL;
    return stack->items[--stack->count];
}

typedef struct {
    const char *name;
    uint32_t index;
} entry_lookup_item_t;

static int compare_lookup_items(const void *a, const void *b){
    const entry_lookup_item_t *ea = a;
    const entry_lookup_item_t *eb = b;
    if(!ea->name && !eb->name) return 0;
    if(!ea->name) return -1;
    if(!eb->name) return 1;
    return strcmp(ea->name, eb->name);
}

static entry_lookup_item_t *build_entry_lookup_items(index_t *idx, size_t *out_count){
    if(out_count) *out_count = 0;
    if(!idx || idx->n == 0) return NULL;
    entry_lookup_item_t *items = malloc(sizeof(*items) * idx->n);
    if(!items) return NULL;
    size_t count = 0;
    for(uint32_t i=0;i<idx->n;i++){
        entry_t *e = &idx->entries[i];
        if(!e->name || (e->flags & 4)) continue;
        items[count].name = e->name;
        items[count].index = i;
        count++;
    }
    if(count > 1){
        qsort(items, count, sizeof(*items), compare_lookup_items);
    }
    if(out_count) *out_count = count;
    return items;
}

static entry_t *find_entry_by_name_fast(entry_lookup_item_t *items, size_t count, index_t *idx, const char *name){
    if(!items || !idx || !name || count == 0) return NULL;
    size_t lo = 0, hi = count;
    while(lo < hi){
        size_t mid = (lo + hi) / 2;
        const char *cur = items[mid].name;
        if(!cur){
            lo = mid + 1;
            continue;
        }
        int cmp = strcmp(name, cur);
        if(cmp == 0){
            uint32_t idx_pos = items[mid].index;
            if(idx_pos < idx->n){
                return &idx->entries[idx_pos];
            }
            return NULL;
        }
        if(cmp < 0) hi = mid;
        else lo = mid + 1;
    }
    return NULL;
}

typedef struct {
    FILE *archive_fp;
    index_t *idx;
    size_t original_entry_count;
    entry_lookup_item_t *entry_lookup;
    size_t entry_lookup_count;
    uint8_t *entry_seen;
    uint32_t **to_remove;
    uint32_t *remove_count;
    const char *pwd;
    int incremental_mode;
    int mirror_mode;
    char **ignore_patterns;
    size_t ignore_count;
} add_stream_ctx_t;

static char *build_child_path(const char *parent, const char *name){
    if(!parent || !name) return NULL;
    size_t pl = strlen(parent);
    size_t nl = strlen(name);
    size_t extra = 2; // slash + nul
    if(pl > 0 && parent[pl-1] == '/') extra--;
    char *out = malloc(pl + nl + extra);
    if(!out) return NULL;
    if(pl == 1 && parent[0] == '/'){
        snprintf(out, pl + nl + extra, "/%s", name);
    } else if(pl > 0 && parent[pl-1] == '/'){
        snprintf(out, pl + nl + extra, "%s%s", parent, name);
    } else {
        snprintf(out, pl + nl + extra, "%s/%s", parent, name);
    }
    return out;
}

static char *resolve_archive_path(const add_job_t *job, const char *src_path){
    if(!job || !src_path) return NULL;
    if(job->archive_override){
        return strdup(job->archive_override);
    }
    return normalize_path_basic(src_path);
}

static void mark_entry_deleted_flag(index_t *idx, uint32_t id){
    if(!idx) return;
    for(uint32_t i=0;i<idx->n;i++){
        if(idx->entries[i].id == id){
            idx->entries[i].flags |= 4;
            break;
        }
    }
}

static int process_single_file(add_stream_ctx_t *ctx,
                               const char *src_path, const char *archive_path,
                               int clevel, const struct stat *st);
static int walk_job_tree(add_stream_ctx_t *ctx, const add_job_t *job);

static int add_ignore_pattern(char ***patterns, size_t *count, const char *pattern){
    if(!patterns || !count || !pattern || !pattern[0]) return -1;
    char *dup = strdup(pattern);
    if(!dup) return -1;
    char **tmp = realloc(*patterns, sizeof(char*) * (*count + 1));
    if(!tmp){
        free(dup);
        return -1;
    }
    *patterns = tmp;
    (*patterns)[*count] = dup;
    (*count)++;
    return 0;
}

static void free_ignore_patterns(char **patterns, size_t count){
    if(!patterns) return;
    for(size_t i=0;i<count;i++){
        free(patterns[i]);
    }
    free(patterns);
}

static int should_ignore_path(const char *src_path, const char *archive_path,
                              char **patterns, size_t pattern_count){
    if(!patterns || pattern_count == 0) return 0;
    const char *candidates[4];
    size_t candidate_count = 0;
    if(archive_path && archive_path[0]){
        candidates[candidate_count++] = archive_path;
    }
    if(src_path && src_path[0]){
        candidates[candidate_count++] = src_path;
        const char *base = strrchr(src_path, '/');
        if(base && base[1]){
            candidates[candidate_count++] = base + 1;
        }
    } else if(archive_path && archive_path[0]){
        const char *base = strrchr(archive_path, '/');
        if(base && base[1]){
            candidates[candidate_count++] = base + 1;
        }
    }
    for(size_t pi=0; pi<pattern_count; pi++){
        const char *pattern = patterns[pi];
        if(!pattern || !pattern[0]) continue;
        for(size_t ci=0; ci<candidate_count; ci++){
            if(fnmatch(pattern, candidates[ci], 0) == 0){
                return 1;
            }
        }
    }
    return 0;
}


typedef struct { const char *name; volatile int *run; } spinner_arg_t;
static void *spinner_fn(void *arg){
    spinner_arg_t *sa = arg;
    const char spin[] = "|/-\\";
    int idx = 0;
    while(*(sa->run)){
        fprintf(stderr, "\r%s %c", sa->name, spin[idx%4]); fflush(stderr);
        idx++;
        struct timespec ts = {0, 120 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return NULL;
}



static void xor_buf(unsigned char *buf, size_t len, const char *pwd){
    if(!pwd || !pwd[0] || !buf || len==0) return;
    const char *legacy = getenv("BAAR_LEGACY_XOR");
    if(legacy && legacy[0]){
        size_t plen = strlen(pwd);
        for(size_t i=0;i<len;i++) buf[i] ^= (unsigned char)pwd[i%plen];
        return;
    }

    unsigned char salt_full[32];
    SHA256_CTX shactx; SHA256_Init(&shactx); SHA256_Update(&shactx, pwd, strlen(pwd)); SHA256_Final(salt_full, &shactx);
    unsigned char salt[16]; memcpy(salt, salt_full, 16);
    unsigned char key[32];
    if(!PKCS5_PBKDF2_HMAC(pwd, (int)strlen(pwd), salt, 16, 100000, EVP_sha256(), 32, key)){
        fprintf(stderr, "[BAAR] PBKDF2 failed\n"); return; }

    uint64_t counter = 0; size_t offset = 0; unsigned char ks[32];
    while(offset < len){
        HMAC_CTX *hctx = HMAC_CTX_new();
        if(!hctx){ fprintf(stderr, "[BAAR] HMAC alloc failed\n"); return; }
        if(!HMAC_Init_ex(hctx, key, 32, EVP_sha256(), NULL)){
            HMAC_CTX_free(hctx); fprintf(stderr, "[BAAR] HMAC init failed\n"); return; }
        const char marker[] = "BAARSTREAM";
        HMAC_Update(hctx, (unsigned char*)marker, sizeof(marker)-1);
        unsigned char ctrbuf[8];
        for(int i=0;i<8;i++) ctrbuf[i] = (unsigned char)((counter >> (56 - i*8)) & 0xFF);
        HMAC_Update(hctx, ctrbuf, 8);
        unsigned int outl=0; HMAC_Final(hctx, ks, &outl); HMAC_CTX_free(hctx);
        if(outl < 32){
            SHA256_CTX sh2; SHA256_Init(&sh2); SHA256_Update(&sh2, ks, outl); SHA256_Final(ks, &sh2); outl = 32; }
        size_t to_xor = (len - offset) < 32 ? (len - offset) : 32;
        for(size_t j=0;j<to_xor;j++) buf[offset + j] ^= ks[j];
        offset += to_xor; counter++;
    }

    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(salt_full, sizeof(salt_full));
}

static index_t load_index(FILE *f){
    index_t idx = {0};
    fseek(f,0,SEEK_SET);
    char magic[8]={0};
    fread(magic,1,8,f);
    if(strncmp(magic,MAGIC,6)!=0){ return idx; }
    uint64_t index_offset = read_u64(f);
    if(index_offset==0){ return idx; }
    fseek(f,index_offset,SEEK_SET);
    uint32_t n = read_u32(f);
    idx.n = n;
    idx.entries = calloc(n,sizeof(entry_t));
    uint32_t maxid=0;
    for(uint32_t i=0;i<n;i++){
        entry_t *e = &idx.entries[i];
        e->id = read_u32(f);
    uint16_t namelen = read_u16(f);
    e->name = malloc(namelen+1);
    fread(e->name,1,namelen,f);
    e->name[namelen]=0;
    /* strip leading slashes so UI shows top-level folders like 'home' instead of '/' */
    if(e->name && e->name[0] == '/'){
        char *tmp = e->name;
        while(tmp[0] == '/') tmp++;
        if(tmp != e->name){
            char *newn = strdup(tmp);
            free(e->name);
            e->name = newn ? newn : strdup("");
        }
    }
    e->flags = fgetc(f);
    e->comp_level = fgetc(f);
    e->data_offset = read_u64(f);
    e->comp_size = read_u64(f);
    e->uncomp_size = read_u64(f);
    e->crc32 = read_u32(f);

    e->mode = read_u32(f);
    e->uid = read_u32(f);
    e->gid = read_u32(f);
    e->mtime = read_u64(f);

    e->meta_n = read_u32(f);
    if(e->meta_n){
        e->meta = calloc(e->meta_n, sizeof(*e->meta));
        for(uint32_t m=0;m<e->meta_n;m++){
            uint16_t klen = read_u16(f);
            if(klen){ e->meta[m].key = malloc(klen+1); fread(e->meta[m].key,1,klen,f); e->meta[m].key[klen]=0; } else e->meta[m].key = NULL;
            uint16_t vlen = read_u16(f);
            if(vlen){ e->meta[m].value = malloc(vlen+1); fread(e->meta[m].value,1,vlen,f); e->meta[m].value[vlen]=0; } else e->meta[m].value = NULL;
        }
    } else { e->meta = NULL; }
    if(e->id>maxid) maxid=e->id;
    }
    idx.next_id = maxid+1;
    return idx;
}


static index_t load_libarchive_index(const char *path){
    index_t idx = {0};

    struct archive *a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);


    if (g_archive_password) {
        archive_read_add_passphrase(a, g_archive_password);

        g_archive_was_encrypted = 1;
    }


    int open_r = archive_read_open_filename(a, path, 10240);
    if (open_r != ARCHIVE_OK) {
        archive_read_free(a);

        if (g_main_window && !g_archive_password) {
            if (show_password_dialog("Archive may be password-protected. Enter password to open or Cancel to skip.")) {
                if (g_archive_password) {
                    fprintf(stderr, "[DEBUG] load_libarchive_index: user provided a password (len=%zu)\n", strlen(g_archive_password));
                } else {
                    fprintf(stderr, "[DEBUG] load_libarchive_index: show_password_dialog returned true but no password set\n");
                }

                a = archive_read_new();
                archive_read_support_filter_all(a);
                archive_read_support_format_all(a);
                if (g_archive_password) archive_read_add_passphrase(a, g_archive_password);
                open_r = archive_read_open_filename(a, path, 10240);
                if (open_r != ARCHIVE_OK) {
                    archive_read_free(a);
                    return idx;
                }

                g_archive_was_encrypted = 1;
            } else {
                return idx;
            }
        } else {
            return idx;
        }
    }


    uint32_t count = 0;
    struct archive_entry *entry;
    int maybe_encrypted = 0;

        if (g_main_window && !g_archive_password) {
            int t = la_test(path, NULL);
            if (t != 0) {
                maybe_encrypted = 1;
            }

    }
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {

        int skip_r = archive_read_data_skip(a);
        if (skip_r != ARCHIVE_OK) {
            const char *estr = archive_error_string(a);
                    if (estr) {
                if (strstr(estr, "Passphrase") || strstr(estr, "passphrase") ||
                    strstr(estr, "encrypted") || strstr(estr, "decryption") ||
                    strstr(estr, "Decryption")) {
                    maybe_encrypted = 1;
                    break;
                } else {

                }
            }
        }
        count++;
    }


    if (maybe_encrypted) {
        archive_read_free(a);
        if (g_main_window && !g_archive_password) {
            if (show_password_dialog("Archive may be password-protected. Enter password to open or Cancel to skip.")) {

                a = archive_read_new();
                archive_read_support_filter_all(a);
                archive_read_support_format_all(a);
                if (g_archive_password) archive_read_add_passphrase(a, g_archive_password);
                int open_r2 = archive_read_open_filename(a, path, 10240);
                if (open_r2 != ARCHIVE_OK) {

                    archive_read_free(a);
                    return idx;
                }

                count = 0;
                while (archive_read_next_header(a, &entry) == ARCHIVE_OK) { count++; archive_read_data_skip(a); }

                g_archive_was_encrypted = 1;

                maybe_encrypted = 0;
                archive_read_free(a);

                a = archive_read_new();
                archive_read_support_filter_all(a);
                archive_read_support_format_all(a);
                if (g_archive_password) archive_read_add_passphrase(a, g_archive_password);
                if (archive_read_open_filename(a, path, 10240) != ARCHIVE_OK) {
                    archive_read_free(a);
                    return idx;
                }
            } else {
                return idx;
            }
        } else {

            a = archive_read_new();
            archive_read_support_filter_all(a);
            archive_read_support_format_all(a);
            if (g_archive_password) archive_read_add_passphrase(a, g_archive_password);
            int open_r2 = archive_read_open_filename(a, path, 10240);
            if (open_r2 != ARCHIVE_OK) {
                archive_read_free(a);
                return idx;
            }

            count = 0;
            while (archive_read_next_header(a, &entry) == ARCHIVE_OK) { count++; archive_read_data_skip(a); }
            archive_read_free(a);
            a = archive_read_new();
            archive_read_support_filter_all(a);
            archive_read_support_format_all(a);
            if (g_archive_password) archive_read_add_passphrase(a, g_archive_password);
            if (archive_read_open_filename(a, path, 10240) != ARCHIVE_OK) { archive_read_free(a); return idx; }
        }
    }


    idx.n = count;
    idx.entries = calloc(count, sizeof(entry_t));
    idx.next_id = count + 1;


    archive_read_free(a);
    a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);
    if (g_archive_password) archive_read_add_passphrase(a, g_archive_password);

    if (archive_read_open_filename(a, path, 10240) != ARCHIVE_OK) {
        archive_read_free(a);
        free(idx.entries);
        idx.entries = NULL;
        idx.n = 0;
        return idx;
    }

    uint32_t i = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK && i < count) {
        entry_t *e = &idx.entries[i];

        e->id = i + 1;
        const char *pathname = archive_entry_pathname(entry);
        const char *name_src = pathname ? pathname : "";
        /* strip leading slashes so GUI doesn't create a root '/' folder for absolute paths */
        const char *name_trim = name_src;
        while(*name_trim == '/') name_trim++;
        e->name = strdup(name_trim);


        int64_t size = archive_entry_size_is_set(entry) ? archive_entry_size(entry) : 0;




        e->flags = (size > 0) ? 0x01 : 0x00;


        e->comp_level = (size > 0) ? 2 : 0;

        e->data_offset = 0;

        e->comp_size = 0;
        e->uncomp_size = size;
        e->crc32 = 0;


        e->mode = archive_entry_mode(entry);
        e->uid = archive_entry_uid(entry);
        e->gid = archive_entry_gid(entry);
        e->mtime = archive_entry_mtime(entry);


        e->meta = NULL;
        e->meta_n = 0;

        archive_read_data_skip(a);
        i++;
    }

    archive_read_free(a);
    return idx;
}

static void free_index(index_t *idx){
    if(!idx) return;
    for(uint32_t i=0;i<idx->n;i++){
        free(idx->entries[i].name);
        if(idx->entries[i].meta){
            for(uint32_t m=0;m<idx->entries[i].meta_n;m++){ free(idx->entries[i].meta[m].key); free(idx->entries[i].meta[m].value); }
            free(idx->entries[i].meta);
        }
    }
    free(idx->entries);
    idx->entries=NULL; idx->n=0;
}

static int write_index(FILE *f, index_t *idx){

    uint64_t off = ftell(f);
    write_u32(f, idx->n);
    for(uint32_t i=0;i<idx->n;i++){
        entry_t *e = &idx->entries[i];
        write_u32(f, e->id);
        uint16_t namelen = strlen(e->name);
        write_u16(f, namelen);
        fwrite(e->name,1,namelen,f);
        fputc(e->flags,f);
        fputc(e->comp_level,f);
        write_u64(f, e->data_offset);
        write_u64(f, e->comp_size);
        write_u64(f, e->uncomp_size);
        write_u32(f, e->crc32);

        write_u32(f, e->mode);
        write_u32(f, e->uid);
        write_u32(f, e->gid);
        write_u64(f, e->mtime);

        write_u32(f, e->meta_n);
        for(uint32_t m=0;m<e->meta_n;m++){
            uint16_t klen = e->meta[m].key ? strlen(e->meta[m].key) : 0;
            uint16_t vlen = e->meta[m].value ? strlen(e->meta[m].value) : 0;
            write_u16(f, klen); if(klen) fwrite(e->meta[m].key,1,klen,f);
            write_u16(f, vlen); if(vlen) fwrite(e->meta[m].value,1,vlen,f);
        }
    }
    return (int)off;
}

static int update_header_index_offset(FILE *f, uint64_t index_offset){
    fseek(f,0,SEEK_SET);
    char magic[8]={0};
    memcpy(magic,MAGIC,6);
    fwrite(magic,1,8,f);
    write_u64(f, index_offset);

    long cur = ftell(f);
    for(long i=cur;i<HEADER_SIZE;i++) fputc(0,f);
    fflush(f);
    return 0;
}

static int ensure_header(FILE *f){
    fseek(f,0,SEEK_SET);
    char buf[8]={0};
    fread(buf,1,8,f);
    if(strncmp(buf,MAGIC,6)==0) return 0;

    fseek(f,0,SEEK_SET);
    char magic[8]; memcpy(magic,MAGIC,6);
    fwrite(magic,1,8,f);
    write_u64(f,0);

    long cur = ftell(f);
    for(long i=cur;i<HEADER_SIZE;i++) fputc(0,f);
    fflush(f);
    return 0;
}

typedef enum {
    FILE_PLAN_ADD = 0,
    FILE_PLAN_SKIP_UNCHANGED,
    FILE_PLAN_SKIP_ERROR
} file_plan_action_t;

typedef struct {
    int stat_ok;
    int readable;
    int errno_code;
    int counts_for_desired;
    struct stat st;
    file_plan_action_t action;
    uint32_t existing_id;
    int existing_valid;
    uint64_t existing_uncomp;
    uint64_t existing_mtime;
    uint32_t existing_mode;
} file_plan_t;

static int compare_entry_ptr(const void *a, const void *b){
    const entry_t *ea = *(const entry_t * const *)a;
    const entry_t *eb = *(const entry_t * const *)b;
    if(!ea || !eb){
        return (ea > eb) - (ea < eb);
    }
    if(!ea->name && !eb->name) return 0;
    if(!ea->name) return -1;
    if(!eb->name) return 1;
    return strcmp(ea->name, eb->name);
}

static entry_t *find_entry_by_name(entry_t **arr, size_t count, const char *name){
    if(!arr || !name) return NULL;
    size_t lo = 0, hi = count;
    while(lo < hi){
        size_t mid = (lo + hi) / 2;
        entry_t *cur = arr[mid];
        if(!cur || !cur->name){
            lo = mid + 1;
            continue;
        }
        int cmp = strcmp(name, cur->name);
        if(cmp == 0) return cur;
        if(cmp < 0) hi = mid;
        else lo = mid + 1;
    }
    return NULL;
}

static int compare_str_ptr(const void *a, const void *b){
    const char *sa = *(const char * const *)a;
    const char *sb = *(const char * const *)b;
    if(!sa && !sb) return 0;
    if(!sa) return -1;
    if(!sb) return 1;
    return strcmp(sa, sb);
}

static int name_in_desired(char **arr, size_t count, const char *name){
    if(!arr || !name || count == 0) return 0;
    size_t lo = 0, hi = count;
    while(lo < hi){
        size_t mid = (lo + hi) / 2;
        const char *cur = arr[mid];
        if(!cur){
            lo = mid + 1;
            continue;
        }
        int cmp = strcmp(name, cur);
        if(cmp == 0) return 1;
        if(cmp < 0) hi = mid;
        else lo = mid + 1;
    }
    return 0;
}

static void append_unique_id(uint32_t **arr, uint32_t *count, uint32_t id){
    if(!arr || !count) return;
    for(uint32_t i=0;i<*count;i++){
        if((*arr)[i] == id) return;
    }
    uint32_t *tmp = realloc(*arr, sizeof(uint32_t) * (*count + 1));
    if(!tmp) return;
    *arr = tmp;
    (*arr)[*count] = id;
    (*count)++;
}

static int add_files(const char *archive, filepair_t *filepairs, int *clevels, int nfiles, const char *pwd, int incremental_mode, int mirror_mode){

    FILE *f = fopen(archive, "r+b");
    if(!f) f = fopen(archive, "w+b");
    if(!f) { perror("open archive"); return 1; }
    ensure_header(f);
    index_t idx = load_index(f);
    const char *mirror_debug = getenv("BAAR_DEBUG_MIRROR");

    entry_t **entry_lookup = NULL;
    size_t entry_lookup_count = 0;
    if(idx.n){
        entry_lookup = malloc(sizeof(entry_t*) * idx.n);
        if(entry_lookup){
            for(uint32_t i=0;i<idx.n;i++){
                if(idx.entries[i].name && !(idx.entries[i].flags & 4)){
                    entry_lookup[entry_lookup_count++] = &idx.entries[i];
                }
            }
            if(entry_lookup_count){
                qsort(entry_lookup, entry_lookup_count, sizeof(entry_t*), compare_entry_ptr);
            }
        }
    }

    file_plan_t *plans = NULL;
    if(nfiles > 0){
        plans = calloc(nfiles, sizeof(*plans));
        if(!plans){
            fprintf(stderr, "Out of memory while preparing file list.\n");
            free(entry_lookup);
            free_index(&idx);
            fclose(f);
            return 1;
        }
    }

    char **desired_names = NULL;
    size_t desired_count = 0;
    int desired_valid = 1;

    if(plans){
        for(int i=0;i<nfiles;i++){
            file_plan_t *plan = &plans[i];
            plan->action = FILE_PLAN_ADD;
            plan->counts_for_desired = 1;
            plan->stat_ok = 0;
            plan->readable = 0;
            plan->errno_code = 0;
            plan->existing_id = 0;
            plan->existing_valid = 0;
            const char *src = filepairs[i].src_path;

            if(stat(src, &plan->st)==0){
                plan->stat_ok = 1;
            } else {
                plan->errno_code = errno;
                plan->counts_for_desired = (plan->errno_code == EACCES || plan->errno_code == EPERM) ? 1 : 0;
                plan->action = FILE_PLAN_SKIP_ERROR;
            }

            if(plan->stat_ok){
                FILE *probe = fopen(src, "rb");
                if(!probe){
                    plan->errno_code = errno;
                    plan->action = FILE_PLAN_SKIP_ERROR;
                } else {
                    plan->readable = 1;
                    fclose(probe);
                }
            }

            if(filepairs[i].archive_path){
                entry_t *existing = find_entry_by_name(entry_lookup, entry_lookup_count, filepairs[i].archive_path);
                if(existing){
                    plan->existing_id = existing->id;
                    plan->existing_valid = 1;
                    plan->existing_uncomp = existing->uncomp_size;
                    plan->existing_mtime = existing->mtime;
                    plan->existing_mode = existing->mode;
                }
            }

            if(mirror_mode){
                if(plan->counts_for_desired && filepairs[i].archive_path && desired_valid){
                    char **tmp = realloc(desired_names, sizeof(char*) * (desired_count + 1));
                    if(!tmp){
                        desired_valid = 0;
                    } else {
                        desired_names = tmp;
                        desired_names[desired_count++] = filepairs[i].archive_path;
                    }
                }
            }

            if(incremental_mode){
                if(plan->stat_ok && plan->readable && plan->existing_valid){
                    if(plan->existing_uncomp == (uint64_t)plan->st.st_size &&
                       plan->existing_mtime == (uint64_t)plan->st.st_mtime &&
                       (plan->existing_mode & 07777u) == (uint32_t)(plan->st.st_mode & 07777u)){
                        plan->action = FILE_PLAN_SKIP_UNCHANGED;
                    }
                }
            }

            if(plan->action == FILE_PLAN_SKIP_ERROR){
                const char *msg = plan->errno_code ? strerror(plan->errno_code) : "unknown error";
                fprintf(stderr, "Skipping %s: %s\n", src, msg);
            }

            if(mirror_debug && mirror_mode){
                fprintf(stderr, "[BAAR mirror plan] %s action=%d existing=%u stat_ok=%d readable=%d size=%lld/%" PRIu64 " mtime=%lld/%" PRIu64 "\n",
                        src,
                        plan->action,
                        plan->existing_valid ? plan->existing_id : UINT32_MAX,
                        plan->stat_ok,
                        plan->readable,
                        (long long)(plan->stat_ok ? (long long)plan->st.st_size : -1),
                        plan->existing_uncomp,
                        (long long)(plan->stat_ok ? (long long)plan->st.st_mtime : -1),
                        plan->existing_mtime);
            }
        }
    }

    uint32_t *to_remove = NULL;
    uint32_t remove_count = 0;

    if(mirror_mode && desired_valid){
        if(desired_count > 1 && desired_names){
            qsort(desired_names, desired_count, sizeof(char*), compare_str_ptr);
        }
        for(uint32_t i=0;i<idx.n;i++){
            entry_t *e = &idx.entries[i];
            if(!e->name || (e->flags & 4)) continue;
            int keep = (desired_names && desired_count > 0) ? name_in_desired(desired_names, desired_count, e->name) : 0;
            if(!desired_names || desired_count == 0){
                keep = 0;
            }
            if(!keep){
                append_unique_id(&to_remove, &remove_count, e->id);
            }
        }
    }

    if(plans){
        for(int i=0;i<nfiles;i++){
            file_plan_t *plan = &plans[i];
            if(plan->existing_valid && plan->action == FILE_PLAN_ADD){
                append_unique_id(&to_remove, &remove_count, plan->existing_id);
            }
        }
    }

    free(entry_lookup);
    entry_lookup = NULL;

    if(mirror_debug && mirror_mode){
        fprintf(stderr, "[BAAR mirror] desired=%zu remove=%u valid=%d\n", desired_count, remove_count, desired_valid);
    }

    if(incremental_mode){
        if(remove_count > 0 && to_remove){
            if(!global_quiet && mirror_mode){
                fprintf(stderr, "Mirror: marking %u entries as deleted\n", remove_count);
            }
            for(uint32_t i=0;i<remove_count;i++){
                uint32_t rid = to_remove[i];
                for(uint32_t j=0;j<idx.n;j++){
                    if(idx.entries[j].id == rid){
                        idx.entries[j].flags |= 4;
                        break;
                    }
                }
            }
        }
        free(to_remove);
        to_remove = NULL;
    } else if(remove_count > 0){
        fclose(f);
        if(rebuild_archive(archive, to_remove, remove_count, global_quiet) != 0){
            free(to_remove);
            free(desired_names);
            free(plans);
            free_index(&idx);
            return 1;
        }
        free(to_remove);
        to_remove = NULL;
        f = fopen(archive, "r+b");
        if(!f) f = fopen(archive, "w+b");
        if(!f){
            perror("reopen archive");
            free(desired_names);
            free(plans);
            free_index(&idx);
            return 1;
        }
        ensure_header(f);
        free_index(&idx);
        idx = load_index(f);
    } else {
        free(to_remove);
    }

    fseek(f,0,SEEK_END);

    if(plans){
        for(int i=0;i<nfiles;i++){
            file_plan_t *plan = &plans[i];
            if(plan->action == FILE_PLAN_SKIP_UNCHANGED){
                if(incremental_mode && !global_quiet){
                    fprintf(stderr, "Skipping unchanged: %s\n", filepairs[i].src_path);
                }
                continue;
            }
            if(plan->action == FILE_PLAN_SKIP_ERROR){
                continue;
            }

            const char *path = filepairs[i].src_path;
            const char *archive_path = filepairs[i].archive_path;
            int clevel = clevels ? clevels[i] : 0;

            if(g_progress_dialog && g_progress_bar && g_progress_label){
                double frac = 0.1 + ((double)i / (double)nfiles) * 0.8;
                char pbuf[512];
                const char *display_name = strrchr(path, '/');
                display_name = display_name ? display_name + 1 : path;
                if(strlen(display_name) > 60){
                    snprintf(pbuf, sizeof(pbuf), "%.57s... (%d/%d)", display_name, i+1, nfiles);
                } else {
                    snprintf(pbuf, sizeof(pbuf), "%s (%d/%d)", display_name, i+1, nfiles);
                }
                update_progress(frac, pbuf);
                while(g_main_context_pending(NULL)) g_main_context_iteration(NULL, FALSE);
            }

            volatile int spinner_run = 1;
            spinner_arg_t *sarg = malloc(sizeof(*sarg));
            if(sarg){
                sarg->name = path;
                sarg->run = &spinner_run;
            }
            pthread_t spinner_thread;
            int spinner_created = 0;
            if(sarg && global_verbose && pthread_create(&spinner_thread, NULL, spinner_fn, sarg)==0){
                spinner_created = 1;
            } else if(sarg){
                free(sarg);
                sarg = NULL;
            }

            FILE *in = fopen(path, "rb");
            if(!in){
                if(spinner_created){ spinner_run = 0; pthread_join(spinner_thread, NULL); }
                if(sarg) free(sarg);
                fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
                continue;
            }

            size_t fsize = (size_t)plan->st.st_size;
            unsigned char *buf = NULL;
            if(fsize > 0){
                buf = malloc(fsize);
                if(!buf){
                    if(spinner_created){ spinner_run = 0; pthread_join(spinner_thread, NULL); }
                    if(sarg) free(sarg);
                    fclose(in);
                    fprintf(stderr, "Warning: not enough memory for %s\n", path);
                    continue;
                }
                size_t readn = fread(buf,1,fsize,in);
                if(readn != fsize){
                    if(spinner_created){ spinner_run = 0; pthread_join(spinner_thread, NULL); }
                    if(sarg) free(sarg);
                    fprintf(stderr, "Read error for %s: %s\n", path, ferror(in) ? strerror(errno) : "unexpected end of file");
                    fclose(in);
                    free(buf);
                    continue;
                }
            }
            fclose(in);

            const unsigned char *crc_buf = fsize > 0 ? buf : (const unsigned char*)"";
            uint32_t crc = crc32(0, crc_buf, fsize);
            unsigned char *out = NULL;
            size_t out_sz = 0;
            int compressed = 0;
            if(clevel>0 && fsize>0 && buf){
                unsigned char *tmpout = NULL; size_t tmpoutsz = 0;
                if(compress_data_level(clevel, buf, fsize, &tmpout, &tmpoutsz)==0){
                    if(tmpoutsz < fsize){ out = tmpout; out_sz = tmpoutsz; compressed = 1; }
                    else { free(tmpout); tmpout = NULL; }
                }
            }

            unsigned char *final = NULL;
            size_t final_sz = 0;
            if(compressed){ final = out; final_sz = out_sz; }
            else { final = buf; final_sz = fsize; }

            unsigned char *enc_buf = NULL;
            if(final_sz > 0){
                enc_buf = malloc(final_sz);
                if(!enc_buf){
                    if(spinner_created){ spinner_run = 0; pthread_join(spinner_thread, NULL); }
                    if(sarg) free(sarg);
                    fprintf(stderr, "Warning: not enough memory while encrypting %s\n", path);
                    if(out) free(out);
                    if(buf) free(buf);
                    continue;
                }
                memcpy(enc_buf, final, final_sz);
                if(pwd && pwd[0]){ xor_buf(enc_buf, final_sz, pwd); }
            }

            uint64_t data_offset = ftell(f);
            if(final_sz > 0){
                fwrite(enc_buf,1,final_sz,f);
            }

            idx.entries = realloc(idx.entries, sizeof(entry_t)*(idx.n+1));
            entry_t *e = &idx.entries[idx.n];
            memset(e,0,sizeof(*e));
            e->id = idx.next_id++;
            e->name = strdup(archive_path);
            e->flags = (compressed?1:0) | ((pwd&&pwd[0])?2:0);
            e->comp_level = clevel;
            e->data_offset = data_offset;
            e->comp_size = final_sz;
            e->uncomp_size = fsize;
            e->crc32 = crc;
            idx.n++;

            e->mode = (uint32_t)(plan->st.st_mode & 07777);
            e->uid = (uint32_t)plan->st.st_uid;
            e->gid = (uint32_t)plan->st.st_gid;
            e->mtime = (uint64_t)plan->st.st_mtime;

            unsigned int percent = 0;
            if(fsize>0 && final_sz <= fsize){
                long long diff = (long long)fsize - (long long)final_sz;
                if(diff < 0) diff = 0;
                unsigned long long p = (unsigned long long)diff * 100ULL / (unsigned long long)fsize;
                if(p>100) p = 100;
                percent = (unsigned int)p;
            }

            spinner_run = 0;
            if(spinner_created){ pthread_join(spinner_thread, NULL); }
            if(sarg) free(sarg);
            const char *base_name = strrchr(path, '/');
            base_name = base_name ? base_name + 1 : path;
            fprintf(stderr, "%s (%u%%)\n", base_name, percent);

            if(enc_buf) free(enc_buf);
            if(out) free(out);
            if(buf) free(buf);
        }
    }

    uint64_t index_offset = ftell(f);
    write_index(f, &idx);
    update_header_index_offset(f, index_offset);
    if(incremental_mode && !global_quiet){
        uint32_t deleted_entries = 0;
        for(uint32_t i=0;i<idx.n;i++){
            if(idx.entries[i].flags & 4) deleted_entries++;
        }
        if(idx.n > 0 && deleted_entries > idx.n / 2){
            fprintf(stderr, "Hint: archive contains many deleted entries; run 'baar f %s' to compact.\n", archive);
        }
    }
    fclose(f);
    free(desired_names);
    free(plans);
    free_index(&idx);
    return 0;
}

static int process_single_file(add_stream_ctx_t *ctx,
                               const char *src_path, const char *archive_path,
                               int clevel, const struct stat *st){
    if(!ctx || !ctx->idx || !ctx->archive_fp || !src_path || !archive_path || !st){
        return 1;
    }
    if(g_abort_requested) return 1;
    if(clevel < 0) clevel = 0;
    if(clevel > 3) clevel = 3;

    entry_t *existing = find_entry_by_name_fast(ctx->entry_lookup, ctx->entry_lookup_count,
                                                ctx->idx, archive_path);
    if(existing){
        size_t existing_idx = (size_t)(existing - ctx->idx->entries);
        if(ctx->entry_seen && existing_idx < ctx->original_entry_count){
            ctx->entry_seen[existing_idx] = 1;
        }
        if(ctx->incremental_mode){
            if(existing->uncomp_size == (uint64_t)st->st_size &&
               existing->mtime == (uint64_t)st->st_mtime &&
               (existing->mode & 07777u) == (uint32_t)(st->st_mode & 07777u)){
                if(!global_quiet){
                    fprintf(stderr, "Skipping unchanged: %s\n", src_path);
                }
                return 0;
            }
        }
        append_unique_id(ctx->to_remove, ctx->remove_count, existing->id);
        if(ctx->incremental_mode){
            mark_entry_deleted_flag(ctx->idx, existing->id);
        }
    }

    uint64_t file_sz64 = (uint64_t)st->st_size;
    if(file_sz64 > SIZE_MAX){
        fprintf(stderr, "Skipping %s: file too large for buffer\n", src_path);
        return 1;
    }
    size_t fsize = (size_t)file_sz64;

    volatile int spinner_run = 1;
    spinner_arg_t *sarg = malloc(sizeof(*sarg));
    pthread_t spinner_thread;
    int spinner_created = 0;
    if(sarg){
        sarg->name = src_path;
        sarg->run = &spinner_run;
        if(global_verbose && pthread_create(&spinner_thread, NULL, spinner_fn, sarg)==0){
            spinner_created = 1;
        } else {
            free(sarg);
            sarg = NULL;
        }
    }

    FILE *in = fopen(src_path, "rb");
    if(!in){
        if(spinner_created){ spinner_run = 0; pthread_join(spinner_thread, NULL); }
        if(sarg) free(sarg);
        fprintf(stderr, "Cannot open %s: %s\n", src_path, strerror(errno));
        return 1;
    }

    unsigned char *buf = NULL;
    if(fsize > 0){
        buf = malloc(fsize);
        if(!buf){
            if(spinner_created){ spinner_run = 0; pthread_join(spinner_thread, NULL); }
            if(sarg) free(sarg);
            fclose(in);
            fprintf(stderr, "Warning: not enough memory for %s\n", src_path);
            return 1;
        }
        size_t readn = fread(buf,1,fsize,in);
        if(readn != fsize){
            if(spinner_created){ spinner_run = 0; pthread_join(spinner_thread, NULL); }
            if(sarg) free(sarg);
            fprintf(stderr, "Read error for %s: %s\n", src_path,
                    ferror(in) ? strerror(errno) : "unexpected end of file");
            fclose(in);
            free(buf);
            return 1;
        }
    }
    fclose(in);

    const unsigned char *crc_buf = (buf && fsize > 0) ? buf : (const unsigned char*)"";
    uint32_t crc = crc32(0, crc_buf, fsize);

    unsigned char *out = NULL;
    size_t out_sz = 0;
    int compressed = 0;
    if(clevel > 0 && fsize > 0 && buf){
        unsigned char *tmpout = NULL; size_t tmpoutsz = 0;
        if(compress_data_level(clevel, buf, fsize, &tmpout, &tmpoutsz)==0){
            if(tmpoutsz < fsize){
                out = tmpout;
                out_sz = tmpoutsz;
                compressed = 1;
            } else {
                free(tmpout);
            }
        }
    }

    unsigned char *final = buf;
    size_t final_sz = fsize;
    if(out){
        final = out;
        final_sz = out_sz;
    }

    unsigned char *enc_buf = NULL;
    if(final_sz > 0){
        enc_buf = malloc(final_sz);
        if(!enc_buf){
            if(spinner_created){ spinner_run = 0; pthread_join(spinner_thread, NULL); }
            if(sarg) free(sarg);
            fprintf(stderr, "Warning: not enough memory while encrypting %s\n", src_path);
            if(out) free(out);
            if(buf) free(buf);
            return 1;
        }
        memcpy(enc_buf, final, final_sz);
        if(ctx->pwd && ctx->pwd[0]){
            xor_buf(enc_buf, final_sz, ctx->pwd);
        }
    }

    char *archive_name = strdup(archive_path);
    if(!archive_name){
        if(spinner_created){ spinner_run = 0; pthread_join(spinner_thread, NULL); }
        if(sarg) free(sarg);
        fprintf(stderr, "Out of memory while tracking %s\n", archive_path);
        if(enc_buf) free(enc_buf);
        if(out) free(out);
        if(buf) free(buf);
        return 1;
    }

    entry_t *tmp_entries = realloc(ctx->idx->entries, sizeof(entry_t) * (ctx->idx->n + 1));
    if(!tmp_entries){
        if(spinner_created){ spinner_run = 0; pthread_join(spinner_thread, NULL); }
        if(sarg) free(sarg);
        fprintf(stderr, "Out of memory while expanding index\n");
        free(archive_name);
        if(enc_buf) free(enc_buf);
        if(out) free(out);
        if(buf) free(buf);
        return 1;
    }
    ctx->idx->entries = tmp_entries;
    entry_t *e = &ctx->idx->entries[ctx->idx->n];
    memset(e,0,sizeof(*e));
    e->id = ctx->idx->next_id++;
    e->name = archive_name;
    e->flags = (compressed ? 1 : 0) | ((ctx->pwd && ctx->pwd[0]) ? 2 : 0);
    e->comp_level = clevel;

    fseek(ctx->archive_fp, 0, SEEK_END);
    uint64_t data_offset = ftell(ctx->archive_fp);
    if(final_sz > 0){
        size_t written = fwrite(enc_buf,1,final_sz,ctx->archive_fp);
        if(written != final_sz){
            fprintf(stderr, "Write error while adding %s\n", src_path);
            ctx->idx->next_id--;
            free(e->name);
            e->name = NULL;
            if(enc_buf) free(enc_buf);
            if(out) free(out);
            if(buf) free(buf);
            if(spinner_created){ spinner_run = 0; pthread_join(spinner_thread, NULL); }
            if(sarg) free(sarg);
            return 1;
        }
    }

    e->data_offset = data_offset;
    e->comp_size = final_sz;
    e->uncomp_size = fsize;
    e->crc32 = crc;
    e->mode = (uint32_t)(st->st_mode & 07777u);
    e->uid = (uint32_t)st->st_uid;
    e->gid = (uint32_t)st->st_gid;
    e->mtime = (uint64_t)st->st_mtime;
    ctx->idx->n++;

    spinner_run = 0;
    if(spinner_created){ pthread_join(spinner_thread, NULL); }
    if(sarg) free(sarg);

    unsigned int percent = 0;
    if(fsize > 0 && final_sz <= fsize){
        long long diff = (long long)fsize - (long long)final_sz;
        if(diff < 0) diff = 0;
        unsigned long long p = (unsigned long long)diff * 100ULL / (unsigned long long)fsize;
        if(p > 100) p = 100;
        percent = (unsigned int)p;
    }
    if(global_verbose){ fprintf(stderr, "%s ... (%u%%)\n", src_path, percent); }
    else {
        const char *base = strrchr(src_path, '/');
        base = base ? base + 1 : src_path;
        fprintf(stderr, "\rAdding files: %s (%u%%)\x1b[K", base, percent);
        fflush(stderr);
    }

    if(enc_buf) free(enc_buf);
    if(out) free(out);
    if(buf) free(buf);
    if(!global_quiet && !global_verbose) fprintf(stderr, "\n");
    return 0;
}

static int walk_job_tree(add_stream_ctx_t *ctx, const add_job_t *job){
    if(!ctx || !job || !job->src_root) return 0;

    char *root_archive = resolve_archive_path(job, job->src_root);
    if(root_archive){
        if(should_ignore_path(job->src_root, root_archive, ctx->ignore_patterns, ctx->ignore_count)){
            free(root_archive);
            return 0;
        }
        free(root_archive);
    }

    path_stack_t stack = {0};
    if(path_stack_push(&stack, job->src_root) != 0){
        fprintf(stderr, "Out of memory while scheduling %s\n", job->src_root);
        path_stack_free(&stack);
        return 1;
    }

    int status = 0;
    while(stack.count){
        if(g_abort_requested){
            status = 1;
            break;
        }
        char *current = path_stack_pop(&stack);
        if(!current) break;
        struct stat st;
        if(stat(current, &st)!=0){
            fprintf(stderr, "Skipping %s: %s\n", current, strerror(errno));
            free(current);
            continue;
        }

        if(S_ISDIR(st.st_mode)){
            DIR *dir = opendir(current);
            if(!dir){
                fprintf(stderr, "Cannot open directory %s: %s\n", current, strerror(errno));
                free(current);
                continue;
            }
            struct dirent *ent;
            while((ent = readdir(dir))){
                if(g_abort_requested){
                    status = 1;
                    break;
                }
                if(strcmp(ent->d_name, ".")==0 || strcmp(ent->d_name, "..") == 0) continue;
                char *child = build_child_path(current, ent->d_name);
                if(!child){
                    fprintf(stderr, "Out of memory while expanding %s/%s\n", current, ent->d_name);
                    status = 1;
                    continue;
                }
                if(g_abort_requested){
                    free(child);
                    status = 1;
                    break;
                }
                struct stat child_st;
                if(stat(child, &child_st)!=0){
                    fprintf(stderr, "Skipping %s: %s\n", child, strerror(errno));
                    free(child);
                    continue;
                }
                if(S_ISDIR(child_st.st_mode)){
                    char *dir_archive = resolve_archive_path(job, child);
                    int skip_dir = dir_archive ? should_ignore_path(child, dir_archive, ctx->ignore_patterns, ctx->ignore_count)
                                               : should_ignore_path(child, child, ctx->ignore_patterns, ctx->ignore_count);
                    if(dir_archive) free(dir_archive);
                    if(skip_dir){
                        free(child);
                        continue;
                    }
                    if(path_stack_push(&stack, child)!=0){
                        fprintf(stderr, "Out of memory while scheduling %s\n", child);
                        free(child);
                        status = 1;
                        continue;
                    }
                    free(child);
                    continue;
                }
                if(S_ISREG(child_st.st_mode)){
                    if(g_abort_requested){
                        free(child);
                        status = 1;
                        break;
                    }
                    char *archive_path = resolve_archive_path(job, child);
                    if(!archive_path){
                        fprintf(stderr, "Out of memory while preparing %s\n", child);
                        free(child);
                        status = 1;
                        continue;
                    }
                    if(!should_ignore_path(child, archive_path, ctx->ignore_patterns, ctx->ignore_count)){
                        if(process_single_file(ctx, child, archive_path, job->clevel, &child_st) != 0){
                            status = 1;
                            free(archive_path);
                            free(child);
                            break;
                        }
                    }
                    free(archive_path);
                    free(child);
                    continue;
                }
                free(child);
            }
            if(g_abort_requested){
                closedir(dir);
                free(current);
                break;
            }
            closedir(dir);
        } else if(S_ISREG(st.st_mode)){
            if(g_abort_requested){
                free(current);
                status = 1;
                break;
            }
            char *archive_path = resolve_archive_path(job, current);
            if(archive_path){
                if(!should_ignore_path(current, archive_path, ctx->ignore_patterns, ctx->ignore_count)){
                    if(process_single_file(ctx, current, archive_path, job->clevel, &st) != 0){
                        status = 1;
                        free(archive_path);
                        free(current);
                        break;
                    }
                }
                free(archive_path);
            }
        }
        free(current);
    }

    if(g_abort_requested){
        status = 1;
    }
    path_stack_free(&stack);
    return status;
}

static int add_files_streaming(const char *archive, add_job_t *jobs, int job_count,
                               const char *pwd, int incremental_mode, int mirror_mode,
                               char **ignore_patterns, size_t ignore_count){
    FILE *f = fopen(archive, "r+b");
    if(!f) f = fopen(archive, "w+b");
    if(!f){ perror("open archive"); return 1; }
    ensure_header(f);
    index_t idx = load_index(f);
    size_t original_entries = idx.n;

    size_t lookup_count = 0;
    entry_lookup_item_t *lookup = build_entry_lookup_items(&idx, &lookup_count);

    uint8_t *entry_seen = NULL;
    int mirror_tracking_ok = 1;
    if(mirror_mode && original_entries > 0){
        entry_seen = calloc(original_entries, 1);
        if(!entry_seen){
            mirror_tracking_ok = 0;
            if(!global_quiet){
                fprintf(stderr, "Warning: mirror tracking disabled due to low memory; skipped deletions.\n");
            }
        }
    }

    uint32_t *to_remove = NULL;
    uint32_t remove_count = 0;

    add_stream_ctx_t ctx = {
        .archive_fp = f,
        .idx = &idx,
        .original_entry_count = original_entries,
        .entry_lookup = lookup,
        .entry_lookup_count = lookup_count,
        .entry_seen = entry_seen,
        .to_remove = &to_remove,
        .remove_count = &remove_count,
        .pwd = pwd,
        .incremental_mode = incremental_mode,
        .mirror_mode = mirror_mode,
        .ignore_patterns = ignore_patterns,
        .ignore_count = ignore_count
    };

    /* Compact CLI mode: print header and a single dynamic info line under it */
    if(!global_quiet && !global_verbose){
        fprintf(stderr, "%s\n", BAAR_HEADER);
        fprintf(stderr, "Adding files: "); fflush(stderr);
    }

    int overall_status = 0;
    for(int i=0;i<job_count;i++){
        if(g_abort_requested) break;
        if(!jobs[i].src_root) continue;
        if(walk_job_tree(&ctx, &jobs[i]) != 0){
            overall_status = 1;
            if(g_abort_requested) break;
        }
    }

    if(mirror_mode && mirror_tracking_ok && original_entries > 0){
        for(size_t i=0;i<original_entries;i++){
            entry_t *e = &idx.entries[i];
            if(!e->name || (e->flags & 4)) continue;
            if(entry_seen && entry_seen[i]) continue;
            append_unique_id(&to_remove, &remove_count, e->id);
            if(incremental_mode){
                e->flags |= 4;
            }
        }
    }

    if(incremental_mode && remove_count > 0 && to_remove){
        if(!global_quiet && mirror_mode){
            fprintf(stderr, "Mirror: marking %u entries as deleted\n", remove_count);
        }
        for(uint32_t i=0;i<remove_count;i++){
            mark_entry_deleted_flag(&idx, to_remove[i]);
        }
    }

    if(g_abort_requested && !global_quiet){
        fprintf(stderr, "\nInterrupt received. Finalizing archive metadata...\n");
    }

    fseek(f,0,SEEK_END);
    uint64_t index_offset = ftell(f);
    write_index(f, &idx);
    update_header_index_offset(f, index_offset);
    if(incremental_mode && !global_quiet){
        uint32_t deleted_entries = 0;
        for(uint32_t i=0;i<idx.n;i++){
            if(idx.entries[i].flags & 4) deleted_entries++;
        }
        if(idx.n > 0 && deleted_entries > idx.n / 2){
            fprintf(stderr, "Hint: archive contains many deleted entries; run 'baar f %s' to compact.\n", archive);
        }
    }
    fclose(f);

    free(lookup);
    free(entry_seen);

    int rebuild_status = 0;
    if(!incremental_mode && remove_count > 0 && to_remove){
        if(!global_verbose && !global_quiet) fprintf(stderr, "\n");
        rebuild_status = rebuild_archive(archive, to_remove, remove_count, global_quiet);
    }

    free(to_remove);
    free_index(&idx);
    if(rebuild_status != 0) overall_status = 1;
    if(!global_verbose && !global_quiet){ fprintf(stderr, "\n"); }
    if(g_abort_requested){
        return overall_status == 0 ? 130 : overall_status;
    }
    return overall_status;
}


static char *escape_json_string(const char *s){
    if(!s) return strdup("");
    size_t len = strlen(s);

    size_t cap = len * 6 + 1;
    char *out = malloc(cap);
    char *p = out;
    for(size_t i=0;i<len;i++){
        unsigned char c = s[i];
        if(c=='\\'){ *p++='\\'; *p++='\\'; }
        else if(c=='"'){ *p++='\\'; *p++='"'; }
        else if(c=='\b'){ *p++='\\'; *p++='b'; }
        else if(c=='\f'){ *p++='\\'; *p++='f'; }
        else if(c=='\n'){ *p++='\\'; *p++='n'; }
        else if(c=='\r'){ *p++='\\'; *p++='r'; }
        else if(c=='\t'){ *p++='\\'; *p++='t'; }
        else if(c < 0x20){
            int written = snprintf(p, 7, "\\u%04x", c);
            p += written;
        } else { *p++ = c; }
    }
    *p = '\0';
    return out;
}

static int list_archive(const char *archive, int json){
    FILE *f = fopen(archive, "rb"); if(!f){ perror("open"); return 1; }
    index_t idx = load_index(f);
    if(!json){
        printf("Archive: %s\n", archive);
        printf("ID  Flags Comp  Size   CSize  Name\n");
        for(uint32_t i=0;i<idx.n;i++){
            entry_t *e = &idx.entries[i];
            printf("%3u  %02x   %u   %6" PRIu64 "  %6" PRIu64 "  %s\n",
                e->id, e->flags, e->comp_level, e->uncomp_size, e->comp_size, e->name);
        }
    } else {

        printf("[");
        for(uint32_t i=0;i<idx.n;i++){
            entry_t *e = &idx.entries[i];
            char *ename = escape_json_string(e->name);
            printf("{\"id\":%u,\"name\":\"%s\",\"flags\":%u,\"comp_level\":%u,\"uncomp_size\":%" PRIu64 ",\"comp_size\":%" PRIu64 ",\"crc32\":%u}",
                e->id, ename, (unsigned)e->flags, (unsigned)e->comp_level, e->uncomp_size, e->comp_size, e->crc32);
            free(ename);
            if(i+1<idx.n) printf(",");
        }
        printf("]\n");
    }
    if(!global_quiet && !global_verbose) fprintf(stderr, "\n");
    free_index(&idx); fclose(f); return 0;
}


static int search_archive(const char *archive, const char *pattern, int json){
    FILE *f = fopen(archive, "rb"); if(!f){ perror("open"); return 1; }
    index_t idx = load_index(f);
    if(!json){
        printf("ID  Flags Comp  Size   CSize  Name\n");
        for(uint32_t i=0;i<idx.n;i++){
            entry_t *e = &idx.entries[i];
            if(e->flags & 4) continue;
            if(fnmatch(pattern, e->name, 0)==0){
                printf("%3u  %02x   %u   %6" PRIu64 "  %6" PRIu64 "  %s\n",
                    e->id, e->flags, e->comp_level, e->uncomp_size, e->comp_size, e->name);
            }
        }
    } else {
        printf("[");
        int first = 1;
        for(uint32_t i=0;i<idx.n;i++){
            entry_t *e = &idx.entries[i];
            if(e->flags & 4) continue;
            if(fnmatch(pattern, e->name, 0)==0){
                if(!first) printf(",");
                first = 0;
                char *ename = escape_json_string(e->name);
                printf("{\"id\":%u,\"name\":\"%s\",\"flags\":%u,\"comp_level\":%u,\"uncomp_size\":%" PRIu64 ",\"comp_size\":%" PRIu64 ",\"crc32\":%u}",
                    e->id, ename, (unsigned)e->flags, (unsigned)e->comp_level, e->uncomp_size, e->comp_size, e->crc32);
                free(ename);
            }
        }
        printf("]\n");
    }
    free_index(&idx); fclose(f); return 0;
}

static int extract_archive(const char *archive, const char *dest, const char *pwd){
    FILE *f = fopen(archive, "rb"); if(!f){ perror("open"); return 1; }
    index_t idx = load_index(f);
    uint32_t total_entries = 0; for(uint32_t ii=0; ii<idx.n; ii++) if(!(idx.entries[ii].flags & 4)) total_entries++;
    uint32_t processed_entries = 0;
    for(uint32_t i=0;i<idx.n;i++){
        entry_t *e = &idx.entries[i];
        if(e->flags & 4) continue;
        fseek(f, e->data_offset, SEEK_SET);
        unsigned char *enc = malloc(e->comp_size);
        fread(enc,1,e->comp_size,f);
        if(e->flags & 2){ xor_buf(enc, e->comp_size, pwd); }
        unsigned char *out = NULL;
        uLong outsz = e->uncomp_size;
        out = malloc(outsz+1);
        if(e->flags & 1){
            int res = uncompress(out, &outsz, enc, e->comp_size);
            if(res!=Z_OK){ fprintf(stderr,"Decompression failed for %s\n", e->name); free(enc); free(out); continue; }
        } else {
            memcpy(out, enc, e->comp_size);
        }

        uint32_t crc = crc32(0, out, outsz);
        if(crc != e->crc32){
            fprintf(stderr, "CRC mismatch (wrong password or corrupted entry): %s\n", e->name);
            free(enc); free(out); continue;
        }

        char outpath[4096];
        const char *basename = strrchr(e->name, '/');
        if(basename) basename++; else basename = e->name;
        if(dest) {
            snprintf(outpath,sizeof(outpath),"%s/%s", dest, basename);
            char dcopy[4096]; strncpy(dcopy, dest, sizeof(dcopy)-1); dcopy[sizeof(dcopy)-1]=0; mkdir(dcopy, 0755);
        } else snprintf(outpath,sizeof(outpath),"%s", basename);
        FILE *outf = fopen(outpath, "wb");
        if(!outf){ fprintf(stderr,"Cannot write to %s: %s\n", outpath, strerror(errno)); }
        else { fwrite(out,1,outsz,outf); fclose(outf); }
        free(enc); free(out);
        processed_entries++;
        if(!global_quiet){
            if(global_verbose) fprintf(stderr, "Extracted: %s\n", e->name);
            else { char bn[PATH_MAX]; compact_basename(e->name, bn, sizeof(bn)); unsigned int prog = 0; if(total_entries>0) prog = (unsigned int)(processed_entries * 100ULL / total_entries); fprintf(stderr, "\rExtracting %u/%u: %s (%u%%)\x1b[K", processed_entries, total_entries, bn, prog); fflush(stderr); }
        }
    }
    free_index(&idx); fclose(f); return 0;
}


static int extract_single_entry(const char *archive, const char *target_name, const char *pwd) {
    FILE *f = fopen(archive, "rb");
    if (!f) { perror("open"); return 1; }
    index_t idx = load_index(f); int found = 0;
    for (uint32_t i = 0; i < idx.n; i++) {
        entry_t *e = &idx.entries[i];
        if (strcmp(e->name, target_name) == 0) {
            found = 1;
            if (e->flags & 4) { fprintf(stderr, "Entry '%s' is marked as deleted.\n", target_name); break; }
            fseek(f, e->data_offset, SEEK_SET);
            unsigned char *enc = malloc(e->comp_size); fread(enc, 1, e->comp_size, f);
            if (e->flags & 2) { xor_buf(enc, e->comp_size, pwd); }
            unsigned char *out = malloc(e->uncomp_size + 1); uLong outsz = e->uncomp_size;
            if (e->flags & 1) {
                int res = uncompress(out, &outsz, enc, e->comp_size);
                if (res != Z_OK) { fprintf(stderr, "Decompression failed for '%s'.\n", target_name); free(enc); free(out); break; }
            } else { memcpy(out, enc, e->comp_size); }
            uint32_t crc = crc32(0, out, outsz);
            if(crc != e->crc32){ fprintf(stderr, "CRC mismatch (wrong password or corrupted entry): %s\n", target_name); free(enc); free(out); break; }
            FILE *outf = fopen(target_name, "wb");
            if (!outf) { fprintf(stderr, "Cannot write to '%s': %s\n", target_name, strerror(errno)); }
            else { fwrite(out, 1, outsz, outf); fclose(outf); }
            free(enc); free(out); break;
        }
    }

    if (!found) {
        fprintf(stderr, "Entry '%s' not found in archive.\n", target_name);
    }

    free_index(&idx);
    fclose(f);
    return found ? 0 : 1;
}

static int test_archive(const char *archive, const char *pwd, int json){
    FILE *f = fopen(archive, "rb"); if(!f){ perror("open"); return 1; }
    index_t idx = load_index(f);
    int ok = 1;
    if(!json){
        for(uint32_t i=0;i<idx.n;i++){
            entry_t *e = &idx.entries[i];
            if(e->flags & 4) continue;
            fseek(f, e->data_offset, SEEK_SET);
            unsigned char *enc = malloc(e->comp_size);
            fread(enc,1,e->comp_size,f);
            if(e->flags & 2) xor_buf(enc, e->comp_size, pwd);
            unsigned char *out = malloc(e->uncomp_size+1);
            uLong outsz = e->uncomp_size;
            int res = Z_OK;
            if(e->flags & 1) res = uncompress(out, &outsz, enc, e->comp_size);
            else { memcpy(out, enc, e->comp_size); }
            if(res!=Z_OK || outsz!=e->uncomp_size){
                printf("%s ERROR\n", e->name); ok=0;
            } else {
                uint32_t crc = crc32(0, out, outsz);
                if(crc!=e->crc32){ printf("%s ERROR\n", e->name); ok=0; }
                else printf("%s OK\n", e->name);
            }
            free(enc); free(out);
        }
    } else {
        printf("[");
        int first = 1;
        for(uint32_t i=0;i<idx.n;i++){
            entry_t *e = &idx.entries[i];
            if(e->flags & 4) continue;
            fseek(f, e->data_offset, SEEK_SET);
            unsigned char *enc = malloc(e->comp_size);
            fread(enc,1,e->comp_size,f);
            if(e->flags & 2) xor_buf(enc, e->comp_size, pwd);
            unsigned char *out = malloc(e->uncomp_size+1);
            uLong outsz = e->uncomp_size;
            int res = Z_OK;
            if(e->flags & 1) res = uncompress(out, &outsz, enc, e->comp_size);
            else { memcpy(out, enc, e->comp_size); }
            const char *status = "OK";
            if(res!=Z_OK || outsz!=e->uncomp_size){ status = "ERROR"; ok=0; }
            else {
                uint32_t crc = crc32(0, out, outsz);
                if(crc!=e->crc32){ status = "ERROR"; ok=0; }
            }
            char *ename = escape_json_string(e->name);
            if(!first) printf(",");
            first = 0;
            printf("{\"name\":\"%s\",\"status\":\"%s\"}", ename, status);
            free(ename);
            free(enc); free(out);
        }
        printf("]\n");
    }
    free_index(&idx); fclose(f); return ok?0:2;
}


static int info_entry(const char *archive, uint32_t id, int json){
    FILE *f = fopen(archive, "rb"); if(!f){ perror("open"); return 1; }
    index_t idx = load_index(f);
    int found = 0;
    for(uint32_t i=0;i<idx.n;i++){
        entry_t *e = &idx.entries[i];
        if(e->id == id){
            found = 1;
            if(json){
                char *ename = escape_json_string(e->name);
                printf("{\"id\":%u,\"name\":\"%s\",\"flags\":%u,\"comp_level\":%u,\"uncomp_size\":%" PRIu64 ",\"comp_size\":%" PRIu64 ",\"crc32\":%u}",
                    e->id, ename, (unsigned)e->flags, (unsigned)e->comp_level, e->uncomp_size, e->comp_size, e->crc32);
                free(ename);
            } else {
                printf("id: %u\nname: %s\nflags: 0x%02x\ncomp_level: %u\nuncomp_size: %" PRIu64 "\ncomp_size: %" PRIu64 "\ncrc32: %u\n",
                    e->id, e->name, (unsigned)e->flags, (unsigned)e->comp_level, e->uncomp_size, e->comp_size, e->crc32);
            }
            break;
        }
    }
    free_index(&idx); fclose(f);
    return found?0:2;
}


static int cat_entry(const char *archive, uint32_t id, const char *pwd){
    FILE *f = fopen(archive, "rb"); if(!f){ perror("open"); return 1; }
    index_t idx = load_index(f); int found = 0;
    for(uint32_t i=0;i<idx.n;i++){
        entry_t *e = &idx.entries[i];
        if(e->id == id){
            found = 1;
            if(e->flags & 4){ fprintf(stderr, "entry deleted\n"); break; }
            fseek(f, e->data_offset, SEEK_SET);
            unsigned char *buf = malloc(e->comp_size); fread(buf,1,e->comp_size,f);
            if(e->flags & 2 && pwd){ xor_buf(buf, e->comp_size, pwd); }
            unsigned char *out = malloc(e->uncomp_size+1); uLong outsz = e->uncomp_size;
            if(e->flags & 1){ int res = uncompress(out, &outsz, buf, e->comp_size); if(res!=Z_OK){ fprintf(stderr,"decompress failed\n"); free(buf); free(out); break; } }
            else { memcpy(out, buf, e->comp_size); outsz = e->comp_size; }
            uint32_t crc = crc32(0, out, outsz);
            if(crc != e->crc32){ fprintf(stderr, "CRC mismatch (wrong password or corrupted entry)\n"); free(buf); free(out); break; }
            fwrite(out,1,outsz,stdout);
            free(buf); free(out); break;
        }
    }
    free_index(&idx); fclose(f); return found?0:2;
}


static int rebuild_archive(const char *archive, const uint32_t *exclude_ids, uint32_t exclude_count, int quiet){
    char bak[4096]; snprintf(bak,sizeof(bak),"%s.bak", archive);
    if(rename(archive, bak)!=0){ if(!quiet) perror("backup"); return 1; }
    if(!quiet){ fprintf(stderr, "Rebuilding archive: reading from '%s' -> writing new '%s'\n", bak, archive); fflush(stderr); }
    FILE *old = fopen(bak, "rb"); if(!old){ perror("open bak"); return 1; }
    index_t idx = load_index(old);
    FILE *newf = fopen(archive, "w+b"); if(!newf){ perror("create new"); fclose(old); return 1; }
    ensure_header(newf);

    index_t newidx = {0}; newidx.next_id = 1;
    uint64_t total_copied = 0;
    uint32_t copied_count = 0;
        uint64_t total_to_copy = 0;
        for(uint32_t i=0;i<idx.n;i++){
            entry_t *e = &idx.entries[i];
            int skip=0;
            if(e->flags & 4) skip=1;
            for(uint32_t j=0;j<exclude_count;j++) if(e->id==exclude_ids[j]) skip=1;
            if(!skip) total_to_copy += e->comp_size;
        }
    char oldsz[64]={0};

        struct stat stbak; if(stat(bak,&stbak)==0) fmt_size(stbak.st_size, oldsz, sizeof(oldsz));
    uint32_t skipped_count = 0;
    for(uint32_t i=0;i<idx.n;i++){
        entry_t *e = &idx.entries[i];
        int skip=0;
        if(e->flags & 4) skip=1;
        for(uint32_t j=0;j<exclude_count;j++) if(e->id==exclude_ids[j]) skip=1;
        if(skip){
            skipped_count++;
            if(!quiet && global_verbose){ fprintf(stderr, "  Skipping id %u  %s\n", e->id, e->name); fflush(stderr); }
            continue;
        }

        if(!quiet && global_verbose){ 
            fprintf(stderr, "  Copying id %u  %s  (comp=%" PRIu64 ") ", e->id, e->name, e->comp_size); fflush(stderr);
        }
        fseek(old, e->data_offset, SEEK_SET);
        unsigned char *buf = malloc(e->comp_size);
        fread(buf,1,e->comp_size,old);
        uint64_t off = ftell(newf);
        fwrite(buf,1,e->comp_size,newf);
        total_copied += e->comp_size;
        copied_count++;
        free(buf);

        if(!quiet){
            if(total_to_copy>0){ unsigned int prog = (unsigned int)(total_copied * 100ULL / total_to_copy);
                if(global_verbose) fprintf(stderr, "(%u%%)\n", prog);
                else { char bn[PATH_MAX]; compact_basename(e->name, bn, sizeof(bn)); fprintf(stderr, "\rRebuilding: %s (%u%%)\x1b[K", bn, prog); fflush(stderr); }
            }
            else { if(global_verbose) fprintf(stderr, "\n"); else { fprintf(stderr, "\r"); fflush(stderr); } }
        }


        newidx.entries = realloc(newidx.entries, sizeof(entry_t)*(newidx.n+1));
        entry_t *ne = &newidx.entries[newidx.n];
        memset(ne,0,sizeof(*ne));
        ne->id = e->id;
        ne->name = strdup(e->name);
        ne->flags = e->flags;
        ne->comp_level = e->comp_level;
        ne->data_offset = off;
        ne->comp_size = e->comp_size;
        ne->uncomp_size = e->uncomp_size;
        ne->crc32 = e->crc32;

        ne->mode = e->mode;
        ne->uid = e->uid;
        ne->gid = e->gid;
        ne->mtime = e->mtime;
        ne->meta_n = e->meta_n;
        if(e->meta_n){
            ne->meta = calloc(e->meta_n, sizeof(*ne->meta));
            for(uint32_t m=0;m<e->meta_n;m++){ ne->meta[m].key = e->meta[m].key ? strdup(e->meta[m].key) : NULL; ne->meta[m].value = e->meta[m].value ? strdup(e->meta[m].value) : NULL; }
        } else ne->meta = NULL;
        newidx.n++;
        if(ne->id >= newidx.next_id) newidx.next_id = ne->id+1;
    }
    uint64_t index_offset = ftell(newf);
    write_index(newf, &newidx);
    update_header_index_offset(newf, index_offset);
    if(!quiet){ fprintf(stderr, "Rebuild complete: copied %u entries, skipped %u entries, total bytes copied: %" PRIu64 "\n", copied_count, skipped_count, total_copied); fflush(stderr); }
    fclose(old); fclose(newf);
    free_index(&idx); free_index(&newidx);

    char bakpath[4096]; snprintf(bakpath,sizeof(bakpath),"%s.bak", archive);
    unlink(bakpath);
    return 0;
}

static int remove_entry(const char *archive, uint32_t id){
    const uint32_t arr[1] = { id };
    return rebuild_archive(archive, arr, 1u, 0);
}

static int fix_archive(const char *archive){

    return rebuild_archive(archive, NULL, 0, 0);
}


static int compress_archive(const char *archive, int target_clevel, const char *pwd){
    (void)pwd;
    if(target_clevel < 0 || target_clevel > 3){ fprintf(stderr, "Invalid compression level\n"); return 1; }

    FILE *src = fopen(archive, "rb"); if(!src){ perror("open"); return 1; }
    index_t idx = load_index(src);

    char *tmp = make_name(archive, ".tmp");
    if(!tmp){ perror("create tmp name"); fclose(src); return 1; }
    FILE *out = fopen(tmp, "w+b"); if(!out){ perror("create tmp"); fclose(src); free(tmp); return 1; }
    ensure_header(out);

    index_t newidx = {0}; newidx.next_id = 1;
    uint32_t total_entries = 0; for(uint32_t ii=0; ii<idx.n; ii++){ if(!(idx.entries[ii].flags & 4)) total_entries++; }
    uint32_t processed_entries = 0;
    for(uint32_t i=0;i<idx.n;i++){
        entry_t *e = &idx.entries[i];
        if(e->flags & 4) continue;

        fseek(src, e->data_offset, SEEK_SET);
        unsigned char *blob = malloc(e->comp_size);
        fread(blob,1,e->comp_size,src);

        unsigned char *final_blob = NULL; size_t final_sz = 0; int final_comp = 0;
        if(e->flags & 2){ final_blob = blob; final_sz = e->comp_size; final_comp = (e->flags & 1)?1:0; }
        else {

            unsigned char *uncomp = NULL; uLong un_sz = e->uncomp_size;
            if(e->flags & 1){ uncomp = malloc(un_sz+1); int zr = uncompress(uncomp, &un_sz, blob, e->comp_size); if(zr!=Z_OK){ fprintf(stderr,"Decompress failed for id %u\n", e->id); free(blob); free_index(&idx); fclose(src); fclose(out); return 2; } }
            else { uncomp = malloc(un_sz); memcpy(uncomp, blob, un_sz); }

            if(target_clevel==0){
                final_blob = uncomp; final_sz = un_sz; final_comp = 0;
            } else {
                unsigned char *outbuf = NULL; size_t outbuf_sz = 0;
                if(compress_data_level(target_clevel, uncomp, un_sz, &outbuf, &outbuf_sz)==0 && outbuf_sz < un_sz){
                    final_blob = outbuf; final_sz = outbuf_sz; final_comp = 1;
                } else {
                    if(outbuf) free(outbuf);

                    if(e->flags & 1){ final_blob = blob; final_sz = e->comp_size; final_comp = 1; free(uncomp); }
                    else { final_blob = uncomp; final_sz = un_sz; final_comp = 0; }
                }
            }
            if(!(e->flags & 1)) {  }
            if((e->flags & 1) && !(final_comp && final_blob==blob)) {  }
        }

        uint64_t off = ftell(out);
        fwrite(final_blob,1,final_sz,out);

        newidx.entries = realloc(newidx.entries, sizeof(entry_t)*(newidx.n+1));
        entry_t *ne = &newidx.entries[newidx.n]; memset(ne,0,sizeof(*ne));
        ne->id = e->id;
        ne->name = strdup(e->name);
        ne->flags = (final_comp?1:0) | ((e->flags & 2)?2:0);
        ne->comp_level = final_comp ? target_clevel : 0;
        ne->data_offset = off;
        ne->comp_size = final_sz;
        ne->uncomp_size = e->uncomp_size;

        uint32_t crc = 0;
        if(e->flags & 2){  crc = e->crc32; }
        else {
            if(ne->flags & 1){
                unsigned char *tmpun = malloc(ne->uncomp_size+1); uLong tmpusz = ne->uncomp_size; int zr = uncompress(tmpun, &tmpusz, final_blob, ne->comp_size); if(zr==Z_OK) crc = crc32(0, tmpun, tmpusz); free(tmpun); }
            else { crc = crc32(0, final_blob, ne->uncomp_size); }
        }
        ne->crc32 = crc;

    ne->mode = e->mode; ne->uid = e->uid; ne->gid = e->gid; ne->mtime = e->mtime;
    ne->meta_n = e->meta_n; if(e->meta_n){ ne->meta = calloc(e->meta_n, sizeof(*ne->meta)); for(uint32_t m=0;m<e->meta_n;m++){ ne->meta[m].key = e->meta[m].key?strdup(e->meta[m].key):NULL; ne->meta[m].value = e->meta[m].value?strdup(e->meta[m].value):NULL; } } else ne->meta = NULL;
        newidx.n++; if(ne->id >= newidx.next_id) newidx.next_id = ne->id+1;
        processed_entries++;
        if(!global_quiet){ unsigned int prog = 0; if(total_entries>0) prog = (unsigned int)(processed_entries * 100ULL / total_entries);
            if(global_verbose) fprintf(stderr, "Recompressing id %u %s (%u%%)\n", e->id, e->name, prog);
            else { char bn[PATH_MAX]; compact_basename(e->name, bn, sizeof(bn)); fprintf(stderr, "\rCompressing: %s (%u%%)", bn, prog); fflush(stderr); }
        }

        if(!(e->flags & 2) && !(final_blob==blob)) free(blob);
        if(!(e->flags & 2) && !(final_blob==NULL) && final_blob!=blob) {   }
        if(!(e->flags & 2) && ( (e->flags & 1) && !(final_comp && final_blob==blob) )){

        }
    }

    uint64_t index_off = ftell(out);
    write_index(out, &newidx);
    update_header_index_offset(out, index_off);
    fclose(src); fclose(out);
    free_index(&idx); free_index(&newidx);

    char *bak = make_name(archive, ".bak");
    if(bak){ rename(archive, bak); }
    if(rename(tmp, archive)!=0){ perror("rename tmp"); if(bak) { rename(bak, archive); free(bak); } free(tmp); return 1; }
    if(bak){ unlink(bak); free(bak); }
    free(tmp);
    if(!global_quiet && !global_verbose) fprintf(stderr, "\n");
    return 0;
}


static int rename_entry(const char *archive, uint32_t id, const char *new_name) {
    FILE *f = fopen(archive, "r+b");
    if (!f) {
        perror("open");
        return 1;
    }

    index_t idx = load_index(f);
    int found = 0;

    for (uint32_t i = 0; i < idx.n; i++) {
        entry_t *e = &idx.entries[i];
        if (e->id == id) {
            found = 1;
            free(e->name);
            e->name = strdup(new_name);
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "Entry with id %u not found\n", id);
        free_index(&idx);
        fclose(f);
        return 1;
    }


    fseek(f, 0, SEEK_END);
    uint64_t index_offset = ftell(f);
    write_index(f, &idx);
    update_header_index_offset(f, index_offset);

    fclose(f);
    free_index(&idx);
    return 0;
}

int main(int argc, char **argv){

    for(int gi=1; gi<argc; gi++){
        if(strcmp(argv[gi], "--gui")==0){

            if(gi+1 < argc && argv[gi+1][0] != '-'){
                if(g_initial_gui_archive) free(g_initial_gui_archive);
                g_initial_gui_archive = strdup(argv[gi+1]);
            }
            return run_gui(argc, argv);
        }
    }

    /* Handle global flags that may appear anywhere; remove them from argv so they
       are not treated as job/file paths later. */
    for(int gi=1; gi<argc; gi++){
        if(strcmp(argv[gi], "--verbose") == 0 || strcmp(argv[gi], "-v") == 0){
            global_verbose = 1;
            /* shift argv left to remove this flag */
            for(int sj = gi; sj < argc - 1; sj++) argv[sj] = argv[sj+1];
            argv[argc-1] = NULL; argc--; gi--; 
        }
    }
    (void)global_verbose; // no-op to avoid unused variable warnings in builds without debug

    if(argc<3){ usage(); return 1; }
    const char *cmd = argv[1];
    const char *archive_arg = argv[2];


    bool use_libarchive = false;
    const char *actual_archive = archive_arg;


    const char *ext = strrchr(archive_arg, '.');
    bool has_non_baar_ext = (ext && strcmp(ext, ".baar") != 0);

    if (access(archive_arg, F_OK) == 0) {

        if (has_non_baar_ext) {

            if (la_is_supported(archive_arg)) {
                use_libarchive = true;
                actual_archive = archive_arg;
                if (!global_quiet) {
                    const char *format = la_get_format(archive_arg);
                    fprintf(stderr, "Detected %s archive, using libarchive.\n",
                            format ? format : "unknown");
                }
            }
        }
    } else {

        if (has_non_baar_ext) {

            if (strcmp(ext, ".zip") == 0 || strcmp(ext, ".tar") == 0 ||
                strcmp(ext, ".7z") == 0 || strcmp(ext, ".gz") == 0 ||
                strstr(archive_arg, ".tar.") != NULL) {
                use_libarchive = true;
                actual_archive = archive_arg;
                if (!global_quiet) {
                    fprintf(stderr, "Creating %s archive using libarchive.\n", ext);
                }
            }
        }
    }


    if (use_libarchive) {

        const char *pwd = NULL;
        int json = 0;
        int compression_level = 6;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
                pwd = argv[i + 1];
                i++;
            } else if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0) {
                json = 1;
            } else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
                global_verbose = 1;
            } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
                compression_level = atoi(argv[i + 1]);
                i++;
            } else if (strcmp(argv[i], "--incremental") == 0 || strcmp(argv[i], "--mirror") == 0 || strcmp(argv[i], "--i") == 0 || strcmp(argv[i], "--m") == 0 || strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "-m") == 0) {
                fprintf(stderr, "--incremental/--mirror are only available for native BAAR archives.\n");
                return 1;
            }
        }


        if (strcmp(cmd, "l") == 0) {
            return la_list(actual_archive, json, false);
        } else if (strcmp(cmd, "x") == 0) {
            const char *dest = (argc >= 4 && argv[3][0] != '-') ? argv[3] : ".";
            return la_extract(actual_archive, dest, pwd);
        } else if (strcmp(cmd, "xx") == 0) {
            if (argc < 4) {
                fprintf(stderr, "Usage: baar xx archive entry_name\n");
                return 1;
            }
            const char *entry_name = argv[3];
            return la_extract_single(actual_archive, entry_name, ".", pwd);
        } else if (strcmp(cmd, "t") == 0) {
            return la_test(actual_archive, pwd);
        } else if (strcmp(cmd, "a") == 0) {

            int file_count = 0;
            const char **file_paths = malloc(sizeof(char*) * (argc - 3));
            char **ignore_patterns = NULL;
            size_t ignore_count = 0;

            for (int i = 3; i < argc; i++) {
                if (strcmp(argv[i], "--ignore") == 0) {
                    if (i + 1 >= argc) {
                        fprintf(stderr, "--ignore requires a pattern\n");
                        free(file_paths);
                        free_ignore_patterns(ignore_patterns, ignore_count);
                        return 1;
                    }
                    if (add_ignore_pattern(&ignore_patterns, &ignore_count, argv[i + 1]) != 0) {
                        fprintf(stderr, "Failed to store ignore pattern\n");
                        free(file_paths);
                        free_ignore_patterns(ignore_patterns, ignore_count);
                        return 1;
                    }
                    i++;
                } else if (strncmp(argv[i], "--ignore=", 9) == 0) {
                    if (add_ignore_pattern(&ignore_patterns, &ignore_count, argv[i] + 9) != 0) {
                        fprintf(stderr, "Failed to store ignore pattern\n");
                        free(file_paths);
                        free_ignore_patterns(ignore_patterns, ignore_count);
                        return 1;
                    }
                }
            }

            for (int i = 3; i < argc; i++) {
                if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-p") == 0) {
                    i++;
                    continue;
                }
                if (strcmp(argv[i], "--ignore") == 0) {
                    i++;
                    continue;
                }
                if (strncmp(argv[i], "--ignore=", 9) == 0) {
                    continue;
                }
                if (argv[i][0] == '-') continue;
                if (should_ignore_path(argv[i], argv[i], ignore_patterns, ignore_count)) {
                    continue;
                }
                file_paths[file_count++] = argv[i];
            }

            int result = la_add_files(actual_archive, file_paths, file_count,
                             compression_level, pwd, global_verbose);
            free(file_paths);
            free_ignore_patterns(ignore_patterns, ignore_count);
            return result;
        } else {
            fprintf(stderr, "Command '%s' not supported for non-BAAR archives.\n", cmd);
            fprintf(stderr, "Supported commands: l, x, xx, t, a\n");
            return 1;
        }
    }



    char archive_buf[4096];
    if(strlen(archive_arg) > 6 && strcmp(archive_arg + strlen(archive_arg) - 5, ".baar") == 0) {
        strncpy(archive_buf, archive_arg, sizeof(archive_buf)-1);
        archive_buf[sizeof(archive_buf)-1]=0;
    } else {
        snprintf(archive_buf, sizeof(archive_buf), "%s.baar", archive_arg);
    }
    const char *archive = archive_buf;

    int clevel = 1;
    const char *pwd = NULL;
    int json = 0;
    int incremental_mode = 0;
    int mirror_mode = 0;
    for(int i=3;i<argc;i++){
        if(strcmp(argv[i],"-c")==0 && i+1<argc){ clevel = atoi(argv[i+1]); i++; }
        else if(strncmp(argv[i], "-c", 2) == 0 && isdigit((unsigned char)argv[i][2])) { clevel = atoi(argv[i]+2); }
        else if(strcmp(argv[i],"-p")==0 && i+1<argc){ pwd = argv[i+1]; i++; }
        else if(strcmp(argv[i],"--json")==0 || strcmp(argv[i],"-j")==0){ json = 1; }
        else if(strcmp(argv[i],"--quiet")==0 || strcmp(argv[i],"-q")==0){ global_quiet = 1; }
        else if(strcmp(argv[i],"--verbose")==0 || strcmp(argv[i],"-v")==0){ global_verbose = 1; }
        else if(strcmp(argv[i],"--incremental")==0 || strcmp(argv[i],"--i")==0 || strcmp(argv[i],"-i")==0){ incremental_mode = 1; }
        else if(strcmp(argv[i],"--mirror")==0 || strcmp(argv[i],"--m")==0 || strcmp(argv[i],"-m")==0){ mirror_mode = 1; incremental_mode = 1; }
    }

    if(!pwd) pwd = getenv("BAAR_PWD");
    if(strcmp(cmd,"a")==0){

            add_job_t *jobs = NULL;
            int job_count = 0;
            char **ignore_patterns = NULL;
            size_t ignore_count = 0;

            for(int i=3;i<argc;i++){
                if(strcmp(argv[i],"--ignore")==0){
                    if(i+1 >= argc){
                        fprintf(stderr, "--ignore requires a pattern\n");
                        free_ignore_patterns(ignore_patterns, ignore_count);
                        return 1;
                    }
                    if(add_ignore_pattern(&ignore_patterns, &ignore_count, argv[i+1]) != 0){
                        fprintf(stderr, "Failed to store ignore pattern\n");
                        free_ignore_patterns(ignore_patterns, ignore_count);
                        return 1;
                    }
                    i++;
                } else if(strncmp(argv[i], "--ignore=", 9) == 0){
                    if(add_ignore_pattern(&ignore_patterns, &ignore_count, argv[i] + 9) != 0){
                        fprintf(stderr, "Failed to store ignore pattern\n");
                        free_ignore_patterns(ignore_patterns, ignore_count);
                        return 1;
                    }
                }
            }

            for(int i=3;i<argc;i++){
                if(strcmp(argv[i],"-c")==0) { i++; continue; }
                if(strcmp(argv[i],"-p")==0) { i++; continue; }
                if(strcmp(argv[i],"--incremental")==0 || strcmp(argv[i],"--mirror")==0 || strcmp(argv[i],"--i")==0 || strcmp(argv[i],"--m")==0 || strcmp(argv[i],"-i")==0 || strcmp(argv[i],"-m")==0){ continue; }
                if(strcmp(argv[i],"--quiet")==0 || strcmp(argv[i],"-q")==0){ continue; }
                if(strcmp(argv[i],"--verbose")==0 || strcmp(argv[i],"-v")==0){ continue; }
                if(strcmp(argv[i],"--ignore")==0){ i++; continue; }
                if(argv[i][0] == '-') continue;
                if(strncmp(argv[i], "--ignore=", 9) == 0){ continue; }

                char *arg = argv[i];
                char *level_colon = NULL;
                char *dst_colon = NULL;

                char *last_colon = strrchr(arg, ':');
                int file_level = clevel;
                char srcbuf[4096], dstbuf[4096];
                if(last_colon && last_colon > arg && *(last_colon+1) >= '0' && *(last_colon+1) <= '9' && strlen(last_colon+1) <= 2) {
                    level_colon = last_colon;
                } else if(last_colon) {
                    dst_colon = last_colon;
                }
                if(level_colon){
                    int lvl = atoi(level_colon+1);
                    if(lvl<0) lvl = 0;
                    if(lvl>3) lvl = 3;
                    file_level = lvl;
                    size_t len = level_colon - arg;
                    strncpy(srcbuf, arg, len);
                    srcbuf[len]=0;
                    arg = srcbuf;
                }
                char *src_path = arg;
                char *archive_path = NULL;
                if(dst_colon){
                    size_t src_len = dst_colon - arg;
                    strncpy(srcbuf, arg, src_len);
                    srcbuf[src_len]=0;
                    strncpy(dstbuf, dst_colon+1, sizeof(dstbuf)-1);
                    dstbuf[sizeof(dstbuf)-1]=0;
                    src_path = srcbuf;
                    archive_path = dstbuf;
                }
                char *src_norm = normalize_path_basic(src_path);
                if(!src_norm){
                    fprintf(stderr, "Invalid path: %s\n", src_path);
                    continue;
                }
                char *archive_override = NULL;
                if(archive_path){
                    archive_override = normalize_path_basic(archive_path);
                    if(!archive_override){
                        fprintf(stderr, "Invalid archive path mapping: %s\n", archive_path);
                        free(src_norm);
                        continue;
                    }
                }
                add_job_t *tmp = realloc(jobs, sizeof(add_job_t) * (job_count + 1));
                if(!tmp){
                    fprintf(stderr, "Out of memory while queuing sources.\n");
                    free(src_norm);
                    if(archive_override) free(archive_override);
                    continue;
                }
                jobs = tmp;
                jobs[job_count].src_root = src_norm;
                jobs[job_count].archive_override = archive_override;
                jobs[job_count].clevel = file_level;
                job_count++;
            }
    if(job_count==0 && !incremental_mode){

        FILE *f = fopen(archive, "rb");
        if(!f) {
            f = fopen(archive, "w+b");
            if(f) {

                fwrite(MAGIC, 1, 8, f);
                uint64_t zero = 0;
                fwrite(&zero, 8, 1, f);
                for(int i=0; i<16; i++) fputc(0, f);

                uint64_t index_offset = 32;
                uint32_t n = 0;
                fwrite(&n, 4, 1, f);

                fseek(f, 8, SEEK_SET);
                fwrite(&index_offset, 8, 1, f);
                fclose(f);
                if(!global_quiet) fprintf(stderr, "Created empty archive: %s\n", archive);
                free_ignore_patterns(ignore_patterns, ignore_count);
                return 0;
            } else {
                fprintf(stderr, "Failed to create archive: %s\n", archive);
                free_ignore_patterns(ignore_patterns, ignore_count);
                return 1;
            }
        } else {

            fclose(f);
            if(!global_quiet) fprintf(stderr, "Archive already exists: %s\n", archive);
            free_ignore_patterns(ignore_patterns, ignore_count);
            return 0;
        }
        for(int j=0;j<job_count;j++){
            free(jobs[j].src_root);
            if(jobs[j].archive_override) free(jobs[j].archive_override);
        }
        free(jobs);
        free_ignore_patterns(ignore_patterns, ignore_count);
        return 0;
    }
        if(job_count > 0){
            install_cli_signal_handlers();
        }
        int res = add_files_streaming(archive, jobs, job_count, pwd, incremental_mode, mirror_mode, ignore_patterns, ignore_count);
        if(job_count > 0){
            restore_cli_signal_handlers();
        }
        for(int j=0;j<job_count;j++){
            free(jobs[j].src_root);
            if(jobs[j].archive_override) free(jobs[j].archive_override);
        }
        free(jobs);
        if(!global_quiet && !global_verbose) fprintf(stderr, "\n");
        free_ignore_patterns(ignore_patterns, ignore_count);
        return res;
    } else if(strcmp(cmd,"l")==0){ return list_archive(archive, json); }
    else if(strcmp(cmd,"search")==0){
        if(argc<4){ fprintf(stderr,"Pattern required\n"); return 1; }
        const char *pattern = argv[3];
        return search_archive(archive, pattern, json);
    }
    else if(strcmp(cmd,"mkdir")==0){
        if(argc<4){ fprintf(stderr,"Directory path required\n"); return 1; }
        const char *dirpath = argv[3];

        char dname[4096]; strncpy(dname, dirpath, sizeof(dname)-1); dname[sizeof(dname)-1]=0;
        size_t ln = strlen(dname);
        if(dname[ln-1] != '/'){
            if(ln + 1 < sizeof(dname)) { dname[ln] = '/'; dname[ln+1]=0; }
        }

        FILE *f = fopen(archive, "r+b");
        if(!f) f = fopen(archive, "w+b");
        if(!f){ perror("open archive"); return 1; }
        ensure_header(f);
        index_t idx = load_index(f);

        for(uint32_t i=0;i<idx.n;i++){
            if(strcmp(idx.entries[i].name, dname)==0 && !(idx.entries[i].flags & 4)){
                fprintf(stderr, "Directory already exists in archive: %s\n", dname);
                free_index(&idx); fclose(f); return 1;
            }
        }

        idx.entries = realloc(idx.entries, sizeof(entry_t)*(idx.n+1));
        entry_t *e = &idx.entries[idx.n]; memset(e,0,sizeof(*e));
        e->id = idx.next_id++;
        e->name = strdup(dname);
        e->flags = 0; e->comp_level = 0; e->data_offset = 0; e->comp_size = 0; e->uncomp_size = 0; e->crc32 = 0;
        idx.n++;

        fseek(f,0,SEEK_END);
        uint64_t index_offset = ftell(f);
        write_index(f, &idx);
        update_header_index_offset(f, index_offset);
        fclose(f);
        free_index(&idx);
        return 0;
    }
    else if(strcmp(cmd,"x")==0){
        const char *dest = NULL;
        if(argc>=4 && argv[3][0] != '-') dest = argv[3];
        return extract_archive(archive, dest, pwd);
    } else if(strcmp(cmd,"t")==0){ return test_archive(archive, pwd, json); }
    else if(strcmp(cmd,"info")==0){
        if(argc<4){ fprintf(stderr,"ID required\n"); return 1; }
        uint32_t id = (uint32_t)strtoul(argv[3], NULL, 10);
        return info_entry(archive, id, json);
    } else if(strcmp(cmd,"cat")==0){
        if(argc<4){ fprintf(stderr,"ID required\n"); return 1; }
        uint32_t id = (uint32_t)strtoul(argv[3], NULL, 10);
        return cat_entry(archive, id, pwd);
    } else if(strcmp(cmd,"f")==0){ return fix_archive(archive); }
    else if(strcmp(cmd,"r")==0){ if(argc<4){ fprintf(stderr,"ID required\n"); return 1; } uint32_t id = atoi(argv[3]); return remove_entry(archive,id); }
    else if(strcmp(cmd,"rename") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Usage: baar rename archive id new_name\n");
            return 1;
        }
        uint32_t id = (uint32_t)strtoul(argv[3], NULL, 10);
        const char *new_name = argv[4];
        return rename_entry(archive, id, new_name);
    }
    else if (strcmp(cmd, "xx") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: baar xx archive entry_name\n");
            return 1;
        }
        const char *target_name = argv[3];
        return extract_single_entry(archive, target_name, pwd);
    }
    else if(strcmp(cmd, "compress") == 0) {

        return compress_archive(archive, clevel, pwd);
    }
    usage();
    return 1;
}
