#if 0
   Copyright 2025 BArko

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
#endif
#ifndef LA_BRIDGE_H
#define LA_BRIDGE_H

#include <stdint.h>
#include <stdbool.h>

/* libarchive adapter for baar - supports ZIP and other formats via libarchive */

/* Check if file is supported by libarchive (quick format detection) */
bool la_is_supported(const char *path);

/* List archive contents (similar to baar list command)
 * Returns 0 on success, non-zero on error
 * If json_output is true, prints JSON format
 */
int la_list(const char *archive_path, bool json_output, bool verbose);

/* Extract all files from archive to destination directory
 * dest_dir: target directory (will be created if needed)
 * password: optional password for encrypted archives (can be NULL)
 * Returns 0 on success, non-zero on error
 */
int la_extract(const char *archive_path, const char *dest_dir, const char *password);

/* Extract single file by name from archive
 * entry_name: path inside archive
 * dest_dir: target directory
 * password: optional password
 * Returns 0 on success, non-zero on error
 */
int la_extract_single(const char *archive_path, const char *entry_name, 
                      const char *dest_dir, const char *password);

/* Extract single file to absolute path (for drag & drop)
 * entry_name: path inside archive
 * dest_path: absolute destination path (full path including filename)
 * password: optional password
 * Returns 0 on success, non-zero on error
 */
int la_extract_to_path(const char *archive_path, const char *entry_name, 
                       const char *dest_path, const char *password);

/* Test archive integrity (decompress and verify)
 * Returns 0 if OK, non-zero on errors
 */
int la_test(const char *archive_path, const char *password);

/* Add files to archive (creates new archive or recreates existing with new files added)
 * archive_path: target archive
 * file_paths: array of source file paths
 * file_count: number of files
 * compression_level: 0-9 (0=store, 9=best)
 * password: optional password for encryption (ZIP only, can be NULL)
 * Returns 0 on success, non-zero on error
 */
int la_add_files(const char *archive_path, const char **file_paths, 
                 int file_count, int compression_level, const char *password);

/* Get format name for archive (e.g., "ZIP", "TAR", "7-Zip")
 * Returns static string or NULL on error
 */
const char *la_get_format(const char *archive_path);

#endif /* LA_BRIDGE_H */
