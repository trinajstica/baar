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
#ifndef LA_BRIDGE_H
#define LA_BRIDGE_H

#include <stdint.h>
#include <stdbool.h>




bool la_is_supported(const char *path);


int la_list(const char *archive_path, bool json_output, bool verbose);


int la_extract(const char *archive_path, const char *dest_dir, const char *password);


int la_extract_single(const char *archive_path, const char *entry_name,
                      const char *dest_dir, const char *password);


int la_extract_to_path(const char *archive_path, const char *entry_name,
                       const char *dest_path, const char *password);


int la_test(const char *archive_path, const char *password);


int la_add_files(const char *archive_path, const char **file_paths,
                 int file_count, int compression_level, const char *password, int verbose);


const char *la_get_format(const char *archive_path);

#endif
