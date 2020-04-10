#pragma once

#include "dll.h"

extern "C" {
  /// decrypt the entire archive and write to an unencrypted file
  DLLEXPORT int pak_decrypt(const char *encryptedPath, const char *outputPath, const char *key, short keySize);

  /// list files in the archive
  /// fileNames will have each file name zero terminated in a single buffer, with a second \0 at the very end.
  /// this buffer has to be freed with freeBuffer
  DLLEXPORT int pak_list_files(const char *encryptedPath, const char *key, short keySize, char **fileNames);

  /// decrypt a list of files to memory buffers.
  /// buffers will be set to an array of character pointers pointing to the buffers, bufferSizes will receive an
  /// array of the same size specifying the size of each buffer (both in the order of the files input)
  /// "buffers" has to be freed with "pak_free_array", "bufferSizes" has to be freed with "pak_free"
  DLLEXPORT int pak_decrypt_files(const char *encryptedPath, const char *key, short keySize,
                                  const char **files, int numFiles,
                                  char ***buffers, int **bufferSizes);

  /// free a buffer as returned 
  DLLEXPORT int pak_free_array(void **buffer, int length);

  /// free a buffer as returned 
  DLLEXPORT int pak_free(void *buffer);

  DLLEXPORT const char *pak_error_to_string(int code);
}

