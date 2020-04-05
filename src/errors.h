#pragma once

enum ErrorCode {
  ERROR_NONE,
  ERROR_UNKNOWN,

  ERROR_FILE_NOT_FOUND,
  ERROR_CDR_NOT_FOUND,
  ERROR_DECRYPTION_FAILED,
  ERROR_READ_KEY_FAILED,
  ERROR_NO_EXTENDED_HEADER,
  ERROR_UNSUPPORTED_ENCRYPTION
};

