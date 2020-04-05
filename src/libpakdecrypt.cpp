#include "libpakdecrypt.h"
#include "ZipUtil.h"
#include "errors.h"
#include <fstream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <sstream>
#include <functional>
#include <stdexcept>

using namespace ZipUtil;


class ErrorCodeException : public std::exception {
public:
  ErrorCodeException(ErrorCode code) : m_Code(code) { }
  virtual const char *what() const throw() { return "An error occurred"; }
  ErrorCode code() const throw() { return m_Code; }
private:
  ErrorCode m_Code;
};

template <typename T> T checked(const std::function<T()> &func, ErrorCode code) {
  try {
    return func();
  }
  catch (const ErrorCodeException &e) {
    throw e;
  }
  catch (...) {
    throw ErrorCodeException(code);
  }
}

CryEngineDecryptionKeys readKeys(std::istream &input, TomCryption &crypto) {
  CryEngineExtendedHeader extendedHeader;
  input.read(reinterpret_cast<char*>(&extendedHeader), sizeof(CryEngineExtendedHeader));

  if (extendedHeader.headerSize != sizeof(CryEngineExtendedHeader)) {
    throw ErrorCodeException(ERROR_NO_EXTENDED_HEADER);
  }
  if (extendedHeader.encryptionType != EncryptionType::StreamCipherKeytable) {
    throw ErrorCodeException(ERROR_UNSUPPORTED_ENCRYPTION);
  }

  // skip signing header, don't care about that
  input.seekg(sizeof(CryEngineSigningHeader), std::ios::cur);
  return CryEngineDecryptionKeys::readFrom(input, crypto);
}

struct __Padding {
  static const uint32_t PADDING_BUFFER_SIZE = 65535;
  __Padding() {
    memset(buffer, 0, PADDING_BUFFER_SIZE);
  }

  char buffer[PADDING_BUFFER_SIZE];
} s_Padding;

void decryptImpl(const char *encryptedPath, const char *outputPath, const char *keyPath) {
  // the process to decrypt cryengine pak files is as follows:
  // a) find the end record of the CDR.
  //    -> This record is not encrypted and is followed by a comment section that the cryengine uses to store
  //       information on how the file is encrypted.
  // b) use the rsa public key to decrypt the table of keys (for the twofish symmetrical cipher) and an initial vector for the rest of the cdr
  //    -> the remaining parts of the file (headers, blocks of file data) are encrypted individually with one of these 16 keys
  // c) decrypt the rest of the cdr which contains references to each of the files in the archive
  // d) decrypt each file in two parts, its header and the data
  // e) write out the updated CDR (decrypted files may be smaller than the encrypted ones so offsets need to be updated)

  std::ifstream input;
  input.open(encryptedPath, std::ios::binary | std::ios::in);

  if (!input.is_open()) {
    throw ErrorCodeException(ERROR_FILE_NOT_FOUND);
  }

  TomCryption crypto;
  checked<void>([&]() { crypto.loadKeys(keyPath); }, ERROR_READ_KEY_FAILED);

  CDREndRecord cdrEndRecord = checked<CDREndRecord>([&]() { return CDREndRecord::from(input); }, ERROR_CDR_NOT_FOUND);

  if (cdrEndRecord.commentLength < sizeof(CryEngineExtendedHeader)) {
    throw ErrorCodeException(ERROR_NO_EXTENDED_HEADER);
  }

  CryEngineDecryptionKeys decryptionKeys = checked<CryEngineDecryptionKeys>([&]() { return readKeys(input, crypto); }, ERROR_DECRYPTION_FAILED);

  // decrypt the CDR
  std::vector<uint8_t> cdrBuffer = decryptCDR(input, cdrEndRecord, crypto, decryptionKeys.cipherKeyTable[0], decryptionKeys.cdrInitialVector);
  std::vector<CDRecordWithData> headers = readCDRecords(cdrBuffer, cdrEndRecord);

  // sort the records so that we don't have to seek back and forth in the archives
  std::sort(headers.begin(), headers.end(), [](const CDRecordWithData &lhs, const CDRecordWithData &rhs) {
    return lhs.first.localHeaderOffset < rhs.first.localHeaderOffset;
    });

  // everything in the input archive seems to be in order so now we can start decrypting actual data
  std::ofstream output;
  output.open(outputPath, std::ios::binary | std::ios::out);

  for (CDRecordWithData &header : headers) {
    unsigned char initialVector[BLOCK_CIPHER_KEY_LENGTH];
    getInitialVector(header.first.descriptor, initialVector);
    int encryptionKeyIndex = getEncryptionKeyIndex(header.first.descriptor.crc);

    input.seekg(header.first.localHeaderOffset);
    LocalFileHeader localHeader;
    input.read(reinterpret_cast<char*>(&localHeader), sizeof(LocalFileHeader));
    union {
      char sig[4];
      uint32_t sigStr;
    };
    sigStr = localHeader.signature;
    crypto.decryptData(reinterpret_cast<uint8_t*>(&localHeader), sizeof(LocalFileHeader), decryptionKeys.cipherKeyTable[encryptionKeyIndex], initialVector);
    input.seekg(header.first.localHeaderOffset);

    header.first.localHeaderOffset = static_cast<uint32_t>(output.tellp());

    decryptFile(input, output, crypto, localHeader, header.first.descriptor.sizeCompressed, decryptionKeys.cipherKeyTable[encryptionKeyIndex], initialVector);
  }

  std::vector<uint8_t> digest = crypto.startHashSHA256()
    .process(cdrBuffer.data(), cdrEndRecord.size)
    .process(reinterpret_cast<const uint8_t*>(outputPath), static_cast<unsigned long>(strlen(outputPath)))
    .digest();

  // write out the cdr
  size_t cdrOffset = output.tellp();
  for (CDRecordWithData &header : headers) {
    output.write(reinterpret_cast<const char*>(&header.first), sizeof(CDRecord));
    output.write(reinterpret_cast<const char*>(header.second.data()), header.second.size());
  }

  cdrEndRecord.commentLength = 0;
  cdrEndRecord.offset = static_cast<uint32_t>(cdrOffset);
  output.write(reinterpret_cast<const char*>(&cdrEndRecord), sizeof(CDREndRecord));
}

void decryptFilesImpl(const char *encryptedPath, const char *keyPath, const char **files, int numFiles, char ***buffers, int **bufferSizes) {
  std::ifstream input;
  input.open(encryptedPath, std::ios::binary | std::ios::in);

  if (!input.is_open()) {
    throw ErrorCodeException(ERROR_FILE_NOT_FOUND);
  }

  TomCryption crypto;
  checked<void>([&]() { crypto.loadKeys(keyPath); }, ERROR_READ_KEY_FAILED);

  CDREndRecord cdrEndRecord = checked<CDREndRecord>([&]() { return CDREndRecord::from(input); }, ERROR_CDR_NOT_FOUND);

  if (cdrEndRecord.commentLength < sizeof(CryEngineExtendedHeader)) {
    throw ErrorCodeException(ERROR_NO_EXTENDED_HEADER);
  }

  CryEngineDecryptionKeys decryptionKeys = checked<CryEngineDecryptionKeys>([&]() { return readKeys(input, crypto); }, ERROR_DECRYPTION_FAILED);

  // decrypt the CDR
  std::vector<uint8_t> cdrBuffer = decryptCDR(input, cdrEndRecord, crypto, decryptionKeys.cipherKeyTable[0], decryptionKeys.cdrInitialVector);
  std::vector<CDRecordWithData> headers = readCDRecords(cdrBuffer, cdrEndRecord);

  // sort the records so that we don't have to seek back and forth in the archives
  std::sort(headers.begin(), headers.end(), [](const CDRecordWithData &lhs, const CDRecordWithData &rhs) {
    return lhs.first.localHeaderOffset < rhs.first.localHeaderOffset;
    });

  *buffers = new char*[numFiles];
  *bufferSizes = new int[numFiles];

  // everything in the input archive seems to be in order so now we can start decrypting actual data
  for (CDRecordWithData &header : headers) {
    std::string iterName(reinterpret_cast<const char*>(&header.second[0]), header.first.nameLength);
    const char **end = files + numFiles;
    auto namePtr = std::find_if(files, end, [&](const char *name) { return strcmp(iterName.c_str(), name) == 0;  });
    if (namePtr == end) {
      // not requested
      continue;
    }

    unsigned char initialVector[BLOCK_CIPHER_KEY_LENGTH];
    getInitialVector(header.first.descriptor, initialVector);
    int encryptionKeyIndex = getEncryptionKeyIndex(header.first.descriptor.crc);

    input.seekg(header.first.localHeaderOffset);
    LocalFileHeader localHeader;
    input.read(reinterpret_cast<char*>(&localHeader), sizeof(LocalFileHeader));
    union {
      char sig[4];
      uint32_t sigStr;
    };
    sigStr = localHeader.signature;
    crypto.decryptData(reinterpret_cast<uint8_t*>(&localHeader), sizeof(LocalFileHeader), decryptionKeys.cipherKeyTable[encryptionKeyIndex], initialVector);
    input.seekg(header.first.localHeaderOffset);

    std::stringstream output;
    decryptFile(input, output, crypto, localHeader, header.first.descriptor.sizeCompressed, decryptionKeys.cipherKeyTable[encryptionKeyIndex], initialVector);

    size_t idx = std::distance(files, namePtr);

    std::string temp = output.str();
    (*buffers)[idx] = new char[temp.size()];
    memcpy((*buffers)[idx], &temp[0], temp.size());
    (*bufferSizes)[idx] = static_cast<int>(temp.size());
  }
}


void listFilesImpl(const char *encryptedPath, const char *keyPath, char **fileNames) {
  std::ifstream input;
  input.open(encryptedPath, std::ios::binary | std::ios::in);

  if (!input.is_open()) {
    throw ErrorCodeException(ERROR_FILE_NOT_FOUND);
  }

  TomCryption crypto;
  checked<void>([&]() { crypto.loadKeys(keyPath); }, ERROR_READ_KEY_FAILED);

  CDREndRecord cdrEndRecord = checked<CDREndRecord>([&]() { return CDREndRecord::from(input); }, ERROR_CDR_NOT_FOUND);

  if (cdrEndRecord.commentLength < sizeof(CryEngineExtendedHeader)) {
    throw ErrorCodeException(ERROR_NO_EXTENDED_HEADER);
  }

  CryEngineDecryptionKeys decryptionKeys = checked<CryEngineDecryptionKeys>([&]() { return readKeys(input, crypto); }, ERROR_DECRYPTION_FAILED);

  // decrypt the CDR
  std::vector<uint8_t> cdrBuffer = decryptCDR(input, cdrEndRecord, crypto, decryptionKeys.cipherKeyTable[0], decryptionKeys.cdrInitialVector);
  std::vector<CDRecordWithData> headers = readCDRecords(cdrBuffer, cdrEndRecord);

  auto lengthAccu = [](int total, const CDRecordWithData &file) {
    return total + file.first.nameLength + 1;
  };

  int totalLength = std::accumulate(headers.begin(), headers.end(), 1, lengthAccu);

  *fileNames = new char[totalLength];
  memset(*fileNames, '\0', totalLength);
  char *target = *fileNames;

  for (const auto &header : headers) {
    memcpy(target, &header.second[0], header.first.nameLength);
    target[header.first.nameLength] = '\0';
    target += header.first.nameLength + 1;
  }
}

DLLEXPORT int pak_decrypt(const char *encryptedPath, const char *outputPath, const char *keyPath) {
  try {
    decryptImpl(encryptedPath, outputPath, keyPath);
    return ERROR_NONE;
  }
  catch (const ErrorCodeException &e) {
    return e.code();
  }
  catch (...) {
    return ERROR_UNKNOWN;
  }
}

DLLEXPORT int pak_list_files(const char *encryptedPath, const char *keyPath, char **fileNames) {
  try {
    listFilesImpl(encryptedPath, keyPath, fileNames);
    return ERROR_NONE;
  }
  catch (const ErrorCodeException &e) {
    return e.code();
  }
  catch (...) {
    return ERROR_UNKNOWN;
  }
}

DLLEXPORT int pak_decrypt_files(const char *encryptedPath, const char *keyPath, const char **files, int numFiles,
                                char ***buffers, int **bufferSizes) {
  try {
    decryptFilesImpl(encryptedPath, keyPath, files, numFiles, buffers, bufferSizes);
    return ERROR_NONE;
  }
  catch (const ErrorCodeException &e) {
    return e.code();
  }
  catch (...) {
    return ERROR_UNKNOWN;
  }
}

DLLEXPORT int pak_free_array(void **buffer, int length) {
  if (buffer == nullptr) {
    return ERROR_NONE;
  }
  for (int i = 0; i < length; ++i) {
    delete[] buffer[i];
  }
  delete[] buffer;

  return ERROR_NONE;
}

DLLEXPORT int pak_free(void *buffer) {
  delete [] buffer;

  return ERROR_NONE;
}


DLLEXPORT const char *pak_error_to_string(int code) {
  switch (code) {
  case ERROR_NONE: return "No error";
  case ERROR_FILE_NOT_FOUND: return "File not found";
  case ERROR_CDR_NOT_FOUND: return "CDR not found";
  case ERROR_DECRYPTION_FAILED: return "Decryption failed";
  case ERROR_READ_KEY_FAILED: return "Failed to read key file";
  default: return "Unknown error";
  }
}

