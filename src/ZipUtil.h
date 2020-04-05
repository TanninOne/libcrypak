#pragma once

#include "TomCryption.h"

#pragma pack(push)
#pragma pack(1)

// utility functions and structures to deal with the way cryengine paks are encrypted
namespace ZipUtil {

  enum class EncryptionType : uint16_t
  {
    None = 0,
    StreamCipher = 1,
    TEA = 2,
    StreamCipherKeytable = 3,
  };

  enum class CompressionMethod : uint16_t
  {
    Store,
    Shrink,
    Reduce1,
    Reduce2,
    Reduce3,
    Reduce4,
    Implode,
    Tokenize,
    Deflate,
    Deflate64,
    ImplodePKWare,
    DeflateAndEncrypt,
    DeflateAndStreamcipher,
    StoreAndStreamcipherKeytable,
    DeflateandStreamcipherKeytable
  };

  struct CDREndRecord
  {
    uint32_t signature;
    uint16_t disk;
    uint16_t startDisk;
    uint16_t entriesOnDisk;
    uint16_t entriesTotal;
    uint32_t size;
    uint32_t offset;
    uint16_t commentLength;

    static CDREndRecord from(std::istream &input);
  };

  struct DataDescriptor
  {
    uint32_t crc;
    uint32_t sizeCompressed;
    uint32_t sizeUncompressed;
  };

  bool operator==(const DataDescriptor &lhs, const DataDescriptor &rhs);
  bool operator!=(const DataDescriptor &lhs, const DataDescriptor &rhs);

  struct CDRecord
  {
    uint32_t signature;
    uint16_t versionAuthor;
    uint16_t versionRequired;
    uint16_t flags;
    uint16_t method;
    uint16_t modifiedTime;
    uint16_t modifiedDate;
    DataDescriptor descriptor;
    uint16_t nameLength;
    uint16_t extraFieldLength;
    uint16_t commentLength;
    uint16_t diskNumStart;
    uint16_t attributeInternal;
    uint32_t attributeExternal;

    uint32_t localHeaderOffset;
  };

  typedef std::pair<CDRecord, std::vector<uint8_t>> CDRecordWithData;

  struct LocalFileHeader
  {
    uint32_t signature;
    uint16_t versionRequired;
    uint16_t flags;
    uint16_t method;
    uint16_t modifiedTime;
    uint16_t modifiedDate;
    DataDescriptor descriptor;
    uint16_t nameLength;
    uint16_t extraFieldLength;
  };

  struct CryEngineExtendedHeader
  {
    uint32_t headerSize;
    EncryptionType encryptionType;
    uint16_t signatureType;
  };

  struct CryEngineEncryptionHeader
  {
    uint32_t headerSize;
    uint8_t initVector[RSA_KEY_MESSAGE_LENGTH];
    uint8_t keys[BLOCK_CIPHER_NUM_KEYS][RSA_KEY_MESSAGE_LENGTH];
  };

  struct CryEngineDecryptionKeys
  {
    CipherKey cipherKeyTable[BLOCK_CIPHER_NUM_KEYS];
    InitialVector cdrInitialVector;

    static CryEngineDecryptionKeys readFrom(std::istream &input, TomCryption &crypto);
  };

  struct CryEngineSigningHeader
  {
    uint32_t headerSize;
    unsigned char signature[RSA_KEY_MESSAGE_LENGTH];
  };

  std::vector<uint8_t> decryptCDR(std::istream &input, const CDREndRecord &cdrEndRecord, const TomCryption &crypto,
                                  CipherKey key, InitialVector iv);

  void decryptFile(std::istream &input, std::ostream &output, const TomCryption &crypto,
    const LocalFileHeader &localHeader, long sizeCompressed,
    CipherKey key, InitialVector iv);

  std::vector<CDRecordWithData> readCDRecords(std::vector<uint8_t> &cdrBuffer, const CDREndRecord &cdrEndRecord);

  uint8_t getEncryptionKeyIndex(uint32_t crc);

  void getInitialVector(const DataDescriptor &descriptor, unsigned char result[BLOCK_CIPHER_KEY_LENGTH]);

}

#pragma pack(pop)

