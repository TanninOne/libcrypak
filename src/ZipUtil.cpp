#include "ZipUtil.h"
#include <tomcrypt.h>
#include <istream>

static const char CDR_SIGNATURE[] = { 0x50, 0x4b, 0x05, 0x06 };

namespace ZipUtil {

  bool operator==(const DataDescriptor &lhs, const DataDescriptor &rhs) {
    return (lhs.crc == rhs.crc)
      && (lhs.sizeCompressed == rhs.sizeCompressed)
      && (lhs.sizeUncompressed == rhs.sizeUncompressed);
  }

  bool operator!=(const DataDescriptor &lhs, const DataDescriptor &rhs) {
    return !(lhs == rhs);
  }

  std::streamoff FindCDREndRecord(std::istream &stream) {
    stream.seekg(0, std::ios::end);
    std::streamsize streamSize = stream.tellg();

    // comment can not be larger than 64kb so the cdr end record can not be further than this from the
    // end of the file
    static const uint32_t readSize = 0xFFFF - sizeof(CDREndRecord);
    char buffer[readSize];

    stream.seekg(streamSize - readSize);
    stream.read(buffer, readSize);

    // search backwards through the buffer to find the cdr end record
    for (char *bufferPos = buffer + readSize - sizeof(CDREndRecord); bufferPos >= buffer; --bufferPos) {
      // first indicator: there is the correct signature.
      if (memcmp(bufferPos, CDR_SIGNATURE, sizeof(CDR_SIGNATURE)) == 0) {
        // if this _is_ the end record, the comment will begin after it, which is the last thing in the file.
        // The record contains the size of the comment so we can verify this _is_ the end record by testing
        // that size field against the actual position in the file
        CDREndRecord *candidate = reinterpret_cast<CDREndRecord*>(bufferPos);
        uint32_t offset = static_cast<uint32_t>(bufferPos - buffer);
        uint32_t cdrEnd = offset + sizeof(CDREndRecord);
        if (candidate->commentLength == (readSize - cdrEnd)) {
          // success
          return streamSize - readSize + offset;
        }
      }
    }

    throw std::runtime_error("CDR end record not found");
  }

  CDREndRecord CDREndRecord::from(std::istream &input) {
    std::streamoff cdr = FindCDREndRecord(input);
    input.seekg(cdr);

    CDREndRecord result;
    input.read(reinterpret_cast<char*>(&result), sizeof(CDREndRecord));
    return result;
  }

  CryEngineDecryptionKeys CryEngineDecryptionKeys::readFrom(std::istream &input, TomCryption &crypto) {
    CryEngineDecryptionKeys result;

    CryEngineEncryptionHeader encHeader;
    input.read(reinterpret_cast<char*>(&encHeader), sizeof(CryEngineEncryptionHeader));

    if (encHeader.headerSize != sizeof(CryEngineEncryptionHeader)) {
      throw std::runtime_error("encryption header corrupted");
    }

    for (int i = 0; i < BLOCK_CIPHER_NUM_KEYS; ++i) {
      std::vector<uint8_t> decryptBuffer = crypto.decryptKey(encHeader.keys[i], RSA_KEY_MESSAGE_LENGTH, LTC_PKCS_1_OAEP);
      memcpy(result.cipherKeyTable[i], decryptBuffer.data(), BLOCK_CIPHER_KEY_LENGTH);
    }

    {
      std::vector<uint8_t> decryptBuffer = crypto.decryptKey(encHeader.initVector, RSA_KEY_MESSAGE_LENGTH, LTC_PKCS_1_OAEP);
      memcpy(result.cdrInitialVector, decryptBuffer.data(), BLOCK_CIPHER_KEY_LENGTH);
    }

    return result;
  }

  uint16_t convertMethod(uint16_t input) {
    CompressionMethod result = static_cast<CompressionMethod>(input);
    switch (result) {
    case CompressionMethod::DeflateandStreamcipherKeytable: result = CompressionMethod::Deflate;
    case CompressionMethod::StoreAndStreamcipherKeytable: result = CompressionMethod::Store;
    }
    return static_cast<uint16_t>(result);
  }

  std::vector<uint8_t> decryptCDR(std::istream &input, const CDREndRecord &cdrEndRecord, const TomCryption &crypto,
                                  CipherKey key, InitialVector iv) {
    std::vector<uint8_t> cdrBuffer(cdrEndRecord.size);
    input.seekg(cdrEndRecord.offset);
    input.read(reinterpret_cast<char*>(&cdrBuffer[0]), cdrEndRecord.size);

    crypto.decryptData(cdrBuffer.data(), cdrEndRecord.size, key, iv);
    return cdrBuffer;
  }

  void decryptFile(std::istream &input, std::ostream &output, const TomCryption &crypto,
                   const LocalFileHeader &localHeader, long sizeCompressed,
                   CipherKey key, InitialVector iv) {
    long localHeaderLength = sizeof(LocalFileHeader) + localHeader.nameLength + localHeader.extraFieldLength;
    crypto.decryptFileSection(input, output, localHeaderLength, key, iv, false);
    if (sizeCompressed > 0) {
      crypto.decryptFileSection(input, output, sizeCompressed, key, iv, true);
    }

    if ((localHeader.flags & 0x08) != 0) {
      unsigned long extraSize = sizeof(DataDescriptor);
      std::streampos inPos = input.tellg();

      //Check for the extra optional signature of the extended section
      uint8_t possibleSignature[4];
      input.read(reinterpret_cast<char*>(&possibleSignature), 4);

      crypto.decryptData(possibleSignature, 4, key, iv);

      if (memcmp(possibleSignature, CDR_SIGNATURE, 4)) {
        extraSize += sizeof(uint32_t);
      }

      input.seekg(inPos);

      crypto.decryptFileSection(input, output, extraSize, key, iv, false);
    }
  }

  std::vector<CDRecordWithData> readCDRecords(std::vector<uint8_t> &cdrBuffer, const CDREndRecord &cdrEndRecord) {
    std::vector<CDRecordWithData> result;
    result.reserve(cdrEndRecord.entriesTotal);

    size_t offset = 0;

    // note: entries in the cdr are of dynamic size so we have to read them sequentially
    for (int i = 0; i < cdrEndRecord.entriesTotal; ++i) {
      CDRecord *fileRecord = reinterpret_cast<CDRecord*>(cdrBuffer.data() + offset);
      fileRecord->method = convertMethod(fileRecord->method);
      size_t dynLength = fileRecord->nameLength + fileRecord->extraFieldLength + fileRecord->commentLength;
      std::vector<uint8_t> dynData(dynLength);
      memcpy(&dynData[0], cdrBuffer.data() + offset + sizeof(CDRecord), dynLength);

      result.push_back(std::make_pair(*fileRecord, dynData));

      offset += sizeof(CDRecord) + fileRecord->nameLength + fileRecord->extraFieldLength + fileRecord->commentLength;
    }

    return result;
  }

  // determine which encryption key to use
  uint8_t getEncryptionKeyIndex(uint32_t crc) {
    return (~(crc >> 2)) & 0x0F;
  }

  void getInitialVector(const DataDescriptor & descriptor, unsigned char result[BLOCK_CIPHER_KEY_LENGTH])
  {
    uint32_t temp[4];

    temp[0] = descriptor.sizeUncompressed ^ (descriptor.sizeCompressed << 12);
    temp[1] = !descriptor.sizeCompressed;
    temp[2] = descriptor.crc ^ (descriptor.sizeCompressed << 12);
    temp[3] = !descriptor.sizeUncompressed ^ descriptor.sizeCompressed;

    uint32_t dummy = static_cast<uint64_t>(descriptor.sizeUncompressed) ^ (static_cast<uint64_t>(descriptor.sizeCompressed) << 12);

    memcpy(result, temp, BLOCK_CIPHER_KEY_LENGTH);
  }
}

