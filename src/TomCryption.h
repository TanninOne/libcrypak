#pragma once

#include <vector>
#include <cstdint>

class TomCryptionImpl;
class HashImpl;
class FileDecoder;

namespace ZipUtil {
  struct CryEngineDecryptionKeys;
}

static const int RSA_KEY_MESSAGE_LENGTH = 128;
static const int BLOCK_CIPHER_NUM_KEYS = 16;
static const int BLOCK_CIPHER_KEY_LENGTH = 16;

typedef uint8_t CipherKey[BLOCK_CIPHER_KEY_LENGTH];
typedef uint8_t InitialVector[BLOCK_CIPHER_KEY_LENGTH];

class Hash {
public:
  Hash(int hashId);

  Hash &process(const uint8_t *data, unsigned long dataSize);

  std::vector<uint8_t> digest();

private:

  HashImpl *m_Impl;
};

/**
 * wrapper for the tomcrypt library
 * https://github.com/libtom/libtomcrypt
 */
class TomCryption
{
public:
  TomCryption();
  ~TomCryption();

  void loadKeys(const unsigned char *key, short keySize);

  std::vector<uint8_t> decryptKey(const uint8_t *input, unsigned long size, int padding);
  void decryptData(uint8_t *buffer, unsigned long bufferSize, CipherKey key, InitialVector iv) const;
  void decryptFileSection(std::istream &input, std::ostream &output, unsigned long size, CipherKey key, InitialVector iv, bool isData) const;

  Hash startHashSHA256() const;

private:
  
  TomCryptionImpl *m_Impl;

};

