#include "TomCryption.h"
#include <fmt/format.h>
#include "ZipUtil.h"
#include <stdexcept>
#include <tomcrypt.h>
#include <vector>
#include <fstream>
#include <algorithm>


static const int PUBLIC_KEY_SIZE = 140;
static const int PRIVATE_KEY_SIZE = 610;

void checked(int res, const char *message) {
  if (res != CRYPT_OK) {
    throw std::runtime_error(fmt::format(message, res, error_to_string(res)));
  }
}

class TomCryptionImpl {
public:

  static int registerHash(const ltc_hash_descriptor &descriptor);
  static int registerCipher(const ltc_cipher_descriptor &descriptor);
  static int registerPRNG(const ltc_prng_descriptor &descriptor);

public:

  TomCryptionImpl();

  void loadKeys(const char *key, short keySize);
  std::vector<uint8_t> decryptKey(const uint8_t *input, unsigned long size, int padding);
  void decryptData(uint8_t *buffer, unsigned long bufferSize, CipherKey key, InitialVector iv) const;
  void decryptFileSection(std::istream &input, std::ostream &output, unsigned long size, CipherKey key, InitialVector iv, bool isData) const;

  Hash startHashSHA256() const;

private:

  int m_MD5;
  int m_SHA1;
  int m_SHA256;
  int m_Twofish;
  int m_Yarrow;

  prng_state m_RNGState;

  uint8_t m_PublicKeyData[PUBLIC_KEY_SIZE];

  rsa_key m_PublicKey;

};


TomCryption::TomCryption()
  : m_Impl(new TomCryptionImpl())
{
}

TomCryption::~TomCryption() {
  delete m_Impl;
}

void TomCryption::loadKeys(const char *key, short keySize) {
  m_Impl->loadKeys(key, keySize);
}

std::vector<uint8_t> TomCryption::decryptKey(const uint8_t *input, unsigned long size, int padding) {
  return m_Impl->decryptKey(input, size, padding);
}

void TomCryption::decryptData(uint8_t *buffer, unsigned long bufferSize, CipherKey key, InitialVector iv) const {
  m_Impl->decryptData(buffer, bufferSize, key, iv);
}

void TomCryption::decryptFileSection(std::istream &input, std::ostream &output, unsigned long size, CipherKey key, InitialVector iv, bool isData) const {
  m_Impl->decryptFileSection(input, output, size, key, iv, isData);
}

Hash TomCryption::startHashSHA256() const {
  return m_Impl->startHashSHA256();
}

TomCryptionImpl::TomCryptionImpl()
  : m_MD5(registerHash(md5_desc))
  , m_SHA1(registerHash(sha1_desc))
  , m_SHA256(registerHash(sha256_desc))
  , m_Twofish(registerCipher(twofish_desc))
  , m_Yarrow(registerPRNG(yarrow_desc))
{
  ltc_mp = ltm_desc;

  int make_prng_result = rng_make_prng(128, m_Yarrow, &m_RNGState, nullptr);

  int md5 = find_hash("md5");
  int sha256 = find_hash("sha256");
  int prngIndex = find_prng("yarrow");
}


int TomCryptionImpl::registerHash(const ltc_hash_descriptor &descriptor) {
  int res = register_hash(&descriptor);
  if (res == -1) {
    throw std::runtime_error("failed to register hash");
  }
  return res;
}

int TomCryptionImpl::registerCipher(const ltc_cipher_descriptor &descriptor) {
  int res = register_cipher(&descriptor);
  if (res == -1) {
    throw std::runtime_error("failed to register cipher");
  }
  return res;
}

int TomCryptionImpl::registerPRNG(const ltc_prng_descriptor &descriptor) {
  int res = register_prng(&descriptor);
  if (res == -1) {
    throw std::runtime_error("failed to register PRNG algorithm");
  }
  return res;
}

void TomCryptionImpl::loadKeys(const char *key, short keySize) {
  memcpy(m_PublicKeyData, key, keySize);
  checked(rsa_import(m_PublicKeyData, keySize, &m_PublicKey), "Invalid public key (error: {1})");
}

void TomCryptionImpl::decryptData(uint8_t *buffer, unsigned long bufferSize, CipherKey key, InitialVector iv) const {
  symmetric_CTR counter;

  checked(ctr_start(m_Twofish, iv, key, BLOCK_CIPHER_KEY_LENGTH, 0, CTR_COUNTER_LITTLE_ENDIAN, &counter),
    "Failed to start decoding");

  checked(ctr_decrypt(buffer, buffer, bufferSize, &counter), "failed to decode");
  checked(ctr_done(&counter), "failed to finalize decoding");
}

void TomCryptionImpl::decryptFileSection(std::istream &input, std::ostream &output, unsigned long size, CipherKey key, InitialVector iv, bool isData) const {
  std::vector<uint8_t> buffer(size);

  input.read(reinterpret_cast<char*>(&buffer[0]), size);
  decryptData(&buffer[0], size, key, iv);

  output.write(reinterpret_cast<char*>(&buffer[0]), buffer.size());
}

Hash TomCryptionImpl::startHashSHA256() const {
  return Hash(m_SHA256);
}

std::vector<uint8_t> TomCryptionImpl::decryptKey(const uint8_t *input, unsigned long size, int padding) {
  if ((padding != LTC_PKCS_1_V1_5) && (padding != LTC_PKCS_1_OAEP)) {
    throw std::runtime_error("invalid padding");
  }

  int modBits = ltc_mp.count_bits(m_PublicKey.N);
  unsigned long modBytes = ltc_mp.unsigned_size(m_PublicKey.N);

  if (modBytes != size) {
    throw std::runtime_error("invalid data");
  }

  std::vector<uint8_t> buffer(size);
  unsigned long bufSize = size;

  checked(ltc_mp.rsa_me(input, size, buffer.data(), &bufSize, PK_PUBLIC, &m_PublicKey), "decryption failed (error {1})");

  int stat = 0;
  unsigned long outputLength = RSA_KEY_MESSAGE_LENGTH;
  std::vector<uint8_t> output(outputLength);
  if (padding == LTC_PKCS_1_OAEP) {
    checked(pkcs_1_oaep_decode(buffer.data(), bufSize, nullptr, 0, modBits, m_SHA256, output.data(), &outputLength, &stat),
      "decoding failed (error {1})");
  } else {
    checked(pkcs_1_v1_5_decode(buffer.data(), bufSize, LTC_PKCS_1_EME, modBits, output.data(), &outputLength, &stat),
      "decoding failed (error {1})");
  }

  if (stat != 1) {
    throw std::runtime_error("decryption failed");
  }

  output.resize(outputLength);

  return output;
}

class HashImpl {
public:
  HashImpl(int hashId)
    : m_HashId(hashId)
  {
    hash_descriptor[hashId].init(&m_State);
  }

  void process(const uint8_t * data, unsigned long dataSize) {
    hash_descriptor[m_HashId].process(&m_State, data, dataSize);
  }

  std::vector<uint8_t> digest() {
    std::vector<uint8_t> result(32);
    hash_descriptor[m_HashId].done(&m_State, &result[0]);
    return result;
  }
private:
  int m_HashId;
  hash_state m_State;
};

Hash::Hash(int hashId)
  : m_Impl(new HashImpl(hashId))
{
}

Hash &Hash::process(const uint8_t * data, unsigned long dataSize) {
  m_Impl->process(data, dataSize);
  return *this;
}

std::vector<uint8_t> Hash::digest() {
  return m_Impl->digest();
}
