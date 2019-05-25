//
//  uniqueIDGenerator.cpp
//
//  Created by Jared Bourgeois on 5/24/19.
//  Copyright © 2019 Jared Bourgeois. All rights reserved.
//

#include "uniqueIDGenerator.hpp"

std::string generateUniqueID() {
  double random1 = rand();
  double random2 = rand();
  double random3 = rand();
  double randomRandom = 0;
  
  int randomSwitch = rand() % 2;
  switch (randomSwitch) {
    case 0 :
      randomRandom += random1;
      break;
    case 1 :
      randomRandom += random2;
      break;
    case 2 :
      randomRandom += random3;
      break;
    default:
      randomRandom += rand();
      break;
  }
  std::string randomString = std::to_string(randomRandom);
  std::string randomHash = sha256(randomString);
  std::string msUnixTime = unixTimeMilliseconds();
  std::string first13MSDigits = msUnixTime.substr(0,13);
  std::string uniqueIdentifier = first13MSDigits.append("-").append(randomHash);
  // eg 1558763373482-68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728
  return uniqueIdentifier;
}

std::string sha256(std::string input)
{
  unsigned char digest[SHA256::DIGEST_SIZE];
  memset(digest,0,SHA256::DIGEST_SIZE);
  
  SHA256 ctx = SHA256();
  ctx.init();
  ctx.update( (unsigned char*)input.c_str(), input.length() );
  ctx.final(digest);
  
  char buf[2*SHA256::DIGEST_SIZE+1];
  buf[2*SHA256::DIGEST_SIZE] = 0;
  for (int i = 0; i < SHA256::DIGEST_SIZE; i++)
    sprintf(buf+i*2, "%02x", digest[i]);
  return std::string(buf);
}

/*
 May 25, 2019
 Unix Timestamp: 1,558,763,373 (1.56 x 10^9) seconds since 1/1/1970
 Milliseconds Unix Timestamp: 1.56 x 10^12
 In another ~49.5 years will get up to 3.12 x 10^12
 int64_t max: 9,223,372,036,854,775,808 (9.22 x 10^18)
 */
std::string unixTime() {
  int64_t now = std::chrono::system_clock::now().time_since_epoch().count();
  return std::to_string(now);
}

std::string unixTimeMilliseconds() {
  int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  return std::to_string(now);
}

void SHA256::transform(const unsigned char *message, unsigned int block_nb)
{
  uint32 w[64];
  uint32 wv[8];
  uint32 t1, t2;
  const unsigned char *sub_block;
  int i;
  int j;
  for (i = 0; i < (int) block_nb; i++) {
    sub_block = message + (i << 6);
    for (j = 0; j < 16; j++) {
      SHA2_PACK32(&sub_block[j << 2], &w[j]);
    }
    for (j = 16; j < 64; j++) {
      w[j] =  SHA256_F4(w[j -  2]) + w[j -  7] + SHA256_F3(w[j - 15]) + w[j - 16];
    }
    for (j = 0; j < 8; j++) {
      wv[j] = m_h[j];
    }
    for (j = 0; j < 64; j++) {
      t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
      + sha256_k[j] + w[j];
      t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
      wv[7] = wv[6];
      wv[6] = wv[5];
      wv[5] = wv[4];
      wv[4] = wv[3] + t1;
      wv[3] = wv[2];
      wv[2] = wv[1];
      wv[1] = wv[0];
      wv[0] = t1 + t2;
    }
    for (j = 0; j < 8; j++) {
      m_h[j] += wv[j];
    }
  }
}

void SHA256::init()
{
  m_h[0] = 0x6a09e667;
  m_h[1] = 0xbb67ae85;
  m_h[2] = 0x3c6ef372;
  m_h[3] = 0xa54ff53a;
  m_h[4] = 0x510e527f;
  m_h[5] = 0x9b05688c;
  m_h[6] = 0x1f83d9ab;
  m_h[7] = 0x5be0cd19;
  m_len = 0;
  m_tot_len = 0;
}
 
void SHA256::update(const unsigned char *message, unsigned int len)
{
  unsigned int block_nb;
  unsigned int new_len, rem_len, tmp_len;
  const unsigned char *shifted_message;
  tmp_len = SHA224_256_BLOCK_SIZE - m_len;
  rem_len = len < tmp_len ? len : tmp_len;
  memcpy(&m_block[m_len], message, rem_len);
  if (m_len + len < SHA224_256_BLOCK_SIZE) {
    m_len += len;
    return;
  }
  new_len = len - rem_len;
  block_nb = new_len / SHA224_256_BLOCK_SIZE;
  shifted_message = message + rem_len;
  transform(m_block, 1);
  transform(shifted_message, block_nb);
  rem_len = new_len % SHA224_256_BLOCK_SIZE;
  memcpy(m_block, &shifted_message[block_nb << 6], rem_len);
  m_len = rem_len;
  m_tot_len += (block_nb + 1) << 6;
}

void SHA256::final(unsigned char *digest)
{
  unsigned int block_nb;
  unsigned int pm_len;
  unsigned int len_b;
  int i;
  block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9)
                   < (m_len % SHA224_256_BLOCK_SIZE)));
  len_b = (m_tot_len + m_len) << 3;
  pm_len = block_nb << 6;
  memset(m_block + m_len, 0, pm_len - m_len);
  m_block[m_len] = 0x80;
  SHA2_UNPACK32(len_b, m_block + pm_len - 4);
  transform(m_block, block_nb);
  for (i = 0 ; i < 8; i++) {
    SHA2_UNPACK32(m_h[i], &digest[i << 2]);
  }
}