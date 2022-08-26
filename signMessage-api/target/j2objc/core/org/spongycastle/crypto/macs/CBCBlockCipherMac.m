//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/macs/CBCBlockCipherMac.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "org/spongycastle/crypto/BlockCipher.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/macs/CBCBlockCipherMac.h"
#include "org/spongycastle/crypto/modes/CBCBlockCipher.h"
#include "org/spongycastle/crypto/paddings/BlockCipherPadding.h"

@interface OrgSpongycastleCryptoMacsCBCBlockCipherMac () {
 @public
  IOSByteArray *mac_;
  IOSByteArray *buf_;
  jint bufOff_;
  id<OrgSpongycastleCryptoBlockCipher> cipher_;
  id<OrgSpongycastleCryptoPaddingsBlockCipherPadding> padding_;
  jint macSize_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoMacsCBCBlockCipherMac, mac_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoMacsCBCBlockCipherMac, buf_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoMacsCBCBlockCipherMac, cipher_, id<OrgSpongycastleCryptoBlockCipher>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoMacsCBCBlockCipherMac, padding_, id<OrgSpongycastleCryptoPaddingsBlockCipherPadding>)

@implementation OrgSpongycastleCryptoMacsCBCBlockCipherMac

- (instancetype)initWithOrgSpongycastleCryptoBlockCipher:(id<OrgSpongycastleCryptoBlockCipher>)cipher {
  OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_(self, cipher);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoBlockCipher:(id<OrgSpongycastleCryptoBlockCipher>)cipher
     withOrgSpongycastleCryptoPaddingsBlockCipherPadding:(id<OrgSpongycastleCryptoPaddingsBlockCipherPadding>)padding {
  OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_withOrgSpongycastleCryptoPaddingsBlockCipherPadding_(self, cipher, padding);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoBlockCipher:(id<OrgSpongycastleCryptoBlockCipher>)cipher
                                                 withInt:(jint)macSizeInBits {
  OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_withInt_(self, cipher, macSizeInBits);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoBlockCipher:(id<OrgSpongycastleCryptoBlockCipher>)cipher
                                                 withInt:(jint)macSizeInBits
     withOrgSpongycastleCryptoPaddingsBlockCipherPadding:(id<OrgSpongycastleCryptoPaddingsBlockCipherPadding>)padding {
  OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_withInt_withOrgSpongycastleCryptoPaddingsBlockCipherPadding_(self, cipher, macSizeInBits, padding);
  return self;
}

- (NSString *)getAlgorithmName {
  return [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher_)) getAlgorithmName];
}

- (void)init__WithOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params {
  [self reset];
  [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher_)) init__WithBoolean:true withOrgSpongycastleCryptoCipherParameters:params];
}

- (jint)getMacSize {
  return macSize_;
}

- (void)updateWithByte:(jbyte)inArg {
  if (bufOff_ == ((IOSByteArray *) nil_chk(buf_))->size_) {
    [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher_)) processBlockWithByteArray:buf_ withInt:0 withByteArray:mac_ withInt:0];
    bufOff_ = 0;
  }
  *IOSByteArray_GetRef(nil_chk(buf_), bufOff_++) = inArg;
}

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len {
  if (len < 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Can't have a negative input length!");
  }
  jint blockSize = [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher_)) getBlockSize];
  jint gapLen = blockSize - bufOff_;
  if (len > gapLen) {
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, buf_, bufOff_, gapLen);
    [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher_)) processBlockWithByteArray:buf_ withInt:0 withByteArray:mac_ withInt:0];
    bufOff_ = 0;
    len -= gapLen;
    inOff += gapLen;
    while (len > blockSize) {
      [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher_)) processBlockWithByteArray:inArg withInt:inOff withByteArray:mac_ withInt:0];
      len -= blockSize;
      inOff += blockSize;
    }
  }
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, buf_, bufOff_, len);
  bufOff_ += len;
}

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff {
  jint blockSize = [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher_)) getBlockSize];
  if (padding_ == nil) {
    while (bufOff_ < blockSize) {
      *IOSByteArray_GetRef(nil_chk(buf_), bufOff_) = 0;
      bufOff_++;
    }
  }
  else {
    if (bufOff_ == blockSize) {
      [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher_)) processBlockWithByteArray:buf_ withInt:0 withByteArray:mac_ withInt:0];
      bufOff_ = 0;
    }
    [((id<OrgSpongycastleCryptoPaddingsBlockCipherPadding>) nil_chk(padding_)) addPaddingWithByteArray:buf_ withInt:bufOff_];
  }
  [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher_)) processBlockWithByteArray:buf_ withInt:0 withByteArray:mac_ withInt:0];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(mac_, 0, outArg, outOff, macSize_);
  [self reset];
  return macSize_;
}

- (void)reset {
  for (jint i = 0; i < ((IOSByteArray *) nil_chk(buf_))->size_; i++) {
    *IOSByteArray_GetRef(buf_, i) = 0;
  }
  bufOff_ = 0;
  [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher_)) reset];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 6, 8, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 9, 10, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoBlockCipher:);
  methods[1].selector = @selector(initWithOrgSpongycastleCryptoBlockCipher:withOrgSpongycastleCryptoPaddingsBlockCipherPadding:);
  methods[2].selector = @selector(initWithOrgSpongycastleCryptoBlockCipher:withInt:);
  methods[3].selector = @selector(initWithOrgSpongycastleCryptoBlockCipher:withInt:withOrgSpongycastleCryptoPaddingsBlockCipherPadding:);
  methods[4].selector = @selector(getAlgorithmName);
  methods[5].selector = @selector(init__WithOrgSpongycastleCryptoCipherParameters:);
  methods[6].selector = @selector(getMacSize);
  methods[7].selector = @selector(updateWithByte:);
  methods[8].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[9].selector = @selector(doFinalWithByteArray:withInt:);
  methods[10].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "mac_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "buf_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "bufOff_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "cipher_", "LOrgSpongycastleCryptoBlockCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "padding_", "LOrgSpongycastleCryptoPaddingsBlockCipherPadding;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "macSize_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoBlockCipher;", "LOrgSpongycastleCryptoBlockCipher;LOrgSpongycastleCryptoPaddingsBlockCipherPadding;", "LOrgSpongycastleCryptoBlockCipher;I", "LOrgSpongycastleCryptoBlockCipher;ILOrgSpongycastleCryptoPaddingsBlockCipherPadding;", "init", "LOrgSpongycastleCryptoCipherParameters;", "update", "B", "[BII", "doFinal", "[BI" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoMacsCBCBlockCipherMac = { "CBCBlockCipherMac", "org.spongycastle.crypto.macs", ptrTable, methods, fields, 7, 0x1, 11, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoMacsCBCBlockCipherMac;
}

@end

void OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_(OrgSpongycastleCryptoMacsCBCBlockCipherMac *self, id<OrgSpongycastleCryptoBlockCipher> cipher) {
  OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_withInt_withOrgSpongycastleCryptoPaddingsBlockCipherPadding_(self, cipher, ([((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher)) getBlockSize] * 8) / 2, nil);
}

OrgSpongycastleCryptoMacsCBCBlockCipherMac *new_OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_(id<OrgSpongycastleCryptoBlockCipher> cipher) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoMacsCBCBlockCipherMac, initWithOrgSpongycastleCryptoBlockCipher_, cipher)
}

OrgSpongycastleCryptoMacsCBCBlockCipherMac *create_OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_(id<OrgSpongycastleCryptoBlockCipher> cipher) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoMacsCBCBlockCipherMac, initWithOrgSpongycastleCryptoBlockCipher_, cipher)
}

void OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_withOrgSpongycastleCryptoPaddingsBlockCipherPadding_(OrgSpongycastleCryptoMacsCBCBlockCipherMac *self, id<OrgSpongycastleCryptoBlockCipher> cipher, id<OrgSpongycastleCryptoPaddingsBlockCipherPadding> padding) {
  OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_withInt_withOrgSpongycastleCryptoPaddingsBlockCipherPadding_(self, cipher, ([((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher)) getBlockSize] * 8) / 2, padding);
}

OrgSpongycastleCryptoMacsCBCBlockCipherMac *new_OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_withOrgSpongycastleCryptoPaddingsBlockCipherPadding_(id<OrgSpongycastleCryptoBlockCipher> cipher, id<OrgSpongycastleCryptoPaddingsBlockCipherPadding> padding) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoMacsCBCBlockCipherMac, initWithOrgSpongycastleCryptoBlockCipher_withOrgSpongycastleCryptoPaddingsBlockCipherPadding_, cipher, padding)
}

OrgSpongycastleCryptoMacsCBCBlockCipherMac *create_OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_withOrgSpongycastleCryptoPaddingsBlockCipherPadding_(id<OrgSpongycastleCryptoBlockCipher> cipher, id<OrgSpongycastleCryptoPaddingsBlockCipherPadding> padding) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoMacsCBCBlockCipherMac, initWithOrgSpongycastleCryptoBlockCipher_withOrgSpongycastleCryptoPaddingsBlockCipherPadding_, cipher, padding)
}

void OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_withInt_(OrgSpongycastleCryptoMacsCBCBlockCipherMac *self, id<OrgSpongycastleCryptoBlockCipher> cipher, jint macSizeInBits) {
  OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_withInt_withOrgSpongycastleCryptoPaddingsBlockCipherPadding_(self, cipher, macSizeInBits, nil);
}

OrgSpongycastleCryptoMacsCBCBlockCipherMac *new_OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_withInt_(id<OrgSpongycastleCryptoBlockCipher> cipher, jint macSizeInBits) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoMacsCBCBlockCipherMac, initWithOrgSpongycastleCryptoBlockCipher_withInt_, cipher, macSizeInBits)
}

OrgSpongycastleCryptoMacsCBCBlockCipherMac *create_OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_withInt_(id<OrgSpongycastleCryptoBlockCipher> cipher, jint macSizeInBits) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoMacsCBCBlockCipherMac, initWithOrgSpongycastleCryptoBlockCipher_withInt_, cipher, macSizeInBits)
}

void OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_withInt_withOrgSpongycastleCryptoPaddingsBlockCipherPadding_(OrgSpongycastleCryptoMacsCBCBlockCipherMac *self, id<OrgSpongycastleCryptoBlockCipher> cipher, jint macSizeInBits, id<OrgSpongycastleCryptoPaddingsBlockCipherPadding> padding) {
  NSObject_init(self);
  if ((macSizeInBits % 8) != 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"MAC size must be multiple of 8");
  }
  self->cipher_ = new_OrgSpongycastleCryptoModesCBCBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_(cipher);
  self->padding_ = padding;
  self->macSize_ = macSizeInBits / 8;
  self->mac_ = [IOSByteArray newArrayWithLength:[((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher)) getBlockSize]];
  self->buf_ = [IOSByteArray newArrayWithLength:[cipher getBlockSize]];
  self->bufOff_ = 0;
}

OrgSpongycastleCryptoMacsCBCBlockCipherMac *new_OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_withInt_withOrgSpongycastleCryptoPaddingsBlockCipherPadding_(id<OrgSpongycastleCryptoBlockCipher> cipher, jint macSizeInBits, id<OrgSpongycastleCryptoPaddingsBlockCipherPadding> padding) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoMacsCBCBlockCipherMac, initWithOrgSpongycastleCryptoBlockCipher_withInt_withOrgSpongycastleCryptoPaddingsBlockCipherPadding_, cipher, macSizeInBits, padding)
}

OrgSpongycastleCryptoMacsCBCBlockCipherMac *create_OrgSpongycastleCryptoMacsCBCBlockCipherMac_initWithOrgSpongycastleCryptoBlockCipher_withInt_withOrgSpongycastleCryptoPaddingsBlockCipherPadding_(id<OrgSpongycastleCryptoBlockCipher> cipher, jint macSizeInBits, id<OrgSpongycastleCryptoPaddingsBlockCipherPadding> padding) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoMacsCBCBlockCipherMac, initWithOrgSpongycastleCryptoBlockCipher_withInt_withOrgSpongycastleCryptoPaddingsBlockCipherPadding_, cipher, macSizeInBits, padding)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoMacsCBCBlockCipherMac)