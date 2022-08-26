//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/encodings/PKCS1Encoding.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "java/security/AccessController.h"
#include "java/security/PrivilegedAction.h"
#include "java/security/SecureRandom.h"
#include "org/spongycastle/crypto/AsymmetricBlockCipher.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/InvalidCipherTextException.h"
#include "org/spongycastle/crypto/encodings/PKCS1Encoding.h"
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"
#include "org/spongycastle/crypto/params/ParametersWithRandom.h"
#include "org/spongycastle/util/Arrays.h"

@interface OrgSpongycastleCryptoEncodingsPKCS1Encoding () {
 @public
  JavaSecuritySecureRandom *random_;
  id<OrgSpongycastleCryptoAsymmetricBlockCipher> engine_;
  jboolean forEncryption_;
  jboolean forPrivateKey_;
  jboolean useStrictLength_;
  jint pLen_;
  IOSByteArray *fallback_;
  IOSByteArray *blockBuffer_;
}

- (jboolean)useStrict;

- (IOSByteArray *)encodeBlockWithByteArray:(IOSByteArray *)inArg
                                   withInt:(jint)inOff
                                   withInt:(jint)inLen;

+ (jint)checkPkcs1EncodingWithByteArray:(IOSByteArray *)encoded
                                withInt:(jint)pLen;

- (IOSByteArray *)decodeBlockOrRandomWithByteArray:(IOSByteArray *)inArg
                                           withInt:(jint)inOff
                                           withInt:(jint)inLen;

- (IOSByteArray *)decodeBlockWithByteArray:(IOSByteArray *)inArg
                                   withInt:(jint)inOff
                                   withInt:(jint)inLen;

- (jint)findStartWithByte:(jbyte)type
            withByteArray:(IOSByteArray *)block;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEncodingsPKCS1Encoding, random_, JavaSecuritySecureRandom *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEncodingsPKCS1Encoding, engine_, id<OrgSpongycastleCryptoAsymmetricBlockCipher>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEncodingsPKCS1Encoding, fallback_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEncodingsPKCS1Encoding, blockBuffer_, IOSByteArray *)

inline jint OrgSpongycastleCryptoEncodingsPKCS1Encoding_get_HEADER_LENGTH(void);
#define OrgSpongycastleCryptoEncodingsPKCS1Encoding_HEADER_LENGTH 10
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoEncodingsPKCS1Encoding, HEADER_LENGTH, jint)

__attribute__((unused)) static jboolean OrgSpongycastleCryptoEncodingsPKCS1Encoding_useStrict(OrgSpongycastleCryptoEncodingsPKCS1Encoding *self);

__attribute__((unused)) static IOSByteArray *OrgSpongycastleCryptoEncodingsPKCS1Encoding_encodeBlockWithByteArray_withInt_withInt_(OrgSpongycastleCryptoEncodingsPKCS1Encoding *self, IOSByteArray *inArg, jint inOff, jint inLen);

__attribute__((unused)) static jint OrgSpongycastleCryptoEncodingsPKCS1Encoding_checkPkcs1EncodingWithByteArray_withInt_(IOSByteArray *encoded, jint pLen);

__attribute__((unused)) static IOSByteArray *OrgSpongycastleCryptoEncodingsPKCS1Encoding_decodeBlockOrRandomWithByteArray_withInt_withInt_(OrgSpongycastleCryptoEncodingsPKCS1Encoding *self, IOSByteArray *inArg, jint inOff, jint inLen);

__attribute__((unused)) static IOSByteArray *OrgSpongycastleCryptoEncodingsPKCS1Encoding_decodeBlockWithByteArray_withInt_withInt_(OrgSpongycastleCryptoEncodingsPKCS1Encoding *self, IOSByteArray *inArg, jint inOff, jint inLen);

__attribute__((unused)) static jint OrgSpongycastleCryptoEncodingsPKCS1Encoding_findStartWithByte_withByteArray_(OrgSpongycastleCryptoEncodingsPKCS1Encoding *self, jbyte type, IOSByteArray *block);

@interface OrgSpongycastleCryptoEncodingsPKCS1Encoding_1 : NSObject < JavaSecurityPrivilegedAction >

- (instancetype)init;

- (id)run;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoEncodingsPKCS1Encoding_1)

__attribute__((unused)) static void OrgSpongycastleCryptoEncodingsPKCS1Encoding_1_init(OrgSpongycastleCryptoEncodingsPKCS1Encoding_1 *self);

__attribute__((unused)) static OrgSpongycastleCryptoEncodingsPKCS1Encoding_1 *new_OrgSpongycastleCryptoEncodingsPKCS1Encoding_1_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleCryptoEncodingsPKCS1Encoding_1 *create_OrgSpongycastleCryptoEncodingsPKCS1Encoding_1_init(void);

@interface OrgSpongycastleCryptoEncodingsPKCS1Encoding_2 : NSObject < JavaSecurityPrivilegedAction >

- (instancetype)init;

- (id)run;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoEncodingsPKCS1Encoding_2)

__attribute__((unused)) static void OrgSpongycastleCryptoEncodingsPKCS1Encoding_2_init(OrgSpongycastleCryptoEncodingsPKCS1Encoding_2 *self);

__attribute__((unused)) static OrgSpongycastleCryptoEncodingsPKCS1Encoding_2 *new_OrgSpongycastleCryptoEncodingsPKCS1Encoding_2_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleCryptoEncodingsPKCS1Encoding_2 *create_OrgSpongycastleCryptoEncodingsPKCS1Encoding_2_init(void);

NSString *OrgSpongycastleCryptoEncodingsPKCS1Encoding_STRICT_LENGTH_ENABLED_PROPERTY = @"org.spongycastle.pkcs1.strict";
NSString *OrgSpongycastleCryptoEncodingsPKCS1Encoding_NOT_STRICT_LENGTH_ENABLED_PROPERTY = @"org.spongycastle.pkcs1.not_strict";

@implementation OrgSpongycastleCryptoEncodingsPKCS1Encoding

- (instancetype)initWithOrgSpongycastleCryptoAsymmetricBlockCipher:(id<OrgSpongycastleCryptoAsymmetricBlockCipher>)cipher {
  OrgSpongycastleCryptoEncodingsPKCS1Encoding_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_(self, cipher);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoAsymmetricBlockCipher:(id<OrgSpongycastleCryptoAsymmetricBlockCipher>)cipher
                                                           withInt:(jint)pLen {
  OrgSpongycastleCryptoEncodingsPKCS1Encoding_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withInt_(self, cipher, pLen);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoAsymmetricBlockCipher:(id<OrgSpongycastleCryptoAsymmetricBlockCipher>)cipher
                                                     withByteArray:(IOSByteArray *)fallback {
  OrgSpongycastleCryptoEncodingsPKCS1Encoding_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withByteArray_(self, cipher, fallback);
  return self;
}

- (jboolean)useStrict {
  return OrgSpongycastleCryptoEncodingsPKCS1Encoding_useStrict(self);
}

- (id<OrgSpongycastleCryptoAsymmetricBlockCipher>)getUnderlyingCipher {
  return engine_;
}

- (void)init__WithBoolean:(jboolean)forEncryption
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)param {
  OrgSpongycastleCryptoParamsAsymmetricKeyParameter *kParam;
  if ([param isKindOfClass:[OrgSpongycastleCryptoParamsParametersWithRandom class]]) {
    OrgSpongycastleCryptoParamsParametersWithRandom *rParam = (OrgSpongycastleCryptoParamsParametersWithRandom *) param;
    self->random_ = [((OrgSpongycastleCryptoParamsParametersWithRandom *) nil_chk(rParam)) getRandom];
    kParam = (OrgSpongycastleCryptoParamsAsymmetricKeyParameter *) cast_chk([rParam getParameters], [OrgSpongycastleCryptoParamsAsymmetricKeyParameter class]);
  }
  else {
    kParam = (OrgSpongycastleCryptoParamsAsymmetricKeyParameter *) cast_chk(param, [OrgSpongycastleCryptoParamsAsymmetricKeyParameter class]);
    if (![((OrgSpongycastleCryptoParamsAsymmetricKeyParameter *) nil_chk(kParam)) isPrivate] && forEncryption) {
      self->random_ = new_JavaSecuritySecureRandom_init();
    }
  }
  [((id<OrgSpongycastleCryptoAsymmetricBlockCipher>) nil_chk(engine_)) init__WithBoolean:forEncryption withOrgSpongycastleCryptoCipherParameters:param];
  self->forPrivateKey_ = [((OrgSpongycastleCryptoParamsAsymmetricKeyParameter *) nil_chk(kParam)) isPrivate];
  self->forEncryption_ = forEncryption;
  self->blockBuffer_ = [IOSByteArray newArrayWithLength:[((id<OrgSpongycastleCryptoAsymmetricBlockCipher>) nil_chk(engine_)) getOutputBlockSize]];
  if (pLen_ > 0 && fallback_ == nil && random_ == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"encoder requires random");
  }
}

- (jint)getInputBlockSize {
  jint baseBlockSize = [((id<OrgSpongycastleCryptoAsymmetricBlockCipher>) nil_chk(engine_)) getInputBlockSize];
  if (forEncryption_) {
    return baseBlockSize - OrgSpongycastleCryptoEncodingsPKCS1Encoding_HEADER_LENGTH;
  }
  else {
    return baseBlockSize;
  }
}

- (jint)getOutputBlockSize {
  jint baseBlockSize = [((id<OrgSpongycastleCryptoAsymmetricBlockCipher>) nil_chk(engine_)) getOutputBlockSize];
  if (forEncryption_) {
    return baseBlockSize;
  }
  else {
    return baseBlockSize - OrgSpongycastleCryptoEncodingsPKCS1Encoding_HEADER_LENGTH;
  }
}

- (IOSByteArray *)processBlockWithByteArray:(IOSByteArray *)inArg
                                    withInt:(jint)inOff
                                    withInt:(jint)inLen {
  if (forEncryption_) {
    return OrgSpongycastleCryptoEncodingsPKCS1Encoding_encodeBlockWithByteArray_withInt_withInt_(self, inArg, inOff, inLen);
  }
  else {
    return OrgSpongycastleCryptoEncodingsPKCS1Encoding_decodeBlockWithByteArray_withInt_withInt_(self, inArg, inOff, inLen);
  }
}

- (IOSByteArray *)encodeBlockWithByteArray:(IOSByteArray *)inArg
                                   withInt:(jint)inOff
                                   withInt:(jint)inLen {
  return OrgSpongycastleCryptoEncodingsPKCS1Encoding_encodeBlockWithByteArray_withInt_withInt_(self, inArg, inOff, inLen);
}

+ (jint)checkPkcs1EncodingWithByteArray:(IOSByteArray *)encoded
                                withInt:(jint)pLen {
  return OrgSpongycastleCryptoEncodingsPKCS1Encoding_checkPkcs1EncodingWithByteArray_withInt_(encoded, pLen);
}

- (IOSByteArray *)decodeBlockOrRandomWithByteArray:(IOSByteArray *)inArg
                                           withInt:(jint)inOff
                                           withInt:(jint)inLen {
  return OrgSpongycastleCryptoEncodingsPKCS1Encoding_decodeBlockOrRandomWithByteArray_withInt_withInt_(self, inArg, inOff, inLen);
}

- (IOSByteArray *)decodeBlockWithByteArray:(IOSByteArray *)inArg
                                   withInt:(jint)inOff
                                   withInt:(jint)inLen {
  return OrgSpongycastleCryptoEncodingsPKCS1Encoding_decodeBlockWithByteArray_withInt_withInt_(self, inArg, inOff, inLen);
}

- (jint)findStartWithByte:(jbyte)type
            withByteArray:(IOSByteArray *)block {
  return OrgSpongycastleCryptoEncodingsPKCS1Encoding_findStartWithByte_withByteArray_(self, type, block);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoAsymmetricBlockCipher;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 5, 6, 7, -1, -1, -1 },
    { NULL, "[B", 0x2, 8, 6, 7, -1, -1, -1 },
    { NULL, "I", 0xa, 9, 10, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 11, 6, 7, -1, -1, -1 },
    { NULL, "[B", 0x2, 12, 6, 7, -1, -1, -1 },
    { NULL, "I", 0x2, 13, 14, 7, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoAsymmetricBlockCipher:);
  methods[1].selector = @selector(initWithOrgSpongycastleCryptoAsymmetricBlockCipher:withInt:);
  methods[2].selector = @selector(initWithOrgSpongycastleCryptoAsymmetricBlockCipher:withByteArray:);
  methods[3].selector = @selector(useStrict);
  methods[4].selector = @selector(getUnderlyingCipher);
  methods[5].selector = @selector(init__WithBoolean:withOrgSpongycastleCryptoCipherParameters:);
  methods[6].selector = @selector(getInputBlockSize);
  methods[7].selector = @selector(getOutputBlockSize);
  methods[8].selector = @selector(processBlockWithByteArray:withInt:withInt:);
  methods[9].selector = @selector(encodeBlockWithByteArray:withInt:withInt:);
  methods[10].selector = @selector(checkPkcs1EncodingWithByteArray:withInt:);
  methods[11].selector = @selector(decodeBlockOrRandomWithByteArray:withInt:withInt:);
  methods[12].selector = @selector(decodeBlockWithByteArray:withInt:withInt:);
  methods[13].selector = @selector(findStartWithByte:withByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "STRICT_LENGTH_ENABLED_PROPERTY", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 15, -1, -1 },
    { "NOT_STRICT_LENGTH_ENABLED_PROPERTY", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 16, -1, -1 },
    { "HEADER_LENGTH", "I", .constantValue.asInt = OrgSpongycastleCryptoEncodingsPKCS1Encoding_HEADER_LENGTH, 0x1a, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "engine_", "LOrgSpongycastleCryptoAsymmetricBlockCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "forEncryption_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "forPrivateKey_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "useStrictLength_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "pLen_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "fallback_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "blockBuffer_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoAsymmetricBlockCipher;", "LOrgSpongycastleCryptoAsymmetricBlockCipher;I", "LOrgSpongycastleCryptoAsymmetricBlockCipher;[B", "init", "ZLOrgSpongycastleCryptoCipherParameters;", "processBlock", "[BII", "LOrgSpongycastleCryptoInvalidCipherTextException;", "encodeBlock", "checkPkcs1Encoding", "[BI", "decodeBlockOrRandom", "decodeBlock", "findStart", "B[B", &OrgSpongycastleCryptoEncodingsPKCS1Encoding_STRICT_LENGTH_ENABLED_PROPERTY, &OrgSpongycastleCryptoEncodingsPKCS1Encoding_NOT_STRICT_LENGTH_ENABLED_PROPERTY };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoEncodingsPKCS1Encoding = { "PKCS1Encoding", "org.spongycastle.crypto.encodings", ptrTable, methods, fields, 7, 0x1, 14, 11, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoEncodingsPKCS1Encoding;
}

@end

void OrgSpongycastleCryptoEncodingsPKCS1Encoding_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_(OrgSpongycastleCryptoEncodingsPKCS1Encoding *self, id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher) {
  NSObject_init(self);
  self->pLen_ = -1;
  self->fallback_ = nil;
  self->engine_ = cipher;
  self->useStrictLength_ = OrgSpongycastleCryptoEncodingsPKCS1Encoding_useStrict(self);
}

OrgSpongycastleCryptoEncodingsPKCS1Encoding *new_OrgSpongycastleCryptoEncodingsPKCS1Encoding_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoEncodingsPKCS1Encoding, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_, cipher)
}

OrgSpongycastleCryptoEncodingsPKCS1Encoding *create_OrgSpongycastleCryptoEncodingsPKCS1Encoding_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoEncodingsPKCS1Encoding, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_, cipher)
}

void OrgSpongycastleCryptoEncodingsPKCS1Encoding_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withInt_(OrgSpongycastleCryptoEncodingsPKCS1Encoding *self, id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, jint pLen) {
  NSObject_init(self);
  self->pLen_ = -1;
  self->fallback_ = nil;
  self->engine_ = cipher;
  self->useStrictLength_ = OrgSpongycastleCryptoEncodingsPKCS1Encoding_useStrict(self);
  self->pLen_ = pLen;
}

OrgSpongycastleCryptoEncodingsPKCS1Encoding *new_OrgSpongycastleCryptoEncodingsPKCS1Encoding_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withInt_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, jint pLen) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoEncodingsPKCS1Encoding, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withInt_, cipher, pLen)
}

OrgSpongycastleCryptoEncodingsPKCS1Encoding *create_OrgSpongycastleCryptoEncodingsPKCS1Encoding_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withInt_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, jint pLen) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoEncodingsPKCS1Encoding, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withInt_, cipher, pLen)
}

void OrgSpongycastleCryptoEncodingsPKCS1Encoding_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withByteArray_(OrgSpongycastleCryptoEncodingsPKCS1Encoding *self, id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, IOSByteArray *fallback) {
  NSObject_init(self);
  self->pLen_ = -1;
  self->fallback_ = nil;
  self->engine_ = cipher;
  self->useStrictLength_ = OrgSpongycastleCryptoEncodingsPKCS1Encoding_useStrict(self);
  self->fallback_ = fallback;
  self->pLen_ = ((IOSByteArray *) nil_chk(fallback))->size_;
}

OrgSpongycastleCryptoEncodingsPKCS1Encoding *new_OrgSpongycastleCryptoEncodingsPKCS1Encoding_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withByteArray_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, IOSByteArray *fallback) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoEncodingsPKCS1Encoding, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withByteArray_, cipher, fallback)
}

OrgSpongycastleCryptoEncodingsPKCS1Encoding *create_OrgSpongycastleCryptoEncodingsPKCS1Encoding_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withByteArray_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, IOSByteArray *fallback) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoEncodingsPKCS1Encoding, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withByteArray_, cipher, fallback)
}

jboolean OrgSpongycastleCryptoEncodingsPKCS1Encoding_useStrict(OrgSpongycastleCryptoEncodingsPKCS1Encoding *self) {
  NSString *strict = (NSString *) cast_chk(JavaSecurityAccessController_doPrivilegedWithJavaSecurityPrivilegedAction_(new_OrgSpongycastleCryptoEncodingsPKCS1Encoding_1_init()), [NSString class]);
  NSString *notStrict = (NSString *) cast_chk(JavaSecurityAccessController_doPrivilegedWithJavaSecurityPrivilegedAction_(new_OrgSpongycastleCryptoEncodingsPKCS1Encoding_2_init()), [NSString class]);
  if (notStrict != nil) {
    return ![notStrict isEqual:@"true"];
  }
  return strict == nil || [strict isEqual:@"true"];
}

IOSByteArray *OrgSpongycastleCryptoEncodingsPKCS1Encoding_encodeBlockWithByteArray_withInt_withInt_(OrgSpongycastleCryptoEncodingsPKCS1Encoding *self, IOSByteArray *inArg, jint inOff, jint inLen) {
  if (inLen > [self getInputBlockSize]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"input data too large");
  }
  IOSByteArray *block = [IOSByteArray newArrayWithLength:[((id<OrgSpongycastleCryptoAsymmetricBlockCipher>) nil_chk(self->engine_)) getInputBlockSize]];
  if (self->forPrivateKey_) {
    *IOSByteArray_GetRef(block, 0) = (jint) 0x01;
    for (jint i = 1; i != block->size_ - inLen - 1; i++) {
      *IOSByteArray_GetRef(block, i) = (jbyte) (jint) 0xFF;
    }
  }
  else {
    [((JavaSecuritySecureRandom *) nil_chk(self->random_)) nextBytesWithByteArray:block];
    *IOSByteArray_GetRef(block, 0) = (jint) 0x02;
    for (jint i = 1; i != block->size_ - inLen - 1; i++) {
      while (IOSByteArray_Get(block, i) == 0) {
        *IOSByteArray_GetRef(block, i) = (jbyte) [((JavaSecuritySecureRandom *) nil_chk(self->random_)) nextInt];
      }
    }
  }
  *IOSByteArray_GetRef(block, block->size_ - inLen - 1) = (jint) 0x00;
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, block, block->size_ - inLen, inLen);
  return [((id<OrgSpongycastleCryptoAsymmetricBlockCipher>) nil_chk(self->engine_)) processBlockWithByteArray:block withInt:0 withInt:block->size_];
}

jint OrgSpongycastleCryptoEncodingsPKCS1Encoding_checkPkcs1EncodingWithByteArray_withInt_(IOSByteArray *encoded, jint pLen) {
  OrgSpongycastleCryptoEncodingsPKCS1Encoding_initialize();
  jint correct = 0;
  correct |= (IOSByteArray_Get(nil_chk(encoded), 0) ^ 2);
  jint plen = encoded->size_ - (pLen + 1);
  for (jint i = 1; i < plen; i++) {
    jint tmp = IOSByteArray_Get(encoded, i);
    tmp |= JreRShift32(tmp, 1);
    tmp |= JreRShift32(tmp, 2);
    tmp |= JreRShift32(tmp, 4);
    correct |= (tmp & 1) - 1;
  }
  correct |= IOSByteArray_Get(encoded, encoded->size_ - (pLen + 1));
  correct |= JreRShift32(correct, 1);
  correct |= JreRShift32(correct, 2);
  correct |= JreRShift32(correct, 4);
  return ~((correct & 1) - 1);
}

IOSByteArray *OrgSpongycastleCryptoEncodingsPKCS1Encoding_decodeBlockOrRandomWithByteArray_withInt_withInt_(OrgSpongycastleCryptoEncodingsPKCS1Encoding *self, IOSByteArray *inArg, jint inOff, jint inLen) {
  if (!self->forPrivateKey_) {
    @throw new_OrgSpongycastleCryptoInvalidCipherTextException_initWithNSString_(@"sorry, this method is only for decryption, not for signing");
  }
  IOSByteArray *block = [((id<OrgSpongycastleCryptoAsymmetricBlockCipher>) nil_chk(self->engine_)) processBlockWithByteArray:inArg withInt:inOff withInt:inLen];
  IOSByteArray *random;
  if (self->fallback_ == nil) {
    random = [IOSByteArray newArrayWithLength:self->pLen_];
    [((JavaSecuritySecureRandom *) nil_chk(self->random_)) nextBytesWithByteArray:random];
  }
  else {
    random = self->fallback_;
  }
  IOSByteArray *data = (self->useStrictLength_ & (((IOSByteArray *) nil_chk(block))->size_ != [((id<OrgSpongycastleCryptoAsymmetricBlockCipher>) nil_chk(self->engine_)) getOutputBlockSize])) ? self->blockBuffer_ : block;
  jint correct = OrgSpongycastleCryptoEncodingsPKCS1Encoding_checkPkcs1EncodingWithByteArray_withInt_(data, self->pLen_);
  IOSByteArray *result = [IOSByteArray newArrayWithLength:self->pLen_];
  for (jint i = 0; i < self->pLen_; i++) {
    *IOSByteArray_GetRef(result, i) = (jbyte) ((IOSByteArray_Get(data, i + (data->size_ - self->pLen_)) & (~correct)) | (IOSByteArray_Get(random, i) & correct));
  }
  OrgSpongycastleUtilArrays_fillWithByteArray_withByte_(data, (jbyte) 0);
  return result;
}

IOSByteArray *OrgSpongycastleCryptoEncodingsPKCS1Encoding_decodeBlockWithByteArray_withInt_withInt_(OrgSpongycastleCryptoEncodingsPKCS1Encoding *self, IOSByteArray *inArg, jint inOff, jint inLen) {
  if (self->pLen_ != -1) {
    return OrgSpongycastleCryptoEncodingsPKCS1Encoding_decodeBlockOrRandomWithByteArray_withInt_withInt_(self, inArg, inOff, inLen);
  }
  IOSByteArray *block = [((id<OrgSpongycastleCryptoAsymmetricBlockCipher>) nil_chk(self->engine_)) processBlockWithByteArray:inArg withInt:inOff withInt:inLen];
  jboolean incorrectLength = (self->useStrictLength_ & (((IOSByteArray *) nil_chk(block))->size_ != [((id<OrgSpongycastleCryptoAsymmetricBlockCipher>) nil_chk(self->engine_)) getOutputBlockSize]));
  IOSByteArray *data;
  if (block->size_ < [self getOutputBlockSize]) {
    data = self->blockBuffer_;
  }
  else {
    data = block;
  }
  jbyte type = IOSByteArray_Get(nil_chk(data), 0);
  jboolean badType;
  if (self->forPrivateKey_) {
    badType = (type != 2);
  }
  else {
    badType = (type != 1);
  }
  jint start = OrgSpongycastleCryptoEncodingsPKCS1Encoding_findStartWithByte_withByteArray_(self, type, data);
  start++;
  if (badType | (start < OrgSpongycastleCryptoEncodingsPKCS1Encoding_HEADER_LENGTH)) {
    OrgSpongycastleUtilArrays_fillWithByteArray_withByte_(data, (jbyte) 0);
    @throw new_OrgSpongycastleCryptoInvalidCipherTextException_initWithNSString_(@"block incorrect");
  }
  if (incorrectLength) {
    OrgSpongycastleUtilArrays_fillWithByteArray_withByte_(data, (jbyte) 0);
    @throw new_OrgSpongycastleCryptoInvalidCipherTextException_initWithNSString_(@"block incorrect size");
  }
  IOSByteArray *result = [IOSByteArray newArrayWithLength:data->size_ - start];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(data, start, result, 0, result->size_);
  return result;
}

jint OrgSpongycastleCryptoEncodingsPKCS1Encoding_findStartWithByte_withByteArray_(OrgSpongycastleCryptoEncodingsPKCS1Encoding *self, jbyte type, IOSByteArray *block) {
  jint start = -1;
  jboolean padErr = false;
  for (jint i = 1; i != ((IOSByteArray *) nil_chk(block))->size_; i++) {
    jbyte pad = IOSByteArray_Get(block, i);
    if ((pad == 0) & (start < 0)) {
      start = i;
    }
    padErr |= ((type == 1) & (start < 0) & (pad != (jbyte) (jint) 0xff));
  }
  if (padErr) {
    return -1;
  }
  return start;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoEncodingsPKCS1Encoding)

@implementation OrgSpongycastleCryptoEncodingsPKCS1Encoding_1

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoEncodingsPKCS1Encoding_1_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (id)run {
  return JavaLangSystem_getPropertyWithNSString_(OrgSpongycastleCryptoEncodingsPKCS1Encoding_STRICT_LENGTH_ENABLED_PROPERTY);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(run);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoEncodingsPKCS1Encoding;", "useStrict" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoEncodingsPKCS1Encoding_1 = { "", "org.spongycastle.crypto.encodings", ptrTable, methods, NULL, 7, 0x8010, 2, 0, 0, -1, 1, -1, -1 };
  return &_OrgSpongycastleCryptoEncodingsPKCS1Encoding_1;
}

@end

void OrgSpongycastleCryptoEncodingsPKCS1Encoding_1_init(OrgSpongycastleCryptoEncodingsPKCS1Encoding_1 *self) {
  NSObject_init(self);
}

OrgSpongycastleCryptoEncodingsPKCS1Encoding_1 *new_OrgSpongycastleCryptoEncodingsPKCS1Encoding_1_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoEncodingsPKCS1Encoding_1, init)
}

OrgSpongycastleCryptoEncodingsPKCS1Encoding_1 *create_OrgSpongycastleCryptoEncodingsPKCS1Encoding_1_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoEncodingsPKCS1Encoding_1, init)
}

@implementation OrgSpongycastleCryptoEncodingsPKCS1Encoding_2

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoEncodingsPKCS1Encoding_2_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (id)run {
  return JavaLangSystem_getPropertyWithNSString_(OrgSpongycastleCryptoEncodingsPKCS1Encoding_NOT_STRICT_LENGTH_ENABLED_PROPERTY);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(run);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoEncodingsPKCS1Encoding;", "useStrict" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoEncodingsPKCS1Encoding_2 = { "", "org.spongycastle.crypto.encodings", ptrTable, methods, NULL, 7, 0x8010, 2, 0, 0, -1, 1, -1, -1 };
  return &_OrgSpongycastleCryptoEncodingsPKCS1Encoding_2;
}

@end

void OrgSpongycastleCryptoEncodingsPKCS1Encoding_2_init(OrgSpongycastleCryptoEncodingsPKCS1Encoding_2 *self) {
  NSObject_init(self);
}

OrgSpongycastleCryptoEncodingsPKCS1Encoding_2 *new_OrgSpongycastleCryptoEncodingsPKCS1Encoding_2_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoEncodingsPKCS1Encoding_2, init)
}

OrgSpongycastleCryptoEncodingsPKCS1Encoding_2 *create_OrgSpongycastleCryptoEncodingsPKCS1Encoding_2_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoEncodingsPKCS1Encoding_2, init)
}
