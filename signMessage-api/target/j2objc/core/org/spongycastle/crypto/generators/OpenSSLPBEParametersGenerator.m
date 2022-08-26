//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/generators/OpenSSLPBEParametersGenerator.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/System.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/Digest.h"
#include "org/spongycastle/crypto/PBEParametersGenerator.h"
#include "org/spongycastle/crypto/generators/OpenSSLPBEParametersGenerator.h"
#include "org/spongycastle/crypto/params/KeyParameter.h"
#include "org/spongycastle/crypto/params/ParametersWithIV.h"
#include "org/spongycastle/crypto/util/DigestFactory.h"

@interface OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator () {
 @public
  id<OrgSpongycastleCryptoDigest> digest_;
}

- (IOSByteArray *)generateDerivedKeyWithInt:(jint)bytesNeeded;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator, digest_, id<OrgSpongycastleCryptoDigest>)

__attribute__((unused)) static IOSByteArray *OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator_generateDerivedKeyWithInt_(OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator *self, jint bytesNeeded);

@implementation OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithByteArray:(IOSByteArray *)password
              withByteArray:(IOSByteArray *)salt {
  [super init__WithByteArray:password withByteArray:salt withInt:1];
}

- (IOSByteArray *)generateDerivedKeyWithInt:(jint)bytesNeeded {
  return OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator_generateDerivedKeyWithInt_(self, bytesNeeded);
}

- (id<OrgSpongycastleCryptoCipherParameters>)generateDerivedParametersWithInt:(jint)keySize {
  keySize = keySize / 8;
  IOSByteArray *dKey = OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator_generateDerivedKeyWithInt_(self, keySize);
  return new_OrgSpongycastleCryptoParamsKeyParameter_initWithByteArray_withInt_withInt_(dKey, 0, keySize);
}

- (id<OrgSpongycastleCryptoCipherParameters>)generateDerivedParametersWithInt:(jint)keySize
                                                                      withInt:(jint)ivSize {
  keySize = keySize / 8;
  ivSize = ivSize / 8;
  IOSByteArray *dKey = OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator_generateDerivedKeyWithInt_(self, keySize + ivSize);
  return new_OrgSpongycastleCryptoParamsParametersWithIV_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_withInt_withInt_(new_OrgSpongycastleCryptoParamsKeyParameter_initWithByteArray_withInt_withInt_(dKey, 0, keySize), dKey, keySize, ivSize);
}

- (id<OrgSpongycastleCryptoCipherParameters>)generateDerivedMacParametersWithInt:(jint)keySize {
  return [self generateDerivedParametersWithInt:keySize];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoCipherParameters;", 0x1, 4, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoCipherParameters;", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoCipherParameters;", 0x1, 6, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithByteArray:withByteArray:);
  methods[2].selector = @selector(generateDerivedKeyWithInt:);
  methods[3].selector = @selector(generateDerivedParametersWithInt:);
  methods[4].selector = @selector(generateDerivedParametersWithInt:withInt:);
  methods[5].selector = @selector(generateDerivedMacParametersWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "digest_", "LOrgSpongycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "[B[B", "generateDerivedKey", "I", "generateDerivedParameters", "II", "generateDerivedMacParameters" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator = { "OpenSSLPBEParametersGenerator", "org.spongycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 6, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator;
}

@end

void OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator_init(OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator *self) {
  OrgSpongycastleCryptoPBEParametersGenerator_init(self);
  self->digest_ = OrgSpongycastleCryptoUtilDigestFactory_createMD5();
}

OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator *new_OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator, init)
}

OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator *create_OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator, init)
}

IOSByteArray *OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator_generateDerivedKeyWithInt_(OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator *self, jint bytesNeeded) {
  IOSByteArray *buf = [IOSByteArray newArrayWithLength:[((id<OrgSpongycastleCryptoDigest>) nil_chk(self->digest_)) getDigestSize]];
  IOSByteArray *key = [IOSByteArray newArrayWithLength:bytesNeeded];
  jint offset = 0;
  for (; ; ) {
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(self->digest_)) updateWithByteArray:self->password_ withInt:0 withInt:((IOSByteArray *) nil_chk(self->password_))->size_];
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(self->digest_)) updateWithByteArray:self->salt_ withInt:0 withInt:((IOSByteArray *) nil_chk(self->salt_))->size_];
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(self->digest_)) doFinalWithByteArray:buf withInt:0];
    jint len = (bytesNeeded > buf->size_) ? buf->size_ : bytesNeeded;
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(buf, 0, key, offset, len);
    offset += len;
    bytesNeeded -= len;
    if (bytesNeeded == 0) {
      break;
    }
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(self->digest_)) reset];
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(self->digest_)) updateWithByteArray:buf withInt:0 withInt:buf->size_];
  }
  return key;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoGeneratorsOpenSSLPBEParametersGenerator)