//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/digest/SHA1.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "com/youzh/lingtu/sign/crypto/config/ConfigurableProvider.h"
#include "com/youzh/lingtu/sign/crypto/digest/BCMessageDigest.h"
#include "com/youzh/lingtu/sign/crypto/digest/DigestAlgorithmProvider.h"
#include "com/youzh/lingtu/sign/crypto/digest/SHA1.h"
#include "com/youzh/lingtu/sign/crypto/utils/BCPBEKey.h"
#include "com/youzh/lingtu/sign/crypto/utils/BaseKeyGenerator.h"
#include "com/youzh/lingtu/sign/crypto/utils/BaseMac.h"
#include "com/youzh/lingtu/sign/crypto/utils/BaseSecretKeyFactory.h"
#include "com/youzh/lingtu/sign/crypto/utils/PBE.h"
#include "com/youzh/lingtu/sign/crypto/utils/PBESecretKeyFactory.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/security/spec/InvalidKeySpecException.h"
#include "java/security/spec/KeySpec.h"
#include "javax/crypto/SecretKey.h"
#include "javax/crypto/spec/PBEKeySpec.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/iana/IANAObjectIdentifiers.h"
#include "org/spongycastle/asn1/oiw/OIWObjectIdentifiers.h"
#include "org/spongycastle/asn1/pkcs/PKCSObjectIdentifiers.h"
#include "org/spongycastle/crypto/CipherKeyGenerator.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/Digest.h"
#include "org/spongycastle/crypto/digests/SHA1Digest.h"
#include "org/spongycastle/crypto/macs/HMac.h"

@interface ComYouzhLingtuSignCryptoDigestSHA1 ()

- (instancetype)init;

@end

__attribute__((unused)) static void ComYouzhLingtuSignCryptoDigestSHA1_init(ComYouzhLingtuSignCryptoDigestSHA1 *self);

__attribute__((unused)) static ComYouzhLingtuSignCryptoDigestSHA1 *new_ComYouzhLingtuSignCryptoDigestSHA1_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static ComYouzhLingtuSignCryptoDigestSHA1 *create_ComYouzhLingtuSignCryptoDigestSHA1_init(void);

@interface ComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1 () {
 @public
  jint scheme_;
}

@end

inline NSString *ComYouzhLingtuSignCryptoDigestSHA1_Mappings_get_PREFIX(void);
static NSString *ComYouzhLingtuSignCryptoDigestSHA1_Mappings_PREFIX;
J2OBJC_STATIC_FIELD_OBJ_FINAL(ComYouzhLingtuSignCryptoDigestSHA1_Mappings, PREFIX, NSString *)

@implementation ComYouzhLingtuSignCryptoDigestSHA1

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestSHA1_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LComYouzhLingtuSignCryptoDigestSHA1_Digest;LComYouzhLingtuSignCryptoDigestSHA1_HashMac;LComYouzhLingtuSignCryptoDigestSHA1_KeyGenerator;LComYouzhLingtuSignCryptoDigestSHA1_SHA1Mac;LComYouzhLingtuSignCryptoDigestSHA1_PBEWithMacKeyFactory;LComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1;LComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA1UTF8;LComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA18BIT;LComYouzhLingtuSignCryptoDigestSHA1_Mappings;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestSHA1 = { "SHA1", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, 0, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestSHA1;
}

@end

void ComYouzhLingtuSignCryptoDigestSHA1_init(ComYouzhLingtuSignCryptoDigestSHA1 *self) {
  NSObject_init(self);
}

ComYouzhLingtuSignCryptoDigestSHA1 *new_ComYouzhLingtuSignCryptoDigestSHA1_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestSHA1, init)
}

ComYouzhLingtuSignCryptoDigestSHA1 *create_ComYouzhLingtuSignCryptoDigestSHA1_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestSHA1, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestSHA1)

@implementation ComYouzhLingtuSignCryptoDigestSHA1_Digest

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestSHA1_Digest_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (id)java_clone {
  ComYouzhLingtuSignCryptoDigestSHA1_Digest *d = (ComYouzhLingtuSignCryptoDigestSHA1_Digest *) cast_chk([super java_clone], [ComYouzhLingtuSignCryptoDigestSHA1_Digest class]);
  ((ComYouzhLingtuSignCryptoDigestSHA1_Digest *) nil_chk(d))->digest_ = new_OrgSpongycastleCryptoDigestsSHA1Digest_initWithOrgSpongycastleCryptoDigestsSHA1Digest_((OrgSpongycastleCryptoDigestsSHA1Digest *) cast_chk(digest_, [OrgSpongycastleCryptoDigestsSHA1Digest class]));
  return d;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, 0, -1, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(java_clone);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "clone", "LJavaLangCloneNotSupportedException;", "LComYouzhLingtuSignCryptoDigestSHA1;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestSHA1_Digest = { "Digest", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x9, 2, 0, 2, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestSHA1_Digest;
}

- (id)copyWithZone:(NSZone *)zone {
  return [self java_clone];
}

@end

void ComYouzhLingtuSignCryptoDigestSHA1_Digest_init(ComYouzhLingtuSignCryptoDigestSHA1_Digest *self) {
  ComYouzhLingtuSignCryptoDigestBCMessageDigest_initWithOrgSpongycastleCryptoDigest_(self, new_OrgSpongycastleCryptoDigestsSHA1Digest_init());
}

ComYouzhLingtuSignCryptoDigestSHA1_Digest *new_ComYouzhLingtuSignCryptoDigestSHA1_Digest_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_Digest, init)
}

ComYouzhLingtuSignCryptoDigestSHA1_Digest *create_ComYouzhLingtuSignCryptoDigestSHA1_Digest_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_Digest, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestSHA1_Digest)

@implementation ComYouzhLingtuSignCryptoDigestSHA1_HashMac

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestSHA1_HashMac_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LComYouzhLingtuSignCryptoDigestSHA1;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestSHA1_HashMac = { "HashMac", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestSHA1_HashMac;
}

@end

void ComYouzhLingtuSignCryptoDigestSHA1_HashMac_init(ComYouzhLingtuSignCryptoDigestSHA1_HashMac *self) {
  ComYouzhLingtuSignCryptoUtilsBaseMac_initWithOrgSpongycastleCryptoMac_(self, new_OrgSpongycastleCryptoMacsHMac_initWithOrgSpongycastleCryptoDigest_(new_OrgSpongycastleCryptoDigestsSHA1Digest_init()));
}

ComYouzhLingtuSignCryptoDigestSHA1_HashMac *new_ComYouzhLingtuSignCryptoDigestSHA1_HashMac_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_HashMac, init)
}

ComYouzhLingtuSignCryptoDigestSHA1_HashMac *create_ComYouzhLingtuSignCryptoDigestSHA1_HashMac_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_HashMac, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestSHA1_HashMac)

@implementation ComYouzhLingtuSignCryptoDigestSHA1_KeyGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestSHA1_KeyGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LComYouzhLingtuSignCryptoDigestSHA1;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestSHA1_KeyGenerator = { "KeyGenerator", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestSHA1_KeyGenerator;
}

@end

void ComYouzhLingtuSignCryptoDigestSHA1_KeyGenerator_init(ComYouzhLingtuSignCryptoDigestSHA1_KeyGenerator *self) {
  ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator_initWithNSString_withInt_withOrgSpongycastleCryptoCipherKeyGenerator_(self, @"HMACSHA1", 160, new_OrgSpongycastleCryptoCipherKeyGenerator_init());
}

ComYouzhLingtuSignCryptoDigestSHA1_KeyGenerator *new_ComYouzhLingtuSignCryptoDigestSHA1_KeyGenerator_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_KeyGenerator, init)
}

ComYouzhLingtuSignCryptoDigestSHA1_KeyGenerator *create_ComYouzhLingtuSignCryptoDigestSHA1_KeyGenerator_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_KeyGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestSHA1_KeyGenerator)

@implementation ComYouzhLingtuSignCryptoDigestSHA1_SHA1Mac

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestSHA1_SHA1Mac_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LComYouzhLingtuSignCryptoDigestSHA1;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestSHA1_SHA1Mac = { "SHA1Mac", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestSHA1_SHA1Mac;
}

@end

void ComYouzhLingtuSignCryptoDigestSHA1_SHA1Mac_init(ComYouzhLingtuSignCryptoDigestSHA1_SHA1Mac *self) {
  ComYouzhLingtuSignCryptoUtilsBaseMac_initWithOrgSpongycastleCryptoMac_(self, new_OrgSpongycastleCryptoMacsHMac_initWithOrgSpongycastleCryptoDigest_(new_OrgSpongycastleCryptoDigestsSHA1Digest_init()));
}

ComYouzhLingtuSignCryptoDigestSHA1_SHA1Mac *new_ComYouzhLingtuSignCryptoDigestSHA1_SHA1Mac_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_SHA1Mac, init)
}

ComYouzhLingtuSignCryptoDigestSHA1_SHA1Mac *create_ComYouzhLingtuSignCryptoDigestSHA1_SHA1Mac_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_SHA1Mac, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestSHA1_SHA1Mac)

@implementation ComYouzhLingtuSignCryptoDigestSHA1_PBEWithMacKeyFactory

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestSHA1_PBEWithMacKeyFactory_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LComYouzhLingtuSignCryptoDigestSHA1;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestSHA1_PBEWithMacKeyFactory = { "PBEWithMacKeyFactory", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestSHA1_PBEWithMacKeyFactory;
}

@end

void ComYouzhLingtuSignCryptoDigestSHA1_PBEWithMacKeyFactory_init(ComYouzhLingtuSignCryptoDigestSHA1_PBEWithMacKeyFactory *self) {
  ComYouzhLingtuSignCryptoUtilsPBESecretKeyFactory_initWithNSString_withOrgSpongycastleAsn1ASN1ObjectIdentifier_withBoolean_withInt_withInt_withInt_withInt_(self, @"PBEwithHmacSHA", nil, false, ComYouzhLingtuSignCryptoUtilsPBE_PKCS12, ComYouzhLingtuSignCryptoUtilsPBE_SHA1, 160, 0);
}

ComYouzhLingtuSignCryptoDigestSHA1_PBEWithMacKeyFactory *new_ComYouzhLingtuSignCryptoDigestSHA1_PBEWithMacKeyFactory_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_PBEWithMacKeyFactory, init)
}

ComYouzhLingtuSignCryptoDigestSHA1_PBEWithMacKeyFactory *create_ComYouzhLingtuSignCryptoDigestSHA1_PBEWithMacKeyFactory_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_PBEWithMacKeyFactory, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestSHA1_PBEWithMacKeyFactory)

@implementation ComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1

- (instancetype)initWithNSString:(NSString *)name
                         withInt:(jint)scheme {
  ComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1_initWithNSString_withInt_(self, name, scheme);
  return self;
}

- (id<JavaxCryptoSecretKey>)engineGenerateSecretWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec {
  if ([keySpec isKindOfClass:[JavaxCryptoSpecPBEKeySpec class]]) {
    JavaxCryptoSpecPBEKeySpec *pbeSpec = (JavaxCryptoSpecPBEKeySpec *) keySpec;
    if ([((JavaxCryptoSpecPBEKeySpec *) nil_chk(pbeSpec)) getSalt] == nil) {
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(@"missing required salt");
    }
    if ([pbeSpec getIterationCount] <= 0) {
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$I", @"positive iteration count required: ", [pbeSpec getIterationCount]));
    }
    if ([pbeSpec getKeyLength] <= 0) {
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$I", @"positive key length required: ", [pbeSpec getKeyLength]));
    }
    if (((IOSCharArray *) nil_chk([pbeSpec getPassword]))->size_ == 0) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"password empty");
    }
    jint digest = ComYouzhLingtuSignCryptoUtilsPBE_SHA1;
    jint keySize = [pbeSpec getKeyLength];
    jint ivSize = -1;
    id<OrgSpongycastleCryptoCipherParameters> param = ComYouzhLingtuSignCryptoUtilsPBE_Util_makePBEMacParametersWithJavaxCryptoSpecPBEKeySpec_withInt_withInt_withInt_(pbeSpec, scheme_, digest, keySize);
    return new_ComYouzhLingtuSignCryptoUtilsBCPBEKey_initWithNSString_withOrgSpongycastleAsn1ASN1ObjectIdentifier_withInt_withInt_withInt_withInt_withJavaxCryptoSpecPBEKeySpec_withOrgSpongycastleCryptoCipherParameters_(self->algName_, self->algOid_, scheme_, digest, keySize, ivSize, pbeSpec, param);
  }
  @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(@"Invalid KeySpec");
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaxCryptoSecretKey;", 0x4, 1, 2, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:withInt:);
  methods[1].selector = @selector(engineGenerateSecretWithJavaSecuritySpecKeySpec:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "scheme_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;I", "engineGenerateSecret", "LJavaSecuritySpecKeySpec;", "LJavaSecuritySpecInvalidKeySpecException;", "LComYouzhLingtuSignCryptoDigestSHA1;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1 = { "BasePBKDF2WithHmacSHA1", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, fields, 7, 0x9, 2, 1, 4, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1;
}

@end

void ComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1_initWithNSString_withInt_(ComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1 *self, NSString *name, jint scheme) {
  ComYouzhLingtuSignCryptoUtilsBaseSecretKeyFactory_initWithNSString_withOrgSpongycastleAsn1ASN1ObjectIdentifier_(self, name, JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, id_PBKDF2));
  self->scheme_ = scheme;
}

ComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1 *new_ComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1_initWithNSString_withInt_(NSString *name, jint scheme) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1, initWithNSString_withInt_, name, scheme)
}

ComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1 *create_ComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1_initWithNSString_withInt_(NSString *name, jint scheme) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1, initWithNSString_withInt_, name, scheme)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1)

@implementation ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA1UTF8

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA1UTF8_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LComYouzhLingtuSignCryptoDigestSHA1;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA1UTF8 = { "PBKDF2WithHmacSHA1UTF8", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA1UTF8;
}

@end

void ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA1UTF8_init(ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA1UTF8 *self) {
  ComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1_initWithNSString_withInt_(self, @"PBKDF2WithHmacSHA1", ComYouzhLingtuSignCryptoUtilsPBE_PKCS5S2_UTF8);
}

ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA1UTF8 *new_ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA1UTF8_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA1UTF8, init)
}

ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA1UTF8 *create_ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA1UTF8_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA1UTF8, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA1UTF8)

@implementation ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA18BIT

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA18BIT_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LComYouzhLingtuSignCryptoDigestSHA1;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA18BIT = { "PBKDF2WithHmacSHA18BIT", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA18BIT;
}

@end

void ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA18BIT_init(ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA18BIT *self) {
  ComYouzhLingtuSignCryptoDigestSHA1_BasePBKDF2WithHmacSHA1_initWithNSString_withInt_(self, @"PBKDF2WithHmacSHA1And8bit", ComYouzhLingtuSignCryptoUtilsPBE_PKCS5S2);
}

ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA18BIT *new_ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA18BIT_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA18BIT, init)
}

ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA18BIT *create_ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA18BIT_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA18BIT, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestSHA1_PBKDF2WithHmacSHA18BIT)

J2OBJC_INITIALIZED_DEFN(ComYouzhLingtuSignCryptoDigestSHA1_Mappings)

@implementation ComYouzhLingtuSignCryptoDigestSHA1_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestSHA1_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithComYouzhLingtuSignCryptoConfigConfigurableProvider:(id<ComYouzhLingtuSignCryptoConfigConfigurableProvider>)provider {
  [((id<ComYouzhLingtuSignCryptoConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"MessageDigest.SHA-1" withNSString:JreStrcat("$$", ComYouzhLingtuSignCryptoDigestSHA1_Mappings_PREFIX, @"$Digest")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.MessageDigest.SHA1" withNSString:@"SHA-1"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.MessageDigest.SHA" withNSString:@"SHA-1"];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.MessageDigest.", JreLoadStatic(OrgSpongycastleAsn1OiwOIWObjectIdentifiers, idSHA1)) withNSString:@"SHA-1"];
  [self addHMACAlgorithmWithComYouzhLingtuSignCryptoConfigConfigurableProvider:provider withNSString:@"SHA1" withNSString:JreStrcat("$$", ComYouzhLingtuSignCryptoDigestSHA1_Mappings_PREFIX, @"$HashMac") withNSString:JreStrcat("$$", ComYouzhLingtuSignCryptoDigestSHA1_Mappings_PREFIX, @"$KeyGenerator")];
  [self addHMACAliasWithComYouzhLingtuSignCryptoConfigConfigurableProvider:provider withNSString:@"SHA1" withOrgSpongycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, id_hmacWithSHA1)];
  [self addHMACAliasWithComYouzhLingtuSignCryptoConfigConfigurableProvider:provider withNSString:@"SHA1" withOrgSpongycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(OrgSpongycastleAsn1IanaIANAObjectIdentifiers, hmacSHA1)];
  [provider addAlgorithmWithNSString:@"Mac.PBEWITHHMACSHA" withNSString:JreStrcat("$$", ComYouzhLingtuSignCryptoDigestSHA1_Mappings_PREFIX, @"$SHA1Mac")];
  [provider addAlgorithmWithNSString:@"Mac.PBEWITHHMACSHA1" withNSString:JreStrcat("$$", ComYouzhLingtuSignCryptoDigestSHA1_Mappings_PREFIX, @"$SHA1Mac")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.SecretKeyFactory.PBEWITHHMACSHA" withNSString:@"PBEWITHHMACSHA1"];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.SecretKeyFactory.", JreLoadStatic(OrgSpongycastleAsn1OiwOIWObjectIdentifiers, idSHA1)) withNSString:@"PBEWITHHMACSHA1"];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.Mac.", JreLoadStatic(OrgSpongycastleAsn1OiwOIWObjectIdentifiers, idSHA1)) withNSString:@"PBEWITHHMACSHA"];
  [provider addAlgorithmWithNSString:@"SecretKeyFactory.PBEWITHHMACSHA1" withNSString:JreStrcat("$$", ComYouzhLingtuSignCryptoDigestSHA1_Mappings_PREFIX, @"$PBEWithMacKeyFactory")];
  [provider addAlgorithmWithNSString:@"SecretKeyFactory.PBKDF2WithHmacSHA1" withNSString:JreStrcat("$$", ComYouzhLingtuSignCryptoDigestSHA1_Mappings_PREFIX, @"$PBKDF2WithHmacSHA1UTF8")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.SecretKeyFactory.PBKDF2WithHmacSHA1AndUTF8" withNSString:@"PBKDF2WithHmacSHA1"];
  [provider addAlgorithmWithNSString:@"SecretKeyFactory.PBKDF2WithHmacSHA1And8BIT" withNSString:JreStrcat("$$", ComYouzhLingtuSignCryptoDigestSHA1_Mappings_PREFIX, @"$PBKDF2WithHmacSHA18BIT")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.SecretKeyFactory.PBKDF2withASCII" withNSString:@"PBKDF2WithHmacSHA1And8BIT"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.SecretKeyFactory.PBKDF2with8BIT" withNSString:@"PBKDF2WithHmacSHA1And8BIT"];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(configureWithComYouzhLingtuSignCryptoConfigConfigurableProvider:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "PREFIX", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 2, -1, -1 },
  };
  static const void *ptrTable[] = { "configure", "LComYouzhLingtuSignCryptoConfigConfigurableProvider;", &ComYouzhLingtuSignCryptoDigestSHA1_Mappings_PREFIX, "LComYouzhLingtuSignCryptoDigestSHA1;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestSHA1_Mappings = { "Mappings", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, fields, 7, 0x9, 2, 1, 3, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestSHA1_Mappings;
}

+ (void)initialize {
  if (self == [ComYouzhLingtuSignCryptoDigestSHA1_Mappings class]) {
    ComYouzhLingtuSignCryptoDigestSHA1_Mappings_PREFIX = [ComYouzhLingtuSignCryptoDigestSHA1_class_() getName];
    J2OBJC_SET_INITIALIZED(ComYouzhLingtuSignCryptoDigestSHA1_Mappings)
  }
}

@end

void ComYouzhLingtuSignCryptoDigestSHA1_Mappings_init(ComYouzhLingtuSignCryptoDigestSHA1_Mappings *self) {
  ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider_init(self);
}

ComYouzhLingtuSignCryptoDigestSHA1_Mappings *new_ComYouzhLingtuSignCryptoDigestSHA1_Mappings_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_Mappings, init)
}

ComYouzhLingtuSignCryptoDigestSHA1_Mappings *create_ComYouzhLingtuSignCryptoDigestSHA1_Mappings_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestSHA1_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestSHA1_Mappings)
