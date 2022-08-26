//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/digest/GOST3411.java
//

#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "com/youzh/lingtu/sign/crypto/config/ConfigurableProvider.h"
#include "com/youzh/lingtu/sign/crypto/digest/BCMessageDigest.h"
#include "com/youzh/lingtu/sign/crypto/digest/DigestAlgorithmProvider.h"
#include "com/youzh/lingtu/sign/crypto/digest/GOST3411.h"
#include "com/youzh/lingtu/sign/crypto/utils/BaseKeyGenerator.h"
#include "com/youzh/lingtu/sign/crypto/utils/BaseMac.h"
#include "com/youzh/lingtu/sign/crypto/utils/PBE.h"
#include "com/youzh/lingtu/sign/crypto/utils/PBESecretKeyFactory.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/cryptopro/CryptoProObjectIdentifiers.h"
#include "org/spongycastle/crypto/CipherKeyGenerator.h"
#include "org/spongycastle/crypto/Digest.h"
#include "org/spongycastle/crypto/digests/GOST3411Digest.h"
#include "org/spongycastle/crypto/macs/HMac.h"

@interface ComYouzhLingtuSignCryptoDigestGOST3411 ()

- (instancetype)init;

@end

__attribute__((unused)) static void ComYouzhLingtuSignCryptoDigestGOST3411_init(ComYouzhLingtuSignCryptoDigestGOST3411 *self);

__attribute__((unused)) static ComYouzhLingtuSignCryptoDigestGOST3411 *new_ComYouzhLingtuSignCryptoDigestGOST3411_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static ComYouzhLingtuSignCryptoDigestGOST3411 *create_ComYouzhLingtuSignCryptoDigestGOST3411_init(void);

inline NSString *ComYouzhLingtuSignCryptoDigestGOST3411_Mappings_get_PREFIX(void);
static NSString *ComYouzhLingtuSignCryptoDigestGOST3411_Mappings_PREFIX;
J2OBJC_STATIC_FIELD_OBJ_FINAL(ComYouzhLingtuSignCryptoDigestGOST3411_Mappings, PREFIX, NSString *)

@implementation ComYouzhLingtuSignCryptoDigestGOST3411

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestGOST3411_init(self);
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
  static const void *ptrTable[] = { "LComYouzhLingtuSignCryptoDigestGOST3411_Digest;LComYouzhLingtuSignCryptoDigestGOST3411_HashMac;LComYouzhLingtuSignCryptoDigestGOST3411_PBEWithMacKeyFactory;LComYouzhLingtuSignCryptoDigestGOST3411_KeyGenerator;LComYouzhLingtuSignCryptoDigestGOST3411_Mappings;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestGOST3411 = { "GOST3411", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, 0, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestGOST3411;
}

@end

void ComYouzhLingtuSignCryptoDigestGOST3411_init(ComYouzhLingtuSignCryptoDigestGOST3411 *self) {
  NSObject_init(self);
}

ComYouzhLingtuSignCryptoDigestGOST3411 *new_ComYouzhLingtuSignCryptoDigestGOST3411_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestGOST3411, init)
}

ComYouzhLingtuSignCryptoDigestGOST3411 *create_ComYouzhLingtuSignCryptoDigestGOST3411_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestGOST3411, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestGOST3411)

@implementation ComYouzhLingtuSignCryptoDigestGOST3411_Digest

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestGOST3411_Digest_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (id)java_clone {
  ComYouzhLingtuSignCryptoDigestGOST3411_Digest *d = (ComYouzhLingtuSignCryptoDigestGOST3411_Digest *) cast_chk([super java_clone], [ComYouzhLingtuSignCryptoDigestGOST3411_Digest class]);
  ((ComYouzhLingtuSignCryptoDigestGOST3411_Digest *) nil_chk(d))->digest_ = new_OrgSpongycastleCryptoDigestsGOST3411Digest_initWithOrgSpongycastleCryptoDigestsGOST3411Digest_((OrgSpongycastleCryptoDigestsGOST3411Digest *) cast_chk(digest_, [OrgSpongycastleCryptoDigestsGOST3411Digest class]));
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
  static const void *ptrTable[] = { "clone", "LJavaLangCloneNotSupportedException;", "LComYouzhLingtuSignCryptoDigestGOST3411;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestGOST3411_Digest = { "Digest", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x9, 2, 0, 2, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestGOST3411_Digest;
}

- (id)copyWithZone:(NSZone *)zone {
  return [self java_clone];
}

@end

void ComYouzhLingtuSignCryptoDigestGOST3411_Digest_init(ComYouzhLingtuSignCryptoDigestGOST3411_Digest *self) {
  ComYouzhLingtuSignCryptoDigestBCMessageDigest_initWithOrgSpongycastleCryptoDigest_(self, new_OrgSpongycastleCryptoDigestsGOST3411Digest_init());
}

ComYouzhLingtuSignCryptoDigestGOST3411_Digest *new_ComYouzhLingtuSignCryptoDigestGOST3411_Digest_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestGOST3411_Digest, init)
}

ComYouzhLingtuSignCryptoDigestGOST3411_Digest *create_ComYouzhLingtuSignCryptoDigestGOST3411_Digest_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestGOST3411_Digest, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestGOST3411_Digest)

@implementation ComYouzhLingtuSignCryptoDigestGOST3411_HashMac

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestGOST3411_HashMac_init(self);
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
  static const void *ptrTable[] = { "LComYouzhLingtuSignCryptoDigestGOST3411;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestGOST3411_HashMac = { "HashMac", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestGOST3411_HashMac;
}

@end

void ComYouzhLingtuSignCryptoDigestGOST3411_HashMac_init(ComYouzhLingtuSignCryptoDigestGOST3411_HashMac *self) {
  ComYouzhLingtuSignCryptoUtilsBaseMac_initWithOrgSpongycastleCryptoMac_(self, new_OrgSpongycastleCryptoMacsHMac_initWithOrgSpongycastleCryptoDigest_(new_OrgSpongycastleCryptoDigestsGOST3411Digest_init()));
}

ComYouzhLingtuSignCryptoDigestGOST3411_HashMac *new_ComYouzhLingtuSignCryptoDigestGOST3411_HashMac_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestGOST3411_HashMac, init)
}

ComYouzhLingtuSignCryptoDigestGOST3411_HashMac *create_ComYouzhLingtuSignCryptoDigestGOST3411_HashMac_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestGOST3411_HashMac, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestGOST3411_HashMac)

@implementation ComYouzhLingtuSignCryptoDigestGOST3411_PBEWithMacKeyFactory

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestGOST3411_PBEWithMacKeyFactory_init(self);
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
  static const void *ptrTable[] = { "LComYouzhLingtuSignCryptoDigestGOST3411;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestGOST3411_PBEWithMacKeyFactory = { "PBEWithMacKeyFactory", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestGOST3411_PBEWithMacKeyFactory;
}

@end

void ComYouzhLingtuSignCryptoDigestGOST3411_PBEWithMacKeyFactory_init(ComYouzhLingtuSignCryptoDigestGOST3411_PBEWithMacKeyFactory *self) {
  ComYouzhLingtuSignCryptoUtilsPBESecretKeyFactory_initWithNSString_withOrgSpongycastleAsn1ASN1ObjectIdentifier_withBoolean_withInt_withInt_withInt_withInt_(self, @"PBEwithHmacGOST3411", nil, false, ComYouzhLingtuSignCryptoUtilsPBE_PKCS12, ComYouzhLingtuSignCryptoUtilsPBE_GOST3411, 256, 0);
}

ComYouzhLingtuSignCryptoDigestGOST3411_PBEWithMacKeyFactory *new_ComYouzhLingtuSignCryptoDigestGOST3411_PBEWithMacKeyFactory_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestGOST3411_PBEWithMacKeyFactory, init)
}

ComYouzhLingtuSignCryptoDigestGOST3411_PBEWithMacKeyFactory *create_ComYouzhLingtuSignCryptoDigestGOST3411_PBEWithMacKeyFactory_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestGOST3411_PBEWithMacKeyFactory, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestGOST3411_PBEWithMacKeyFactory)

@implementation ComYouzhLingtuSignCryptoDigestGOST3411_KeyGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestGOST3411_KeyGenerator_init(self);
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
  static const void *ptrTable[] = { "LComYouzhLingtuSignCryptoDigestGOST3411;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestGOST3411_KeyGenerator = { "KeyGenerator", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestGOST3411_KeyGenerator;
}

@end

void ComYouzhLingtuSignCryptoDigestGOST3411_KeyGenerator_init(ComYouzhLingtuSignCryptoDigestGOST3411_KeyGenerator *self) {
  ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator_initWithNSString_withInt_withOrgSpongycastleCryptoCipherKeyGenerator_(self, @"HMACGOST3411", 256, new_OrgSpongycastleCryptoCipherKeyGenerator_init());
}

ComYouzhLingtuSignCryptoDigestGOST3411_KeyGenerator *new_ComYouzhLingtuSignCryptoDigestGOST3411_KeyGenerator_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestGOST3411_KeyGenerator, init)
}

ComYouzhLingtuSignCryptoDigestGOST3411_KeyGenerator *create_ComYouzhLingtuSignCryptoDigestGOST3411_KeyGenerator_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestGOST3411_KeyGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestGOST3411_KeyGenerator)

J2OBJC_INITIALIZED_DEFN(ComYouzhLingtuSignCryptoDigestGOST3411_Mappings)

@implementation ComYouzhLingtuSignCryptoDigestGOST3411_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestGOST3411_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithComYouzhLingtuSignCryptoConfigConfigurableProvider:(id<ComYouzhLingtuSignCryptoConfigConfigurableProvider>)provider {
  [((id<ComYouzhLingtuSignCryptoConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"MessageDigest.GOST3411" withNSString:JreStrcat("$$", ComYouzhLingtuSignCryptoDigestGOST3411_Mappings_PREFIX, @"$Digest")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.MessageDigest.GOST" withNSString:@"GOST3411"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.MessageDigest.GOST-3411" withNSString:@"GOST3411"];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.MessageDigest.", JreLoadStatic(OrgSpongycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3411)) withNSString:@"GOST3411"];
  [provider addAlgorithmWithNSString:@"SecretKeyFactory.PBEWITHHMACGOST3411" withNSString:JreStrcat("$$", ComYouzhLingtuSignCryptoDigestGOST3411_Mappings_PREFIX, @"$PBEWithMacKeyFactory")];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.SecretKeyFactory.", JreLoadStatic(OrgSpongycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3411)) withNSString:@"PBEWITHHMACGOST3411"];
  [self addHMACAlgorithmWithComYouzhLingtuSignCryptoConfigConfigurableProvider:provider withNSString:@"GOST3411" withNSString:JreStrcat("$$", ComYouzhLingtuSignCryptoDigestGOST3411_Mappings_PREFIX, @"$HashMac") withNSString:JreStrcat("$$", ComYouzhLingtuSignCryptoDigestGOST3411_Mappings_PREFIX, @"$KeyGenerator")];
  [self addHMACAliasWithComYouzhLingtuSignCryptoConfigConfigurableProvider:provider withNSString:@"GOST3411" withOrgSpongycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(OrgSpongycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3411)];
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
  static const void *ptrTable[] = { "configure", "LComYouzhLingtuSignCryptoConfigConfigurableProvider;", &ComYouzhLingtuSignCryptoDigestGOST3411_Mappings_PREFIX, "LComYouzhLingtuSignCryptoDigestGOST3411;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestGOST3411_Mappings = { "Mappings", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, fields, 7, 0x9, 2, 1, 3, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestGOST3411_Mappings;
}

+ (void)initialize {
  if (self == [ComYouzhLingtuSignCryptoDigestGOST3411_Mappings class]) {
    ComYouzhLingtuSignCryptoDigestGOST3411_Mappings_PREFIX = [ComYouzhLingtuSignCryptoDigestGOST3411_class_() getName];
    J2OBJC_SET_INITIALIZED(ComYouzhLingtuSignCryptoDigestGOST3411_Mappings)
  }
}

@end

void ComYouzhLingtuSignCryptoDigestGOST3411_Mappings_init(ComYouzhLingtuSignCryptoDigestGOST3411_Mappings *self) {
  ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider_init(self);
}

ComYouzhLingtuSignCryptoDigestGOST3411_Mappings *new_ComYouzhLingtuSignCryptoDigestGOST3411_Mappings_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestGOST3411_Mappings, init)
}

ComYouzhLingtuSignCryptoDigestGOST3411_Mappings *create_ComYouzhLingtuSignCryptoDigestGOST3411_Mappings_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestGOST3411_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestGOST3411_Mappings)