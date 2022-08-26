//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/digest/MD5.java
//

#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "com/youzh/lingtu/sign/crypto/config/ConfigurableProvider.h"
#include "com/youzh/lingtu/sign/crypto/digest/BCMessageDigest.h"
#include "com/youzh/lingtu/sign/crypto/digest/DigestAlgorithmProvider.h"
#include "com/youzh/lingtu/sign/crypto/digest/MD5.h"
#include "com/youzh/lingtu/sign/crypto/utils/BaseKeyGenerator.h"
#include "com/youzh/lingtu/sign/crypto/utils/BaseMac.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/iana/IANAObjectIdentifiers.h"
#include "org/spongycastle/asn1/pkcs/PKCSObjectIdentifiers.h"
#include "org/spongycastle/crypto/CipherKeyGenerator.h"
#include "org/spongycastle/crypto/Digest.h"
#include "org/spongycastle/crypto/digests/MD5Digest.h"
#include "org/spongycastle/crypto/macs/HMac.h"

@interface ComYouzhLingtuSignCryptoDigestMD5 ()

- (instancetype)init;

@end

__attribute__((unused)) static void ComYouzhLingtuSignCryptoDigestMD5_init(ComYouzhLingtuSignCryptoDigestMD5 *self);

__attribute__((unused)) static ComYouzhLingtuSignCryptoDigestMD5 *new_ComYouzhLingtuSignCryptoDigestMD5_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static ComYouzhLingtuSignCryptoDigestMD5 *create_ComYouzhLingtuSignCryptoDigestMD5_init(void);

inline NSString *ComYouzhLingtuSignCryptoDigestMD5_Mappings_get_PREFIX(void);
static NSString *ComYouzhLingtuSignCryptoDigestMD5_Mappings_PREFIX;
J2OBJC_STATIC_FIELD_OBJ_FINAL(ComYouzhLingtuSignCryptoDigestMD5_Mappings, PREFIX, NSString *)

@implementation ComYouzhLingtuSignCryptoDigestMD5

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestMD5_init(self);
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
  static const void *ptrTable[] = { "LComYouzhLingtuSignCryptoDigestMD5_HashMac;LComYouzhLingtuSignCryptoDigestMD5_KeyGenerator;LComYouzhLingtuSignCryptoDigestMD5_Digest;LComYouzhLingtuSignCryptoDigestMD5_Mappings;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestMD5 = { "MD5", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, 0, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestMD5;
}

@end

void ComYouzhLingtuSignCryptoDigestMD5_init(ComYouzhLingtuSignCryptoDigestMD5 *self) {
  NSObject_init(self);
}

ComYouzhLingtuSignCryptoDigestMD5 *new_ComYouzhLingtuSignCryptoDigestMD5_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestMD5, init)
}

ComYouzhLingtuSignCryptoDigestMD5 *create_ComYouzhLingtuSignCryptoDigestMD5_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestMD5, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestMD5)

@implementation ComYouzhLingtuSignCryptoDigestMD5_HashMac

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestMD5_HashMac_init(self);
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
  static const void *ptrTable[] = { "LComYouzhLingtuSignCryptoDigestMD5;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestMD5_HashMac = { "HashMac", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestMD5_HashMac;
}

@end

void ComYouzhLingtuSignCryptoDigestMD5_HashMac_init(ComYouzhLingtuSignCryptoDigestMD5_HashMac *self) {
  ComYouzhLingtuSignCryptoUtilsBaseMac_initWithOrgSpongycastleCryptoMac_(self, new_OrgSpongycastleCryptoMacsHMac_initWithOrgSpongycastleCryptoDigest_(new_OrgSpongycastleCryptoDigestsMD5Digest_init()));
}

ComYouzhLingtuSignCryptoDigestMD5_HashMac *new_ComYouzhLingtuSignCryptoDigestMD5_HashMac_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestMD5_HashMac, init)
}

ComYouzhLingtuSignCryptoDigestMD5_HashMac *create_ComYouzhLingtuSignCryptoDigestMD5_HashMac_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestMD5_HashMac, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestMD5_HashMac)

@implementation ComYouzhLingtuSignCryptoDigestMD5_KeyGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestMD5_KeyGenerator_init(self);
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
  static const void *ptrTable[] = { "LComYouzhLingtuSignCryptoDigestMD5;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestMD5_KeyGenerator = { "KeyGenerator", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestMD5_KeyGenerator;
}

@end

void ComYouzhLingtuSignCryptoDigestMD5_KeyGenerator_init(ComYouzhLingtuSignCryptoDigestMD5_KeyGenerator *self) {
  ComYouzhLingtuSignCryptoUtilsBaseKeyGenerator_initWithNSString_withInt_withOrgSpongycastleCryptoCipherKeyGenerator_(self, @"HMACMD5", 128, new_OrgSpongycastleCryptoCipherKeyGenerator_init());
}

ComYouzhLingtuSignCryptoDigestMD5_KeyGenerator *new_ComYouzhLingtuSignCryptoDigestMD5_KeyGenerator_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestMD5_KeyGenerator, init)
}

ComYouzhLingtuSignCryptoDigestMD5_KeyGenerator *create_ComYouzhLingtuSignCryptoDigestMD5_KeyGenerator_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestMD5_KeyGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestMD5_KeyGenerator)

@implementation ComYouzhLingtuSignCryptoDigestMD5_Digest

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestMD5_Digest_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (id)java_clone {
  ComYouzhLingtuSignCryptoDigestMD5_Digest *d = (ComYouzhLingtuSignCryptoDigestMD5_Digest *) cast_chk([super java_clone], [ComYouzhLingtuSignCryptoDigestMD5_Digest class]);
  ((ComYouzhLingtuSignCryptoDigestMD5_Digest *) nil_chk(d))->digest_ = new_OrgSpongycastleCryptoDigestsMD5Digest_initWithOrgSpongycastleCryptoDigestsMD5Digest_((OrgSpongycastleCryptoDigestsMD5Digest *) cast_chk(digest_, [OrgSpongycastleCryptoDigestsMD5Digest class]));
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
  static const void *ptrTable[] = { "clone", "LJavaLangCloneNotSupportedException;", "LComYouzhLingtuSignCryptoDigestMD5;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestMD5_Digest = { "Digest", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, NULL, 7, 0x9, 2, 0, 2, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestMD5_Digest;
}

- (id)copyWithZone:(NSZone *)zone {
  return [self java_clone];
}

@end

void ComYouzhLingtuSignCryptoDigestMD5_Digest_init(ComYouzhLingtuSignCryptoDigestMD5_Digest *self) {
  ComYouzhLingtuSignCryptoDigestBCMessageDigest_initWithOrgSpongycastleCryptoDigest_(self, new_OrgSpongycastleCryptoDigestsMD5Digest_init());
}

ComYouzhLingtuSignCryptoDigestMD5_Digest *new_ComYouzhLingtuSignCryptoDigestMD5_Digest_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestMD5_Digest, init)
}

ComYouzhLingtuSignCryptoDigestMD5_Digest *create_ComYouzhLingtuSignCryptoDigestMD5_Digest_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestMD5_Digest, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestMD5_Digest)

J2OBJC_INITIALIZED_DEFN(ComYouzhLingtuSignCryptoDigestMD5_Mappings)

@implementation ComYouzhLingtuSignCryptoDigestMD5_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoDigestMD5_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithComYouzhLingtuSignCryptoConfigConfigurableProvider:(id<ComYouzhLingtuSignCryptoConfigConfigurableProvider>)provider {
  [((id<ComYouzhLingtuSignCryptoConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"MessageDigest.MD5" withNSString:JreStrcat("$$", ComYouzhLingtuSignCryptoDigestMD5_Mappings_PREFIX, @"$Digest")];
  [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.MessageDigest.", JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, md5)) withNSString:@"MD5"];
  [self addHMACAlgorithmWithComYouzhLingtuSignCryptoConfigConfigurableProvider:provider withNSString:@"MD5" withNSString:JreStrcat("$$", ComYouzhLingtuSignCryptoDigestMD5_Mappings_PREFIX, @"$HashMac") withNSString:JreStrcat("$$", ComYouzhLingtuSignCryptoDigestMD5_Mappings_PREFIX, @"$KeyGenerator")];
  [self addHMACAliasWithComYouzhLingtuSignCryptoConfigConfigurableProvider:provider withNSString:@"MD5" withOrgSpongycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(OrgSpongycastleAsn1IanaIANAObjectIdentifiers, hmacMD5)];
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
  static const void *ptrTable[] = { "configure", "LComYouzhLingtuSignCryptoConfigConfigurableProvider;", &ComYouzhLingtuSignCryptoDigestMD5_Mappings_PREFIX, "LComYouzhLingtuSignCryptoDigestMD5;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoDigestMD5_Mappings = { "Mappings", "com.youzh.lingtu.sign.crypto.digest", ptrTable, methods, fields, 7, 0x9, 2, 1, 3, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoDigestMD5_Mappings;
}

+ (void)initialize {
  if (self == [ComYouzhLingtuSignCryptoDigestMD5_Mappings class]) {
    ComYouzhLingtuSignCryptoDigestMD5_Mappings_PREFIX = [ComYouzhLingtuSignCryptoDigestMD5_class_() getName];
    J2OBJC_SET_INITIALIZED(ComYouzhLingtuSignCryptoDigestMD5_Mappings)
  }
}

@end

void ComYouzhLingtuSignCryptoDigestMD5_Mappings_init(ComYouzhLingtuSignCryptoDigestMD5_Mappings *self) {
  ComYouzhLingtuSignCryptoDigestDigestAlgorithmProvider_init(self);
}

ComYouzhLingtuSignCryptoDigestMD5_Mappings *new_ComYouzhLingtuSignCryptoDigestMD5_Mappings_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoDigestMD5_Mappings, init)
}

ComYouzhLingtuSignCryptoDigestMD5_Mappings *create_ComYouzhLingtuSignCryptoDigestMD5_Mappings_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoDigestMD5_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoDigestMD5_Mappings)
