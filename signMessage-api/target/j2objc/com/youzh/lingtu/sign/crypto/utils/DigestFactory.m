//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/DigestFactory.java
//

#include "J2ObjC_source.h"
#include "com/youzh/lingtu/sign/crypto/utils/DigestFactory.h"
#include "java/util/HashMap.h"
#include "java/util/HashSet.h"
#include "java/util/Map.h"
#include "java/util/Set.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/nist/NISTObjectIdentifiers.h"
#include "org/spongycastle/asn1/oiw/OIWObjectIdentifiers.h"
#include "org/spongycastle/asn1/pkcs/PKCSObjectIdentifiers.h"
#include "org/spongycastle/crypto/Digest.h"
#include "org/spongycastle/crypto/digests/MD5Digest.h"
#include "org/spongycastle/crypto/digests/SHA1Digest.h"
#include "org/spongycastle/crypto/digests/SHA224Digest.h"
#include "org/spongycastle/crypto/digests/SHA256Digest.h"
#include "org/spongycastle/crypto/digests/SHA384Digest.h"
#include "org/spongycastle/crypto/digests/SHA512Digest.h"
#include "org/spongycastle/crypto/digests/SHA512tDigest.h"
#include "org/spongycastle/util/Strings.h"

inline id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_get_md5(void);
inline id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_set_md5(id<JavaUtilSet> value);
static id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_md5;
J2OBJC_STATIC_FIELD_OBJ(ComYouzhLingtuSignCryptoUtilsDigestFactory, md5, id<JavaUtilSet>)

inline id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_get_sha1(void);
inline id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_set_sha1(id<JavaUtilSet> value);
static id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_sha1;
J2OBJC_STATIC_FIELD_OBJ(ComYouzhLingtuSignCryptoUtilsDigestFactory, sha1, id<JavaUtilSet>)

inline id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_get_sha224(void);
inline id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_set_sha224(id<JavaUtilSet> value);
static id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_sha224;
J2OBJC_STATIC_FIELD_OBJ(ComYouzhLingtuSignCryptoUtilsDigestFactory, sha224, id<JavaUtilSet>)

inline id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_get_sha256(void);
inline id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_set_sha256(id<JavaUtilSet> value);
static id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_sha256;
J2OBJC_STATIC_FIELD_OBJ(ComYouzhLingtuSignCryptoUtilsDigestFactory, sha256, id<JavaUtilSet>)

inline id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_get_sha384(void);
inline id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_set_sha384(id<JavaUtilSet> value);
static id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_sha384;
J2OBJC_STATIC_FIELD_OBJ(ComYouzhLingtuSignCryptoUtilsDigestFactory, sha384, id<JavaUtilSet>)

inline id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_get_sha512(void);
inline id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_set_sha512(id<JavaUtilSet> value);
static id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512;
J2OBJC_STATIC_FIELD_OBJ(ComYouzhLingtuSignCryptoUtilsDigestFactory, sha512, id<JavaUtilSet>)

inline id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_get_sha512_224(void);
inline id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_set_sha512_224(id<JavaUtilSet> value);
static id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_224;
J2OBJC_STATIC_FIELD_OBJ(ComYouzhLingtuSignCryptoUtilsDigestFactory, sha512_224, id<JavaUtilSet>)

inline id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_get_sha512_256(void);
inline id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_set_sha512_256(id<JavaUtilSet> value);
static id<JavaUtilSet> ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_256;
J2OBJC_STATIC_FIELD_OBJ(ComYouzhLingtuSignCryptoUtilsDigestFactory, sha512_256, id<JavaUtilSet>)

inline id<JavaUtilMap> ComYouzhLingtuSignCryptoUtilsDigestFactory_get_oids(void);
inline id<JavaUtilMap> ComYouzhLingtuSignCryptoUtilsDigestFactory_set_oids(id<JavaUtilMap> value);
static id<JavaUtilMap> ComYouzhLingtuSignCryptoUtilsDigestFactory_oids;
J2OBJC_STATIC_FIELD_OBJ(ComYouzhLingtuSignCryptoUtilsDigestFactory, oids, id<JavaUtilMap>)

J2OBJC_INITIALIZED_DEFN(ComYouzhLingtuSignCryptoUtilsDigestFactory)

@implementation ComYouzhLingtuSignCryptoUtilsDigestFactory

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoUtilsDigestFactory_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (id<OrgSpongycastleCryptoDigest>)getDigestWithNSString:(NSString *)digestName {
  return ComYouzhLingtuSignCryptoUtilsDigestFactory_getDigestWithNSString_(digestName);
}

+ (jboolean)isSameDigestWithNSString:(NSString *)digest1
                        withNSString:(NSString *)digest2 {
  return ComYouzhLingtuSignCryptoUtilsDigestFactory_isSameDigestWithNSString_withNSString_(digest1, digest2);
}

+ (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getOIDWithNSString:(NSString *)digestName {
  return ComYouzhLingtuSignCryptoUtilsDigestFactory_getOIDWithNSString_(digestName);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoDigest;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", 0x9, 4, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getDigestWithNSString:);
  methods[2].selector = @selector(isSameDigestWithNSString:withNSString:);
  methods[3].selector = @selector(getOIDWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "md5", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 5, -1, -1 },
    { "sha1", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 6, -1, -1 },
    { "sha224", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 7, -1, -1 },
    { "sha256", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 8, -1, -1 },
    { "sha384", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 9, -1, -1 },
    { "sha512", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 10, -1, -1 },
    { "sha512_224", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 11, -1, -1 },
    { "sha512_256", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 12, -1, -1 },
    { "oids", "LJavaUtilMap;", .constantValue.asLong = 0, 0xa, -1, 13, -1, -1 },
  };
  static const void *ptrTable[] = { "getDigest", "LNSString;", "isSameDigest", "LNSString;LNSString;", "getOID", &ComYouzhLingtuSignCryptoUtilsDigestFactory_md5, &ComYouzhLingtuSignCryptoUtilsDigestFactory_sha1, &ComYouzhLingtuSignCryptoUtilsDigestFactory_sha224, &ComYouzhLingtuSignCryptoUtilsDigestFactory_sha256, &ComYouzhLingtuSignCryptoUtilsDigestFactory_sha384, &ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512, &ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_224, &ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_256, &ComYouzhLingtuSignCryptoUtilsDigestFactory_oids };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoUtilsDigestFactory = { "DigestFactory", "com.youzh.lingtu.sign.crypto.utils", ptrTable, methods, fields, 7, 0x1, 4, 9, -1, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoUtilsDigestFactory;
}

+ (void)initialize {
  if (self == [ComYouzhLingtuSignCryptoUtilsDigestFactory class]) {
    ComYouzhLingtuSignCryptoUtilsDigestFactory_md5 = new_JavaUtilHashSet_init();
    ComYouzhLingtuSignCryptoUtilsDigestFactory_sha1 = new_JavaUtilHashSet_init();
    ComYouzhLingtuSignCryptoUtilsDigestFactory_sha224 = new_JavaUtilHashSet_init();
    ComYouzhLingtuSignCryptoUtilsDigestFactory_sha256 = new_JavaUtilHashSet_init();
    ComYouzhLingtuSignCryptoUtilsDigestFactory_sha384 = new_JavaUtilHashSet_init();
    ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512 = new_JavaUtilHashSet_init();
    ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_224 = new_JavaUtilHashSet_init();
    ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_256 = new_JavaUtilHashSet_init();
    ComYouzhLingtuSignCryptoUtilsDigestFactory_oids = new_JavaUtilHashMap_init();
    {
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_md5)) addWithId:@"MD5"];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_md5)) addWithId:[((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, md5))) getId]];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha1)) addWithId:@"SHA1"];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha1)) addWithId:@"SHA-1"];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha1)) addWithId:[((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(OrgSpongycastleAsn1OiwOIWObjectIdentifiers, idSHA1))) getId]];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha224)) addWithId:@"SHA224"];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha224)) addWithId:@"SHA-224"];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha224)) addWithId:[((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha224))) getId]];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha256)) addWithId:@"SHA256"];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha256)) addWithId:@"SHA-256"];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha256)) addWithId:[((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha256))) getId]];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha384)) addWithId:@"SHA384"];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha384)) addWithId:@"SHA-384"];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha384)) addWithId:[((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha384))) getId]];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512)) addWithId:@"SHA512"];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512)) addWithId:@"SHA-512"];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512)) addWithId:[((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha512))) getId]];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_224)) addWithId:@"SHA512(224)"];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_224)) addWithId:@"SHA-512(224)"];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_224)) addWithId:[((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha512_224))) getId]];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_256)) addWithId:@"SHA512(256)"];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_256)) addWithId:@"SHA-512(256)"];
      [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_256)) addWithId:[((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha512_256))) getId]];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:@"MD5" withId:JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, md5)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:[JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, md5) getId] withId:JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, md5)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:@"SHA1" withId:JreLoadStatic(OrgSpongycastleAsn1OiwOIWObjectIdentifiers, idSHA1)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:@"SHA-1" withId:JreLoadStatic(OrgSpongycastleAsn1OiwOIWObjectIdentifiers, idSHA1)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:[JreLoadStatic(OrgSpongycastleAsn1OiwOIWObjectIdentifiers, idSHA1) getId] withId:JreLoadStatic(OrgSpongycastleAsn1OiwOIWObjectIdentifiers, idSHA1)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:@"SHA224" withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha224)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:@"SHA-224" withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha224)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:[JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha224) getId] withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha224)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:@"SHA256" withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha256)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:@"SHA-256" withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha256)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:[JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha256) getId] withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha256)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:@"SHA384" withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha384)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:@"SHA-384" withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha384)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:[JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha384) getId] withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha384)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:@"SHA512" withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha512)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:@"SHA-512" withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha512)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:[JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha512) getId] withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha512)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:@"SHA512(224)" withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha512_224)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:@"SHA-512(224)" withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha512_224)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:[JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha512_224) getId] withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha512_224)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:@"SHA512(256)" withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha512_256)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:@"SHA-512(256)" withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha512_256)];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) putWithId:[JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha512_256) getId] withId:JreLoadStatic(OrgSpongycastleAsn1NistNISTObjectIdentifiers, id_sha512_256)];
    }
    J2OBJC_SET_INITIALIZED(ComYouzhLingtuSignCryptoUtilsDigestFactory)
  }
}

@end

void ComYouzhLingtuSignCryptoUtilsDigestFactory_init(ComYouzhLingtuSignCryptoUtilsDigestFactory *self) {
  NSObject_init(self);
}

ComYouzhLingtuSignCryptoUtilsDigestFactory *new_ComYouzhLingtuSignCryptoUtilsDigestFactory_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsDigestFactory, init)
}

ComYouzhLingtuSignCryptoUtilsDigestFactory *create_ComYouzhLingtuSignCryptoUtilsDigestFactory_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsDigestFactory, init)
}

id<OrgSpongycastleCryptoDigest> ComYouzhLingtuSignCryptoUtilsDigestFactory_getDigestWithNSString_(NSString *digestName) {
  ComYouzhLingtuSignCryptoUtilsDigestFactory_initialize();
  digestName = OrgSpongycastleUtilStrings_toUpperCaseWithNSString_(digestName);
  if ([((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha1)) containsWithId:digestName]) {
    return new_OrgSpongycastleCryptoDigestsSHA1Digest_init();
  }
  if ([((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_md5)) containsWithId:digestName]) {
    return new_OrgSpongycastleCryptoDigestsMD5Digest_init();
  }
  if ([((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha224)) containsWithId:digestName]) {
    return new_OrgSpongycastleCryptoDigestsSHA224Digest_init();
  }
  if ([((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha256)) containsWithId:digestName]) {
    return new_OrgSpongycastleCryptoDigestsSHA256Digest_init();
  }
  if ([((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha384)) containsWithId:digestName]) {
    return new_OrgSpongycastleCryptoDigestsSHA384Digest_init();
  }
  if ([((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512)) containsWithId:digestName]) {
    return new_OrgSpongycastleCryptoDigestsSHA512Digest_init();
  }
  if ([((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_224)) containsWithId:digestName]) {
    return new_OrgSpongycastleCryptoDigestsSHA512tDigest_initWithInt_(224);
  }
  if ([((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_256)) containsWithId:digestName]) {
    return new_OrgSpongycastleCryptoDigestsSHA512tDigest_initWithInt_(256);
  }
  return nil;
}

jboolean ComYouzhLingtuSignCryptoUtilsDigestFactory_isSameDigestWithNSString_withNSString_(NSString *digest1, NSString *digest2) {
  ComYouzhLingtuSignCryptoUtilsDigestFactory_initialize();
  return ([((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha1)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha1)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha224)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha224)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha256)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha256)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha384)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha384)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_224)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_224)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_256)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_sha512_256)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_md5)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_md5)) containsWithId:digest2]);
}

OrgSpongycastleAsn1ASN1ObjectIdentifier *ComYouzhLingtuSignCryptoUtilsDigestFactory_getOIDWithNSString_(NSString *digestName) {
  ComYouzhLingtuSignCryptoUtilsDigestFactory_initialize();
  return (OrgSpongycastleAsn1ASN1ObjectIdentifier *) cast_chk([((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsDigestFactory_oids)) getWithId:digestName], [OrgSpongycastleAsn1ASN1ObjectIdentifier class]);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoUtilsDigestFactory)