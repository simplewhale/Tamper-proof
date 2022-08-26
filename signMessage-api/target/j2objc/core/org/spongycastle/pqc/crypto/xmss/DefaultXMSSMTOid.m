//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/xmss/DefaultXMSSMTOid.java
//

#include "J2ObjC_source.h"
#include "java/lang/NullPointerException.h"
#include "java/util/Collections.h"
#include "java/util/HashMap.h"
#include "java/util/Map.h"
#include "org/spongycastle/pqc/crypto/xmss/DefaultXMSSMTOid.h"

@interface OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid () {
 @public
  jint oid_;
  NSString *stringRepresentation_;
}

- (instancetype)initWithInt:(jint)oid
               withNSString:(NSString *)stringRepresentation;

+ (NSString *)createKeyWithNSString:(NSString *)algorithmName
                            withInt:(jint)digestSize
                            withInt:(jint)winternitzParameter
                            withInt:(jint)len
                            withInt:(jint)height
                            withInt:(jint)layers;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid, stringRepresentation_, NSString *)

inline id<JavaUtilMap> OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_get_oidLookupTable(void);
static id<JavaUtilMap> OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_oidLookupTable;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid, oidLookupTable, id<JavaUtilMap>)

__attribute__((unused)) static void OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_(OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid *self, jint oid, NSString *stringRepresentation);

__attribute__((unused)) static OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid *new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_(jint oid, NSString *stringRepresentation) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid *create_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_(jint oid, NSString *stringRepresentation);

__attribute__((unused)) static NSString *OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(NSString *algorithmName, jint digestSize, jint winternitzParameter, jint len, jint height, jint layers);

J2OBJC_INITIALIZED_DEFN(OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid)

@implementation OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid

- (instancetype)initWithInt:(jint)oid
               withNSString:(NSString *)stringRepresentation {
  OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_(self, oid, stringRepresentation);
  return self;
}

+ (OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid *)lookupWithNSString:(NSString *)algorithmName
                                                             withInt:(jint)digestSize
                                                             withInt:(jint)winternitzParameter
                                                             withInt:(jint)len
                                                             withInt:(jint)height
                                                             withInt:(jint)layers {
  return OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_lookupWithNSString_withInt_withInt_withInt_withInt_withInt_(algorithmName, digestSize, winternitzParameter, len, height, layers);
}

+ (NSString *)createKeyWithNSString:(NSString *)algorithmName
                            withInt:(jint)digestSize
                            withInt:(jint)winternitzParameter
                            withInt:(jint)len
                            withInt:(jint)height
                            withInt:(jint)layers {
  return OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(algorithmName, digestSize, winternitzParameter, len, height, layers);
}

- (jint)getOid {
  return oid_;
}

- (NSString *)description {
  return stringRepresentation_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0xa, 3, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 4, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withNSString:);
  methods[1].selector = @selector(lookupWithNSString:withInt:withInt:withInt:withInt:withInt:);
  methods[2].selector = @selector(createKeyWithNSString:withInt:withInt:withInt:withInt:withInt:);
  methods[3].selector = @selector(getOid);
  methods[4].selector = @selector(description);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "oidLookupTable", "LJavaUtilMap;", .constantValue.asLong = 0, 0x1a, -1, 5, 6, -1 },
    { "oid_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "stringRepresentation_", "LNSString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ILNSString;", "lookup", "LNSString;IIIII", "createKey", "toString", &OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_oidLookupTable, "Ljava/util/Map<Ljava/lang/String;Lorg/spongycastle/pqc/crypto/xmss/DefaultXMSSMTOid;>;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid = { "DefaultXMSSMTOid", "org.spongycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x11, 5, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid;
}

+ (void)initialize {
  if (self == [OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid class]) {
    {
      id<JavaUtilMap> map = new_JavaUtilHashMap_init();
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHA-256", 32, 16, 67, 20, 2) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHA2-256_W16_H20_D2")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHA-256", 32, 16, 67, 20, 4) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHA2-256_W16_H20_D4")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHA-256", 32, 16, 67, 40, 2) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHA2-256_W16_H40_D2")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHA-256", 32, 16, 67, 40, 2) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHA2-256_W16_H40_D4")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHA-256", 32, 16, 67, 40, 4) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHA2-256_W16_H40_D8")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHA-256", 32, 16, 67, 60, 8) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHA2-256_W16_H60_D3")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHA-256", 32, 16, 67, 60, 6) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHA2-256_W16_H60_D6")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHA-256", 32, 16, 67, 60, 12) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHA2-256_W16_H60_D12")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHA2-512", 64, 16, 131, 20, 2) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHA2-512_W16_H20_D2")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHA2-512", 64, 16, 131, 20, 4) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHA2-512_W16_H20_D4")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHA2-512", 64, 16, 131, 40, 2) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHA2-512_W16_H40_D2")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHA2-512", 64, 16, 131, 40, 4) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHA2-512_W16_H40_D4")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHA2-512", 64, 16, 131, 40, 8) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHA2-512_W16_H40_D8")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHA2-512", 64, 16, 131, 60, 3) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHA2-512_W16_H60_D3")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHA2-512", 64, 16, 131, 60, 6) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHA2-512_W16_H60_D6")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHA2-512", 64, 16, 131, 60, 12) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHA2-512_W16_H60_D12")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHAKE128", 32, 16, 67, 20, 2) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHAKE128_W16_H20_D2")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHAKE128", 32, 16, 67, 20, 4) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHAKE128_W16_H20_D4")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHAKE128", 32, 16, 67, 40, 2) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHAKE128_W16_H40_D2")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHAKE128", 32, 16, 67, 40, 4) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHAKE128_W16_H40_D4")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHAKE128", 32, 16, 67, 40, 8) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHAKE128_W16_H40_D8")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHAKE128", 32, 16, 67, 60, 3) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHAKE128_W16_H60_D3")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHAKE128", 32, 16, 67, 60, 6) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHAKE128_W16_H60_D6")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHAKE128", 32, 16, 67, 60, 12) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHAKE128_W16_H60_D12")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHAKE256", 64, 16, 131, 20, 2) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHAKE256_W16_H20_D2")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHAKE256", 64, 16, 131, 20, 4) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHAKE256_W16_H20_D4")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHAKE256", 64, 16, 131, 40, 2) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHAKE256_W16_H40_D2")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHAKE256", 64, 16, 131, 40, 4) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHAKE256_W16_H40_D4")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHAKE256", 64, 16, 131, 40, 8) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHAKE256_W16_H40_D8")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHAKE256", 64, 16, 131, 60, 3) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHAKE256_W16_H60_D3")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHAKE256", 64, 16, 131, 60, 6) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHAKE256_W16_H60_D6")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(@"SHAKE256", 64, 16, 131, 60, 12) withId:new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_((jint) 0x01000001, @"XMSSMT_SHAKE256_W16_H60_D12")];
      OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_oidLookupTable = JavaUtilCollections_unmodifiableMapWithJavaUtilMap_(map);
    }
    J2OBJC_SET_INITIALIZED(OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid)
  }
}

@end

void OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_(OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid *self, jint oid, NSString *stringRepresentation) {
  NSObject_init(self);
  self->oid_ = oid;
  self->stringRepresentation_ = stringRepresentation;
}

OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid *new_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_(jint oid, NSString *stringRepresentation) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid, initWithInt_withNSString_, oid, stringRepresentation)
}

OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid *create_OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initWithInt_withNSString_(jint oid, NSString *stringRepresentation) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid, initWithInt_withNSString_, oid, stringRepresentation)
}

OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid *OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_lookupWithNSString_withInt_withInt_withInt_withInt_withInt_(NSString *algorithmName, jint digestSize, jint winternitzParameter, jint len, jint height, jint layers) {
  OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initialize();
  if (algorithmName == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"algorithmName == null");
  }
  return [((id<JavaUtilMap>) nil_chk(OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_oidLookupTable)) getWithId:OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(algorithmName, digestSize, winternitzParameter, len, height, layers)];
}

NSString *OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_createKeyWithNSString_withInt_withInt_withInt_withInt_withInt_(NSString *algorithmName, jint digestSize, jint winternitzParameter, jint len, jint height, jint layers) {
  OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid_initialize();
  if (algorithmName == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"algorithmName == null");
  }
  return JreStrcat("$CICICICICI", algorithmName, '-', digestSize, '-', winternitzParameter, '-', len, '-', height, '-', layers);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoXmssDefaultXMSSMTOid)