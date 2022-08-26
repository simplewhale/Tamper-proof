//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/xmss/WOTSPlusOid.java
//

#include "J2ObjC_source.h"
#include "java/lang/NullPointerException.h"
#include "java/util/Collections.h"
#include "java/util/HashMap.h"
#include "java/util/Map.h"
#include "org/spongycastle/pqc/crypto/xmss/WOTSPlusOid.h"

@interface OrgSpongycastlePqcCryptoXmssWOTSPlusOid () {
 @public
  jint oid_;
  NSString *stringRepresentation_;
}

- (instancetype)initWithInt:(jint)oid
               withNSString:(NSString *)stringRepresentation;

+ (NSString *)createKeyWithNSString:(NSString *)algorithmName
                            withInt:(jint)digestSize
                            withInt:(jint)winternitzParameter
                            withInt:(jint)len;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssWOTSPlusOid, stringRepresentation_, NSString *)

inline id<JavaUtilMap> OrgSpongycastlePqcCryptoXmssWOTSPlusOid_get_oidLookupTable(void);
static id<JavaUtilMap> OrgSpongycastlePqcCryptoXmssWOTSPlusOid_oidLookupTable;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastlePqcCryptoXmssWOTSPlusOid, oidLookupTable, id<JavaUtilMap>)

__attribute__((unused)) static void OrgSpongycastlePqcCryptoXmssWOTSPlusOid_initWithInt_withNSString_(OrgSpongycastlePqcCryptoXmssWOTSPlusOid *self, jint oid, NSString *stringRepresentation);

__attribute__((unused)) static OrgSpongycastlePqcCryptoXmssWOTSPlusOid *new_OrgSpongycastlePqcCryptoXmssWOTSPlusOid_initWithInt_withNSString_(jint oid, NSString *stringRepresentation) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastlePqcCryptoXmssWOTSPlusOid *create_OrgSpongycastlePqcCryptoXmssWOTSPlusOid_initWithInt_withNSString_(jint oid, NSString *stringRepresentation);

__attribute__((unused)) static NSString *OrgSpongycastlePqcCryptoXmssWOTSPlusOid_createKeyWithNSString_withInt_withInt_withInt_(NSString *algorithmName, jint digestSize, jint winternitzParameter, jint len);

J2OBJC_INITIALIZED_DEFN(OrgSpongycastlePqcCryptoXmssWOTSPlusOid)

@implementation OrgSpongycastlePqcCryptoXmssWOTSPlusOid

- (instancetype)initWithInt:(jint)oid
               withNSString:(NSString *)stringRepresentation {
  OrgSpongycastlePqcCryptoXmssWOTSPlusOid_initWithInt_withNSString_(self, oid, stringRepresentation);
  return self;
}

+ (OrgSpongycastlePqcCryptoXmssWOTSPlusOid *)lookupWithNSString:(NSString *)algorithmName
                                                        withInt:(jint)digestSize
                                                        withInt:(jint)winternitzParameter
                                                        withInt:(jint)len {
  return OrgSpongycastlePqcCryptoXmssWOTSPlusOid_lookupWithNSString_withInt_withInt_withInt_(algorithmName, digestSize, winternitzParameter, len);
}

+ (NSString *)createKeyWithNSString:(NSString *)algorithmName
                            withInt:(jint)digestSize
                            withInt:(jint)winternitzParameter
                            withInt:(jint)len {
  return OrgSpongycastlePqcCryptoXmssWOTSPlusOid_createKeyWithNSString_withInt_withInt_withInt_(algorithmName, digestSize, winternitzParameter, len);
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
    { NULL, "LOrgSpongycastlePqcCryptoXmssWOTSPlusOid;", 0xc, 1, 2, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0xa, 3, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 4, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withNSString:);
  methods[1].selector = @selector(lookupWithNSString:withInt:withInt:withInt:);
  methods[2].selector = @selector(createKeyWithNSString:withInt:withInt:withInt:);
  methods[3].selector = @selector(getOid);
  methods[4].selector = @selector(description);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "oidLookupTable", "LJavaUtilMap;", .constantValue.asLong = 0, 0x1a, -1, 5, 6, -1 },
    { "oid_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "stringRepresentation_", "LNSString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ILNSString;", "lookup", "LNSString;III", "createKey", "toString", &OrgSpongycastlePqcCryptoXmssWOTSPlusOid_oidLookupTable, "Ljava/util/Map<Ljava/lang/String;Lorg/spongycastle/pqc/crypto/xmss/WOTSPlusOid;>;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoXmssWOTSPlusOid = { "WOTSPlusOid", "org.spongycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x10, 5, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoXmssWOTSPlusOid;
}

+ (void)initialize {
  if (self == [OrgSpongycastlePqcCryptoXmssWOTSPlusOid class]) {
    {
      id<JavaUtilMap> map = new_JavaUtilHashMap_init();
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssWOTSPlusOid_createKeyWithNSString_withInt_withInt_withInt_(@"SHA-256", 32, 16, 67) withId:new_OrgSpongycastlePqcCryptoXmssWOTSPlusOid_initWithInt_withNSString_((jint) 0x01000001, @"WOTSP_SHA2-256_W16")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssWOTSPlusOid_createKeyWithNSString_withInt_withInt_withInt_(@"SHA-512", 64, 16, 131) withId:new_OrgSpongycastlePqcCryptoXmssWOTSPlusOid_initWithInt_withNSString_((jint) 0x02000002, @"WOTSP_SHA2-512_W16")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssWOTSPlusOid_createKeyWithNSString_withInt_withInt_withInt_(@"SHAKE128", 32, 16, 67) withId:new_OrgSpongycastlePqcCryptoXmssWOTSPlusOid_initWithInt_withNSString_((jint) 0x03000003, @"WOTSP_SHAKE128_W16")];
      (void) [map putWithId:OrgSpongycastlePqcCryptoXmssWOTSPlusOid_createKeyWithNSString_withInt_withInt_withInt_(@"SHAKE256", 64, 16, 131) withId:new_OrgSpongycastlePqcCryptoXmssWOTSPlusOid_initWithInt_withNSString_((jint) 0x04000004, @"WOTSP_SHAKE256_W16")];
      OrgSpongycastlePqcCryptoXmssWOTSPlusOid_oidLookupTable = JavaUtilCollections_unmodifiableMapWithJavaUtilMap_(map);
    }
    J2OBJC_SET_INITIALIZED(OrgSpongycastlePqcCryptoXmssWOTSPlusOid)
  }
}

@end

void OrgSpongycastlePqcCryptoXmssWOTSPlusOid_initWithInt_withNSString_(OrgSpongycastlePqcCryptoXmssWOTSPlusOid *self, jint oid, NSString *stringRepresentation) {
  NSObject_init(self);
  self->oid_ = oid;
  self->stringRepresentation_ = stringRepresentation;
}

OrgSpongycastlePqcCryptoXmssWOTSPlusOid *new_OrgSpongycastlePqcCryptoXmssWOTSPlusOid_initWithInt_withNSString_(jint oid, NSString *stringRepresentation) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoXmssWOTSPlusOid, initWithInt_withNSString_, oid, stringRepresentation)
}

OrgSpongycastlePqcCryptoXmssWOTSPlusOid *create_OrgSpongycastlePqcCryptoXmssWOTSPlusOid_initWithInt_withNSString_(jint oid, NSString *stringRepresentation) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoXmssWOTSPlusOid, initWithInt_withNSString_, oid, stringRepresentation)
}

OrgSpongycastlePqcCryptoXmssWOTSPlusOid *OrgSpongycastlePqcCryptoXmssWOTSPlusOid_lookupWithNSString_withInt_withInt_withInt_(NSString *algorithmName, jint digestSize, jint winternitzParameter, jint len) {
  OrgSpongycastlePqcCryptoXmssWOTSPlusOid_initialize();
  if (algorithmName == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"algorithmName == null");
  }
  return [((id<JavaUtilMap>) nil_chk(OrgSpongycastlePqcCryptoXmssWOTSPlusOid_oidLookupTable)) getWithId:OrgSpongycastlePqcCryptoXmssWOTSPlusOid_createKeyWithNSString_withInt_withInt_withInt_(algorithmName, digestSize, winternitzParameter, len)];
}

NSString *OrgSpongycastlePqcCryptoXmssWOTSPlusOid_createKeyWithNSString_withInt_withInt_withInt_(NSString *algorithmName, jint digestSize, jint winternitzParameter, jint len) {
  OrgSpongycastlePqcCryptoXmssWOTSPlusOid_initialize();
  if (algorithmName == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"algorithmName == null");
  }
  return JreStrcat("$CICICI", algorithmName, '-', digestSize, '-', winternitzParameter, '-', len);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoXmssWOTSPlusOid)