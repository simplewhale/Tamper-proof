//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/GOST28147ParameterSpec.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "com/youzh/lingtu/sign/crypto/utils/GOST28147ParameterSpec.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "java/util/HashMap.h"
#include "java/util/Map.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/cryptopro/CryptoProObjectIdentifiers.h"
#include "org/spongycastle/crypto/engines/GOST28147Engine.h"
#include "org/spongycastle/util/Arrays.h"

@interface ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec () {
 @public
  IOSByteArray *iv_;
  IOSByteArray *sBox_;
}

+ (NSString *)getNameWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)sBoxOid;

@end

J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec, iv_, IOSByteArray *)
J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec, sBox_, IOSByteArray *)

inline id<JavaUtilMap> ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_get_oidMappings(void);
inline id<JavaUtilMap> ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_set_oidMappings(id<JavaUtilMap> value);
static id<JavaUtilMap> ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_oidMappings;
J2OBJC_STATIC_FIELD_OBJ(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec, oidMappings, id<JavaUtilMap>)

__attribute__((unused)) static NSString *ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_getNameWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(OrgSpongycastleAsn1ASN1ObjectIdentifier *sBoxOid);

J2OBJC_INITIALIZED_DEFN(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec)

@implementation ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec

- (instancetype)initWithByteArray:(IOSByteArray *)sBox {
  ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithByteArray_(self, sBox);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)sBox
                    withByteArray:(IOSByteArray *)iv {
  ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithByteArray_withByteArray_(self, sBox, iv);
  return self;
}

- (instancetype)initWithNSString:(NSString *)sBoxName {
  ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithNSString_(self, sBoxName);
  return self;
}

- (instancetype)initWithNSString:(NSString *)sBoxName
                   withByteArray:(IOSByteArray *)iv {
  ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithNSString_withByteArray_(self, sBoxName, iv);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)sBoxName
                                                  withByteArray:(IOSByteArray *)iv {
  ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withByteArray_(self, sBoxName, iv);
  return self;
}

- (IOSByteArray *)getSbox {
  return OrgSpongycastleUtilArrays_cloneWithByteArray_(sBox_);
}

- (IOSByteArray *)getIV {
  return OrgSpongycastleUtilArrays_cloneWithByteArray_(iv_);
}

+ (NSString *)getNameWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)sBoxOid {
  return ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_getNameWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(sBoxOid);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0xa, 5, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:);
  methods[1].selector = @selector(initWithByteArray:withByteArray:);
  methods[2].selector = @selector(initWithNSString:);
  methods[3].selector = @selector(initWithNSString:withByteArray:);
  methods[4].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withByteArray:);
  methods[5].selector = @selector(getSbox);
  methods[6].selector = @selector(getIV);
  methods[7].selector = @selector(getNameWithOrgSpongycastleAsn1ASN1ObjectIdentifier:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "iv_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sBox_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "oidMappings", "LJavaUtilMap;", .constantValue.asLong = 0, 0xa, -1, 7, -1, -1 },
  };
  static const void *ptrTable[] = { "[B", "[B[B", "LNSString;", "LNSString;[B", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;[B", "getName", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", &ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_oidMappings };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec = { "GOST28147ParameterSpec", "com.youzh.lingtu.sign.crypto.utils", ptrTable, methods, fields, 7, 0x1, 8, 3, -1, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec;
}

+ (void)initialize {
  if (self == [ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec class]) {
    ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_oidMappings = new_JavaUtilHashMap_init();
    {
      (void) [ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_oidMappings putWithId:JreLoadStatic(OrgSpongycastleAsn1CryptoproCryptoProObjectIdentifiers, id_Gost28147_89_CryptoPro_A_ParamSet) withId:@"E-A"];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_oidMappings)) putWithId:JreLoadStatic(OrgSpongycastleAsn1CryptoproCryptoProObjectIdentifiers, id_Gost28147_89_CryptoPro_B_ParamSet) withId:@"E-B"];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_oidMappings)) putWithId:JreLoadStatic(OrgSpongycastleAsn1CryptoproCryptoProObjectIdentifiers, id_Gost28147_89_CryptoPro_C_ParamSet) withId:@"E-C"];
      (void) [((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_oidMappings)) putWithId:JreLoadStatic(OrgSpongycastleAsn1CryptoproCryptoProObjectIdentifiers, id_Gost28147_89_CryptoPro_D_ParamSet) withId:@"E-D"];
    }
    J2OBJC_SET_INITIALIZED(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec)
  }
}

@end

void ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithByteArray_(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *self, IOSByteArray *sBox) {
  NSObject_init(self);
  self->iv_ = nil;
  self->sBox_ = nil;
  self->sBox_ = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(sBox))->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(sBox, 0, self->sBox_, 0, sBox->size_);
}

ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *new_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithByteArray_(IOSByteArray *sBox) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec, initWithByteArray_, sBox)
}

ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *create_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithByteArray_(IOSByteArray *sBox) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec, initWithByteArray_, sBox)
}

void ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithByteArray_withByteArray_(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *self, IOSByteArray *sBox, IOSByteArray *iv) {
  ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithByteArray_(self, sBox);
  self->iv_ = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(iv))->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(iv, 0, self->iv_, 0, iv->size_);
}

ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *new_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithByteArray_withByteArray_(IOSByteArray *sBox, IOSByteArray *iv) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec, initWithByteArray_withByteArray_, sBox, iv)
}

ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *create_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithByteArray_withByteArray_(IOSByteArray *sBox, IOSByteArray *iv) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec, initWithByteArray_withByteArray_, sBox, iv)
}

void ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithNSString_(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *self, NSString *sBoxName) {
  NSObject_init(self);
  self->iv_ = nil;
  self->sBox_ = nil;
  self->sBox_ = OrgSpongycastleCryptoEnginesGOST28147Engine_getSBoxWithNSString_(sBoxName);
}

ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *new_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithNSString_(NSString *sBoxName) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec, initWithNSString_, sBoxName)
}

ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *create_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithNSString_(NSString *sBoxName) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec, initWithNSString_, sBoxName)
}

void ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithNSString_withByteArray_(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *self, NSString *sBoxName, IOSByteArray *iv) {
  ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithNSString_(self, sBoxName);
  self->iv_ = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(iv))->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(iv, 0, self->iv_, 0, iv->size_);
}

ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *new_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithNSString_withByteArray_(NSString *sBoxName, IOSByteArray *iv) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec, initWithNSString_withByteArray_, sBoxName, iv)
}

ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *create_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithNSString_withByteArray_(NSString *sBoxName, IOSByteArray *iv) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec, initWithNSString_withByteArray_, sBoxName, iv)
}

void ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withByteArray_(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *sBoxName, IOSByteArray *iv) {
  ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithNSString_(self, ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_getNameWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(sBoxName));
  self->iv_ = OrgSpongycastleUtilArrays_cloneWithByteArray_(iv);
}

ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *new_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withByteArray_(OrgSpongycastleAsn1ASN1ObjectIdentifier *sBoxName, IOSByteArray *iv) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withByteArray_, sBoxName, iv)
}

ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *create_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withByteArray_(OrgSpongycastleAsn1ASN1ObjectIdentifier *sBoxName, IOSByteArray *iv) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withByteArray_, sBoxName, iv)
}

NSString *ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_getNameWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(OrgSpongycastleAsn1ASN1ObjectIdentifier *sBoxOid) {
  ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initialize();
  NSString *sBoxName = (NSString *) cast_chk([((id<JavaUtilMap>) nil_chk(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_oidMappings)) getWithId:sBoxOid], [NSString class]);
  if (sBoxName == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$@", @"unknown OID: ", sBoxOid));
  }
  return sBoxName;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec)
