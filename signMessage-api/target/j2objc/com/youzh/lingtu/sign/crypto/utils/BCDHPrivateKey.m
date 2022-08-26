//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/BCDHPrivateKey.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "com/youzh/lingtu/sign/crypto/utils/BCDHPrivateKey.h"
#include "com/youzh/lingtu/sign/crypto/utils/PKCS12BagAttributeCarrierImpl.h"
#include "java/io/ObjectInputStream.h"
#include "java/io/ObjectOutputStream.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "java/util/Enumeration.h"
#include "javax/crypto/interfaces/DHPrivateKey.h"
#include "javax/crypto/spec/DHParameterSpec.h"
#include "javax/crypto/spec/DHPrivateKeySpec.h"
#include "javax/security/auth/Destroyable.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1Encoding.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/pkcs/DHParameter.h"
#include "org/spongycastle/asn1/pkcs/PKCSObjectIdentifiers.h"
#include "org/spongycastle/asn1/pkcs/PrivateKeyInfo.h"
#include "org/spongycastle/asn1/x509/AlgorithmIdentifier.h"
#include "org/spongycastle/asn1/x9/DomainParameters.h"
#include "org/spongycastle/asn1/x9/X9ObjectIdentifiers.h"
#include "org/spongycastle/crypto/params/DHParameters.h"
#include "org/spongycastle/crypto/params/DHPrivateKeyParameters.h"

@interface ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey () {
 @public
  JavaMathBigInteger *x_;
  JavaxCryptoSpecDHParameterSpec *dhSpec_;
  OrgSpongycastleAsn1PkcsPrivateKeyInfo *info_;
  ComYouzhLingtuSignCryptoUtilsPKCS12BagAttributeCarrierImpl *attrCarrier_;
}

- (void)readObjectWithJavaIoObjectInputStream:(JavaIoObjectInputStream *)inArg;

- (void)writeObjectWithJavaIoObjectOutputStream:(JavaIoObjectOutputStream *)outArg;

@end

J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey, x_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey, dhSpec_, JavaxCryptoSpecDHParameterSpec *)
J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey, info_, OrgSpongycastleAsn1PkcsPrivateKeyInfo *)
J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey, attrCarrier_, ComYouzhLingtuSignCryptoUtilsPKCS12BagAttributeCarrierImpl *)

__attribute__((unused)) static void ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_readObjectWithJavaIoObjectInputStream_(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *self, JavaIoObjectInputStream *inArg);

__attribute__((unused)) static void ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_writeObjectWithJavaIoObjectOutputStream_(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *self, JavaIoObjectOutputStream *outArg);

@implementation ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithJavaxCryptoInterfacesDHPrivateKey:(id<JavaxCryptoInterfacesDHPrivateKey>)key {
  ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_initWithJavaxCryptoInterfacesDHPrivateKey_(self, key);
  return self;
}

- (instancetype)initWithJavaxCryptoSpecDHPrivateKeySpec:(JavaxCryptoSpecDHPrivateKeySpec *)spec {
  ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_initWithJavaxCryptoSpecDHPrivateKeySpec_(self, spec);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo:(OrgSpongycastleAsn1PkcsPrivateKeyInfo *)info {
  ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_(self, info);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoParamsDHPrivateKeyParameters:(OrgSpongycastleCryptoParamsDHPrivateKeyParameters *)params {
  ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_initWithOrgSpongycastleCryptoParamsDHPrivateKeyParameters_(self, params);
  return self;
}

- (NSString *)getAlgorithm {
  return @"DH";
}

- (NSString *)getFormat {
  return @"PKCS#8";
}

- (IOSByteArray *)getEncoded {
  @try {
    if (info_ != nil) {
      return [info_ getEncodedWithNSString:OrgSpongycastleAsn1ASN1Encoding_DER];
    }
    OrgSpongycastleAsn1PkcsPrivateKeyInfo *info = new_OrgSpongycastleAsn1PkcsPrivateKeyInfo_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(new_OrgSpongycastleAsn1X509AlgorithmIdentifier_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, dhKeyAgreement), [new_OrgSpongycastleAsn1PkcsDHParameter_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_([((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec_)) getP], [((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec_)) getG], [((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec_)) getL]) toASN1Primitive]), new_OrgSpongycastleAsn1ASN1Integer_initWithJavaMathBigInteger_([self getX]));
    return [info getEncodedWithNSString:OrgSpongycastleAsn1ASN1Encoding_DER];
  }
  @catch (JavaLangException *e) {
    return nil;
  }
}

- (JavaxCryptoSpecDHParameterSpec *)getParams {
  return dhSpec_;
}

- (JavaMathBigInteger *)getX {
  return x_;
}

- (jboolean)isEqual:(id)o {
  if (!([JavaxCryptoInterfacesDHPrivateKey_class_() isInstance:o])) {
    return false;
  }
  id<JavaxCryptoInterfacesDHPrivateKey> other = (id<JavaxCryptoInterfacesDHPrivateKey>) cast_check(o, JavaxCryptoInterfacesDHPrivateKey_class_());
  return [((JavaMathBigInteger *) nil_chk([self getX])) isEqual:[((id<JavaxCryptoInterfacesDHPrivateKey>) nil_chk(other)) getX]] && [((JavaMathBigInteger *) nil_chk([((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getG])) isEqual:[((JavaxCryptoSpecDHParameterSpec *) nil_chk([other getParams])) getG]] && [((JavaMathBigInteger *) nil_chk([((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getP])) isEqual:[((JavaxCryptoSpecDHParameterSpec *) nil_chk([other getParams])) getP]] && [((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getL] == [((JavaxCryptoSpecDHParameterSpec *) nil_chk([other getParams])) getL];
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk([self getX])) hash]) ^ ((jint) [((JavaMathBigInteger *) nil_chk([((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getG])) hash]) ^ ((jint) [((JavaMathBigInteger *) nil_chk([((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getP])) hash]) ^ [((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getL];
}

- (void)setBagAttributeWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid
                              withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)attribute {
  [((ComYouzhLingtuSignCryptoUtilsPKCS12BagAttributeCarrierImpl *) nil_chk(attrCarrier_)) setBagAttributeWithOrgSpongycastleAsn1ASN1ObjectIdentifier:oid withOrgSpongycastleAsn1ASN1Encodable:attribute];
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)getBagAttributeWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid {
  return [((ComYouzhLingtuSignCryptoUtilsPKCS12BagAttributeCarrierImpl *) nil_chk(attrCarrier_)) getBagAttributeWithOrgSpongycastleAsn1ASN1ObjectIdentifier:oid];
}

- (id<JavaUtilEnumeration>)getBagAttributeKeys {
  return [((ComYouzhLingtuSignCryptoUtilsPKCS12BagAttributeCarrierImpl *) nil_chk(attrCarrier_)) getBagAttributeKeys];
}

- (void)readObjectWithJavaIoObjectInputStream:(JavaIoObjectInputStream *)inArg {
  ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_readObjectWithJavaIoObjectInputStream_(self, inArg);
}

- (void)writeObjectWithJavaIoObjectOutputStream:(JavaIoObjectOutputStream *)outArg {
  ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_writeObjectWithJavaIoObjectOutputStream_(self, outArg);
}

- (void)destroy {
  JavaxSecurityAuthDestroyable_destroy(self);
}

- (jboolean)isDestroyed {
  return JavaxSecurityAuthDestroyable_isDestroyed(self);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, 3, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 4, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaxCryptoSpecDHParameterSpec;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 7, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 8, 9, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Encodable;", 0x1, 10, 11, -1, -1, -1, -1 },
    { NULL, "LJavaUtilEnumeration;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 12, 13, 14, -1, -1, -1 },
    { NULL, "V", 0x2, 15, 16, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithJavaxCryptoInterfacesDHPrivateKey:);
  methods[2].selector = @selector(initWithJavaxCryptoSpecDHPrivateKeySpec:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo:);
  methods[4].selector = @selector(initWithOrgSpongycastleCryptoParamsDHPrivateKeyParameters:);
  methods[5].selector = @selector(getAlgorithm);
  methods[6].selector = @selector(getFormat);
  methods[7].selector = @selector(getEncoded);
  methods[8].selector = @selector(getParams);
  methods[9].selector = @selector(getX);
  methods[10].selector = @selector(isEqual:);
  methods[11].selector = @selector(hash);
  methods[12].selector = @selector(setBagAttributeWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withOrgSpongycastleAsn1ASN1Encodable:);
  methods[13].selector = @selector(getBagAttributeWithOrgSpongycastleAsn1ASN1ObjectIdentifier:);
  methods[14].selector = @selector(getBagAttributeKeys);
  methods[15].selector = @selector(readObjectWithJavaIoObjectInputStream:);
  methods[16].selector = @selector(writeObjectWithJavaIoObjectOutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "serialVersionUID", "J", .constantValue.asLong = ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_serialVersionUID, 0x18, -1, -1, -1, -1 },
    { "x_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "dhSpec_", "LJavaxCryptoSpecDHParameterSpec;", .constantValue.asLong = 0, 0x82, -1, -1, -1, -1 },
    { "info_", "LOrgSpongycastleAsn1PkcsPrivateKeyInfo;", .constantValue.asLong = 0, 0x82, -1, -1, -1, -1 },
    { "attrCarrier_", "LComYouzhLingtuSignCryptoUtilsPKCS12BagAttributeCarrierImpl;", .constantValue.asLong = 0, 0x82, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaxCryptoInterfacesDHPrivateKey;", "LJavaxCryptoSpecDHPrivateKeySpec;", "LOrgSpongycastleAsn1PkcsPrivateKeyInfo;", "LJavaIoIOException;", "LOrgSpongycastleCryptoParamsDHPrivateKeyParameters;", "equals", "LNSObject;", "hashCode", "setBagAttribute", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;LOrgSpongycastleAsn1ASN1Encodable;", "getBagAttribute", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", "readObject", "LJavaIoObjectInputStream;", "LJavaIoIOException;LJavaLangClassNotFoundException;", "writeObject", "LJavaIoObjectOutputStream;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey = { "BCDHPrivateKey", "com.youzh.lingtu.sign.crypto.utils", ptrTable, methods, fields, 7, 0x1, 17, 5, -1, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey;
}

@end

void ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_init(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *self) {
  NSObject_init(self);
  self->attrCarrier_ = new_ComYouzhLingtuSignCryptoUtilsPKCS12BagAttributeCarrierImpl_init();
}

ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *new_ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey, init)
}

ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *create_ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey, init)
}

void ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_initWithJavaxCryptoInterfacesDHPrivateKey_(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *self, id<JavaxCryptoInterfacesDHPrivateKey> key) {
  NSObject_init(self);
  self->attrCarrier_ = new_ComYouzhLingtuSignCryptoUtilsPKCS12BagAttributeCarrierImpl_init();
  self->x_ = [((id<JavaxCryptoInterfacesDHPrivateKey>) nil_chk(key)) getX];
  self->dhSpec_ = [key getParams];
}

ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *new_ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_initWithJavaxCryptoInterfacesDHPrivateKey_(id<JavaxCryptoInterfacesDHPrivateKey> key) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey, initWithJavaxCryptoInterfacesDHPrivateKey_, key)
}

ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *create_ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_initWithJavaxCryptoInterfacesDHPrivateKey_(id<JavaxCryptoInterfacesDHPrivateKey> key) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey, initWithJavaxCryptoInterfacesDHPrivateKey_, key)
}

void ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_initWithJavaxCryptoSpecDHPrivateKeySpec_(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *self, JavaxCryptoSpecDHPrivateKeySpec *spec) {
  NSObject_init(self);
  self->attrCarrier_ = new_ComYouzhLingtuSignCryptoUtilsPKCS12BagAttributeCarrierImpl_init();
  self->x_ = [((JavaxCryptoSpecDHPrivateKeySpec *) nil_chk(spec)) getX];
  self->dhSpec_ = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_([spec getP], [spec getG]);
}

ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *new_ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_initWithJavaxCryptoSpecDHPrivateKeySpec_(JavaxCryptoSpecDHPrivateKeySpec *spec) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey, initWithJavaxCryptoSpecDHPrivateKeySpec_, spec)
}

ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *create_ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_initWithJavaxCryptoSpecDHPrivateKeySpec_(JavaxCryptoSpecDHPrivateKeySpec *spec) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey, initWithJavaxCryptoSpecDHPrivateKeySpec_, spec)
}

void ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *self, OrgSpongycastleAsn1PkcsPrivateKeyInfo *info) {
  NSObject_init(self);
  self->attrCarrier_ = new_ComYouzhLingtuSignCryptoUtilsPKCS12BagAttributeCarrierImpl_init();
  OrgSpongycastleAsn1ASN1Sequence *seq = OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_([((OrgSpongycastleAsn1X509AlgorithmIdentifier *) nil_chk([((OrgSpongycastleAsn1PkcsPrivateKeyInfo *) nil_chk(info)) getPrivateKeyAlgorithm])) getParameters]);
  OrgSpongycastleAsn1ASN1Integer *derX = (OrgSpongycastleAsn1ASN1Integer *) cast_chk([info parsePrivateKey], [OrgSpongycastleAsn1ASN1Integer class]);
  OrgSpongycastleAsn1ASN1ObjectIdentifier *id_ = [((OrgSpongycastleAsn1X509AlgorithmIdentifier *) nil_chk([info getPrivateKeyAlgorithm])) getAlgorithm];
  self->info_ = info;
  self->x_ = [((OrgSpongycastleAsn1ASN1Integer *) nil_chk(derX)) getValue];
  if ([((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk(id_)) isEqual:JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, dhKeyAgreement)]) {
    OrgSpongycastleAsn1PkcsDHParameter *params = OrgSpongycastleAsn1PkcsDHParameter_getInstanceWithId_(seq);
    if ([((OrgSpongycastleAsn1PkcsDHParameter *) nil_chk(params)) getL] != nil) {
      self->dhSpec_ = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_([params getP], [params getG], [((JavaMathBigInteger *) nil_chk([params getL])) intValue]);
    }
    else {
      self->dhSpec_ = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_([params getP], [params getG]);
    }
  }
  else if ([id_ isEqual:JreLoadStatic(OrgSpongycastleAsn1X9X9ObjectIdentifiers, dhpublicnumber)]) {
    OrgSpongycastleAsn1X9DomainParameters *params = OrgSpongycastleAsn1X9DomainParameters_getInstanceWithId_(seq);
    self->dhSpec_ = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_([((OrgSpongycastleAsn1X9DomainParameters *) nil_chk(params)) getP], [params getG]);
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$@", @"unknown algorithm type: ", id_));
  }
}

ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *new_ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_(OrgSpongycastleAsn1PkcsPrivateKeyInfo *info) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey, initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_, info)
}

ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *create_ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_(OrgSpongycastleAsn1PkcsPrivateKeyInfo *info) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey, initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_, info)
}

void ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_initWithOrgSpongycastleCryptoParamsDHPrivateKeyParameters_(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *self, OrgSpongycastleCryptoParamsDHPrivateKeyParameters *params) {
  NSObject_init(self);
  self->attrCarrier_ = new_ComYouzhLingtuSignCryptoUtilsPKCS12BagAttributeCarrierImpl_init();
  self->x_ = [((OrgSpongycastleCryptoParamsDHPrivateKeyParameters *) nil_chk(params)) getX];
  self->dhSpec_ = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_([((OrgSpongycastleCryptoParamsDHParameters *) nil_chk([params getParameters])) getP], [((OrgSpongycastleCryptoParamsDHParameters *) nil_chk([params getParameters])) getG], [((OrgSpongycastleCryptoParamsDHParameters *) nil_chk([params getParameters])) getL]);
}

ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *new_ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_initWithOrgSpongycastleCryptoParamsDHPrivateKeyParameters_(OrgSpongycastleCryptoParamsDHPrivateKeyParameters *params) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey, initWithOrgSpongycastleCryptoParamsDHPrivateKeyParameters_, params)
}

ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *create_ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_initWithOrgSpongycastleCryptoParamsDHPrivateKeyParameters_(OrgSpongycastleCryptoParamsDHPrivateKeyParameters *params) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey, initWithOrgSpongycastleCryptoParamsDHPrivateKeyParameters_, params)
}

void ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_readObjectWithJavaIoObjectInputStream_(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *self, JavaIoObjectInputStream *inArg) {
  [((JavaIoObjectInputStream *) nil_chk(inArg)) defaultReadObject];
  self->dhSpec_ = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_((JavaMathBigInteger *) cast_chk([inArg readObject], [JavaMathBigInteger class]), (JavaMathBigInteger *) cast_chk([inArg readObject], [JavaMathBigInteger class]), [inArg readInt]);
  self->info_ = nil;
  self->attrCarrier_ = new_ComYouzhLingtuSignCryptoUtilsPKCS12BagAttributeCarrierImpl_init();
}

void ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey_writeObjectWithJavaIoObjectOutputStream_(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey *self, JavaIoObjectOutputStream *outArg) {
  [((JavaIoObjectOutputStream *) nil_chk(outArg)) defaultWriteObject];
  [outArg writeObjectWithId:[((JavaxCryptoSpecDHParameterSpec *) nil_chk(self->dhSpec_)) getP]];
  [outArg writeObjectWithId:[((JavaxCryptoSpecDHParameterSpec *) nil_chk(self->dhSpec_)) getG]];
  [outArg writeIntWithInt:[((JavaxCryptoSpecDHParameterSpec *) nil_chk(self->dhSpec_)) getL]];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoUtilsBCDHPrivateKey)
