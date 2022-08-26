//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/RsaKemParameters.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/cms/RsaKemParameters.h"
#include "org/spongycastle/asn1/x509/AlgorithmIdentifier.h"

@interface OrgSpongycastleAsn1CmsRsaKemParameters () {
 @public
  OrgSpongycastleAsn1X509AlgorithmIdentifier *keyDerivationFunction_;
  JavaMathBigInteger *keyLength_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)sequence;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsRsaKemParameters, keyDerivationFunction_, OrgSpongycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsRsaKemParameters, keyLength_, JavaMathBigInteger *)

__attribute__((unused)) static void OrgSpongycastleAsn1CmsRsaKemParameters_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmsRsaKemParameters *self, OrgSpongycastleAsn1ASN1Sequence *sequence);

__attribute__((unused)) static OrgSpongycastleAsn1CmsRsaKemParameters *new_OrgSpongycastleAsn1CmsRsaKemParameters_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *sequence) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CmsRsaKemParameters *create_OrgSpongycastleAsn1CmsRsaKemParameters_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *sequence);

@implementation OrgSpongycastleAsn1CmsRsaKemParameters

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)sequence {
  OrgSpongycastleAsn1CmsRsaKemParameters_initWithOrgSpongycastleAsn1ASN1Sequence_(self, sequence);
  return self;
}

+ (OrgSpongycastleAsn1CmsRsaKemParameters *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CmsRsaKemParameters_getInstanceWithId_(o);
}

- (instancetype)initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)keyDerivationFunction
                                                           withInt:(jint)keyLength {
  OrgSpongycastleAsn1CmsRsaKemParameters_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withInt_(self, keyDerivationFunction, keyLength);
  return self;
}

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getKeyDerivationFunction {
  return keyDerivationFunction_;
}

- (JavaMathBigInteger *)getKeyLength {
  return keyLength_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:keyDerivationFunction_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(keyLength_)];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsRsaKemParameters;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:withInt:);
  methods[3].selector = @selector(getKeyDerivationFunction);
  methods[4].selector = @selector(getKeyLength);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "keyDerivationFunction_", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "keyLength_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;I" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmsRsaKemParameters = { "RsaKemParameters", "org.spongycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmsRsaKemParameters;
}

@end

void OrgSpongycastleAsn1CmsRsaKemParameters_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmsRsaKemParameters *self, OrgSpongycastleAsn1ASN1Sequence *sequence) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(sequence)) size] != 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"ASN.1 SEQUENCE should be of length 2");
  }
  self->keyDerivationFunction_ = OrgSpongycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([sequence getObjectAtWithInt:0]);
  self->keyLength_ = [((OrgSpongycastleAsn1ASN1Integer *) nil_chk(OrgSpongycastleAsn1ASN1Integer_getInstanceWithId_([sequence getObjectAtWithInt:1]))) getValue];
}

OrgSpongycastleAsn1CmsRsaKemParameters *new_OrgSpongycastleAsn1CmsRsaKemParameters_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *sequence) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsRsaKemParameters, initWithOrgSpongycastleAsn1ASN1Sequence_, sequence)
}

OrgSpongycastleAsn1CmsRsaKemParameters *create_OrgSpongycastleAsn1CmsRsaKemParameters_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *sequence) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsRsaKemParameters, initWithOrgSpongycastleAsn1ASN1Sequence_, sequence)
}

OrgSpongycastleAsn1CmsRsaKemParameters *OrgSpongycastleAsn1CmsRsaKemParameters_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CmsRsaKemParameters_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1CmsRsaKemParameters class]]) {
    return (OrgSpongycastleAsn1CmsRsaKemParameters *) o;
  }
  else if (o != nil) {
    return new_OrgSpongycastleAsn1CmsRsaKemParameters_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void OrgSpongycastleAsn1CmsRsaKemParameters_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withInt_(OrgSpongycastleAsn1CmsRsaKemParameters *self, OrgSpongycastleAsn1X509AlgorithmIdentifier *keyDerivationFunction, jint keyLength) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->keyDerivationFunction_ = keyDerivationFunction;
  self->keyLength_ = JavaMathBigInteger_valueOfWithLong_(keyLength);
}

OrgSpongycastleAsn1CmsRsaKemParameters *new_OrgSpongycastleAsn1CmsRsaKemParameters_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withInt_(OrgSpongycastleAsn1X509AlgorithmIdentifier *keyDerivationFunction, jint keyLength) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsRsaKemParameters, initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withInt_, keyDerivationFunction, keyLength)
}

OrgSpongycastleAsn1CmsRsaKemParameters *create_OrgSpongycastleAsn1CmsRsaKemParameters_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withInt_(OrgSpongycastleAsn1X509AlgorithmIdentifier *keyDerivationFunction, jint keyLength) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsRsaKemParameters, initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withInt_, keyDerivationFunction, keyLength)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmsRsaKemParameters)
