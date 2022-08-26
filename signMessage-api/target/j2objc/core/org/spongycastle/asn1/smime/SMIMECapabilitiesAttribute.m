//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/smime/SMIMECapabilitiesAttribute.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/DERSet.h"
#include "org/spongycastle/asn1/cms/Attribute.h"
#include "org/spongycastle/asn1/smime/SMIMEAttributes.h"
#include "org/spongycastle/asn1/smime/SMIMECapabilitiesAttribute.h"
#include "org/spongycastle/asn1/smime/SMIMECapabilityVector.h"

@implementation OrgSpongycastleAsn1SmimeSMIMECapabilitiesAttribute

- (instancetype)initWithOrgSpongycastleAsn1SmimeSMIMECapabilityVector:(OrgSpongycastleAsn1SmimeSMIMECapabilityVector *)capabilities {
  OrgSpongycastleAsn1SmimeSMIMECapabilitiesAttribute_initWithOrgSpongycastleAsn1SmimeSMIMECapabilityVector_(self, capabilities);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1SmimeSMIMECapabilityVector:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1SmimeSMIMECapabilityVector;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1SmimeSMIMECapabilitiesAttribute = { "SMIMECapabilitiesAttribute", "org.spongycastle.asn1.smime", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1SmimeSMIMECapabilitiesAttribute;
}

@end

void OrgSpongycastleAsn1SmimeSMIMECapabilitiesAttribute_initWithOrgSpongycastleAsn1SmimeSMIMECapabilityVector_(OrgSpongycastleAsn1SmimeSMIMECapabilitiesAttribute *self, OrgSpongycastleAsn1SmimeSMIMECapabilityVector *capabilities) {
  OrgSpongycastleAsn1CmsAttribute_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Set_(self, JreLoadStatic(OrgSpongycastleAsn1SmimeSMIMEAttributes, smimeCapabilities), new_OrgSpongycastleAsn1DERSet_initWithOrgSpongycastleAsn1ASN1Encodable_(new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_([((OrgSpongycastleAsn1SmimeSMIMECapabilityVector *) nil_chk(capabilities)) toASN1EncodableVector])));
}

OrgSpongycastleAsn1SmimeSMIMECapabilitiesAttribute *new_OrgSpongycastleAsn1SmimeSMIMECapabilitiesAttribute_initWithOrgSpongycastleAsn1SmimeSMIMECapabilityVector_(OrgSpongycastleAsn1SmimeSMIMECapabilityVector *capabilities) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1SmimeSMIMECapabilitiesAttribute, initWithOrgSpongycastleAsn1SmimeSMIMECapabilityVector_, capabilities)
}

OrgSpongycastleAsn1SmimeSMIMECapabilitiesAttribute *create_OrgSpongycastleAsn1SmimeSMIMECapabilitiesAttribute_initWithOrgSpongycastleAsn1SmimeSMIMECapabilityVector_(OrgSpongycastleAsn1SmimeSMIMECapabilityVector *capabilities) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1SmimeSMIMECapabilitiesAttribute, initWithOrgSpongycastleAsn1SmimeSMIMECapabilityVector_, capabilities)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1SmimeSMIMECapabilitiesAttribute)
