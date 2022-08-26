//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/crmf/EncryptedValue.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERBitString.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/crmf/EncryptedValue.h"
#include "org/spongycastle/asn1/x509/AlgorithmIdentifier.h"

@interface OrgSpongycastleAsn1CrmfEncryptedValue () {
 @public
  OrgSpongycastleAsn1X509AlgorithmIdentifier *intendedAlg_;
  OrgSpongycastleAsn1X509AlgorithmIdentifier *symmAlg_;
  OrgSpongycastleAsn1DERBitString *encSymmKey_;
  OrgSpongycastleAsn1X509AlgorithmIdentifier *keyAlg_;
  OrgSpongycastleAsn1ASN1OctetString *valueHint_;
  OrgSpongycastleAsn1DERBitString *encValue_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

- (void)addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector:(OrgSpongycastleAsn1ASN1EncodableVector *)v
                                                      withInt:(jint)tagNo
                         withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)obj;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CrmfEncryptedValue, intendedAlg_, OrgSpongycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CrmfEncryptedValue, symmAlg_, OrgSpongycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CrmfEncryptedValue, encSymmKey_, OrgSpongycastleAsn1DERBitString *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CrmfEncryptedValue, keyAlg_, OrgSpongycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CrmfEncryptedValue, valueHint_, OrgSpongycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CrmfEncryptedValue, encValue_, OrgSpongycastleAsn1DERBitString *)

__attribute__((unused)) static void OrgSpongycastleAsn1CrmfEncryptedValue_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CrmfEncryptedValue *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1CrmfEncryptedValue *new_OrgSpongycastleAsn1CrmfEncryptedValue_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CrmfEncryptedValue *create_OrgSpongycastleAsn1CrmfEncryptedValue_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static void OrgSpongycastleAsn1CrmfEncryptedValue_addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1CrmfEncryptedValue *self, OrgSpongycastleAsn1ASN1EncodableVector *v, jint tagNo, id<OrgSpongycastleAsn1ASN1Encodable> obj);

@implementation OrgSpongycastleAsn1CrmfEncryptedValue

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CrmfEncryptedValue_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (OrgSpongycastleAsn1CrmfEncryptedValue *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CrmfEncryptedValue_getInstanceWithId_(o);
}

- (instancetype)initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)intendedAlg
                    withOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)symmAlg
                               withOrgSpongycastleAsn1DERBitString:(OrgSpongycastleAsn1DERBitString *)encSymmKey
                    withOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)keyAlg
                            withOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)valueHint
                               withOrgSpongycastleAsn1DERBitString:(OrgSpongycastleAsn1DERBitString *)encValue {
  OrgSpongycastleAsn1CrmfEncryptedValue_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1DERBitString_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1DERBitString_(self, intendedAlg, symmAlg, encSymmKey, keyAlg, valueHint, encValue);
  return self;
}

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getIntendedAlg {
  return intendedAlg_;
}

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getSymmAlg {
  return symmAlg_;
}

- (OrgSpongycastleAsn1DERBitString *)getEncSymmKey {
  return encSymmKey_;
}

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getKeyAlg {
  return keyAlg_;
}

- (OrgSpongycastleAsn1ASN1OctetString *)getValueHint {
  return valueHint_;
}

- (OrgSpongycastleAsn1DERBitString *)getEncValue {
  return encValue_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  OrgSpongycastleAsn1CrmfEncryptedValue_addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_withOrgSpongycastleAsn1ASN1Encodable_(self, v, 0, intendedAlg_);
  OrgSpongycastleAsn1CrmfEncryptedValue_addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_withOrgSpongycastleAsn1ASN1Encodable_(self, v, 1, symmAlg_);
  OrgSpongycastleAsn1CrmfEncryptedValue_addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_withOrgSpongycastleAsn1ASN1Encodable_(self, v, 2, encSymmKey_);
  OrgSpongycastleAsn1CrmfEncryptedValue_addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_withOrgSpongycastleAsn1ASN1Encodable_(self, v, 3, keyAlg_);
  OrgSpongycastleAsn1CrmfEncryptedValue_addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_withOrgSpongycastleAsn1ASN1Encodable_(self, v, 4, valueHint_);
  [v addWithOrgSpongycastleAsn1ASN1Encodable:encValue_];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

- (void)addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector:(OrgSpongycastleAsn1ASN1EncodableVector *)v
                                                      withInt:(jint)tagNo
                         withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)obj {
  OrgSpongycastleAsn1CrmfEncryptedValue_addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_withOrgSpongycastleAsn1ASN1Encodable_(self, v, tagNo, obj);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CrmfEncryptedValue;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1DERBitString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1DERBitString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 4, 5, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:withOrgSpongycastleAsn1X509AlgorithmIdentifier:withOrgSpongycastleAsn1DERBitString:withOrgSpongycastleAsn1X509AlgorithmIdentifier:withOrgSpongycastleAsn1ASN1OctetString:withOrgSpongycastleAsn1DERBitString:);
  methods[3].selector = @selector(getIntendedAlg);
  methods[4].selector = @selector(getSymmAlg);
  methods[5].selector = @selector(getEncSymmKey);
  methods[6].selector = @selector(getKeyAlg);
  methods[7].selector = @selector(getValueHint);
  methods[8].selector = @selector(getEncValue);
  methods[9].selector = @selector(toASN1Primitive);
  methods[10].selector = @selector(addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector:withInt:withOrgSpongycastleAsn1ASN1Encodable:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "intendedAlg_", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "symmAlg_", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "encSymmKey_", "LOrgSpongycastleAsn1DERBitString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "keyAlg_", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "valueHint_", "LOrgSpongycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "encValue_", "LOrgSpongycastleAsn1DERBitString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;LOrgSpongycastleAsn1X509AlgorithmIdentifier;LOrgSpongycastleAsn1DERBitString;LOrgSpongycastleAsn1X509AlgorithmIdentifier;LOrgSpongycastleAsn1ASN1OctetString;LOrgSpongycastleAsn1DERBitString;", "addOptional", "LOrgSpongycastleAsn1ASN1EncodableVector;ILOrgSpongycastleAsn1ASN1Encodable;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CrmfEncryptedValue = { "EncryptedValue", "org.spongycastle.asn1.crmf", ptrTable, methods, fields, 7, 0x1, 11, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CrmfEncryptedValue;
}

@end

void OrgSpongycastleAsn1CrmfEncryptedValue_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CrmfEncryptedValue *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  jint index = 0;
  while ([[((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:index] isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]]) {
    OrgSpongycastleAsn1ASN1TaggedObject *tObj = (OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:index], [OrgSpongycastleAsn1ASN1TaggedObject class]);
    switch ([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(tObj)) getTagNo]) {
      case 0:
      self->intendedAlg_ = OrgSpongycastleAsn1X509AlgorithmIdentifier_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(tObj, false);
      break;
      case 1:
      self->symmAlg_ = OrgSpongycastleAsn1X509AlgorithmIdentifier_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(tObj, false);
      break;
      case 2:
      self->encSymmKey_ = OrgSpongycastleAsn1DERBitString_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(tObj, false);
      break;
      case 3:
      self->keyAlg_ = OrgSpongycastleAsn1X509AlgorithmIdentifier_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(tObj, false);
      break;
      case 4:
      self->valueHint_ = OrgSpongycastleAsn1ASN1OctetString_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(tObj, false);
      break;
      default:
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Unknown tag encountered: ", [tObj getTagNo]));
    }
    index++;
  }
  self->encValue_ = OrgSpongycastleAsn1DERBitString_getInstanceWithId_([seq getObjectAtWithInt:index]);
}

OrgSpongycastleAsn1CrmfEncryptedValue *new_OrgSpongycastleAsn1CrmfEncryptedValue_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CrmfEncryptedValue, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CrmfEncryptedValue *create_OrgSpongycastleAsn1CrmfEncryptedValue_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CrmfEncryptedValue, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CrmfEncryptedValue *OrgSpongycastleAsn1CrmfEncryptedValue_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CrmfEncryptedValue_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1CrmfEncryptedValue class]]) {
    return (OrgSpongycastleAsn1CrmfEncryptedValue *) o;
  }
  else if (o != nil) {
    return new_OrgSpongycastleAsn1CrmfEncryptedValue_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void OrgSpongycastleAsn1CrmfEncryptedValue_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1DERBitString_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1DERBitString_(OrgSpongycastleAsn1CrmfEncryptedValue *self, OrgSpongycastleAsn1X509AlgorithmIdentifier *intendedAlg, OrgSpongycastleAsn1X509AlgorithmIdentifier *symmAlg, OrgSpongycastleAsn1DERBitString *encSymmKey, OrgSpongycastleAsn1X509AlgorithmIdentifier *keyAlg, OrgSpongycastleAsn1ASN1OctetString *valueHint, OrgSpongycastleAsn1DERBitString *encValue) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if (encValue == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'encValue' cannot be null");
  }
  self->intendedAlg_ = intendedAlg;
  self->symmAlg_ = symmAlg;
  self->encSymmKey_ = encSymmKey;
  self->keyAlg_ = keyAlg;
  self->valueHint_ = valueHint;
  self->encValue_ = encValue;
}

OrgSpongycastleAsn1CrmfEncryptedValue *new_OrgSpongycastleAsn1CrmfEncryptedValue_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1DERBitString_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1DERBitString_(OrgSpongycastleAsn1X509AlgorithmIdentifier *intendedAlg, OrgSpongycastleAsn1X509AlgorithmIdentifier *symmAlg, OrgSpongycastleAsn1DERBitString *encSymmKey, OrgSpongycastleAsn1X509AlgorithmIdentifier *keyAlg, OrgSpongycastleAsn1ASN1OctetString *valueHint, OrgSpongycastleAsn1DERBitString *encValue) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CrmfEncryptedValue, initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1DERBitString_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1DERBitString_, intendedAlg, symmAlg, encSymmKey, keyAlg, valueHint, encValue)
}

OrgSpongycastleAsn1CrmfEncryptedValue *create_OrgSpongycastleAsn1CrmfEncryptedValue_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1DERBitString_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1DERBitString_(OrgSpongycastleAsn1X509AlgorithmIdentifier *intendedAlg, OrgSpongycastleAsn1X509AlgorithmIdentifier *symmAlg, OrgSpongycastleAsn1DERBitString *encSymmKey, OrgSpongycastleAsn1X509AlgorithmIdentifier *keyAlg, OrgSpongycastleAsn1ASN1OctetString *valueHint, OrgSpongycastleAsn1DERBitString *encValue) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CrmfEncryptedValue, initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1DERBitString_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1DERBitString_, intendedAlg, symmAlg, encSymmKey, keyAlg, valueHint, encValue)
}

void OrgSpongycastleAsn1CrmfEncryptedValue_addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1CrmfEncryptedValue *self, OrgSpongycastleAsn1ASN1EncodableVector *v, jint tagNo, id<OrgSpongycastleAsn1ASN1Encodable> obj) {
  if (obj != nil) {
    [((OrgSpongycastleAsn1ASN1EncodableVector *) nil_chk(v)) addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, tagNo, obj)];
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CrmfEncryptedValue)
