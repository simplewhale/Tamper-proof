//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/pkcs/RSAESOAEPparams.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERNull.h"
#include "org/spongycastle/asn1/DEROctetString.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/oiw/OIWObjectIdentifiers.h"
#include "org/spongycastle/asn1/pkcs/PKCSObjectIdentifiers.h"
#include "org/spongycastle/asn1/pkcs/RSAESOAEPparams.h"
#include "org/spongycastle/asn1/x509/AlgorithmIdentifier.h"

@interface OrgSpongycastleAsn1PkcsRSAESOAEPparams () {
 @public
  OrgSpongycastleAsn1X509AlgorithmIdentifier *hashAlgorithm_;
  OrgSpongycastleAsn1X509AlgorithmIdentifier *maskGenAlgorithm_;
  OrgSpongycastleAsn1X509AlgorithmIdentifier *pSourceAlgorithm_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1PkcsRSAESOAEPparams, hashAlgorithm_, OrgSpongycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1PkcsRSAESOAEPparams, maskGenAlgorithm_, OrgSpongycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1PkcsRSAESOAEPparams, pSourceAlgorithm_, OrgSpongycastleAsn1X509AlgorithmIdentifier *)

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleAsn1PkcsRSAESOAEPparams)

OrgSpongycastleAsn1X509AlgorithmIdentifier *OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_HASH_ALGORITHM;
OrgSpongycastleAsn1X509AlgorithmIdentifier *OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_MASK_GEN_FUNCTION;
OrgSpongycastleAsn1X509AlgorithmIdentifier *OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_P_SOURCE_ALGORITHM;

@implementation OrgSpongycastleAsn1PkcsRSAESOAEPparams

+ (OrgSpongycastleAsn1PkcsRSAESOAEPparams *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1PkcsRSAESOAEPparams_getInstanceWithId_(obj);
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleAsn1PkcsRSAESOAEPparams_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)hashAlgorithm
                    withOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)maskGenAlgorithm
                    withOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)pSourceAlgorithm {
  OrgSpongycastleAsn1PkcsRSAESOAEPparams_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_(self, hashAlgorithm, maskGenAlgorithm, pSourceAlgorithm);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1PkcsRSAESOAEPparams_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getHashAlgorithm {
  return hashAlgorithm_;
}

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getMaskGenAlgorithm {
  return maskGenAlgorithm_;
}

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getPSourceAlgorithm {
  return pSourceAlgorithm_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  if (![((OrgSpongycastleAsn1X509AlgorithmIdentifier *) nil_chk(hashAlgorithm_)) isEqual:OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_HASH_ALGORITHM]) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(true, 0, hashAlgorithm_)];
  }
  if (![((OrgSpongycastleAsn1X509AlgorithmIdentifier *) nil_chk(maskGenAlgorithm_)) isEqual:OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_MASK_GEN_FUNCTION]) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(true, 1, maskGenAlgorithm_)];
  }
  if (![((OrgSpongycastleAsn1X509AlgorithmIdentifier *) nil_chk(pSourceAlgorithm_)) isEqual:OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_P_SOURCE_ALGORITHM]) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(true, 2, pSourceAlgorithm_)];
  }
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1PkcsRSAESOAEPparams;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(init);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:withOrgSpongycastleAsn1X509AlgorithmIdentifier:withOrgSpongycastleAsn1X509AlgorithmIdentifier:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[4].selector = @selector(getHashAlgorithm);
  methods[5].selector = @selector(getMaskGenAlgorithm);
  methods[6].selector = @selector(getPSourceAlgorithm);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "hashAlgorithm_", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "maskGenAlgorithm_", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "pSourceAlgorithm_", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "DEFAULT_HASH_ALGORITHM", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x19, -1, 4, -1, -1 },
    { "DEFAULT_MASK_GEN_FUNCTION", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x19, -1, 5, -1, -1 },
    { "DEFAULT_P_SOURCE_ALGORITHM", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x19, -1, 6, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;LOrgSpongycastleAsn1X509AlgorithmIdentifier;LOrgSpongycastleAsn1X509AlgorithmIdentifier;", "LOrgSpongycastleAsn1ASN1Sequence;", &OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_HASH_ALGORITHM, &OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_MASK_GEN_FUNCTION, &OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_P_SOURCE_ALGORITHM };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1PkcsRSAESOAEPparams = { "RSAESOAEPparams", "org.spongycastle.asn1.pkcs", ptrTable, methods, fields, 7, 0x1, 8, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1PkcsRSAESOAEPparams;
}

+ (void)initialize {
  if (self == [OrgSpongycastleAsn1PkcsRSAESOAEPparams class]) {
    OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_HASH_ALGORITHM = new_OrgSpongycastleAsn1X509AlgorithmIdentifier_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(JreLoadStatic(OrgSpongycastleAsn1OiwOIWObjectIdentifiers, idSHA1), JreLoadStatic(OrgSpongycastleAsn1DERNull, INSTANCE));
    OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_MASK_GEN_FUNCTION = new_OrgSpongycastleAsn1X509AlgorithmIdentifier_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, id_mgf1), OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_HASH_ALGORITHM);
    OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_P_SOURCE_ALGORITHM = new_OrgSpongycastleAsn1X509AlgorithmIdentifier_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, id_pSpecified), new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_([IOSByteArray newArrayWithLength:0]));
    J2OBJC_SET_INITIALIZED(OrgSpongycastleAsn1PkcsRSAESOAEPparams)
  }
}

@end

OrgSpongycastleAsn1PkcsRSAESOAEPparams *OrgSpongycastleAsn1PkcsRSAESOAEPparams_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1PkcsRSAESOAEPparams_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1PkcsRSAESOAEPparams class]]) {
    return (OrgSpongycastleAsn1PkcsRSAESOAEPparams *) obj;
  }
  else if (obj != nil) {
    return new_OrgSpongycastleAsn1PkcsRSAESOAEPparams_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void OrgSpongycastleAsn1PkcsRSAESOAEPparams_init(OrgSpongycastleAsn1PkcsRSAESOAEPparams *self) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->hashAlgorithm_ = OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_HASH_ALGORITHM;
  self->maskGenAlgorithm_ = OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_MASK_GEN_FUNCTION;
  self->pSourceAlgorithm_ = OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_P_SOURCE_ALGORITHM;
}

OrgSpongycastleAsn1PkcsRSAESOAEPparams *new_OrgSpongycastleAsn1PkcsRSAESOAEPparams_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1PkcsRSAESOAEPparams, init)
}

OrgSpongycastleAsn1PkcsRSAESOAEPparams *create_OrgSpongycastleAsn1PkcsRSAESOAEPparams_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1PkcsRSAESOAEPparams, init)
}

void OrgSpongycastleAsn1PkcsRSAESOAEPparams_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_(OrgSpongycastleAsn1PkcsRSAESOAEPparams *self, OrgSpongycastleAsn1X509AlgorithmIdentifier *hashAlgorithm, OrgSpongycastleAsn1X509AlgorithmIdentifier *maskGenAlgorithm, OrgSpongycastleAsn1X509AlgorithmIdentifier *pSourceAlgorithm) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->hashAlgorithm_ = hashAlgorithm;
  self->maskGenAlgorithm_ = maskGenAlgorithm;
  self->pSourceAlgorithm_ = pSourceAlgorithm;
}

OrgSpongycastleAsn1PkcsRSAESOAEPparams *new_OrgSpongycastleAsn1PkcsRSAESOAEPparams_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_(OrgSpongycastleAsn1X509AlgorithmIdentifier *hashAlgorithm, OrgSpongycastleAsn1X509AlgorithmIdentifier *maskGenAlgorithm, OrgSpongycastleAsn1X509AlgorithmIdentifier *pSourceAlgorithm) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1PkcsRSAESOAEPparams, initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_, hashAlgorithm, maskGenAlgorithm, pSourceAlgorithm)
}

OrgSpongycastleAsn1PkcsRSAESOAEPparams *create_OrgSpongycastleAsn1PkcsRSAESOAEPparams_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_(OrgSpongycastleAsn1X509AlgorithmIdentifier *hashAlgorithm, OrgSpongycastleAsn1X509AlgorithmIdentifier *maskGenAlgorithm, OrgSpongycastleAsn1X509AlgorithmIdentifier *pSourceAlgorithm) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1PkcsRSAESOAEPparams, initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_, hashAlgorithm, maskGenAlgorithm, pSourceAlgorithm)
}

void OrgSpongycastleAsn1PkcsRSAESOAEPparams_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1PkcsRSAESOAEPparams *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->hashAlgorithm_ = OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_HASH_ALGORITHM;
  self->maskGenAlgorithm_ = OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_MASK_GEN_FUNCTION;
  self->pSourceAlgorithm_ = OrgSpongycastleAsn1PkcsRSAESOAEPparams_DEFAULT_P_SOURCE_ALGORITHM;
  for (jint i = 0; i != [((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size]; i++) {
    OrgSpongycastleAsn1ASN1TaggedObject *o = (OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:i], [OrgSpongycastleAsn1ASN1TaggedObject class]);
    switch ([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(o)) getTagNo]) {
      case 0:
      self->hashAlgorithm_ = OrgSpongycastleAsn1X509AlgorithmIdentifier_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, true);
      break;
      case 1:
      self->maskGenAlgorithm_ = OrgSpongycastleAsn1X509AlgorithmIdentifier_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, true);
      break;
      case 2:
      self->pSourceAlgorithm_ = OrgSpongycastleAsn1X509AlgorithmIdentifier_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, true);
      break;
      default:
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unknown tag");
    }
  }
}

OrgSpongycastleAsn1PkcsRSAESOAEPparams *new_OrgSpongycastleAsn1PkcsRSAESOAEPparams_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1PkcsRSAESOAEPparams, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1PkcsRSAESOAEPparams *create_OrgSpongycastleAsn1PkcsRSAESOAEPparams_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1PkcsRSAESOAEPparams, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1PkcsRSAESOAEPparams)