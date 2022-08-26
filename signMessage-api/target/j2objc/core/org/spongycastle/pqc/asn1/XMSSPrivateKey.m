//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/asn1/XMSSPrivateKey.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DEROctetString.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/pqc/asn1/XMSSPrivateKey.h"
#include "org/spongycastle/util/Arrays.h"

@interface OrgSpongycastlePqcAsn1XMSSPrivateKey () {
 @public
  jint index_;
  IOSByteArray *secretKeySeed_;
  IOSByteArray *secretKeyPRF_;
  IOSByteArray *publicSeed_;
  IOSByteArray *root_;
  IOSByteArray *bdsState_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcAsn1XMSSPrivateKey, secretKeySeed_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcAsn1XMSSPrivateKey, secretKeyPRF_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcAsn1XMSSPrivateKey, publicSeed_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcAsn1XMSSPrivateKey, root_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcAsn1XMSSPrivateKey, bdsState_, IOSByteArray *)

__attribute__((unused)) static void OrgSpongycastlePqcAsn1XMSSPrivateKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastlePqcAsn1XMSSPrivateKey *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastlePqcAsn1XMSSPrivateKey *new_OrgSpongycastlePqcAsn1XMSSPrivateKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastlePqcAsn1XMSSPrivateKey *create_OrgSpongycastlePqcAsn1XMSSPrivateKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastlePqcAsn1XMSSPrivateKey

- (instancetype)initWithInt:(jint)index
              withByteArray:(IOSByteArray *)secretKeySeed
              withByteArray:(IOSByteArray *)secretKeyPRF
              withByteArray:(IOSByteArray *)publicSeed
              withByteArray:(IOSByteArray *)root
              withByteArray:(IOSByteArray *)bdsState {
  OrgSpongycastlePqcAsn1XMSSPrivateKey_initWithInt_withByteArray_withByteArray_withByteArray_withByteArray_withByteArray_(self, index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsState);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastlePqcAsn1XMSSPrivateKey_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (OrgSpongycastlePqcAsn1XMSSPrivateKey *)getInstanceWithId:(id)o {
  return OrgSpongycastlePqcAsn1XMSSPrivateKey_getInstanceWithId_(o);
}

- (jint)getIndex {
  return index_;
}

- (IOSByteArray *)getSecretKeySeed {
  return OrgSpongycastleUtilArrays_cloneWithByteArray_(secretKeySeed_);
}

- (IOSByteArray *)getSecretKeyPRF {
  return OrgSpongycastleUtilArrays_cloneWithByteArray_(secretKeyPRF_);
}

- (IOSByteArray *)getPublicSeed {
  return OrgSpongycastleUtilArrays_cloneWithByteArray_(publicSeed_);
}

- (IOSByteArray *)getRoot {
  return OrgSpongycastleUtilArrays_cloneWithByteArray_(root_);
}

- (IOSByteArray *)getBdsState {
  return OrgSpongycastleUtilArrays_cloneWithByteArray_(bdsState_);
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1ASN1Integer_initWithLong_(0)];
  OrgSpongycastleAsn1ASN1EncodableVector *vK = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [vK addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1ASN1Integer_initWithLong_(index_)];
  [vK addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_(secretKeySeed_)];
  [vK addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_(secretKeyPRF_)];
  [vK addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_(publicSeed_)];
  [vK addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_(root_)];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(vK)];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(true, 0, new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_(bdsState_))];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcAsn1XMSSPrivateKey;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withByteArray:withByteArray:withByteArray:withByteArray:withByteArray:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getIndex);
  methods[4].selector = @selector(getSecretKeySeed);
  methods[5].selector = @selector(getSecretKeyPRF);
  methods[6].selector = @selector(getPublicSeed);
  methods[7].selector = @selector(getRoot);
  methods[8].selector = @selector(getBdsState);
  methods[9].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "index_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "secretKeySeed_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "secretKeyPRF_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "publicSeed_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "root_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "bdsState_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "I[B[B[B[B[B", "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcAsn1XMSSPrivateKey = { "XMSSPrivateKey", "org.spongycastle.pqc.asn1", ptrTable, methods, fields, 7, 0x1, 10, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcAsn1XMSSPrivateKey;
}

@end

void OrgSpongycastlePqcAsn1XMSSPrivateKey_initWithInt_withByteArray_withByteArray_withByteArray_withByteArray_withByteArray_(OrgSpongycastlePqcAsn1XMSSPrivateKey *self, jint index, IOSByteArray *secretKeySeed, IOSByteArray *secretKeyPRF, IOSByteArray *publicSeed, IOSByteArray *root, IOSByteArray *bdsState) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->index_ = index;
  self->secretKeySeed_ = OrgSpongycastleUtilArrays_cloneWithByteArray_(secretKeySeed);
  self->secretKeyPRF_ = OrgSpongycastleUtilArrays_cloneWithByteArray_(secretKeyPRF);
  self->publicSeed_ = OrgSpongycastleUtilArrays_cloneWithByteArray_(publicSeed);
  self->root_ = OrgSpongycastleUtilArrays_cloneWithByteArray_(root);
  self->bdsState_ = OrgSpongycastleUtilArrays_cloneWithByteArray_(bdsState);
}

OrgSpongycastlePqcAsn1XMSSPrivateKey *new_OrgSpongycastlePqcAsn1XMSSPrivateKey_initWithInt_withByteArray_withByteArray_withByteArray_withByteArray_withByteArray_(jint index, IOSByteArray *secretKeySeed, IOSByteArray *secretKeyPRF, IOSByteArray *publicSeed, IOSByteArray *root, IOSByteArray *bdsState) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcAsn1XMSSPrivateKey, initWithInt_withByteArray_withByteArray_withByteArray_withByteArray_withByteArray_, index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsState)
}

OrgSpongycastlePqcAsn1XMSSPrivateKey *create_OrgSpongycastlePqcAsn1XMSSPrivateKey_initWithInt_withByteArray_withByteArray_withByteArray_withByteArray_withByteArray_(jint index, IOSByteArray *secretKeySeed, IOSByteArray *secretKeyPRF, IOSByteArray *publicSeed, IOSByteArray *root, IOSByteArray *bdsState) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcAsn1XMSSPrivateKey, initWithInt_withByteArray_withByteArray_withByteArray_withByteArray_withByteArray_, index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsState)
}

void OrgSpongycastlePqcAsn1XMSSPrivateKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastlePqcAsn1XMSSPrivateKey *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if (![((JavaMathBigInteger *) nil_chk([((OrgSpongycastleAsn1ASN1Integer *) nil_chk(OrgSpongycastleAsn1ASN1Integer_getInstanceWithId_([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]))) getValue])) isEqual:JavaMathBigInteger_valueOfWithLong_(0)]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unknown version of sequence");
  }
  if ([seq size] != 2 && [seq size] != 3) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"key sequence wrong size");
  }
  OrgSpongycastleAsn1ASN1Sequence *keySeq = OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_([seq getObjectAtWithInt:1]);
  self->index_ = [((JavaMathBigInteger *) nil_chk([((OrgSpongycastleAsn1ASN1Integer *) nil_chk(OrgSpongycastleAsn1ASN1Integer_getInstanceWithId_([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(keySeq)) getObjectAtWithInt:0]))) getValue])) intValue];
  self->secretKeySeed_ = OrgSpongycastleUtilArrays_cloneWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_([keySeq getObjectAtWithInt:1]))) getOctets]);
  self->secretKeyPRF_ = OrgSpongycastleUtilArrays_cloneWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_([keySeq getObjectAtWithInt:2]))) getOctets]);
  self->publicSeed_ = OrgSpongycastleUtilArrays_cloneWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_([keySeq getObjectAtWithInt:3]))) getOctets]);
  self->root_ = OrgSpongycastleUtilArrays_cloneWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_([keySeq getObjectAtWithInt:4]))) getOctets]);
  if ([seq size] == 3) {
    self->bdsState_ = OrgSpongycastleUtilArrays_cloneWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(OrgSpongycastleAsn1ASN1OctetString_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject_getInstanceWithId_([seq getObjectAtWithInt:2]), true))) getOctets]);
  }
  else {
    self->bdsState_ = nil;
  }
}

OrgSpongycastlePqcAsn1XMSSPrivateKey *new_OrgSpongycastlePqcAsn1XMSSPrivateKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcAsn1XMSSPrivateKey, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastlePqcAsn1XMSSPrivateKey *create_OrgSpongycastlePqcAsn1XMSSPrivateKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcAsn1XMSSPrivateKey, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastlePqcAsn1XMSSPrivateKey *OrgSpongycastlePqcAsn1XMSSPrivateKey_getInstanceWithId_(id o) {
  OrgSpongycastlePqcAsn1XMSSPrivateKey_initialize();
  if ([o isKindOfClass:[OrgSpongycastlePqcAsn1XMSSPrivateKey class]]) {
    return (OrgSpongycastlePqcAsn1XMSSPrivateKey *) o;
  }
  else if (o != nil) {
    return new_OrgSpongycastlePqcAsn1XMSSPrivateKey_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcAsn1XMSSPrivateKey)
