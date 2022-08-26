//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/DERSequence.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/util/Enumeration.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1OutputStream.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/BERTags.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/StreamUtil.h"

@interface OrgSpongycastleAsn1DERSequence () {
 @public
  jint bodyLength_;
}

- (jint)getBodyLength;

@end

__attribute__((unused)) static jint OrgSpongycastleAsn1DERSequence_getBodyLength(OrgSpongycastleAsn1DERSequence *self);

@implementation OrgSpongycastleAsn1DERSequence

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleAsn1DERSequence_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)obj {
  OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1Encodable_(self, obj);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1EncodableVector:(OrgSpongycastleAsn1ASN1EncodableVector *)v {
  OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(self, v);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1EncodableArray:(IOSObjectArray *)array {
  OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableArray_(self, array);
  return self;
}

- (jint)getBodyLength {
  return OrgSpongycastleAsn1DERSequence_getBodyLength(self);
}

- (jint)encodedLength {
  jint length = OrgSpongycastleAsn1DERSequence_getBodyLength(self);
  return 1 + OrgSpongycastleAsn1StreamUtil_calculateBodyLengthWithInt_(length) + length;
}

- (void)encodeWithOrgSpongycastleAsn1ASN1OutputStream:(OrgSpongycastleAsn1ASN1OutputStream *)outArg {
  OrgSpongycastleAsn1ASN1OutputStream *dOut = [((OrgSpongycastleAsn1ASN1OutputStream *) nil_chk(outArg)) getDERSubStream];
  jint length = OrgSpongycastleAsn1DERSequence_getBodyLength(self);
  [outArg writeWithInt:OrgSpongycastleAsn1BERTags_SEQUENCE | OrgSpongycastleAsn1BERTags_CONSTRUCTED];
  [outArg writeLengthWithInt:length];
  for (id<JavaUtilEnumeration> e = [self getObjects]; [((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]; ) {
    id obj = [e nextElement];
    [((OrgSpongycastleAsn1ASN1OutputStream *) nil_chk(dOut)) writeObjectWithOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>) cast_check(obj, OrgSpongycastleAsn1ASN1Encodable_class_())];
  }
}

- (NSUInteger)countByEnumeratingWithState:(NSFastEnumerationState *)state objects:(__unsafe_unretained id *)stackbuf count:(NSUInteger)len {
  return JreDefaultFastEnumeration(self, state, stackbuf);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x2, -1, -1, 3, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, 3, -1, -1, -1 },
    { NULL, "V", 0x0, 4, 5, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Encodable:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1ASN1EncodableVector:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1ASN1EncodableArray:);
  methods[4].selector = @selector(getBodyLength);
  methods[5].selector = @selector(encodedLength);
  methods[6].selector = @selector(encodeWithOrgSpongycastleAsn1ASN1OutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "bodyLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1Encodable;", "LOrgSpongycastleAsn1ASN1EncodableVector;", "[LOrgSpongycastleAsn1ASN1Encodable;", "LJavaIoIOException;", "encode", "LOrgSpongycastleAsn1ASN1OutputStream;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1DERSequence = { "DERSequence", "org.spongycastle.asn1", ptrTable, methods, fields, 7, 0x1, 7, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1DERSequence;
}

@end

void OrgSpongycastleAsn1DERSequence_init(OrgSpongycastleAsn1DERSequence *self) {
  OrgSpongycastleAsn1ASN1Sequence_init(self);
  self->bodyLength_ = -1;
}

OrgSpongycastleAsn1DERSequence *new_OrgSpongycastleAsn1DERSequence_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DERSequence, init)
}

OrgSpongycastleAsn1DERSequence *create_OrgSpongycastleAsn1DERSequence_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DERSequence, init)
}

void OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1DERSequence *self, id<OrgSpongycastleAsn1ASN1Encodable> obj) {
  OrgSpongycastleAsn1ASN1Sequence_initWithOrgSpongycastleAsn1ASN1Encodable_(self, obj);
  self->bodyLength_ = -1;
}

OrgSpongycastleAsn1DERSequence *new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1Encodable_(id<OrgSpongycastleAsn1ASN1Encodable> obj) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DERSequence, initWithOrgSpongycastleAsn1ASN1Encodable_, obj)
}

OrgSpongycastleAsn1DERSequence *create_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1Encodable_(id<OrgSpongycastleAsn1ASN1Encodable> obj) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DERSequence, initWithOrgSpongycastleAsn1ASN1Encodable_, obj)
}

void OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1DERSequence *self, OrgSpongycastleAsn1ASN1EncodableVector *v) {
  OrgSpongycastleAsn1ASN1Sequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(self, v);
  self->bodyLength_ = -1;
}

OrgSpongycastleAsn1DERSequence *new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1ASN1EncodableVector *v) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DERSequence, initWithOrgSpongycastleAsn1ASN1EncodableVector_, v)
}

OrgSpongycastleAsn1DERSequence *create_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1ASN1EncodableVector *v) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DERSequence, initWithOrgSpongycastleAsn1ASN1EncodableVector_, v)
}

void OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableArray_(OrgSpongycastleAsn1DERSequence *self, IOSObjectArray *array) {
  OrgSpongycastleAsn1ASN1Sequence_initWithOrgSpongycastleAsn1ASN1EncodableArray_(self, array);
  self->bodyLength_ = -1;
}

OrgSpongycastleAsn1DERSequence *new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableArray_(IOSObjectArray *array) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DERSequence, initWithOrgSpongycastleAsn1ASN1EncodableArray_, array)
}

OrgSpongycastleAsn1DERSequence *create_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableArray_(IOSObjectArray *array) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DERSequence, initWithOrgSpongycastleAsn1ASN1EncodableArray_, array)
}

jint OrgSpongycastleAsn1DERSequence_getBodyLength(OrgSpongycastleAsn1DERSequence *self) {
  if (self->bodyLength_ < 0) {
    jint length = 0;
    for (id<JavaUtilEnumeration> e = [self getObjects]; [((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]; ) {
      id obj = [e nextElement];
      length += [((OrgSpongycastleAsn1ASN1Primitive *) nil_chk([((OrgSpongycastleAsn1ASN1Primitive *) nil_chk([((id<OrgSpongycastleAsn1ASN1Encodable>) nil_chk(((id<OrgSpongycastleAsn1ASN1Encodable>) cast_check(obj, OrgSpongycastleAsn1ASN1Encodable_class_())))) toASN1Primitive])) toDERObject])) encodedLength];
    }
    self->bodyLength_ = length;
  }
  return self->bodyLength_;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1DERSequence)
