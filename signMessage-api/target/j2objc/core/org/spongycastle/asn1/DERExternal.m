//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/DERExternal.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Encoding.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1OutputStream.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/BERTags.h"
#include "org/spongycastle/asn1/DERExternal.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"

@interface OrgSpongycastleAsn1DERExternal () {
 @public
  OrgSpongycastleAsn1ASN1ObjectIdentifier *directReference_;
  OrgSpongycastleAsn1ASN1Integer *indirectReference_;
  OrgSpongycastleAsn1ASN1Primitive *dataValueDescriptor_;
  jint encoding_;
  OrgSpongycastleAsn1ASN1Primitive *externalContent_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)getObjFromVectorWithOrgSpongycastleAsn1ASN1EncodableVector:(OrgSpongycastleAsn1ASN1EncodableVector *)v
                                                                                         withInt:(jint)index;

- (void)setDataValueDescriptorWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)dataValueDescriptor;

- (void)setDirectReferenceWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)directReferemce;

- (void)setEncodingWithInt:(jint)encoding;

- (void)setExternalContentWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)externalContent;

- (void)setIndirectReferenceWithOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)indirectReference;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1DERExternal, directReference_, OrgSpongycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1DERExternal, indirectReference_, OrgSpongycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1DERExternal, dataValueDescriptor_, OrgSpongycastleAsn1ASN1Primitive *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1DERExternal, externalContent_, OrgSpongycastleAsn1ASN1Primitive *)

__attribute__((unused)) static OrgSpongycastleAsn1ASN1Primitive *OrgSpongycastleAsn1DERExternal_getObjFromVectorWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_(OrgSpongycastleAsn1DERExternal *self, OrgSpongycastleAsn1ASN1EncodableVector *v, jint index);

__attribute__((unused)) static void OrgSpongycastleAsn1DERExternal_setDataValueDescriptorWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1DERExternal *self, OrgSpongycastleAsn1ASN1Primitive *dataValueDescriptor);

__attribute__((unused)) static void OrgSpongycastleAsn1DERExternal_setDirectReferenceWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(OrgSpongycastleAsn1DERExternal *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *directReferemce);

__attribute__((unused)) static void OrgSpongycastleAsn1DERExternal_setEncodingWithInt_(OrgSpongycastleAsn1DERExternal *self, jint encoding);

__attribute__((unused)) static void OrgSpongycastleAsn1DERExternal_setExternalContentWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1DERExternal *self, OrgSpongycastleAsn1ASN1Primitive *externalContent);

__attribute__((unused)) static void OrgSpongycastleAsn1DERExternal_setIndirectReferenceWithOrgSpongycastleAsn1ASN1Integer_(OrgSpongycastleAsn1DERExternal *self, OrgSpongycastleAsn1ASN1Integer *indirectReference);

@implementation OrgSpongycastleAsn1DERExternal

- (instancetype)initWithOrgSpongycastleAsn1ASN1EncodableVector:(OrgSpongycastleAsn1ASN1EncodableVector *)vector {
  OrgSpongycastleAsn1DERExternal_initWithOrgSpongycastleAsn1ASN1EncodableVector_(self, vector);
  return self;
}

- (OrgSpongycastleAsn1ASN1Primitive *)getObjFromVectorWithOrgSpongycastleAsn1ASN1EncodableVector:(OrgSpongycastleAsn1ASN1EncodableVector *)v
                                                                                         withInt:(jint)index {
  return OrgSpongycastleAsn1DERExternal_getObjFromVectorWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_(self, v, index);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)directReference
                             withOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)indirectReference
                           withOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)dataValueDescriptor
                         withOrgSpongycastleAsn1DERTaggedObject:(OrgSpongycastleAsn1DERTaggedObject *)externalData {
  OrgSpongycastleAsn1DERExternal_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Primitive_withOrgSpongycastleAsn1DERTaggedObject_(self, directReference, indirectReference, dataValueDescriptor, externalData);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)directReference
                             withOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)indirectReference
                           withOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)dataValueDescriptor
                                                        withInt:(jint)encoding
                           withOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)externalData {
  OrgSpongycastleAsn1DERExternal_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Primitive_withInt_withOrgSpongycastleAsn1ASN1Primitive_(self, directReference, indirectReference, dataValueDescriptor, encoding, externalData);
  return self;
}

- (NSUInteger)hash {
  jint ret = 0;
  if (directReference_ != nil) {
    ret = ((jint) [directReference_ hash]);
  }
  if (indirectReference_ != nil) {
    ret ^= ((jint) [indirectReference_ hash]);
  }
  if (dataValueDescriptor_ != nil) {
    ret ^= ((jint) [dataValueDescriptor_ hash]);
  }
  ret ^= ((jint) [((OrgSpongycastleAsn1ASN1Primitive *) nil_chk(externalContent_)) hash]);
  return ret;
}

- (jboolean)isConstructed {
  return true;
}

- (jint)encodedLength {
  return ((IOSByteArray *) nil_chk([self getEncoded]))->size_;
}

- (void)encodeWithOrgSpongycastleAsn1ASN1OutputStream:(OrgSpongycastleAsn1ASN1OutputStream *)outArg {
  JavaIoByteArrayOutputStream *baos = new_JavaIoByteArrayOutputStream_init();
  if (directReference_ != nil) {
    [baos writeWithByteArray:[directReference_ getEncodedWithNSString:OrgSpongycastleAsn1ASN1Encoding_DER]];
  }
  if (indirectReference_ != nil) {
    [baos writeWithByteArray:[indirectReference_ getEncodedWithNSString:OrgSpongycastleAsn1ASN1Encoding_DER]];
  }
  if (dataValueDescriptor_ != nil) {
    [baos writeWithByteArray:[dataValueDescriptor_ getEncodedWithNSString:OrgSpongycastleAsn1ASN1Encoding_DER]];
  }
  OrgSpongycastleAsn1DERTaggedObject *obj = new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(true, encoding_, externalContent_);
  [baos writeWithByteArray:[obj getEncodedWithNSString:OrgSpongycastleAsn1ASN1Encoding_DER]];
  [((OrgSpongycastleAsn1ASN1OutputStream *) nil_chk(outArg)) writeEncodedWithInt:OrgSpongycastleAsn1BERTags_CONSTRUCTED withInt:OrgSpongycastleAsn1BERTags_EXTERNAL withByteArray:[baos toByteArray]];
}

- (jboolean)asn1EqualsWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)o {
  if (!([o isKindOfClass:[OrgSpongycastleAsn1DERExternal class]])) {
    return false;
  }
  if (self == o) {
    return true;
  }
  OrgSpongycastleAsn1DERExternal *other = (OrgSpongycastleAsn1DERExternal *) cast_chk(o, [OrgSpongycastleAsn1DERExternal class]);
  if (directReference_ != nil) {
    if (((OrgSpongycastleAsn1DERExternal *) nil_chk(other))->directReference_ == nil || ![other->directReference_ isEqual:directReference_]) {
      return false;
    }
  }
  if (indirectReference_ != nil) {
    if (((OrgSpongycastleAsn1DERExternal *) nil_chk(other))->indirectReference_ == nil || ![other->indirectReference_ isEqual:indirectReference_]) {
      return false;
    }
  }
  if (dataValueDescriptor_ != nil) {
    if (((OrgSpongycastleAsn1DERExternal *) nil_chk(other))->dataValueDescriptor_ == nil || ![other->dataValueDescriptor_ isEqual:dataValueDescriptor_]) {
      return false;
    }
  }
  return [((OrgSpongycastleAsn1ASN1Primitive *) nil_chk(externalContent_)) isEqual:((OrgSpongycastleAsn1DERExternal *) nil_chk(other))->externalContent_];
}

- (OrgSpongycastleAsn1ASN1Primitive *)getDataValueDescriptor {
  return dataValueDescriptor_;
}

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getDirectReference {
  return directReference_;
}

- (jint)getEncoding {
  return encoding_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)getExternalContent {
  return externalContent_;
}

- (OrgSpongycastleAsn1ASN1Integer *)getIndirectReference {
  return indirectReference_;
}

- (void)setDataValueDescriptorWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)dataValueDescriptor {
  OrgSpongycastleAsn1DERExternal_setDataValueDescriptorWithOrgSpongycastleAsn1ASN1Primitive_(self, dataValueDescriptor);
}

- (void)setDirectReferenceWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)directReferemce {
  OrgSpongycastleAsn1DERExternal_setDirectReferenceWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(self, directReferemce);
}

- (void)setEncodingWithInt:(jint)encoding {
  OrgSpongycastleAsn1DERExternal_setEncodingWithInt_(self, encoding);
}

- (void)setExternalContentWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)externalContent {
  OrgSpongycastleAsn1DERExternal_setExternalContentWithOrgSpongycastleAsn1ASN1Primitive_(self, externalContent);
}

- (void)setIndirectReferenceWithOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)indirectReference {
  OrgSpongycastleAsn1DERExternal_setIndirectReferenceWithOrgSpongycastleAsn1ASN1Integer_(self, indirectReference);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x2, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 5, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, 6, -1, -1, -1 },
    { NULL, "V", 0x0, 7, 8, 6, -1, -1, -1 },
    { NULL, "Z", 0x0, 9, 10, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 11, 10, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 12, 13, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 14, 15, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 16, 10, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 17, 18, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1EncodableVector:);
  methods[1].selector = @selector(getObjFromVectorWithOrgSpongycastleAsn1ASN1EncodableVector:withInt:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withOrgSpongycastleAsn1ASN1Integer:withOrgSpongycastleAsn1ASN1Primitive:withOrgSpongycastleAsn1DERTaggedObject:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withOrgSpongycastleAsn1ASN1Integer:withOrgSpongycastleAsn1ASN1Primitive:withInt:withOrgSpongycastleAsn1ASN1Primitive:);
  methods[4].selector = @selector(hash);
  methods[5].selector = @selector(isConstructed);
  methods[6].selector = @selector(encodedLength);
  methods[7].selector = @selector(encodeWithOrgSpongycastleAsn1ASN1OutputStream:);
  methods[8].selector = @selector(asn1EqualsWithOrgSpongycastleAsn1ASN1Primitive:);
  methods[9].selector = @selector(getDataValueDescriptor);
  methods[10].selector = @selector(getDirectReference);
  methods[11].selector = @selector(getEncoding);
  methods[12].selector = @selector(getExternalContent);
  methods[13].selector = @selector(getIndirectReference);
  methods[14].selector = @selector(setDataValueDescriptorWithOrgSpongycastleAsn1ASN1Primitive:);
  methods[15].selector = @selector(setDirectReferenceWithOrgSpongycastleAsn1ASN1ObjectIdentifier:);
  methods[16].selector = @selector(setEncodingWithInt:);
  methods[17].selector = @selector(setExternalContentWithOrgSpongycastleAsn1ASN1Primitive:);
  methods[18].selector = @selector(setIndirectReferenceWithOrgSpongycastleAsn1ASN1Integer:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "directReference_", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "indirectReference_", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "dataValueDescriptor_", "LOrgSpongycastleAsn1ASN1Primitive;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "encoding_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "externalContent_", "LOrgSpongycastleAsn1ASN1Primitive;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1EncodableVector;", "getObjFromVector", "LOrgSpongycastleAsn1ASN1EncodableVector;I", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;LOrgSpongycastleAsn1ASN1Integer;LOrgSpongycastleAsn1ASN1Primitive;LOrgSpongycastleAsn1DERTaggedObject;", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;LOrgSpongycastleAsn1ASN1Integer;LOrgSpongycastleAsn1ASN1Primitive;ILOrgSpongycastleAsn1ASN1Primitive;", "hashCode", "LJavaIoIOException;", "encode", "LOrgSpongycastleAsn1ASN1OutputStream;", "asn1Equals", "LOrgSpongycastleAsn1ASN1Primitive;", "setDataValueDescriptor", "setDirectReference", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", "setEncoding", "I", "setExternalContent", "setIndirectReference", "LOrgSpongycastleAsn1ASN1Integer;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1DERExternal = { "DERExternal", "org.spongycastle.asn1", ptrTable, methods, fields, 7, 0x1, 19, 5, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1DERExternal;
}

@end

void OrgSpongycastleAsn1DERExternal_initWithOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1DERExternal *self, OrgSpongycastleAsn1ASN1EncodableVector *vector) {
  OrgSpongycastleAsn1ASN1Primitive_init(self);
  jint offset = 0;
  OrgSpongycastleAsn1ASN1Primitive *enc = OrgSpongycastleAsn1DERExternal_getObjFromVectorWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_(self, vector, offset);
  if ([enc isKindOfClass:[OrgSpongycastleAsn1ASN1ObjectIdentifier class]]) {
    self->directReference_ = (OrgSpongycastleAsn1ASN1ObjectIdentifier *) enc;
    offset++;
    enc = OrgSpongycastleAsn1DERExternal_getObjFromVectorWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_(self, vector, offset);
  }
  if ([enc isKindOfClass:[OrgSpongycastleAsn1ASN1Integer class]]) {
    self->indirectReference_ = (OrgSpongycastleAsn1ASN1Integer *) enc;
    offset++;
    enc = OrgSpongycastleAsn1DERExternal_getObjFromVectorWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_(self, vector, offset);
  }
  if (!([enc isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]])) {
    self->dataValueDescriptor_ = enc;
    offset++;
    enc = OrgSpongycastleAsn1DERExternal_getObjFromVectorWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_(self, vector, offset);
  }
  if ([((OrgSpongycastleAsn1ASN1EncodableVector *) nil_chk(vector)) size] != offset + 1) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"input vector too large");
  }
  if (!([enc isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]])) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"No tagged object found in vector. Structure doesn't seem to be of type External");
  }
  OrgSpongycastleAsn1ASN1TaggedObject *obj = (OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk(enc, [OrgSpongycastleAsn1ASN1TaggedObject class]);
  OrgSpongycastleAsn1DERExternal_setEncodingWithInt_(self, [((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(obj)) getTagNo]);
  self->externalContent_ = [obj getObject];
}

OrgSpongycastleAsn1DERExternal *new_OrgSpongycastleAsn1DERExternal_initWithOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1ASN1EncodableVector *vector) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DERExternal, initWithOrgSpongycastleAsn1ASN1EncodableVector_, vector)
}

OrgSpongycastleAsn1DERExternal *create_OrgSpongycastleAsn1DERExternal_initWithOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1ASN1EncodableVector *vector) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DERExternal, initWithOrgSpongycastleAsn1ASN1EncodableVector_, vector)
}

OrgSpongycastleAsn1ASN1Primitive *OrgSpongycastleAsn1DERExternal_getObjFromVectorWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_(OrgSpongycastleAsn1DERExternal *self, OrgSpongycastleAsn1ASN1EncodableVector *v, jint index) {
  if ([((OrgSpongycastleAsn1ASN1EncodableVector *) nil_chk(v)) size] <= index) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"too few objects in input vector");
  }
  return [((id<OrgSpongycastleAsn1ASN1Encodable>) nil_chk([v getWithInt:index])) toASN1Primitive];
}

void OrgSpongycastleAsn1DERExternal_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Primitive_withOrgSpongycastleAsn1DERTaggedObject_(OrgSpongycastleAsn1DERExternal *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *directReference, OrgSpongycastleAsn1ASN1Integer *indirectReference, OrgSpongycastleAsn1ASN1Primitive *dataValueDescriptor, OrgSpongycastleAsn1DERTaggedObject *externalData) {
  OrgSpongycastleAsn1DERExternal_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Primitive_withInt_withOrgSpongycastleAsn1ASN1Primitive_(self, directReference, indirectReference, dataValueDescriptor, [((OrgSpongycastleAsn1DERTaggedObject *) nil_chk(externalData)) getTagNo], [externalData toASN1Primitive]);
}

OrgSpongycastleAsn1DERExternal *new_OrgSpongycastleAsn1DERExternal_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Primitive_withOrgSpongycastleAsn1DERTaggedObject_(OrgSpongycastleAsn1ASN1ObjectIdentifier *directReference, OrgSpongycastleAsn1ASN1Integer *indirectReference, OrgSpongycastleAsn1ASN1Primitive *dataValueDescriptor, OrgSpongycastleAsn1DERTaggedObject *externalData) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DERExternal, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Primitive_withOrgSpongycastleAsn1DERTaggedObject_, directReference, indirectReference, dataValueDescriptor, externalData)
}

OrgSpongycastleAsn1DERExternal *create_OrgSpongycastleAsn1DERExternal_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Primitive_withOrgSpongycastleAsn1DERTaggedObject_(OrgSpongycastleAsn1ASN1ObjectIdentifier *directReference, OrgSpongycastleAsn1ASN1Integer *indirectReference, OrgSpongycastleAsn1ASN1Primitive *dataValueDescriptor, OrgSpongycastleAsn1DERTaggedObject *externalData) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DERExternal, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Primitive_withOrgSpongycastleAsn1DERTaggedObject_, directReference, indirectReference, dataValueDescriptor, externalData)
}

void OrgSpongycastleAsn1DERExternal_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Primitive_withInt_withOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1DERExternal *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *directReference, OrgSpongycastleAsn1ASN1Integer *indirectReference, OrgSpongycastleAsn1ASN1Primitive *dataValueDescriptor, jint encoding, OrgSpongycastleAsn1ASN1Primitive *externalData) {
  OrgSpongycastleAsn1ASN1Primitive_init(self);
  OrgSpongycastleAsn1DERExternal_setDirectReferenceWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(self, directReference);
  OrgSpongycastleAsn1DERExternal_setIndirectReferenceWithOrgSpongycastleAsn1ASN1Integer_(self, indirectReference);
  OrgSpongycastleAsn1DERExternal_setDataValueDescriptorWithOrgSpongycastleAsn1ASN1Primitive_(self, dataValueDescriptor);
  OrgSpongycastleAsn1DERExternal_setEncodingWithInt_(self, encoding);
  OrgSpongycastleAsn1DERExternal_setExternalContentWithOrgSpongycastleAsn1ASN1Primitive_(self, [((OrgSpongycastleAsn1ASN1Primitive *) nil_chk(externalData)) toASN1Primitive]);
}

OrgSpongycastleAsn1DERExternal *new_OrgSpongycastleAsn1DERExternal_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Primitive_withInt_withOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1ASN1ObjectIdentifier *directReference, OrgSpongycastleAsn1ASN1Integer *indirectReference, OrgSpongycastleAsn1ASN1Primitive *dataValueDescriptor, jint encoding, OrgSpongycastleAsn1ASN1Primitive *externalData) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DERExternal, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Primitive_withInt_withOrgSpongycastleAsn1ASN1Primitive_, directReference, indirectReference, dataValueDescriptor, encoding, externalData)
}

OrgSpongycastleAsn1DERExternal *create_OrgSpongycastleAsn1DERExternal_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Primitive_withInt_withOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1ASN1ObjectIdentifier *directReference, OrgSpongycastleAsn1ASN1Integer *indirectReference, OrgSpongycastleAsn1ASN1Primitive *dataValueDescriptor, jint encoding, OrgSpongycastleAsn1ASN1Primitive *externalData) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DERExternal, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Primitive_withInt_withOrgSpongycastleAsn1ASN1Primitive_, directReference, indirectReference, dataValueDescriptor, encoding, externalData)
}

void OrgSpongycastleAsn1DERExternal_setDataValueDescriptorWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1DERExternal *self, OrgSpongycastleAsn1ASN1Primitive *dataValueDescriptor) {
  self->dataValueDescriptor_ = dataValueDescriptor;
}

void OrgSpongycastleAsn1DERExternal_setDirectReferenceWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(OrgSpongycastleAsn1DERExternal *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *directReferemce) {
  self->directReference_ = directReferemce;
}

void OrgSpongycastleAsn1DERExternal_setEncodingWithInt_(OrgSpongycastleAsn1DERExternal *self, jint encoding) {
  if (encoding < 0 || encoding > 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"invalid encoding value: ", encoding));
  }
  self->encoding_ = encoding;
}

void OrgSpongycastleAsn1DERExternal_setExternalContentWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1DERExternal *self, OrgSpongycastleAsn1ASN1Primitive *externalContent) {
  self->externalContent_ = externalContent;
}

void OrgSpongycastleAsn1DERExternal_setIndirectReferenceWithOrgSpongycastleAsn1ASN1Integer_(OrgSpongycastleAsn1DERExternal *self, OrgSpongycastleAsn1ASN1Integer *indirectReference) {
  self->indirectReference_ = indirectReference;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1DERExternal)
