//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x9/X9ECPoint.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/DEROctetString.h"
#include "org/spongycastle/asn1/x9/X9ECPoint.h"
#include "org/spongycastle/math/ec/ECCurve.h"
#include "org/spongycastle/math/ec/ECPoint.h"
#include "org/spongycastle/util/Arrays.h"

@interface OrgSpongycastleAsn1X9X9ECPoint () {
 @public
  OrgSpongycastleAsn1ASN1OctetString *encoding_;
  OrgSpongycastleMathEcECCurve *c_;
  OrgSpongycastleMathEcECPoint *p_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X9X9ECPoint, encoding_, OrgSpongycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X9X9ECPoint, c_, OrgSpongycastleMathEcECCurve *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X9X9ECPoint, p_, OrgSpongycastleMathEcECPoint *)

@implementation OrgSpongycastleAsn1X9X9ECPoint

- (instancetype)initWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)p {
  OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECPoint_(self, p);
  return self;
}

- (instancetype)initWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)p
                                         withBoolean:(jboolean)compressed {
  OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECPoint_withBoolean_(self, p, compressed);
  return self;
}

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)c
                                       withByteArray:(IOSByteArray *)encoding {
  OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECCurve_withByteArray_(self, c, encoding);
  return self;
}

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)c
              withOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)s {
  OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleAsn1ASN1OctetString_(self, c, s);
  return self;
}

- (IOSByteArray *)getPointEncoding {
  return OrgSpongycastleUtilArrays_cloneWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(encoding_)) getOctets]);
}

- (OrgSpongycastleMathEcECPoint *)getPoint {
  @synchronized(self) {
    if (p_ == nil) {
      p_ = [((OrgSpongycastleMathEcECPoint *) nil_chk([((OrgSpongycastleMathEcECCurve *) nil_chk(c_)) decodePointWithByteArray:[((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(encoding_)) getOctets]])) normalize];
    }
    return p_;
  }
}

- (jboolean)isPointCompressed {
  IOSByteArray *octets = [((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(encoding_)) getOctets];
  return octets != nil && octets->size_ > 0 && (IOSByteArray_Get(octets, 0) == 2 || IOSByteArray_Get(octets, 0) == 3);
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  return encoding_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x21, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleMathEcECPoint:);
  methods[1].selector = @selector(initWithOrgSpongycastleMathEcECPoint:withBoolean:);
  methods[2].selector = @selector(initWithOrgSpongycastleMathEcECCurve:withByteArray:);
  methods[3].selector = @selector(initWithOrgSpongycastleMathEcECCurve:withOrgSpongycastleAsn1ASN1OctetString:);
  methods[4].selector = @selector(getPointEncoding);
  methods[5].selector = @selector(getPoint);
  methods[6].selector = @selector(isPointCompressed);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "encoding_", "LOrgSpongycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "c_", "LOrgSpongycastleMathEcECCurve;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "p_", "LOrgSpongycastleMathEcECPoint;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleMathEcECPoint;", "LOrgSpongycastleMathEcECPoint;Z", "LOrgSpongycastleMathEcECCurve;[B", "LOrgSpongycastleMathEcECCurve;LOrgSpongycastleAsn1ASN1OctetString;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X9X9ECPoint = { "X9ECPoint", "org.spongycastle.asn1.x9", ptrTable, methods, fields, 7, 0x1, 8, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X9X9ECPoint;
}

@end

void OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECPoint_(OrgSpongycastleAsn1X9X9ECPoint *self, OrgSpongycastleMathEcECPoint *p) {
  OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECPoint_withBoolean_(self, p, false);
}

OrgSpongycastleAsn1X9X9ECPoint *new_OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECPoint_(OrgSpongycastleMathEcECPoint *p) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X9X9ECPoint, initWithOrgSpongycastleMathEcECPoint_, p)
}

OrgSpongycastleAsn1X9X9ECPoint *create_OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECPoint_(OrgSpongycastleMathEcECPoint *p) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X9X9ECPoint, initWithOrgSpongycastleMathEcECPoint_, p)
}

void OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECPoint_withBoolean_(OrgSpongycastleAsn1X9X9ECPoint *self, OrgSpongycastleMathEcECPoint *p, jboolean compressed) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->p_ = [((OrgSpongycastleMathEcECPoint *) nil_chk(p)) normalize];
  self->encoding_ = new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_([p getEncodedWithBoolean:compressed]);
}

OrgSpongycastleAsn1X9X9ECPoint *new_OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECPoint_withBoolean_(OrgSpongycastleMathEcECPoint *p, jboolean compressed) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X9X9ECPoint, initWithOrgSpongycastleMathEcECPoint_withBoolean_, p, compressed)
}

OrgSpongycastleAsn1X9X9ECPoint *create_OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECPoint_withBoolean_(OrgSpongycastleMathEcECPoint *p, jboolean compressed) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X9X9ECPoint, initWithOrgSpongycastleMathEcECPoint_withBoolean_, p, compressed)
}

void OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECCurve_withByteArray_(OrgSpongycastleAsn1X9X9ECPoint *self, OrgSpongycastleMathEcECCurve *c, IOSByteArray *encoding) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->c_ = c;
  self->encoding_ = new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_(OrgSpongycastleUtilArrays_cloneWithByteArray_(encoding));
}

OrgSpongycastleAsn1X9X9ECPoint *new_OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECCurve_withByteArray_(OrgSpongycastleMathEcECCurve *c, IOSByteArray *encoding) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X9X9ECPoint, initWithOrgSpongycastleMathEcECCurve_withByteArray_, c, encoding)
}

OrgSpongycastleAsn1X9X9ECPoint *create_OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECCurve_withByteArray_(OrgSpongycastleMathEcECCurve *c, IOSByteArray *encoding) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X9X9ECPoint, initWithOrgSpongycastleMathEcECCurve_withByteArray_, c, encoding)
}

void OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1X9X9ECPoint *self, OrgSpongycastleMathEcECCurve *c, OrgSpongycastleAsn1ASN1OctetString *s) {
  OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECCurve_withByteArray_(self, c, [((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(s)) getOctets]);
}

OrgSpongycastleAsn1X9X9ECPoint *new_OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleMathEcECCurve *c, OrgSpongycastleAsn1ASN1OctetString *s) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X9X9ECPoint, initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleAsn1ASN1OctetString_, c, s)
}

OrgSpongycastleAsn1X9X9ECPoint *create_OrgSpongycastleAsn1X9X9ECPoint_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleMathEcECCurve *c, OrgSpongycastleAsn1ASN1OctetString *s) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X9X9ECPoint, initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleAsn1ASN1OctetString_, c, s)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X9X9ECPoint)