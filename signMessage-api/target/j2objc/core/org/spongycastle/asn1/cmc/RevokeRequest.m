//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmc/RevokeRequest.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1GeneralizedTime.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/DERUTF8String.h"
#include "org/spongycastle/asn1/cmc/RevokeRequest.h"
#include "org/spongycastle/asn1/x500/X500Name.h"
#include "org/spongycastle/asn1/x509/CRLReason.h"
#include "org/spongycastle/util/Arrays.h"

@interface OrgSpongycastleAsn1CmcRevokeRequest () {
 @public
  OrgSpongycastleAsn1X500X500Name *name_;
  OrgSpongycastleAsn1ASN1Integer *serialNumber_;
  OrgSpongycastleAsn1X509CRLReason *reason_;
  OrgSpongycastleAsn1ASN1GeneralizedTime *invalidityDate_;
  OrgSpongycastleAsn1ASN1OctetString *passphrase_;
  OrgSpongycastleAsn1DERUTF8String *comment_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcRevokeRequest, name_, OrgSpongycastleAsn1X500X500Name *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcRevokeRequest, serialNumber_, OrgSpongycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcRevokeRequest, reason_, OrgSpongycastleAsn1X509CRLReason *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcRevokeRequest, invalidityDate_, OrgSpongycastleAsn1ASN1GeneralizedTime *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcRevokeRequest, passphrase_, OrgSpongycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcRevokeRequest, comment_, OrgSpongycastleAsn1DERUTF8String *)

__attribute__((unused)) static void OrgSpongycastleAsn1CmcRevokeRequest_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmcRevokeRequest *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1CmcRevokeRequest *new_OrgSpongycastleAsn1CmcRevokeRequest_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CmcRevokeRequest *create_OrgSpongycastleAsn1CmcRevokeRequest_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1CmcRevokeRequest

- (instancetype)initWithOrgSpongycastleAsn1X500X500Name:(OrgSpongycastleAsn1X500X500Name *)name
                     withOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)serialNumber
                   withOrgSpongycastleAsn1X509CRLReason:(OrgSpongycastleAsn1X509CRLReason *)reason
             withOrgSpongycastleAsn1ASN1GeneralizedTime:(OrgSpongycastleAsn1ASN1GeneralizedTime *)invalidityDate
                 withOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)passphrase
                   withOrgSpongycastleAsn1DERUTF8String:(OrgSpongycastleAsn1DERUTF8String *)comment {
  OrgSpongycastleAsn1CmcRevokeRequest_initWithOrgSpongycastleAsn1X500X500Name_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1X509CRLReason_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1DERUTF8String_(self, name, serialNumber, reason, invalidityDate, passphrase, comment);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CmcRevokeRequest_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (OrgSpongycastleAsn1CmcRevokeRequest *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CmcRevokeRequest_getInstanceWithId_(o);
}

- (OrgSpongycastleAsn1X500X500Name *)getName {
  return name_;
}

- (JavaMathBigInteger *)getSerialNumber {
  return [((OrgSpongycastleAsn1ASN1Integer *) nil_chk(serialNumber_)) getValue];
}

- (OrgSpongycastleAsn1X509CRLReason *)getReason {
  return reason_;
}

- (OrgSpongycastleAsn1ASN1GeneralizedTime *)getInvalidityDate {
  return invalidityDate_;
}

- (void)setInvalidityDateWithOrgSpongycastleAsn1ASN1GeneralizedTime:(OrgSpongycastleAsn1ASN1GeneralizedTime *)invalidityDate {
  self->invalidityDate_ = invalidityDate;
}

- (OrgSpongycastleAsn1ASN1OctetString *)getPassphrase {
  return passphrase_;
}

- (void)setPassphraseWithOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)passphrase {
  self->passphrase_ = passphrase;
}

- (OrgSpongycastleAsn1DERUTF8String *)getComment {
  return comment_;
}

- (void)setCommentWithOrgSpongycastleAsn1DERUTF8String:(OrgSpongycastleAsn1DERUTF8String *)comment {
  self->comment_ = comment;
}

- (IOSByteArray *)getPassPhrase {
  if (passphrase_ != nil) {
    return OrgSpongycastleUtilArrays_cloneWithByteArray_([passphrase_ getOctets]);
  }
  return nil;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:name_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:serialNumber_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:reason_];
  if (invalidityDate_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:invalidityDate_];
  }
  if (passphrase_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:passphrase_];
  }
  if (comment_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:comment_];
  }
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmcRevokeRequest;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X500X500Name;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509CRLReason;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1GeneralizedTime;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1DERUTF8String;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 8, 9, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1X500X500Name:withOrgSpongycastleAsn1ASN1Integer:withOrgSpongycastleAsn1X509CRLReason:withOrgSpongycastleAsn1ASN1GeneralizedTime:withOrgSpongycastleAsn1ASN1OctetString:withOrgSpongycastleAsn1DERUTF8String:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getName);
  methods[4].selector = @selector(getSerialNumber);
  methods[5].selector = @selector(getReason);
  methods[6].selector = @selector(getInvalidityDate);
  methods[7].selector = @selector(setInvalidityDateWithOrgSpongycastleAsn1ASN1GeneralizedTime:);
  methods[8].selector = @selector(getPassphrase);
  methods[9].selector = @selector(setPassphraseWithOrgSpongycastleAsn1ASN1OctetString:);
  methods[10].selector = @selector(getComment);
  methods[11].selector = @selector(setCommentWithOrgSpongycastleAsn1DERUTF8String:);
  methods[12].selector = @selector(getPassPhrase);
  methods[13].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "name_", "LOrgSpongycastleAsn1X500X500Name;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "serialNumber_", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "reason_", "LOrgSpongycastleAsn1X509CRLReason;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "invalidityDate_", "LOrgSpongycastleAsn1ASN1GeneralizedTime;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "passphrase_", "LOrgSpongycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "comment_", "LOrgSpongycastleAsn1DERUTF8String;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1X500X500Name;LOrgSpongycastleAsn1ASN1Integer;LOrgSpongycastleAsn1X509CRLReason;LOrgSpongycastleAsn1ASN1GeneralizedTime;LOrgSpongycastleAsn1ASN1OctetString;LOrgSpongycastleAsn1DERUTF8String;", "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "setInvalidityDate", "LOrgSpongycastleAsn1ASN1GeneralizedTime;", "setPassphrase", "LOrgSpongycastleAsn1ASN1OctetString;", "setComment", "LOrgSpongycastleAsn1DERUTF8String;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmcRevokeRequest = { "RevokeRequest", "org.spongycastle.asn1.cmc", ptrTable, methods, fields, 7, 0x1, 14, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmcRevokeRequest;
}

@end

void OrgSpongycastleAsn1CmcRevokeRequest_initWithOrgSpongycastleAsn1X500X500Name_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1X509CRLReason_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1DERUTF8String_(OrgSpongycastleAsn1CmcRevokeRequest *self, OrgSpongycastleAsn1X500X500Name *name, OrgSpongycastleAsn1ASN1Integer *serialNumber, OrgSpongycastleAsn1X509CRLReason *reason, OrgSpongycastleAsn1ASN1GeneralizedTime *invalidityDate, OrgSpongycastleAsn1ASN1OctetString *passphrase, OrgSpongycastleAsn1DERUTF8String *comment) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->name_ = name;
  self->serialNumber_ = serialNumber;
  self->reason_ = reason;
  self->invalidityDate_ = invalidityDate;
  self->passphrase_ = passphrase;
  self->comment_ = comment;
}

OrgSpongycastleAsn1CmcRevokeRequest *new_OrgSpongycastleAsn1CmcRevokeRequest_initWithOrgSpongycastleAsn1X500X500Name_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1X509CRLReason_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1DERUTF8String_(OrgSpongycastleAsn1X500X500Name *name, OrgSpongycastleAsn1ASN1Integer *serialNumber, OrgSpongycastleAsn1X509CRLReason *reason, OrgSpongycastleAsn1ASN1GeneralizedTime *invalidityDate, OrgSpongycastleAsn1ASN1OctetString *passphrase, OrgSpongycastleAsn1DERUTF8String *comment) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmcRevokeRequest, initWithOrgSpongycastleAsn1X500X500Name_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1X509CRLReason_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1DERUTF8String_, name, serialNumber, reason, invalidityDate, passphrase, comment)
}

OrgSpongycastleAsn1CmcRevokeRequest *create_OrgSpongycastleAsn1CmcRevokeRequest_initWithOrgSpongycastleAsn1X500X500Name_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1X509CRLReason_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1DERUTF8String_(OrgSpongycastleAsn1X500X500Name *name, OrgSpongycastleAsn1ASN1Integer *serialNumber, OrgSpongycastleAsn1X509CRLReason *reason, OrgSpongycastleAsn1ASN1GeneralizedTime *invalidityDate, OrgSpongycastleAsn1ASN1OctetString *passphrase, OrgSpongycastleAsn1DERUTF8String *comment) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmcRevokeRequest, initWithOrgSpongycastleAsn1X500X500Name_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1X509CRLReason_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1DERUTF8String_, name, serialNumber, reason, invalidityDate, passphrase, comment)
}

void OrgSpongycastleAsn1CmcRevokeRequest_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmcRevokeRequest *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size] < 3 || [seq size] > 6) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"incorrect sequence size");
  }
  self->name_ = OrgSpongycastleAsn1X500X500Name_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->serialNumber_ = OrgSpongycastleAsn1ASN1Integer_getInstanceWithId_([seq getObjectAtWithInt:1]);
  self->reason_ = OrgSpongycastleAsn1X509CRLReason_getInstanceWithId_([seq getObjectAtWithInt:2]);
  jint index = 3;
  if ([seq size] > index && [[((id<OrgSpongycastleAsn1ASN1Encodable>) nil_chk([seq getObjectAtWithInt:index])) toASN1Primitive] isKindOfClass:[OrgSpongycastleAsn1ASN1GeneralizedTime class]]) {
    self->invalidityDate_ = OrgSpongycastleAsn1ASN1GeneralizedTime_getInstanceWithId_([seq getObjectAtWithInt:index++]);
  }
  if ([seq size] > index && [[((id<OrgSpongycastleAsn1ASN1Encodable>) nil_chk([seq getObjectAtWithInt:index])) toASN1Primitive] isKindOfClass:[OrgSpongycastleAsn1ASN1OctetString class]]) {
    self->passphrase_ = OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:index++]);
  }
  if ([seq size] > index && [[((id<OrgSpongycastleAsn1ASN1Encodable>) nil_chk([seq getObjectAtWithInt:index])) toASN1Primitive] isKindOfClass:[OrgSpongycastleAsn1DERUTF8String class]]) {
    self->comment_ = OrgSpongycastleAsn1DERUTF8String_getInstanceWithId_([seq getObjectAtWithInt:index]);
  }
}

OrgSpongycastleAsn1CmcRevokeRequest *new_OrgSpongycastleAsn1CmcRevokeRequest_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmcRevokeRequest, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmcRevokeRequest *create_OrgSpongycastleAsn1CmcRevokeRequest_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmcRevokeRequest, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmcRevokeRequest *OrgSpongycastleAsn1CmcRevokeRequest_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CmcRevokeRequest_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1CmcRevokeRequest class]]) {
    return (OrgSpongycastleAsn1CmcRevokeRequest *) o;
  }
  if (o != nil) {
    return new_OrgSpongycastleAsn1CmcRevokeRequest_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmcRevokeRequest)