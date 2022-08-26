//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/dvcs/Data.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DEROctetString.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/dvcs/Data.h"
#include "org/spongycastle/asn1/dvcs/TargetEtcChain.h"
#include "org/spongycastle/asn1/x509/DigestInfo.h"

@interface OrgSpongycastleAsn1DvcsData () {
 @public
  OrgSpongycastleAsn1ASN1OctetString *message_;
  OrgSpongycastleAsn1X509DigestInfo *messageImprint_;
  OrgSpongycastleAsn1ASN1Sequence *certs_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)certs;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1DvcsData, message_, OrgSpongycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1DvcsData, messageImprint_, OrgSpongycastleAsn1X509DigestInfo *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1DvcsData, certs_, OrgSpongycastleAsn1ASN1Sequence *)

__attribute__((unused)) static void OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1DvcsData *self, OrgSpongycastleAsn1ASN1Sequence *certs);

__attribute__((unused)) static OrgSpongycastleAsn1DvcsData *new_OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *certs) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1DvcsData *create_OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *certs);

@implementation OrgSpongycastleAsn1DvcsData

- (instancetype)initWithByteArray:(IOSByteArray *)messageBytes {
  OrgSpongycastleAsn1DvcsData_initWithByteArray_(self, messageBytes);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)message {
  OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1ASN1OctetString_(self, message);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1X509DigestInfo:(OrgSpongycastleAsn1X509DigestInfo *)messageImprint {
  OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1X509DigestInfo_(self, messageImprint);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1DvcsTargetEtcChain:(OrgSpongycastleAsn1DvcsTargetEtcChain *)cert {
  OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1DvcsTargetEtcChain_(self, cert);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1DvcsTargetEtcChainArray:(IOSObjectArray *)certs {
  OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1DvcsTargetEtcChainArray_(self, certs);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)certs {
  OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1ASN1Sequence_(self, certs);
  return self;
}

+ (OrgSpongycastleAsn1DvcsData *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1DvcsData_getInstanceWithId_(obj);
}

+ (OrgSpongycastleAsn1DvcsData *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                        withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1DvcsData_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  if (message_ != nil) {
    return [message_ toASN1Primitive];
  }
  if (messageImprint_ != nil) {
    return [messageImprint_ toASN1Primitive];
  }
  else {
    return new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 0, certs_);
  }
}

- (NSString *)description {
  if (message_ != nil) {
    return JreStrcat("$@$", @"Data {\n", message_, @"}\n");
  }
  if (messageImprint_ != nil) {
    return JreStrcat("$@$", @"Data {\n", messageImprint_, @"}\n");
  }
  else {
    return JreStrcat("$@$", @"Data {\n", certs_, @"}\n");
  }
}

- (OrgSpongycastleAsn1ASN1OctetString *)getMessage {
  return message_;
}

- (OrgSpongycastleAsn1X509DigestInfo *)getMessageImprint {
  return messageImprint_;
}

- (IOSObjectArray *)getCerts {
  if (certs_ == nil) {
    return nil;
  }
  IOSObjectArray *tmp = [IOSObjectArray newArrayWithLength:[certs_ size] type:OrgSpongycastleAsn1DvcsTargetEtcChain_class_()];
  for (jint i = 0; i != tmp->size_; i++) {
    (void) IOSObjectArray_Set(tmp, i, OrgSpongycastleAsn1DvcsTargetEtcChain_getInstanceWithId_([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(certs_)) getObjectAtWithInt:i]));
  }
  return tmp;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1DvcsData;", 0x9, 6, 7, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1DvcsData;", 0x9, 6, 8, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 9, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509DigestInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1DvcsTargetEtcChain;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1OctetString:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1X509DigestInfo:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1DvcsTargetEtcChain:);
  methods[4].selector = @selector(initWithOrgSpongycastleAsn1DvcsTargetEtcChainArray:);
  methods[5].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[6].selector = @selector(getInstanceWithId:);
  methods[7].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[8].selector = @selector(toASN1Primitive);
  methods[9].selector = @selector(description);
  methods[10].selector = @selector(getMessage);
  methods[11].selector = @selector(getMessageImprint);
  methods[12].selector = @selector(getCerts);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "message_", "LOrgSpongycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "messageImprint_", "LOrgSpongycastleAsn1X509DigestInfo;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "certs_", "LOrgSpongycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[B", "LOrgSpongycastleAsn1ASN1OctetString;", "LOrgSpongycastleAsn1X509DigestInfo;", "LOrgSpongycastleAsn1DvcsTargetEtcChain;", "[LOrgSpongycastleAsn1DvcsTargetEtcChain;", "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "toString" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1DvcsData = { "Data", "org.spongycastle.asn1.dvcs", ptrTable, methods, fields, 7, 0x1, 13, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1DvcsData;
}

@end

void OrgSpongycastleAsn1DvcsData_initWithByteArray_(OrgSpongycastleAsn1DvcsData *self, IOSByteArray *messageBytes) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->message_ = new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_(messageBytes);
}

OrgSpongycastleAsn1DvcsData *new_OrgSpongycastleAsn1DvcsData_initWithByteArray_(IOSByteArray *messageBytes) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DvcsData, initWithByteArray_, messageBytes)
}

OrgSpongycastleAsn1DvcsData *create_OrgSpongycastleAsn1DvcsData_initWithByteArray_(IOSByteArray *messageBytes) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DvcsData, initWithByteArray_, messageBytes)
}

void OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1DvcsData *self, OrgSpongycastleAsn1ASN1OctetString *message) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->message_ = message;
}

OrgSpongycastleAsn1DvcsData *new_OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1OctetString *message) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DvcsData, initWithOrgSpongycastleAsn1ASN1OctetString_, message)
}

OrgSpongycastleAsn1DvcsData *create_OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1OctetString *message) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DvcsData, initWithOrgSpongycastleAsn1ASN1OctetString_, message)
}

void OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1X509DigestInfo_(OrgSpongycastleAsn1DvcsData *self, OrgSpongycastleAsn1X509DigestInfo *messageImprint) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->messageImprint_ = messageImprint;
}

OrgSpongycastleAsn1DvcsData *new_OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1X509DigestInfo_(OrgSpongycastleAsn1X509DigestInfo *messageImprint) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DvcsData, initWithOrgSpongycastleAsn1X509DigestInfo_, messageImprint)
}

OrgSpongycastleAsn1DvcsData *create_OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1X509DigestInfo_(OrgSpongycastleAsn1X509DigestInfo *messageImprint) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DvcsData, initWithOrgSpongycastleAsn1X509DigestInfo_, messageImprint)
}

void OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1DvcsTargetEtcChain_(OrgSpongycastleAsn1DvcsData *self, OrgSpongycastleAsn1DvcsTargetEtcChain *cert) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->certs_ = new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1Encodable_(cert);
}

OrgSpongycastleAsn1DvcsData *new_OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1DvcsTargetEtcChain_(OrgSpongycastleAsn1DvcsTargetEtcChain *cert) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DvcsData, initWithOrgSpongycastleAsn1DvcsTargetEtcChain_, cert)
}

OrgSpongycastleAsn1DvcsData *create_OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1DvcsTargetEtcChain_(OrgSpongycastleAsn1DvcsTargetEtcChain *cert) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DvcsData, initWithOrgSpongycastleAsn1DvcsTargetEtcChain_, cert)
}

void OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1DvcsTargetEtcChainArray_(OrgSpongycastleAsn1DvcsData *self, IOSObjectArray *certs) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->certs_ = new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableArray_(certs);
}

OrgSpongycastleAsn1DvcsData *new_OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1DvcsTargetEtcChainArray_(IOSObjectArray *certs) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DvcsData, initWithOrgSpongycastleAsn1DvcsTargetEtcChainArray_, certs)
}

OrgSpongycastleAsn1DvcsData *create_OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1DvcsTargetEtcChainArray_(IOSObjectArray *certs) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DvcsData, initWithOrgSpongycastleAsn1DvcsTargetEtcChainArray_, certs)
}

void OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1DvcsData *self, OrgSpongycastleAsn1ASN1Sequence *certs) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->certs_ = certs;
}

OrgSpongycastleAsn1DvcsData *new_OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *certs) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DvcsData, initWithOrgSpongycastleAsn1ASN1Sequence_, certs)
}

OrgSpongycastleAsn1DvcsData *create_OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *certs) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DvcsData, initWithOrgSpongycastleAsn1ASN1Sequence_, certs)
}

OrgSpongycastleAsn1DvcsData *OrgSpongycastleAsn1DvcsData_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1DvcsData_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1DvcsData class]]) {
    return (OrgSpongycastleAsn1DvcsData *) obj;
  }
  else if ([obj isKindOfClass:[OrgSpongycastleAsn1ASN1OctetString class]]) {
    return new_OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1ASN1OctetString_((OrgSpongycastleAsn1ASN1OctetString *) obj);
  }
  else if ([obj isKindOfClass:[OrgSpongycastleAsn1ASN1Sequence class]]) {
    return new_OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1X509DigestInfo_(OrgSpongycastleAsn1X509DigestInfo_getInstanceWithId_(obj));
  }
  else if ([obj isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]]) {
    return new_OrgSpongycastleAsn1DvcsData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_((OrgSpongycastleAsn1ASN1TaggedObject *) obj, false));
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"Unknown object submitted to getInstance: ", [[nil_chk(obj) java_getClass] getName]));
}

OrgSpongycastleAsn1DvcsData *OrgSpongycastleAsn1DvcsData_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1DvcsData_initialize();
  return OrgSpongycastleAsn1DvcsData_getInstanceWithId_([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(obj)) getObject]);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1DvcsData)