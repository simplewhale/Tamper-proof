//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/crmf/EncKeyWithID.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/DERUTF8String.h"
#include "org/spongycastle/asn1/crmf/EncKeyWithID.h"
#include "org/spongycastle/asn1/pkcs/PrivateKeyInfo.h"
#include "org/spongycastle/asn1/x509/GeneralName.h"

@interface OrgSpongycastleAsn1CrmfEncKeyWithID () {
 @public
  OrgSpongycastleAsn1PkcsPrivateKeyInfo *privKeyInfo_;
  id<OrgSpongycastleAsn1ASN1Encodable> identifier_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CrmfEncKeyWithID, privKeyInfo_, OrgSpongycastleAsn1PkcsPrivateKeyInfo *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CrmfEncKeyWithID, identifier_, id<OrgSpongycastleAsn1ASN1Encodable>)

__attribute__((unused)) static void OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CrmfEncKeyWithID *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1CrmfEncKeyWithID *new_OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CrmfEncKeyWithID *create_OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1CrmfEncKeyWithID

+ (OrgSpongycastleAsn1CrmfEncKeyWithID *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CrmfEncKeyWithID_getInstanceWithId_(o);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo:(OrgSpongycastleAsn1PkcsPrivateKeyInfo *)privKeyInfo {
  OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_(self, privKeyInfo);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo:(OrgSpongycastleAsn1PkcsPrivateKeyInfo *)privKeyInfo
                         withOrgSpongycastleAsn1DERUTF8String:(OrgSpongycastleAsn1DERUTF8String *)str {
  OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_withOrgSpongycastleAsn1DERUTF8String_(self, privKeyInfo, str);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo:(OrgSpongycastleAsn1PkcsPrivateKeyInfo *)privKeyInfo
                       withOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)generalName {
  OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_withOrgSpongycastleAsn1X509GeneralName_(self, privKeyInfo, generalName);
  return self;
}

- (OrgSpongycastleAsn1PkcsPrivateKeyInfo *)getPrivateKey {
  return privKeyInfo_;
}

- (jboolean)hasIdentifier {
  return identifier_ != nil;
}

- (jboolean)isIdentifierUTF8String {
  return [identifier_ isKindOfClass:[OrgSpongycastleAsn1DERUTF8String class]];
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)getIdentifier {
  return identifier_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:privKeyInfo_];
  if (identifier_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:identifier_];
  }
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1CrmfEncKeyWithID;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1PkcsPrivateKeyInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo:withOrgSpongycastleAsn1DERUTF8String:);
  methods[4].selector = @selector(initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo:withOrgSpongycastleAsn1X509GeneralName:);
  methods[5].selector = @selector(getPrivateKey);
  methods[6].selector = @selector(hasIdentifier);
  methods[7].selector = @selector(isIdentifierUTF8String);
  methods[8].selector = @selector(getIdentifier);
  methods[9].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "privKeyInfo_", "LOrgSpongycastleAsn1PkcsPrivateKeyInfo;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "identifier_", "LOrgSpongycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1Sequence;", "LOrgSpongycastleAsn1PkcsPrivateKeyInfo;", "LOrgSpongycastleAsn1PkcsPrivateKeyInfo;LOrgSpongycastleAsn1DERUTF8String;", "LOrgSpongycastleAsn1PkcsPrivateKeyInfo;LOrgSpongycastleAsn1X509GeneralName;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CrmfEncKeyWithID = { "EncKeyWithID", "org.spongycastle.asn1.crmf", ptrTable, methods, fields, 7, 0x1, 10, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CrmfEncKeyWithID;
}

@end

OrgSpongycastleAsn1CrmfEncKeyWithID *OrgSpongycastleAsn1CrmfEncKeyWithID_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CrmfEncKeyWithID_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1CrmfEncKeyWithID class]]) {
    return (OrgSpongycastleAsn1CrmfEncKeyWithID *) o;
  }
  else if (o != nil) {
    return new_OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CrmfEncKeyWithID *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->privKeyInfo_ = OrgSpongycastleAsn1PkcsPrivateKeyInfo_getInstanceWithId_([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  if ([seq size] > 1) {
    if (!([[seq getObjectAtWithInt:1] isKindOfClass:[OrgSpongycastleAsn1DERUTF8String class]])) {
      self->identifier_ = OrgSpongycastleAsn1X509GeneralName_getInstanceWithId_([seq getObjectAtWithInt:1]);
    }
    else {
      self->identifier_ = [seq getObjectAtWithInt:1];
    }
  }
  else {
    self->identifier_ = nil;
  }
}

OrgSpongycastleAsn1CrmfEncKeyWithID *new_OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CrmfEncKeyWithID, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CrmfEncKeyWithID *create_OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CrmfEncKeyWithID, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

void OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_(OrgSpongycastleAsn1CrmfEncKeyWithID *self, OrgSpongycastleAsn1PkcsPrivateKeyInfo *privKeyInfo) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->privKeyInfo_ = privKeyInfo;
  self->identifier_ = nil;
}

OrgSpongycastleAsn1CrmfEncKeyWithID *new_OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_(OrgSpongycastleAsn1PkcsPrivateKeyInfo *privKeyInfo) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CrmfEncKeyWithID, initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_, privKeyInfo)
}

OrgSpongycastleAsn1CrmfEncKeyWithID *create_OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_(OrgSpongycastleAsn1PkcsPrivateKeyInfo *privKeyInfo) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CrmfEncKeyWithID, initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_, privKeyInfo)
}

void OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_withOrgSpongycastleAsn1DERUTF8String_(OrgSpongycastleAsn1CrmfEncKeyWithID *self, OrgSpongycastleAsn1PkcsPrivateKeyInfo *privKeyInfo, OrgSpongycastleAsn1DERUTF8String *str) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->privKeyInfo_ = privKeyInfo;
  self->identifier_ = str;
}

OrgSpongycastleAsn1CrmfEncKeyWithID *new_OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_withOrgSpongycastleAsn1DERUTF8String_(OrgSpongycastleAsn1PkcsPrivateKeyInfo *privKeyInfo, OrgSpongycastleAsn1DERUTF8String *str) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CrmfEncKeyWithID, initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_withOrgSpongycastleAsn1DERUTF8String_, privKeyInfo, str)
}

OrgSpongycastleAsn1CrmfEncKeyWithID *create_OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_withOrgSpongycastleAsn1DERUTF8String_(OrgSpongycastleAsn1PkcsPrivateKeyInfo *privKeyInfo, OrgSpongycastleAsn1DERUTF8String *str) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CrmfEncKeyWithID, initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_withOrgSpongycastleAsn1DERUTF8String_, privKeyInfo, str)
}

void OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_withOrgSpongycastleAsn1X509GeneralName_(OrgSpongycastleAsn1CrmfEncKeyWithID *self, OrgSpongycastleAsn1PkcsPrivateKeyInfo *privKeyInfo, OrgSpongycastleAsn1X509GeneralName *generalName) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->privKeyInfo_ = privKeyInfo;
  self->identifier_ = generalName;
}

OrgSpongycastleAsn1CrmfEncKeyWithID *new_OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_withOrgSpongycastleAsn1X509GeneralName_(OrgSpongycastleAsn1PkcsPrivateKeyInfo *privKeyInfo, OrgSpongycastleAsn1X509GeneralName *generalName) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CrmfEncKeyWithID, initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_withOrgSpongycastleAsn1X509GeneralName_, privKeyInfo, generalName)
}

OrgSpongycastleAsn1CrmfEncKeyWithID *create_OrgSpongycastleAsn1CrmfEncKeyWithID_initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_withOrgSpongycastleAsn1X509GeneralName_(OrgSpongycastleAsn1PkcsPrivateKeyInfo *privKeyInfo, OrgSpongycastleAsn1X509GeneralName *generalName) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CrmfEncKeyWithID, initWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_withOrgSpongycastleAsn1X509GeneralName_, privKeyInfo, generalName)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CrmfEncKeyWithID)
