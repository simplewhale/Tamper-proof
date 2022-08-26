//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/AuthEnvelopedData.java
//

#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1Set.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/BERSequence.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/cms/AuthEnvelopedData.h"
#include "org/spongycastle/asn1/cms/CMSObjectIdentifiers.h"
#include "org/spongycastle/asn1/cms/EncryptedContentInfo.h"
#include "org/spongycastle/asn1/cms/OriginatorInfo.h"

@interface OrgSpongycastleAsn1CmsAuthEnvelopedData () {
 @public
  OrgSpongycastleAsn1ASN1Integer *version__;
  OrgSpongycastleAsn1CmsOriginatorInfo *originatorInfo_;
  OrgSpongycastleAsn1ASN1Set *recipientInfos_;
  OrgSpongycastleAsn1CmsEncryptedContentInfo *authEncryptedContentInfo_;
  OrgSpongycastleAsn1ASN1Set *authAttrs_;
  OrgSpongycastleAsn1ASN1OctetString *mac_;
  OrgSpongycastleAsn1ASN1Set *unauthAttrs_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsAuthEnvelopedData, version__, OrgSpongycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsAuthEnvelopedData, originatorInfo_, OrgSpongycastleAsn1CmsOriginatorInfo *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsAuthEnvelopedData, recipientInfos_, OrgSpongycastleAsn1ASN1Set *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsAuthEnvelopedData, authEncryptedContentInfo_, OrgSpongycastleAsn1CmsEncryptedContentInfo *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsAuthEnvelopedData, authAttrs_, OrgSpongycastleAsn1ASN1Set *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsAuthEnvelopedData, mac_, OrgSpongycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsAuthEnvelopedData, unauthAttrs_, OrgSpongycastleAsn1ASN1Set *)

__attribute__((unused)) static void OrgSpongycastleAsn1CmsAuthEnvelopedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmsAuthEnvelopedData *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1CmsAuthEnvelopedData *new_OrgSpongycastleAsn1CmsAuthEnvelopedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CmsAuthEnvelopedData *create_OrgSpongycastleAsn1CmsAuthEnvelopedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1CmsAuthEnvelopedData

- (instancetype)initWithOrgSpongycastleAsn1CmsOriginatorInfo:(OrgSpongycastleAsn1CmsOriginatorInfo *)originatorInfo
                              withOrgSpongycastleAsn1ASN1Set:(OrgSpongycastleAsn1ASN1Set *)recipientInfos
              withOrgSpongycastleAsn1CmsEncryptedContentInfo:(OrgSpongycastleAsn1CmsEncryptedContentInfo *)authEncryptedContentInfo
                              withOrgSpongycastleAsn1ASN1Set:(OrgSpongycastleAsn1ASN1Set *)authAttrs
                      withOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)mac
                              withOrgSpongycastleAsn1ASN1Set:(OrgSpongycastleAsn1ASN1Set *)unauthAttrs {
  OrgSpongycastleAsn1CmsAuthEnvelopedData_initWithOrgSpongycastleAsn1CmsOriginatorInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1CmsEncryptedContentInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1ASN1Set_(self, originatorInfo, recipientInfos, authEncryptedContentInfo, authAttrs, mac, unauthAttrs);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CmsAuthEnvelopedData_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (OrgSpongycastleAsn1CmsAuthEnvelopedData *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                    withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1CmsAuthEnvelopedData_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (OrgSpongycastleAsn1CmsAuthEnvelopedData *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1CmsAuthEnvelopedData_getInstanceWithId_(obj);
}

- (OrgSpongycastleAsn1ASN1Integer *)getVersion {
  return version__;
}

- (OrgSpongycastleAsn1CmsOriginatorInfo *)getOriginatorInfo {
  return originatorInfo_;
}

- (OrgSpongycastleAsn1ASN1Set *)getRecipientInfos {
  return recipientInfos_;
}

- (OrgSpongycastleAsn1CmsEncryptedContentInfo *)getAuthEncryptedContentInfo {
  return authEncryptedContentInfo_;
}

- (OrgSpongycastleAsn1ASN1Set *)getAuthAttrs {
  return authAttrs_;
}

- (OrgSpongycastleAsn1ASN1OctetString *)getMac {
  return mac_;
}

- (OrgSpongycastleAsn1ASN1Set *)getUnauthAttrs {
  return unauthAttrs_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:version__];
  if (originatorInfo_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 0, originatorInfo_)];
  }
  [v addWithOrgSpongycastleAsn1ASN1Encodable:recipientInfos_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:authEncryptedContentInfo_];
  if (authAttrs_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 1, authAttrs_)];
  }
  [v addWithOrgSpongycastleAsn1ASN1Encodable:mac_];
  if (unauthAttrs_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 2, unauthAttrs_)];
  }
  return new_OrgSpongycastleAsn1BERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsAuthEnvelopedData;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsAuthEnvelopedData;", 0x9, 2, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsOriginatorInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Set;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsEncryptedContentInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Set;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Set;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1CmsOriginatorInfo:withOrgSpongycastleAsn1ASN1Set:withOrgSpongycastleAsn1CmsEncryptedContentInfo:withOrgSpongycastleAsn1ASN1Set:withOrgSpongycastleAsn1ASN1OctetString:withOrgSpongycastleAsn1ASN1Set:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(getVersion);
  methods[5].selector = @selector(getOriginatorInfo);
  methods[6].selector = @selector(getRecipientInfos);
  methods[7].selector = @selector(getAuthEncryptedContentInfo);
  methods[8].selector = @selector(getAuthAttrs);
  methods[9].selector = @selector(getMac);
  methods[10].selector = @selector(getUnauthAttrs);
  methods[11].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, 5, -1, -1, -1 },
    { "originatorInfo_", "LOrgSpongycastleAsn1CmsOriginatorInfo;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "recipientInfos_", "LOrgSpongycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "authEncryptedContentInfo_", "LOrgSpongycastleAsn1CmsEncryptedContentInfo;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "authAttrs_", "LOrgSpongycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "mac_", "LOrgSpongycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "unauthAttrs_", "LOrgSpongycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1CmsOriginatorInfo;LOrgSpongycastleAsn1ASN1Set;LOrgSpongycastleAsn1CmsEncryptedContentInfo;LOrgSpongycastleAsn1ASN1Set;LOrgSpongycastleAsn1ASN1OctetString;LOrgSpongycastleAsn1ASN1Set;", "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "version" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmsAuthEnvelopedData = { "AuthEnvelopedData", "org.spongycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 12, 7, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmsAuthEnvelopedData;
}

@end

void OrgSpongycastleAsn1CmsAuthEnvelopedData_initWithOrgSpongycastleAsn1CmsOriginatorInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1CmsEncryptedContentInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1CmsAuthEnvelopedData *self, OrgSpongycastleAsn1CmsOriginatorInfo *originatorInfo, OrgSpongycastleAsn1ASN1Set *recipientInfos, OrgSpongycastleAsn1CmsEncryptedContentInfo *authEncryptedContentInfo, OrgSpongycastleAsn1ASN1Set *authAttrs, OrgSpongycastleAsn1ASN1OctetString *mac, OrgSpongycastleAsn1ASN1Set *unauthAttrs) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->version__ = new_OrgSpongycastleAsn1ASN1Integer_initWithLong_(0);
  self->originatorInfo_ = originatorInfo;
  self->recipientInfos_ = recipientInfos;
  if ([((OrgSpongycastleAsn1ASN1Set *) nil_chk(self->recipientInfos_)) size] == 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"AuthEnvelopedData requires at least 1 RecipientInfo");
  }
  self->authEncryptedContentInfo_ = authEncryptedContentInfo;
  self->authAttrs_ = authAttrs;
  if (![((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk([((OrgSpongycastleAsn1CmsEncryptedContentInfo *) nil_chk(authEncryptedContentInfo)) getContentType])) isEqual:JreLoadStatic(OrgSpongycastleAsn1CmsCMSObjectIdentifiers, data)]) {
    if (authAttrs == nil || [authAttrs size] == 0) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"authAttrs must be present with non-data content");
    }
  }
  self->mac_ = mac;
  self->unauthAttrs_ = unauthAttrs;
}

OrgSpongycastleAsn1CmsAuthEnvelopedData *new_OrgSpongycastleAsn1CmsAuthEnvelopedData_initWithOrgSpongycastleAsn1CmsOriginatorInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1CmsEncryptedContentInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1CmsOriginatorInfo *originatorInfo, OrgSpongycastleAsn1ASN1Set *recipientInfos, OrgSpongycastleAsn1CmsEncryptedContentInfo *authEncryptedContentInfo, OrgSpongycastleAsn1ASN1Set *authAttrs, OrgSpongycastleAsn1ASN1OctetString *mac, OrgSpongycastleAsn1ASN1Set *unauthAttrs) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsAuthEnvelopedData, initWithOrgSpongycastleAsn1CmsOriginatorInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1CmsEncryptedContentInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1ASN1Set_, originatorInfo, recipientInfos, authEncryptedContentInfo, authAttrs, mac, unauthAttrs)
}

OrgSpongycastleAsn1CmsAuthEnvelopedData *create_OrgSpongycastleAsn1CmsAuthEnvelopedData_initWithOrgSpongycastleAsn1CmsOriginatorInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1CmsEncryptedContentInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1CmsOriginatorInfo *originatorInfo, OrgSpongycastleAsn1ASN1Set *recipientInfos, OrgSpongycastleAsn1CmsEncryptedContentInfo *authEncryptedContentInfo, OrgSpongycastleAsn1ASN1Set *authAttrs, OrgSpongycastleAsn1ASN1OctetString *mac, OrgSpongycastleAsn1ASN1Set *unauthAttrs) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsAuthEnvelopedData, initWithOrgSpongycastleAsn1CmsOriginatorInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1CmsEncryptedContentInfo_withOrgSpongycastleAsn1ASN1Set_withOrgSpongycastleAsn1ASN1OctetString_withOrgSpongycastleAsn1ASN1Set_, originatorInfo, recipientInfos, authEncryptedContentInfo, authAttrs, mac, unauthAttrs)
}

void OrgSpongycastleAsn1CmsAuthEnvelopedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmsAuthEnvelopedData *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  jint index = 0;
  OrgSpongycastleAsn1ASN1Primitive *tmp = [((id<OrgSpongycastleAsn1ASN1Encodable>) nil_chk([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:index++])) toASN1Primitive];
  self->version__ = (OrgSpongycastleAsn1ASN1Integer *) cast_chk(tmp, [OrgSpongycastleAsn1ASN1Integer class]);
  if ([((JavaMathBigInteger *) nil_chk([((OrgSpongycastleAsn1ASN1Integer *) nil_chk(self->version__)) getValue])) intValue] != 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"AuthEnvelopedData version number must be 0");
  }
  tmp = [((id<OrgSpongycastleAsn1ASN1Encodable>) nil_chk([seq getObjectAtWithInt:index++])) toASN1Primitive];
  if ([tmp isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]]) {
    self->originatorInfo_ = OrgSpongycastleAsn1CmsOriginatorInfo_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_((OrgSpongycastleAsn1ASN1TaggedObject *) tmp, false);
    tmp = [((id<OrgSpongycastleAsn1ASN1Encodable>) nil_chk([seq getObjectAtWithInt:index++])) toASN1Primitive];
  }
  self->recipientInfos_ = OrgSpongycastleAsn1ASN1Set_getInstanceWithId_(tmp);
  if ([((OrgSpongycastleAsn1ASN1Set *) nil_chk(self->recipientInfos_)) size] == 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"AuthEnvelopedData requires at least 1 RecipientInfo");
  }
  tmp = [((id<OrgSpongycastleAsn1ASN1Encodable>) nil_chk([seq getObjectAtWithInt:index++])) toASN1Primitive];
  self->authEncryptedContentInfo_ = OrgSpongycastleAsn1CmsEncryptedContentInfo_getInstanceWithId_(tmp);
  tmp = [((id<OrgSpongycastleAsn1ASN1Encodable>) nil_chk([seq getObjectAtWithInt:index++])) toASN1Primitive];
  if ([tmp isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]]) {
    self->authAttrs_ = OrgSpongycastleAsn1ASN1Set_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_((OrgSpongycastleAsn1ASN1TaggedObject *) tmp, false);
    tmp = [((id<OrgSpongycastleAsn1ASN1Encodable>) nil_chk([seq getObjectAtWithInt:index++])) toASN1Primitive];
  }
  else {
    if (![((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk([((OrgSpongycastleAsn1CmsEncryptedContentInfo *) nil_chk(self->authEncryptedContentInfo_)) getContentType])) isEqual:JreLoadStatic(OrgSpongycastleAsn1CmsCMSObjectIdentifiers, data)]) {
      if (self->authAttrs_ == nil || [self->authAttrs_ size] == 0) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"authAttrs must be present with non-data content");
      }
    }
  }
  self->mac_ = OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_(tmp);
  if ([seq size] > index) {
    tmp = [((id<OrgSpongycastleAsn1ASN1Encodable>) nil_chk([seq getObjectAtWithInt:index])) toASN1Primitive];
    self->unauthAttrs_ = OrgSpongycastleAsn1ASN1Set_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_((OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk(tmp, [OrgSpongycastleAsn1ASN1TaggedObject class]), false);
  }
}

OrgSpongycastleAsn1CmsAuthEnvelopedData *new_OrgSpongycastleAsn1CmsAuthEnvelopedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsAuthEnvelopedData, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmsAuthEnvelopedData *create_OrgSpongycastleAsn1CmsAuthEnvelopedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsAuthEnvelopedData, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmsAuthEnvelopedData *OrgSpongycastleAsn1CmsAuthEnvelopedData_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1CmsAuthEnvelopedData_initialize();
  return OrgSpongycastleAsn1CmsAuthEnvelopedData_getInstanceWithId_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

OrgSpongycastleAsn1CmsAuthEnvelopedData *OrgSpongycastleAsn1CmsAuthEnvelopedData_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1CmsAuthEnvelopedData_initialize();
  if (obj == nil || [obj isKindOfClass:[OrgSpongycastleAsn1CmsAuthEnvelopedData class]]) {
    return (OrgSpongycastleAsn1CmsAuthEnvelopedData *) cast_chk(obj, [OrgSpongycastleAsn1CmsAuthEnvelopedData class]);
  }
  if ([obj isKindOfClass:[OrgSpongycastleAsn1ASN1Sequence class]]) {
    return new_OrgSpongycastleAsn1CmsAuthEnvelopedData_initWithOrgSpongycastleAsn1ASN1Sequence_((OrgSpongycastleAsn1ASN1Sequence *) obj);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"Invalid AuthEnvelopedData: ", [[obj java_getClass] getName]));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmsAuthEnvelopedData)
