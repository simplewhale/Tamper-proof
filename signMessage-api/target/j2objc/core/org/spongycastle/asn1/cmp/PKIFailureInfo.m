//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmp/PKIFailureInfo.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/Integer.h"
#include "org/spongycastle/asn1/ASN1BitString.h"
#include "org/spongycastle/asn1/DERBitString.h"
#include "org/spongycastle/asn1/cmp/PKIFailureInfo.h"

@implementation OrgSpongycastleAsn1CmpPKIFailureInfo

- (instancetype)initWithInt:(jint)info {
  OrgSpongycastleAsn1CmpPKIFailureInfo_initWithInt_(self, info);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1DERBitString:(OrgSpongycastleAsn1DERBitString *)info {
  OrgSpongycastleAsn1CmpPKIFailureInfo_initWithOrgSpongycastleAsn1DERBitString_(self, info);
  return self;
}

- (NSString *)description {
  return JreStrcat("$$", @"PKIFailureInfo: 0x", JavaLangInteger_toHexStringWithInt_([self intValue]));
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 2, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1DERBitString:);
  methods[2].selector = @selector(description);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "badAlg", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_badAlg, 0x19, -1, -1, -1, -1 },
    { "badMessageCheck", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_badMessageCheck, 0x19, -1, -1, -1, -1 },
    { "badRequest", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_badRequest, 0x19, -1, -1, -1, -1 },
    { "badTime", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_badTime, 0x19, -1, -1, -1, -1 },
    { "badCertId", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_badCertId, 0x19, -1, -1, -1, -1 },
    { "badDataFormat", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_badDataFormat, 0x19, -1, -1, -1, -1 },
    { "wrongAuthority", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_wrongAuthority, 0x19, -1, -1, -1, -1 },
    { "incorrectData", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_incorrectData, 0x19, -1, -1, -1, -1 },
    { "missingTimeStamp", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_missingTimeStamp, 0x19, -1, -1, -1, -1 },
    { "badPOP", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_badPOP, 0x19, -1, -1, -1, -1 },
    { "certRevoked", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_certRevoked, 0x19, -1, -1, -1, -1 },
    { "certConfirmed", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_certConfirmed, 0x19, -1, -1, -1, -1 },
    { "wrongIntegrity", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_wrongIntegrity, 0x19, -1, -1, -1, -1 },
    { "badRecipientNonce", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_badRecipientNonce, 0x19, -1, -1, -1, -1 },
    { "timeNotAvailable", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_timeNotAvailable, 0x19, -1, -1, -1, -1 },
    { "unacceptedPolicy", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_unacceptedPolicy, 0x19, -1, -1, -1, -1 },
    { "unacceptedExtension", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_unacceptedExtension, 0x19, -1, -1, -1, -1 },
    { "addInfoNotAvailable", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_addInfoNotAvailable, 0x19, -1, -1, -1, -1 },
    { "badSenderNonce", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_badSenderNonce, 0x19, -1, -1, -1, -1 },
    { "badCertTemplate", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_badCertTemplate, 0x19, -1, -1, -1, -1 },
    { "signerNotTrusted", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_signerNotTrusted, 0x19, -1, -1, -1, -1 },
    { "transactionIdInUse", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_transactionIdInUse, 0x19, -1, -1, -1, -1 },
    { "unsupportedVersion", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_unsupportedVersion, 0x19, -1, -1, -1, -1 },
    { "notAuthorized", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_notAuthorized, 0x19, -1, -1, -1, -1 },
    { "systemUnavail", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_systemUnavail, 0x19, -1, -1, -1, -1 },
    { "systemFailure", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_systemFailure, 0x19, -1, -1, -1, -1 },
    { "duplicateCertReq", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_duplicateCertReq, 0x19, -1, -1, -1, -1 },
    { "BAD_ALG", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_BAD_ALG, 0x19, -1, -1, -1, -1 },
    { "BAD_MESSAGE_CHECK", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_BAD_MESSAGE_CHECK, 0x19, -1, -1, -1, -1 },
    { "BAD_REQUEST", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_BAD_REQUEST, 0x19, -1, -1, -1, -1 },
    { "BAD_TIME", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_BAD_TIME, 0x19, -1, -1, -1, -1 },
    { "BAD_CERT_ID", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_BAD_CERT_ID, 0x19, -1, -1, -1, -1 },
    { "BAD_DATA_FORMAT", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_BAD_DATA_FORMAT, 0x19, -1, -1, -1, -1 },
    { "WRONG_AUTHORITY", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_WRONG_AUTHORITY, 0x19, -1, -1, -1, -1 },
    { "INCORRECT_DATA", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_INCORRECT_DATA, 0x19, -1, -1, -1, -1 },
    { "MISSING_TIME_STAMP", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_MISSING_TIME_STAMP, 0x19, -1, -1, -1, -1 },
    { "BAD_POP", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_BAD_POP, 0x19, -1, -1, -1, -1 },
    { "TIME_NOT_AVAILABLE", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_TIME_NOT_AVAILABLE, 0x19, -1, -1, -1, -1 },
    { "UNACCEPTED_POLICY", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_UNACCEPTED_POLICY, 0x19, -1, -1, -1, -1 },
    { "UNACCEPTED_EXTENSION", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_UNACCEPTED_EXTENSION, 0x19, -1, -1, -1, -1 },
    { "ADD_INFO_NOT_AVAILABLE", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_ADD_INFO_NOT_AVAILABLE, 0x19, -1, -1, -1, -1 },
    { "SYSTEM_FAILURE", "I", .constantValue.asInt = OrgSpongycastleAsn1CmpPKIFailureInfo_SYSTEM_FAILURE, 0x19, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "I", "LOrgSpongycastleAsn1DERBitString;", "toString" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmpPKIFailureInfo = { "PKIFailureInfo", "org.spongycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 3, 42, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmpPKIFailureInfo;
}

@end

void OrgSpongycastleAsn1CmpPKIFailureInfo_initWithInt_(OrgSpongycastleAsn1CmpPKIFailureInfo *self, jint info) {
  OrgSpongycastleAsn1DERBitString_initWithByteArray_withInt_(self, OrgSpongycastleAsn1ASN1BitString_getBytesWithInt_(info), OrgSpongycastleAsn1ASN1BitString_getPadBitsWithInt_(info));
}

OrgSpongycastleAsn1CmpPKIFailureInfo *new_OrgSpongycastleAsn1CmpPKIFailureInfo_initWithInt_(jint info) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmpPKIFailureInfo, initWithInt_, info)
}

OrgSpongycastleAsn1CmpPKIFailureInfo *create_OrgSpongycastleAsn1CmpPKIFailureInfo_initWithInt_(jint info) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmpPKIFailureInfo, initWithInt_, info)
}

void OrgSpongycastleAsn1CmpPKIFailureInfo_initWithOrgSpongycastleAsn1DERBitString_(OrgSpongycastleAsn1CmpPKIFailureInfo *self, OrgSpongycastleAsn1DERBitString *info) {
  OrgSpongycastleAsn1DERBitString_initWithByteArray_withInt_(self, [((OrgSpongycastleAsn1DERBitString *) nil_chk(info)) getBytes], [info getPadBits]);
}

OrgSpongycastleAsn1CmpPKIFailureInfo *new_OrgSpongycastleAsn1CmpPKIFailureInfo_initWithOrgSpongycastleAsn1DERBitString_(OrgSpongycastleAsn1DERBitString *info) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmpPKIFailureInfo, initWithOrgSpongycastleAsn1DERBitString_, info)
}

OrgSpongycastleAsn1CmpPKIFailureInfo *create_OrgSpongycastleAsn1CmpPKIFailureInfo_initWithOrgSpongycastleAsn1DERBitString_(OrgSpongycastleAsn1DERBitString *info) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmpPKIFailureInfo, initWithOrgSpongycastleAsn1DERBitString_, info)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmpPKIFailureInfo)
