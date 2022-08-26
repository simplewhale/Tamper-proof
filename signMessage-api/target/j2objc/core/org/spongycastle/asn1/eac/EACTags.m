//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/eac/EACTags.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1ApplicationSpecific.h"
#include "org/spongycastle/asn1/BERTags.h"
#include "org/spongycastle/asn1/eac/EACTags.h"

@implementation OrgSpongycastleAsn1EacEACTags

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleAsn1EacEACTags_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jint)getTagWithInt:(jint)encodedTag {
  return OrgSpongycastleAsn1EacEACTags_getTagWithInt_(encodedTag);
}

+ (jint)getTagNoWithInt:(jint)tag {
  return OrgSpongycastleAsn1EacEACTags_getTagNoWithInt_(tag);
}

+ (jint)encodeTagWithOrgSpongycastleAsn1ASN1ApplicationSpecific:(OrgSpongycastleAsn1ASN1ApplicationSpecific *)spec {
  return OrgSpongycastleAsn1EacEACTags_encodeTagWithOrgSpongycastleAsn1ASN1ApplicationSpecific_(spec);
}

+ (jint)decodeTagWithInt:(jint)tag {
  return OrgSpongycastleAsn1EacEACTags_decodeTagWithInt_(tag);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 2, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 5, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getTagWithInt:);
  methods[2].selector = @selector(getTagNoWithInt:);
  methods[3].selector = @selector(encodeTagWithOrgSpongycastleAsn1ASN1ApplicationSpecific:);
  methods[4].selector = @selector(decodeTagWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "COUNTRY_CODE_NATIONAL_DATA", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_COUNTRY_CODE_NATIONAL_DATA, 0x19, -1, -1, -1, -1 },
    { "ISSUER_IDENTIFICATION_NUMBER", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_ISSUER_IDENTIFICATION_NUMBER, 0x19, -1, -1, -1, -1 },
    { "CARD_SERVICE_DATA", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARD_SERVICE_DATA, 0x19, -1, -1, -1, -1 },
    { "INITIAL_ACCESS_DATA", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_INITIAL_ACCESS_DATA, 0x19, -1, -1, -1, -1 },
    { "CARD_ISSUER_DATA", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARD_ISSUER_DATA, 0x19, -1, -1, -1, -1 },
    { "PRE_ISSUING_DATA", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_PRE_ISSUING_DATA, 0x19, -1, -1, -1, -1 },
    { "CARD_CAPABILITIES", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARD_CAPABILITIES, 0x19, -1, -1, -1, -1 },
    { "STATUS_INFORMATION", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_STATUS_INFORMATION, 0x19, -1, -1, -1, -1 },
    { "EXTENDED_HEADER_LIST", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_EXTENDED_HEADER_LIST, 0x19, -1, -1, -1, -1 },
    { "APPLICATION_IDENTIFIER", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_APPLICATION_IDENTIFIER, 0x19, -1, -1, -1, -1 },
    { "APPLICATION_LABEL", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_APPLICATION_LABEL, 0x19, -1, -1, -1, -1 },
    { "FILE_REFERENCE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_FILE_REFERENCE, 0x19, -1, -1, -1, -1 },
    { "COMMAND_TO_PERFORM", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_COMMAND_TO_PERFORM, 0x19, -1, -1, -1, -1 },
    { "DISCRETIONARY_DATA", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_DISCRETIONARY_DATA, 0x19, -1, -1, -1, -1 },
    { "OFFSET_DATA_OBJECT", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_OFFSET_DATA_OBJECT, 0x19, -1, -1, -1, -1 },
    { "TRACK1_APPLICATION", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_TRACK1_APPLICATION, 0x19, -1, -1, -1, -1 },
    { "TRACK2_APPLICATION", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_TRACK2_APPLICATION, 0x19, -1, -1, -1, -1 },
    { "TRACK3_APPLICATION", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_TRACK3_APPLICATION, 0x19, -1, -1, -1, -1 },
    { "CARD_EXPIRATION_DATA", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARD_EXPIRATION_DATA, 0x19, -1, -1, -1, -1 },
    { "PRIMARY_ACCOUNT_NUMBER", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_PRIMARY_ACCOUNT_NUMBER, 0x19, -1, -1, -1, -1 },
    { "NAME", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_NAME, 0x19, -1, -1, -1, -1 },
    { "TAG_LIST", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_TAG_LIST, 0x19, -1, -1, -1, -1 },
    { "HEADER_LIST", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_HEADER_LIST, 0x19, -1, -1, -1, -1 },
    { "LOGIN_DATA", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_LOGIN_DATA, 0x19, -1, -1, -1, -1 },
    { "CARDHOLDER_NAME", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARDHOLDER_NAME, 0x19, -1, -1, -1, -1 },
    { "TRACK1_CARD", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_TRACK1_CARD, 0x19, -1, -1, -1, -1 },
    { "TRACK2_CARD", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_TRACK2_CARD, 0x19, -1, -1, -1, -1 },
    { "TRACK3_CARD", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_TRACK3_CARD, 0x19, -1, -1, -1, -1 },
    { "APPLICATION_EXPIRATION_DATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_APPLICATION_EXPIRATION_DATE, 0x19, -1, -1, -1, -1 },
    { "APPLICATION_EFFECTIVE_DATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_APPLICATION_EFFECTIVE_DATE, 0x19, -1, -1, -1, -1 },
    { "CARD_EFFECTIVE_DATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARD_EFFECTIVE_DATE, 0x19, -1, -1, -1, -1 },
    { "INTERCHANGE_CONTROL", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_INTERCHANGE_CONTROL, 0x19, -1, -1, -1, -1 },
    { "COUNTRY_CODE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_COUNTRY_CODE, 0x19, -1, -1, -1, -1 },
    { "INTERCHANGE_PROFILE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_INTERCHANGE_PROFILE, 0x19, -1, -1, -1, -1 },
    { "CURRENCY_CODE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CURRENCY_CODE, 0x19, -1, -1, -1, -1 },
    { "DATE_OF_BIRTH", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_DATE_OF_BIRTH, 0x19, -1, -1, -1, -1 },
    { "CARDHOLDER_NATIONALITY", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARDHOLDER_NATIONALITY, 0x19, -1, -1, -1, -1 },
    { "LANGUAGE_PREFERENCES", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_LANGUAGE_PREFERENCES, 0x19, -1, -1, -1, -1 },
    { "CARDHOLDER_BIOMETRIC_DATA", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARDHOLDER_BIOMETRIC_DATA, 0x19, -1, -1, -1, -1 },
    { "PIN_USAGE_POLICY", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_PIN_USAGE_POLICY, 0x19, -1, -1, -1, -1 },
    { "SERVICE_CODE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_SERVICE_CODE, 0x19, -1, -1, -1, -1 },
    { "TRANSACTION_COUNTER", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_TRANSACTION_COUNTER, 0x19, -1, -1, -1, -1 },
    { "TRANSACTION_DATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_TRANSACTION_DATE, 0x19, -1, -1, -1, -1 },
    { "CARD_SEQUENCE_NUMBER", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARD_SEQUENCE_NUMBER, 0x19, -1, -1, -1, -1 },
    { "SEX", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_SEX, 0x19, -1, -1, -1, -1 },
    { "CURRENCY_EXPONENT", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CURRENCY_EXPONENT, 0x19, -1, -1, -1, -1 },
    { "STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP, 0x19, -1, -1, -1, -1 },
    { "SIGNATURE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_SIGNATURE, 0x19, -1, -1, -1, -1 },
    { "STATIC_INTERNAL_AUTHENTIFICATION_FIRST_DATA", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_STATIC_INTERNAL_AUTHENTIFICATION_FIRST_DATA, 0x19, -1, -1, -1, -1 },
    { "STATIC_INTERNAL_AUTHENTIFICATION_SECOND_DATA", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_STATIC_INTERNAL_AUTHENTIFICATION_SECOND_DATA, 0x19, -1, -1, -1, -1 },
    { "DYNAMIC_INTERNAL_AUTHENTIFICATION", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_DYNAMIC_INTERNAL_AUTHENTIFICATION, 0x19, -1, -1, -1, -1 },
    { "DYNAMIC_EXTERNAL_AUTHENTIFICATION", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_DYNAMIC_EXTERNAL_AUTHENTIFICATION, 0x19, -1, -1, -1, -1 },
    { "DYNAMIC_MUTUAL_AUTHENTIFICATION", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_DYNAMIC_MUTUAL_AUTHENTIFICATION, 0x19, -1, -1, -1, -1 },
    { "CARDHOLDER_PORTRAIT_IMAGE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARDHOLDER_PORTRAIT_IMAGE, 0x19, -1, -1, -1, -1 },
    { "ELEMENT_LIST", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_ELEMENT_LIST, 0x19, -1, -1, -1, -1 },
    { "ADDRESS", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_ADDRESS, 0x19, -1, -1, -1, -1 },
    { "CARDHOLDER_HANDWRITTEN_SIGNATURE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARDHOLDER_HANDWRITTEN_SIGNATURE, 0x19, -1, -1, -1, -1 },
    { "APPLICATION_IMAGE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_APPLICATION_IMAGE, 0x19, -1, -1, -1, -1 },
    { "DISPLAY_IMAGE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_DISPLAY_IMAGE, 0x19, -1, -1, -1, -1 },
    { "TIMER", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_TIMER, 0x19, -1, -1, -1, -1 },
    { "MESSAGE_REFERENCE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_MESSAGE_REFERENCE, 0x19, -1, -1, -1, -1 },
    { "CARDHOLDER_PRIVATE_KEY", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARDHOLDER_PRIVATE_KEY, 0x19, -1, -1, -1, -1 },
    { "CARDHOLDER_PUBLIC_KEY", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARDHOLDER_PUBLIC_KEY, 0x19, -1, -1, -1, -1 },
    { "CERTIFICATION_AUTHORITY_PUBLIC_KEY", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CERTIFICATION_AUTHORITY_PUBLIC_KEY, 0x19, -1, -1, -1, -1 },
    { "DEPRECATED", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_DEPRECATED, 0x19, -1, -1, -1, -1 },
    { "CERTIFICATE_HOLDER_AUTHORIZATION", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CERTIFICATE_HOLDER_AUTHORIZATION, 0x19, -1, -1, -1, -1 },
    { "INTEGRATED_CIRCUIT_MANUFACTURER_ID", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_INTEGRATED_CIRCUIT_MANUFACTURER_ID, 0x19, -1, -1, -1, -1 },
    { "CERTIFICATE_CONTENT", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CERTIFICATE_CONTENT, 0x19, -1, -1, -1, -1 },
    { "UNIFORM_RESOURCE_LOCATOR", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_UNIFORM_RESOURCE_LOCATOR, 0x19, -1, -1, -1, -1 },
    { "ANSWER_TO_RESET", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_ANSWER_TO_RESET, 0x19, -1, -1, -1, -1 },
    { "HISTORICAL_BYTES", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_HISTORICAL_BYTES, 0x19, -1, -1, -1, -1 },
    { "DIGITAL_SIGNATURE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_DIGITAL_SIGNATURE, 0x19, -1, -1, -1, -1 },
    { "APPLICATION_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_APPLICATION_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "FCP_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_FCP_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "WRAPPER", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_WRAPPER, 0x19, -1, -1, -1, -1 },
    { "FMD_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_FMD_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "CARDHOLDER_RELATIVE_DATA", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARDHOLDER_RELATIVE_DATA, 0x19, -1, -1, -1, -1 },
    { "CARD_DATA", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARD_DATA, 0x19, -1, -1, -1, -1 },
    { "AUTHENTIFICATION_DATA", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_AUTHENTIFICATION_DATA, 0x19, -1, -1, -1, -1 },
    { "SPECIAL_USER_REQUIREMENTS", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_SPECIAL_USER_REQUIREMENTS, 0x19, -1, -1, -1, -1 },
    { "LOGIN_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_LOGIN_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "QUALIFIED_NAME", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_QUALIFIED_NAME, 0x19, -1, -1, -1, -1 },
    { "CARDHOLDER_IMAGE_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARDHOLDER_IMAGE_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "APPLICATION_IMAGE_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_APPLICATION_IMAGE_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "APPLICATION_RELATED_DATA", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_APPLICATION_RELATED_DATA, 0x19, -1, -1, -1, -1 },
    { "FCI_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_FCI_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "DISCRETIONARY_DATA_OBJECTS", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_DISCRETIONARY_DATA_OBJECTS, 0x19, -1, -1, -1, -1 },
    { "COMPATIBLE_TAG_ALLOCATION_AUTHORITY", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_COMPATIBLE_TAG_ALLOCATION_AUTHORITY, 0x19, -1, -1, -1, -1 },
    { "COEXISTANT_TAG_ALLOCATION_AUTHORITY", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_COEXISTANT_TAG_ALLOCATION_AUTHORITY, 0x19, -1, -1, -1, -1 },
    { "SECURITY_SUPPORT_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_SECURITY_SUPPORT_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "SECURITY_ENVIRONMENT_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_SECURITY_ENVIRONMENT_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "DYNAMIC_AUTHENTIFICATION_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_DYNAMIC_AUTHENTIFICATION_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "SECURE_MESSAGING_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_SECURE_MESSAGING_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "NON_INTERINDUSTRY_DATA_OBJECT_NESTING_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_NON_INTERINDUSTRY_DATA_OBJECT_NESTING_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "DISPLAY_CONTROL", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_DISPLAY_CONTROL, 0x19, -1, -1, -1, -1 },
    { "CARDHOLDER_CERTIFICATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARDHOLDER_CERTIFICATE, 0x19, -1, -1, -1, -1 },
    { "CV_CERTIFICATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CV_CERTIFICATE, 0x19, -1, -1, -1, -1 },
    { "CARDHOLER_REQUIREMENTS_INCLUDED_FEATURES", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARDHOLER_REQUIREMENTS_INCLUDED_FEATURES, 0x19, -1, -1, -1, -1 },
    { "CARDHOLER_REQUIREMENTS_EXCLUDED_FEATURES", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARDHOLER_REQUIREMENTS_EXCLUDED_FEATURES, 0x19, -1, -1, -1, -1 },
    { "BIOMETRIC_DATA_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_BIOMETRIC_DATA_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "DIGITAL_SIGNATURE_BLOCK", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_DIGITAL_SIGNATURE_BLOCK, 0x19, -1, -1, -1, -1 },
    { "CARDHOLDER_PRIVATE_KEY_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARDHOLDER_PRIVATE_KEY_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "CARDHOLDER_PUBLIC_KEY_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CARDHOLDER_PUBLIC_KEY_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "CERTIFICATE_CONTENT_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CERTIFICATE_CONTENT_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "CERTIFICATE_BODY", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_CERTIFICATE_BODY, 0x19, -1, -1, -1, -1 },
    { "BIOMETRIC_INFORMATION_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_BIOMETRIC_INFORMATION_TEMPLATE, 0x19, -1, -1, -1, -1 },
    { "BIOMETRIC_INFORMATION_GROUP_TEMPLATE", "I", .constantValue.asInt = OrgSpongycastleAsn1EacEACTags_BIOMETRIC_INFORMATION_GROUP_TEMPLATE, 0x19, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getTag", "I", "getTagNo", "encodeTag", "LOrgSpongycastleAsn1ASN1ApplicationSpecific;", "decodeTag" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1EacEACTags = { "EACTags", "org.spongycastle.asn1.eac", ptrTable, methods, fields, 7, 0x1, 5, 108, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1EacEACTags;
}

@end

void OrgSpongycastleAsn1EacEACTags_init(OrgSpongycastleAsn1EacEACTags *self) {
  NSObject_init(self);
}

OrgSpongycastleAsn1EacEACTags *new_OrgSpongycastleAsn1EacEACTags_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1EacEACTags, init)
}

OrgSpongycastleAsn1EacEACTags *create_OrgSpongycastleAsn1EacEACTags_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1EacEACTags, init)
}

jint OrgSpongycastleAsn1EacEACTags_getTagWithInt_(jint encodedTag) {
  OrgSpongycastleAsn1EacEACTags_initialize();
  return OrgSpongycastleAsn1EacEACTags_decodeTagWithInt_(encodedTag);
}

jint OrgSpongycastleAsn1EacEACTags_getTagNoWithInt_(jint tag) {
  OrgSpongycastleAsn1EacEACTags_initialize();
  jint i;
  for (i = 24; i >= 0; i -= 8) {
    if (((JreLShift32((jint) 0xFF, i)) & tag) != 0) {
      return ((~(JreLShift32((jint) 0xFF, i))) & tag);
    }
  }
  return 0;
}

jint OrgSpongycastleAsn1EacEACTags_encodeTagWithOrgSpongycastleAsn1ASN1ApplicationSpecific_(OrgSpongycastleAsn1ASN1ApplicationSpecific *spec) {
  OrgSpongycastleAsn1EacEACTags_initialize();
  jint retValue = OrgSpongycastleAsn1BERTags_APPLICATION;
  jboolean constructed = [((OrgSpongycastleAsn1ASN1ApplicationSpecific *) nil_chk(spec)) isConstructed];
  if (constructed) {
    retValue |= OrgSpongycastleAsn1BERTags_CONSTRUCTED;
  }
  jint tag = [spec getApplicationTag];
  if (tag > 31) {
    retValue |= (jint) 0x1F;
    JreLShiftAssignInt(&retValue, 8);
    jint currentByte = tag & (jint) 0x7F;
    retValue |= currentByte;
    JreRShiftAssignInt(&tag, 7);
    while (tag > 0) {
      retValue |= (jint) 0x80;
      JreLShiftAssignInt(&retValue, 8);
      currentByte = tag & (jint) 0x7F;
      JreRShiftAssignInt(&tag, 7);
    }
  }
  else {
    retValue |= tag;
  }
  return retValue;
}

jint OrgSpongycastleAsn1EacEACTags_decodeTagWithInt_(jint tag) {
  OrgSpongycastleAsn1EacEACTags_initialize();
  jint retValue = 0;
  jboolean multiBytes = false;
  for (jint i = 24; i >= 0; i -= 8) {
    jint currentByte = (JreRShift32(tag, i)) & (jint) 0xFF;
    if (currentByte == 0) {
      continue;
    }
    if (multiBytes) {
      JreLShiftAssignInt(&retValue, 7);
      retValue |= currentByte & (jint) 0x7F;
    }
    else if ((currentByte & (jint) 0x1F) == (jint) 0x1F) {
      multiBytes = true;
    }
    else {
      return currentByte & (jint) 0x1F;
    }
  }
  return retValue;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1EacEACTags)
