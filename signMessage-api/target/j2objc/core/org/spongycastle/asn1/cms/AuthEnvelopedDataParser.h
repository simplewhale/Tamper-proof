//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/AuthEnvelopedDataParser.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsAuthEnvelopedDataParser")
#ifdef RESTRICT_OrgSpongycastleAsn1CmsAuthEnvelopedDataParser
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsAuthEnvelopedDataParser 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsAuthEnvelopedDataParser 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmsAuthEnvelopedDataParser

#if !defined (OrgSpongycastleAsn1CmsAuthEnvelopedDataParser_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmsAuthEnvelopedDataParser || defined(INCLUDE_OrgSpongycastleAsn1CmsAuthEnvelopedDataParser))
#define OrgSpongycastleAsn1CmsAuthEnvelopedDataParser_

@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1ASN1OctetString;
@class OrgSpongycastleAsn1CmsEncryptedContentInfoParser;
@class OrgSpongycastleAsn1CmsOriginatorInfo;
@protocol OrgSpongycastleAsn1ASN1SequenceParser;
@protocol OrgSpongycastleAsn1ASN1SetParser;

@interface OrgSpongycastleAsn1CmsAuthEnvelopedDataParser : NSObject

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1SequenceParser:(id<OrgSpongycastleAsn1ASN1SequenceParser>)seq;

- (id<OrgSpongycastleAsn1ASN1SetParser>)getAuthAttrs;

- (OrgSpongycastleAsn1CmsEncryptedContentInfoParser *)getAuthEncryptedContentInfo;

- (OrgSpongycastleAsn1ASN1OctetString *)getMac;

- (OrgSpongycastleAsn1CmsOriginatorInfo *)getOriginatorInfo;

- (id<OrgSpongycastleAsn1ASN1SetParser>)getRecipientInfos;

- (id<OrgSpongycastleAsn1ASN1SetParser>)getUnauthAttrs;

- (OrgSpongycastleAsn1ASN1Integer *)getVersion;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmsAuthEnvelopedDataParser)

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsAuthEnvelopedDataParser_initWithOrgSpongycastleAsn1ASN1SequenceParser_(OrgSpongycastleAsn1CmsAuthEnvelopedDataParser *self, id<OrgSpongycastleAsn1ASN1SequenceParser> seq);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsAuthEnvelopedDataParser *new_OrgSpongycastleAsn1CmsAuthEnvelopedDataParser_initWithOrgSpongycastleAsn1ASN1SequenceParser_(id<OrgSpongycastleAsn1ASN1SequenceParser> seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsAuthEnvelopedDataParser *create_OrgSpongycastleAsn1CmsAuthEnvelopedDataParser_initWithOrgSpongycastleAsn1ASN1SequenceParser_(id<OrgSpongycastleAsn1ASN1SequenceParser> seq);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmsAuthEnvelopedDataParser)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsAuthEnvelopedDataParser")