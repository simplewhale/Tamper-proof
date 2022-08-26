//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/EncryptedContentInfoParser.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsEncryptedContentInfoParser")
#ifdef RESTRICT_OrgSpongycastleAsn1CmsEncryptedContentInfoParser
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsEncryptedContentInfoParser 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmsEncryptedContentInfoParser 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmsEncryptedContentInfoParser

#if !defined (OrgSpongycastleAsn1CmsEncryptedContentInfoParser_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmsEncryptedContentInfoParser || defined(INCLUDE_OrgSpongycastleAsn1CmsEncryptedContentInfoParser))
#define OrgSpongycastleAsn1CmsEncryptedContentInfoParser_

@class OrgSpongycastleAsn1ASN1ObjectIdentifier;
@class OrgSpongycastleAsn1X509AlgorithmIdentifier;
@protocol OrgSpongycastleAsn1ASN1Encodable;
@protocol OrgSpongycastleAsn1ASN1SequenceParser;

@interface OrgSpongycastleAsn1CmsEncryptedContentInfoParser : NSObject

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1SequenceParser:(id<OrgSpongycastleAsn1ASN1SequenceParser>)seq;

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getContentEncryptionAlgorithm;

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getContentType;

- (id<OrgSpongycastleAsn1ASN1Encodable>)getEncryptedContentWithInt:(jint)tag;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmsEncryptedContentInfoParser)

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmsEncryptedContentInfoParser_initWithOrgSpongycastleAsn1ASN1SequenceParser_(OrgSpongycastleAsn1CmsEncryptedContentInfoParser *self, id<OrgSpongycastleAsn1ASN1SequenceParser> seq);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsEncryptedContentInfoParser *new_OrgSpongycastleAsn1CmsEncryptedContentInfoParser_initWithOrgSpongycastleAsn1ASN1SequenceParser_(id<OrgSpongycastleAsn1ASN1SequenceParser> seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmsEncryptedContentInfoParser *create_OrgSpongycastleAsn1CmsEncryptedContentInfoParser_initWithOrgSpongycastleAsn1ASN1SequenceParser_(id<OrgSpongycastleAsn1ASN1SequenceParser> seq);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmsEncryptedContentInfoParser)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmsEncryptedContentInfoParser")
