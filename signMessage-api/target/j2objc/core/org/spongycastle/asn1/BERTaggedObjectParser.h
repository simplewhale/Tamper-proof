//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/BERTaggedObjectParser.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1BERTaggedObjectParser")
#ifdef RESTRICT_OrgSpongycastleAsn1BERTaggedObjectParser
#define INCLUDE_ALL_OrgSpongycastleAsn1BERTaggedObjectParser 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1BERTaggedObjectParser 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1BERTaggedObjectParser

#if !defined (OrgSpongycastleAsn1BERTaggedObjectParser_) && (INCLUDE_ALL_OrgSpongycastleAsn1BERTaggedObjectParser || defined(INCLUDE_OrgSpongycastleAsn1BERTaggedObjectParser))
#define OrgSpongycastleAsn1BERTaggedObjectParser_

#define RESTRICT_OrgSpongycastleAsn1ASN1TaggedObjectParser 1
#define INCLUDE_OrgSpongycastleAsn1ASN1TaggedObjectParser 1
#include "org/spongycastle/asn1/ASN1TaggedObjectParser.h"

@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1StreamParser;
@protocol OrgSpongycastleAsn1ASN1Encodable;

@interface OrgSpongycastleAsn1BERTaggedObjectParser : NSObject < OrgSpongycastleAsn1ASN1TaggedObjectParser >

#pragma mark Public

- (OrgSpongycastleAsn1ASN1Primitive *)getLoadedObject;

- (id<OrgSpongycastleAsn1ASN1Encodable>)getObjectParserWithInt:(jint)tag
                                                   withBoolean:(jboolean)isExplicit;

- (jint)getTagNo;

- (jboolean)isConstructed;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

#pragma mark Package-Private

- (instancetype)initWithBoolean:(jboolean)constructed
                        withInt:(jint)tagNumber
withOrgSpongycastleAsn1ASN1StreamParser:(OrgSpongycastleAsn1ASN1StreamParser *)parser;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1BERTaggedObjectParser)

FOUNDATION_EXPORT void OrgSpongycastleAsn1BERTaggedObjectParser_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1StreamParser_(OrgSpongycastleAsn1BERTaggedObjectParser *self, jboolean constructed, jint tagNumber, OrgSpongycastleAsn1ASN1StreamParser *parser);

FOUNDATION_EXPORT OrgSpongycastleAsn1BERTaggedObjectParser *new_OrgSpongycastleAsn1BERTaggedObjectParser_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1StreamParser_(jboolean constructed, jint tagNumber, OrgSpongycastleAsn1ASN1StreamParser *parser) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1BERTaggedObjectParser *create_OrgSpongycastleAsn1BERTaggedObjectParser_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1StreamParser_(jboolean constructed, jint tagNumber, OrgSpongycastleAsn1ASN1StreamParser *parser);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1BERTaggedObjectParser)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1BERTaggedObjectParser")
