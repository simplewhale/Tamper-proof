//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/BEROctetStringParser.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1BEROctetStringParser")
#ifdef RESTRICT_OrgSpongycastleAsn1BEROctetStringParser
#define INCLUDE_ALL_OrgSpongycastleAsn1BEROctetStringParser 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1BEROctetStringParser 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1BEROctetStringParser

#if !defined (OrgSpongycastleAsn1BEROctetStringParser_) && (INCLUDE_ALL_OrgSpongycastleAsn1BEROctetStringParser || defined(INCLUDE_OrgSpongycastleAsn1BEROctetStringParser))
#define OrgSpongycastleAsn1BEROctetStringParser_

#define RESTRICT_OrgSpongycastleAsn1ASN1OctetStringParser 1
#define INCLUDE_OrgSpongycastleAsn1ASN1OctetStringParser 1
#include "org/spongycastle/asn1/ASN1OctetStringParser.h"

@class JavaIoInputStream;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1StreamParser;

@interface OrgSpongycastleAsn1BEROctetStringParser : NSObject < OrgSpongycastleAsn1ASN1OctetStringParser >

#pragma mark Public

- (OrgSpongycastleAsn1ASN1Primitive *)getLoadedObject;

- (JavaIoInputStream *)getOctetStream;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

#pragma mark Package-Private

- (instancetype)initWithOrgSpongycastleAsn1ASN1StreamParser:(OrgSpongycastleAsn1ASN1StreamParser *)parser;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1BEROctetStringParser)

FOUNDATION_EXPORT void OrgSpongycastleAsn1BEROctetStringParser_initWithOrgSpongycastleAsn1ASN1StreamParser_(OrgSpongycastleAsn1BEROctetStringParser *self, OrgSpongycastleAsn1ASN1StreamParser *parser);

FOUNDATION_EXPORT OrgSpongycastleAsn1BEROctetStringParser *new_OrgSpongycastleAsn1BEROctetStringParser_initWithOrgSpongycastleAsn1ASN1StreamParser_(OrgSpongycastleAsn1ASN1StreamParser *parser) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1BEROctetStringParser *create_OrgSpongycastleAsn1BEROctetStringParser_initWithOrgSpongycastleAsn1ASN1StreamParser_(OrgSpongycastleAsn1ASN1StreamParser *parser);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1BEROctetStringParser)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1BEROctetStringParser")
