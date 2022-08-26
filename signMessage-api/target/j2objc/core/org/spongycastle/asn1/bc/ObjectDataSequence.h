//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/bc/ObjectDataSequence.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1BcObjectDataSequence")
#ifdef RESTRICT_OrgSpongycastleAsn1BcObjectDataSequence
#define INCLUDE_ALL_OrgSpongycastleAsn1BcObjectDataSequence 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1BcObjectDataSequence 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1BcObjectDataSequence

#if !defined (OrgSpongycastleAsn1BcObjectDataSequence_) && (INCLUDE_ALL_OrgSpongycastleAsn1BcObjectDataSequence || defined(INCLUDE_OrgSpongycastleAsn1BcObjectDataSequence))
#define OrgSpongycastleAsn1BcObjectDataSequence_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

#define RESTRICT_OrgSpongycastleUtilIterable 1
#define INCLUDE_OrgSpongycastleUtilIterable 1
#include "org/spongycastle/util/Iterable.h"

@class IOSObjectArray;
@class OrgSpongycastleAsn1ASN1Primitive;
@protocol JavaUtilFunctionConsumer;
@protocol JavaUtilIterator;
@protocol JavaUtilSpliterator;

@interface OrgSpongycastleAsn1BcObjectDataSequence : OrgSpongycastleAsn1ASN1Object < OrgSpongycastleUtilIterable >

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1BcObjectDataArray:(IOSObjectArray *)dataSequence;

+ (OrgSpongycastleAsn1BcObjectDataSequence *)getInstanceWithId:(id)obj;

- (id<JavaUtilIterator>)iterator;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

#pragma mark Package-Private

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1BcObjectDataSequence)

FOUNDATION_EXPORT void OrgSpongycastleAsn1BcObjectDataSequence_initWithOrgSpongycastleAsn1BcObjectDataArray_(OrgSpongycastleAsn1BcObjectDataSequence *self, IOSObjectArray *dataSequence);

FOUNDATION_EXPORT OrgSpongycastleAsn1BcObjectDataSequence *new_OrgSpongycastleAsn1BcObjectDataSequence_initWithOrgSpongycastleAsn1BcObjectDataArray_(IOSObjectArray *dataSequence) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1BcObjectDataSequence *create_OrgSpongycastleAsn1BcObjectDataSequence_initWithOrgSpongycastleAsn1BcObjectDataArray_(IOSObjectArray *dataSequence);

FOUNDATION_EXPORT OrgSpongycastleAsn1BcObjectDataSequence *OrgSpongycastleAsn1BcObjectDataSequence_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1BcObjectDataSequence)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1BcObjectDataSequence")
