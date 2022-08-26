//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x500/X500Name.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1X500X500Name")
#ifdef RESTRICT_OrgSpongycastleAsn1X500X500Name
#define INCLUDE_ALL_OrgSpongycastleAsn1X500X500Name 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1X500X500Name 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1X500X500Name

#if !defined (OrgSpongycastleAsn1X500X500Name_) && (INCLUDE_ALL_OrgSpongycastleAsn1X500X500Name || defined(INCLUDE_OrgSpongycastleAsn1X500X500Name))
#define OrgSpongycastleAsn1X500X500Name_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

#define RESTRICT_OrgSpongycastleAsn1ASN1Choice 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Choice 1
#include "org/spongycastle/asn1/ASN1Choice.h"

@class IOSObjectArray;
@class OrgSpongycastleAsn1ASN1ObjectIdentifier;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1TaggedObject;
@protocol OrgSpongycastleAsn1X500X500NameStyle;

@interface OrgSpongycastleAsn1X500X500Name : OrgSpongycastleAsn1ASN1Object < OrgSpongycastleAsn1ASN1Choice >

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1X500RDNArray:(IOSObjectArray *)rDNs;

- (instancetype)initWithNSString:(NSString *)dirName;

- (instancetype)initWithOrgSpongycastleAsn1X500X500NameStyle:(id<OrgSpongycastleAsn1X500X500NameStyle>)style
                         withOrgSpongycastleAsn1X500RDNArray:(IOSObjectArray *)rDNs;

- (instancetype)initWithOrgSpongycastleAsn1X500X500NameStyle:(id<OrgSpongycastleAsn1X500X500NameStyle>)style
                                                withNSString:(NSString *)dirName;

- (instancetype)initWithOrgSpongycastleAsn1X500X500NameStyle:(id<OrgSpongycastleAsn1X500X500NameStyle>)style
                         withOrgSpongycastleAsn1X500X500Name:(OrgSpongycastleAsn1X500X500Name *)name;

- (jboolean)isEqual:(id)obj;

- (IOSObjectArray *)getAttributeTypes;

+ (id<OrgSpongycastleAsn1X500X500NameStyle>)getDefaultStyle;

+ (OrgSpongycastleAsn1X500X500Name *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                            withBoolean:(jboolean)explicit_;

+ (OrgSpongycastleAsn1X500X500Name *)getInstanceWithId:(id)obj;

+ (OrgSpongycastleAsn1X500X500Name *)getInstanceWithOrgSpongycastleAsn1X500X500NameStyle:(id<OrgSpongycastleAsn1X500X500NameStyle>)style
                                                                                  withId:(id)obj;

- (IOSObjectArray *)getRDNs;

- (IOSObjectArray *)getRDNsWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)attributeType;

- (NSUInteger)hash;

+ (void)setDefaultStyleWithOrgSpongycastleAsn1X500X500NameStyle:(id<OrgSpongycastleAsn1X500X500NameStyle>)style;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleAsn1X500X500Name)

FOUNDATION_EXPORT void OrgSpongycastleAsn1X500X500Name_initWithOrgSpongycastleAsn1X500X500NameStyle_withOrgSpongycastleAsn1X500X500Name_(OrgSpongycastleAsn1X500X500Name *self, id<OrgSpongycastleAsn1X500X500NameStyle> style, OrgSpongycastleAsn1X500X500Name *name);

FOUNDATION_EXPORT OrgSpongycastleAsn1X500X500Name *new_OrgSpongycastleAsn1X500X500Name_initWithOrgSpongycastleAsn1X500X500NameStyle_withOrgSpongycastleAsn1X500X500Name_(id<OrgSpongycastleAsn1X500X500NameStyle> style, OrgSpongycastleAsn1X500X500Name *name) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X500X500Name *create_OrgSpongycastleAsn1X500X500Name_initWithOrgSpongycastleAsn1X500X500NameStyle_withOrgSpongycastleAsn1X500X500Name_(id<OrgSpongycastleAsn1X500X500NameStyle> style, OrgSpongycastleAsn1X500X500Name *name);

FOUNDATION_EXPORT OrgSpongycastleAsn1X500X500Name *OrgSpongycastleAsn1X500X500Name_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT OrgSpongycastleAsn1X500X500Name *OrgSpongycastleAsn1X500X500Name_getInstanceWithId_(id obj);

FOUNDATION_EXPORT OrgSpongycastleAsn1X500X500Name *OrgSpongycastleAsn1X500X500Name_getInstanceWithOrgSpongycastleAsn1X500X500NameStyle_withId_(id<OrgSpongycastleAsn1X500X500NameStyle> style, id obj);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X500X500Name_initWithOrgSpongycastleAsn1X500RDNArray_(OrgSpongycastleAsn1X500X500Name *self, IOSObjectArray *rDNs);

FOUNDATION_EXPORT OrgSpongycastleAsn1X500X500Name *new_OrgSpongycastleAsn1X500X500Name_initWithOrgSpongycastleAsn1X500RDNArray_(IOSObjectArray *rDNs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X500X500Name *create_OrgSpongycastleAsn1X500X500Name_initWithOrgSpongycastleAsn1X500RDNArray_(IOSObjectArray *rDNs);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X500X500Name_initWithOrgSpongycastleAsn1X500X500NameStyle_withOrgSpongycastleAsn1X500RDNArray_(OrgSpongycastleAsn1X500X500Name *self, id<OrgSpongycastleAsn1X500X500NameStyle> style, IOSObjectArray *rDNs);

FOUNDATION_EXPORT OrgSpongycastleAsn1X500X500Name *new_OrgSpongycastleAsn1X500X500Name_initWithOrgSpongycastleAsn1X500X500NameStyle_withOrgSpongycastleAsn1X500RDNArray_(id<OrgSpongycastleAsn1X500X500NameStyle> style, IOSObjectArray *rDNs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X500X500Name *create_OrgSpongycastleAsn1X500X500Name_initWithOrgSpongycastleAsn1X500X500NameStyle_withOrgSpongycastleAsn1X500RDNArray_(id<OrgSpongycastleAsn1X500X500NameStyle> style, IOSObjectArray *rDNs);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X500X500Name_initWithNSString_(OrgSpongycastleAsn1X500X500Name *self, NSString *dirName);

FOUNDATION_EXPORT OrgSpongycastleAsn1X500X500Name *new_OrgSpongycastleAsn1X500X500Name_initWithNSString_(NSString *dirName) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X500X500Name *create_OrgSpongycastleAsn1X500X500Name_initWithNSString_(NSString *dirName);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X500X500Name_initWithOrgSpongycastleAsn1X500X500NameStyle_withNSString_(OrgSpongycastleAsn1X500X500Name *self, id<OrgSpongycastleAsn1X500X500NameStyle> style, NSString *dirName);

FOUNDATION_EXPORT OrgSpongycastleAsn1X500X500Name *new_OrgSpongycastleAsn1X500X500Name_initWithOrgSpongycastleAsn1X500X500NameStyle_withNSString_(id<OrgSpongycastleAsn1X500X500NameStyle> style, NSString *dirName) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X500X500Name *create_OrgSpongycastleAsn1X500X500Name_initWithOrgSpongycastleAsn1X500X500NameStyle_withNSString_(id<OrgSpongycastleAsn1X500X500NameStyle> style, NSString *dirName);

FOUNDATION_EXPORT void OrgSpongycastleAsn1X500X500Name_setDefaultStyleWithOrgSpongycastleAsn1X500X500NameStyle_(id<OrgSpongycastleAsn1X500X500NameStyle> style);

FOUNDATION_EXPORT id<OrgSpongycastleAsn1X500X500NameStyle> OrgSpongycastleAsn1X500X500Name_getDefaultStyle(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X500X500Name)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1X500X500Name")