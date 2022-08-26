//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/DERNumericString.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1DERNumericString")
#ifdef RESTRICT_OrgSpongycastleAsn1DERNumericString
#define INCLUDE_ALL_OrgSpongycastleAsn1DERNumericString 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1DERNumericString 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1DERNumericString

#if !defined (OrgSpongycastleAsn1DERNumericString_) && (INCLUDE_ALL_OrgSpongycastleAsn1DERNumericString || defined(INCLUDE_OrgSpongycastleAsn1DERNumericString))
#define OrgSpongycastleAsn1DERNumericString_

#define RESTRICT_OrgSpongycastleAsn1ASN1Primitive 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Primitive 1
#include "org/spongycastle/asn1/ASN1Primitive.h"

#define RESTRICT_OrgSpongycastleAsn1ASN1String 1
#define INCLUDE_OrgSpongycastleAsn1ASN1String 1
#include "org/spongycastle/asn1/ASN1String.h"

@class IOSByteArray;
@class OrgSpongycastleAsn1ASN1OutputStream;
@class OrgSpongycastleAsn1ASN1TaggedObject;

@interface OrgSpongycastleAsn1DERNumericString : OrgSpongycastleAsn1ASN1Primitive < OrgSpongycastleAsn1ASN1String >

#pragma mark Public

- (instancetype)initWithNSString:(NSString *)string;

- (instancetype)initWithNSString:(NSString *)string
                     withBoolean:(jboolean)validate;

+ (OrgSpongycastleAsn1DERNumericString *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                withBoolean:(jboolean)explicit_;

+ (OrgSpongycastleAsn1DERNumericString *)getInstanceWithId:(id)obj;

- (IOSByteArray *)getOctets;

- (NSString *)getString;

- (NSUInteger)hash;

+ (jboolean)isNumericStringWithNSString:(NSString *)str;

- (NSString *)description;

#pragma mark Package-Private

- (instancetype)initWithByteArray:(IOSByteArray *)string;

- (jboolean)asn1EqualsWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)o;

- (void)encodeWithOrgSpongycastleAsn1ASN1OutputStream:(OrgSpongycastleAsn1ASN1OutputStream *)outArg;

- (jint)encodedLength;

- (jboolean)isConstructed;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1DERNumericString)

FOUNDATION_EXPORT OrgSpongycastleAsn1DERNumericString *OrgSpongycastleAsn1DERNumericString_getInstanceWithId_(id obj);

FOUNDATION_EXPORT OrgSpongycastleAsn1DERNumericString *OrgSpongycastleAsn1DERNumericString_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT void OrgSpongycastleAsn1DERNumericString_initWithByteArray_(OrgSpongycastleAsn1DERNumericString *self, IOSByteArray *string);

FOUNDATION_EXPORT OrgSpongycastleAsn1DERNumericString *new_OrgSpongycastleAsn1DERNumericString_initWithByteArray_(IOSByteArray *string) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1DERNumericString *create_OrgSpongycastleAsn1DERNumericString_initWithByteArray_(IOSByteArray *string);

FOUNDATION_EXPORT void OrgSpongycastleAsn1DERNumericString_initWithNSString_(OrgSpongycastleAsn1DERNumericString *self, NSString *string);

FOUNDATION_EXPORT OrgSpongycastleAsn1DERNumericString *new_OrgSpongycastleAsn1DERNumericString_initWithNSString_(NSString *string) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1DERNumericString *create_OrgSpongycastleAsn1DERNumericString_initWithNSString_(NSString *string);

FOUNDATION_EXPORT void OrgSpongycastleAsn1DERNumericString_initWithNSString_withBoolean_(OrgSpongycastleAsn1DERNumericString *self, NSString *string, jboolean validate);

FOUNDATION_EXPORT OrgSpongycastleAsn1DERNumericString *new_OrgSpongycastleAsn1DERNumericString_initWithNSString_withBoolean_(NSString *string, jboolean validate) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1DERNumericString *create_OrgSpongycastleAsn1DERNumericString_initWithNSString_withBoolean_(NSString *string, jboolean validate);

FOUNDATION_EXPORT jboolean OrgSpongycastleAsn1DERNumericString_isNumericStringWithNSString_(NSString *str);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1DERNumericString)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1DERNumericString")