//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/PKIXNameConstraintValidator.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509PKIXNameConstraintValidator")
#ifdef RESTRICT_OrgSpongycastleAsn1X509PKIXNameConstraintValidator
#define INCLUDE_ALL_OrgSpongycastleAsn1X509PKIXNameConstraintValidator 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1X509PKIXNameConstraintValidator 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1X509PKIXNameConstraintValidator

#if !defined (OrgSpongycastleAsn1X509PKIXNameConstraintValidator_) && (INCLUDE_ALL_OrgSpongycastleAsn1X509PKIXNameConstraintValidator || defined(INCLUDE_OrgSpongycastleAsn1X509PKIXNameConstraintValidator))
#define OrgSpongycastleAsn1X509PKIXNameConstraintValidator_

#define RESTRICT_OrgSpongycastleAsn1X509NameConstraintValidator 1
#define INCLUDE_OrgSpongycastleAsn1X509NameConstraintValidator 1
#include "org/spongycastle/asn1/x509/NameConstraintValidator.h"

@class IOSObjectArray;
@class OrgSpongycastleAsn1X509GeneralName;
@class OrgSpongycastleAsn1X509GeneralSubtree;

@interface OrgSpongycastleAsn1X509PKIXNameConstraintValidator : NSObject < OrgSpongycastleAsn1X509NameConstraintValidator >

#pragma mark Public

- (instancetype)init;

- (void)addExcludedSubtreeWithOrgSpongycastleAsn1X509GeneralSubtree:(OrgSpongycastleAsn1X509GeneralSubtree *)subtree;

- (void)checkExcludedWithOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)name;

- (void)checkPermittedWithOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)name;

- (jboolean)isEqual:(id)o;

- (NSUInteger)hash;

- (void)intersectEmptyPermittedSubtreeWithInt:(jint)nameType;

- (void)intersectPermittedSubtreeWithOrgSpongycastleAsn1X509GeneralSubtree:(OrgSpongycastleAsn1X509GeneralSubtree *)permitted;

- (void)intersectPermittedSubtreeWithOrgSpongycastleAsn1X509GeneralSubtreeArray:(IOSObjectArray *)permitted;

- (NSString *)description;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1X509PKIXNameConstraintValidator)

FOUNDATION_EXPORT void OrgSpongycastleAsn1X509PKIXNameConstraintValidator_init(OrgSpongycastleAsn1X509PKIXNameConstraintValidator *self);

FOUNDATION_EXPORT OrgSpongycastleAsn1X509PKIXNameConstraintValidator *new_OrgSpongycastleAsn1X509PKIXNameConstraintValidator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1X509PKIXNameConstraintValidator *create_OrgSpongycastleAsn1X509PKIXNameConstraintValidator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1X509PKIXNameConstraintValidator)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1X509PKIXNameConstraintValidator")