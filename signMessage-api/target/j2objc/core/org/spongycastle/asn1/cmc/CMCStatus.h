//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmc/CMCStatus.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmcCMCStatus")
#ifdef RESTRICT_OrgSpongycastleAsn1CmcCMCStatus
#define INCLUDE_ALL_OrgSpongycastleAsn1CmcCMCStatus 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmcCMCStatus 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmcCMCStatus

#if !defined (OrgSpongycastleAsn1CmcCMCStatus_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmcCMCStatus || defined(INCLUDE_OrgSpongycastleAsn1CmcCMCStatus))
#define OrgSpongycastleAsn1CmcCMCStatus_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1Primitive;

@interface OrgSpongycastleAsn1CmcCMCStatus : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

+ (OrgSpongycastleAsn1CmcCMCStatus *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleAsn1CmcCMCStatus)

inline OrgSpongycastleAsn1CmcCMCStatus *OrgSpongycastleAsn1CmcCMCStatus_get_success(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1CmcCMCStatus *OrgSpongycastleAsn1CmcCMCStatus_success;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1CmcCMCStatus, success, OrgSpongycastleAsn1CmcCMCStatus *)

inline OrgSpongycastleAsn1CmcCMCStatus *OrgSpongycastleAsn1CmcCMCStatus_get_failed(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1CmcCMCStatus *OrgSpongycastleAsn1CmcCMCStatus_failed;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1CmcCMCStatus, failed, OrgSpongycastleAsn1CmcCMCStatus *)

inline OrgSpongycastleAsn1CmcCMCStatus *OrgSpongycastleAsn1CmcCMCStatus_get_pending(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1CmcCMCStatus *OrgSpongycastleAsn1CmcCMCStatus_pending;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1CmcCMCStatus, pending, OrgSpongycastleAsn1CmcCMCStatus *)

inline OrgSpongycastleAsn1CmcCMCStatus *OrgSpongycastleAsn1CmcCMCStatus_get_noSupport(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1CmcCMCStatus *OrgSpongycastleAsn1CmcCMCStatus_noSupport;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1CmcCMCStatus, noSupport, OrgSpongycastleAsn1CmcCMCStatus *)

inline OrgSpongycastleAsn1CmcCMCStatus *OrgSpongycastleAsn1CmcCMCStatus_get_confirmRequired(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1CmcCMCStatus *OrgSpongycastleAsn1CmcCMCStatus_confirmRequired;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1CmcCMCStatus, confirmRequired, OrgSpongycastleAsn1CmcCMCStatus *)

inline OrgSpongycastleAsn1CmcCMCStatus *OrgSpongycastleAsn1CmcCMCStatus_get_popRequired(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1CmcCMCStatus *OrgSpongycastleAsn1CmcCMCStatus_popRequired;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1CmcCMCStatus, popRequired, OrgSpongycastleAsn1CmcCMCStatus *)

inline OrgSpongycastleAsn1CmcCMCStatus *OrgSpongycastleAsn1CmcCMCStatus_get_partial(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1CmcCMCStatus *OrgSpongycastleAsn1CmcCMCStatus_partial;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1CmcCMCStatus, partial, OrgSpongycastleAsn1CmcCMCStatus *)

FOUNDATION_EXPORT OrgSpongycastleAsn1CmcCMCStatus *OrgSpongycastleAsn1CmcCMCStatus_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmcCMCStatus)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmcCMCStatus")