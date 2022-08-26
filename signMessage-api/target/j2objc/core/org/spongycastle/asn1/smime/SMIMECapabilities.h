//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/smime/SMIMECapabilities.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1SmimeSMIMECapabilities")
#ifdef RESTRICT_OrgSpongycastleAsn1SmimeSMIMECapabilities
#define INCLUDE_ALL_OrgSpongycastleAsn1SmimeSMIMECapabilities 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1SmimeSMIMECapabilities 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1SmimeSMIMECapabilities

#if !defined (OrgSpongycastleAsn1SmimeSMIMECapabilities_) && (INCLUDE_ALL_OrgSpongycastleAsn1SmimeSMIMECapabilities || defined(INCLUDE_OrgSpongycastleAsn1SmimeSMIMECapabilities))
#define OrgSpongycastleAsn1SmimeSMIMECapabilities_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class JavaUtilVector;
@class OrgSpongycastleAsn1ASN1ObjectIdentifier;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1Sequence;

@interface OrgSpongycastleAsn1SmimeSMIMECapabilities : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

- (JavaUtilVector *)getCapabilitiesWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)capability;

+ (OrgSpongycastleAsn1SmimeSMIMECapabilities *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleAsn1SmimeSMIMECapabilities)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_get_preferSignedData(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_preferSignedData;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1SmimeSMIMECapabilities, preferSignedData, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_get_canNotDecryptAny(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_canNotDecryptAny;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1SmimeSMIMECapabilities, canNotDecryptAny, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_get_sMIMECapabilitesVersions(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_sMIMECapabilitesVersions;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1SmimeSMIMECapabilities, sMIMECapabilitesVersions, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_get_aes256_CBC(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_aes256_CBC;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1SmimeSMIMECapabilities, aes256_CBC, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_get_aes192_CBC(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_aes192_CBC;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1SmimeSMIMECapabilities, aes192_CBC, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_get_aes128_CBC(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_aes128_CBC;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1SmimeSMIMECapabilities, aes128_CBC, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_get_idea_CBC(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_idea_CBC;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1SmimeSMIMECapabilities, idea_CBC, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_get_cast5_CBC(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_cast5_CBC;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1SmimeSMIMECapabilities, cast5_CBC, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_get_dES_CBC(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_dES_CBC;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1SmimeSMIMECapabilities, dES_CBC, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_get_dES_EDE3_CBC(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_dES_EDE3_CBC;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1SmimeSMIMECapabilities, dES_EDE3_CBC, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

inline OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_get_rC2_CBC(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleAsn1ASN1ObjectIdentifier *OrgSpongycastleAsn1SmimeSMIMECapabilities_rC2_CBC;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1SmimeSMIMECapabilities, rC2_CBC, OrgSpongycastleAsn1ASN1ObjectIdentifier *)

FOUNDATION_EXPORT OrgSpongycastleAsn1SmimeSMIMECapabilities *OrgSpongycastleAsn1SmimeSMIMECapabilities_getInstanceWithId_(id o);

FOUNDATION_EXPORT void OrgSpongycastleAsn1SmimeSMIMECapabilities_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1SmimeSMIMECapabilities *self, OrgSpongycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT OrgSpongycastleAsn1SmimeSMIMECapabilities *new_OrgSpongycastleAsn1SmimeSMIMECapabilities_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1SmimeSMIMECapabilities *create_OrgSpongycastleAsn1SmimeSMIMECapabilities_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1SmimeSMIMECapabilities)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1SmimeSMIMECapabilities")
