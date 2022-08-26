//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmc/IdentityProofV2.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmcIdentityProofV2")
#ifdef RESTRICT_OrgSpongycastleAsn1CmcIdentityProofV2
#define INCLUDE_ALL_OrgSpongycastleAsn1CmcIdentityProofV2 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmcIdentityProofV2 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmcIdentityProofV2

#if !defined (OrgSpongycastleAsn1CmcIdentityProofV2_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmcIdentityProofV2 || defined(INCLUDE_OrgSpongycastleAsn1CmcIdentityProofV2))
#define OrgSpongycastleAsn1CmcIdentityProofV2_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSByteArray;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1X509AlgorithmIdentifier;

@interface OrgSpongycastleAsn1CmcIdentityProofV2 : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)proofAlgID
                    withOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)macAlgId
                                                     withByteArray:(IOSByteArray *)witness;

+ (OrgSpongycastleAsn1CmcIdentityProofV2 *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getMacAlgId;

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getProofAlgID;

- (IOSByteArray *)getWitness;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmcIdentityProofV2)

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmcIdentityProofV2_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_(OrgSpongycastleAsn1CmcIdentityProofV2 *self, OrgSpongycastleAsn1X509AlgorithmIdentifier *proofAlgID, OrgSpongycastleAsn1X509AlgorithmIdentifier *macAlgId, IOSByteArray *witness);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmcIdentityProofV2 *new_OrgSpongycastleAsn1CmcIdentityProofV2_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_(OrgSpongycastleAsn1X509AlgorithmIdentifier *proofAlgID, OrgSpongycastleAsn1X509AlgorithmIdentifier *macAlgId, IOSByteArray *witness) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmcIdentityProofV2 *create_OrgSpongycastleAsn1CmcIdentityProofV2_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_(OrgSpongycastleAsn1X509AlgorithmIdentifier *proofAlgID, OrgSpongycastleAsn1X509AlgorithmIdentifier *macAlgId, IOSByteArray *witness);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmcIdentityProofV2 *OrgSpongycastleAsn1CmcIdentityProofV2_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmcIdentityProofV2)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmcIdentityProofV2")