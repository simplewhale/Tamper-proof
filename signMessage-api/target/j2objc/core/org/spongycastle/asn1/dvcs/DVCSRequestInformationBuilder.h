//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/dvcs/DVCSRequestInformationBuilder.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder")
#ifdef RESTRICT_OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder
#define INCLUDE_ALL_OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder

#if !defined (OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder_) && (INCLUDE_ALL_OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder || defined(INCLUDE_OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder))
#define OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder_

@class JavaMathBigInteger;
@class OrgSpongycastleAsn1DvcsDVCSRequestInformation;
@class OrgSpongycastleAsn1DvcsDVCSTime;
@class OrgSpongycastleAsn1DvcsServiceType;
@class OrgSpongycastleAsn1X509Extensions;
@class OrgSpongycastleAsn1X509GeneralName;
@class OrgSpongycastleAsn1X509GeneralNames;
@class OrgSpongycastleAsn1X509PolicyInformation;

@interface OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder : NSObject

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1DvcsDVCSRequestInformation:(OrgSpongycastleAsn1DvcsDVCSRequestInformation *)initialInfo;

- (instancetype)initWithOrgSpongycastleAsn1DvcsServiceType:(OrgSpongycastleAsn1DvcsServiceType *)service;

- (OrgSpongycastleAsn1DvcsDVCSRequestInformation *)build;

- (void)setDataLocationsWithOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)dataLocation;

- (void)setDataLocationsWithOrgSpongycastleAsn1X509GeneralNames:(OrgSpongycastleAsn1X509GeneralNames *)dataLocations;

- (void)setDVCSWithOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)dvcs;

- (void)setDVCSWithOrgSpongycastleAsn1X509GeneralNames:(OrgSpongycastleAsn1X509GeneralNames *)dvcs;

- (void)setExtensionsWithOrgSpongycastleAsn1X509Extensions:(OrgSpongycastleAsn1X509Extensions *)extensions;

- (void)setNonceWithJavaMathBigInteger:(JavaMathBigInteger *)nonce;

- (void)setRequesterWithOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)requester;

- (void)setRequesterWithOrgSpongycastleAsn1X509GeneralNames:(OrgSpongycastleAsn1X509GeneralNames *)requester;

- (void)setRequestPolicyWithOrgSpongycastleAsn1X509PolicyInformation:(OrgSpongycastleAsn1X509PolicyInformation *)requestPolicy;

- (void)setRequestTimeWithOrgSpongycastleAsn1DvcsDVCSTime:(OrgSpongycastleAsn1DvcsDVCSTime *)requestTime;

- (void)setVersionWithInt:(jint)version_;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder)

FOUNDATION_EXPORT void OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder_initWithOrgSpongycastleAsn1DvcsServiceType_(OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder *self, OrgSpongycastleAsn1DvcsServiceType *service);

FOUNDATION_EXPORT OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder *new_OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder_initWithOrgSpongycastleAsn1DvcsServiceType_(OrgSpongycastleAsn1DvcsServiceType *service) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder *create_OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder_initWithOrgSpongycastleAsn1DvcsServiceType_(OrgSpongycastleAsn1DvcsServiceType *service);

FOUNDATION_EXPORT void OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder_initWithOrgSpongycastleAsn1DvcsDVCSRequestInformation_(OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder *self, OrgSpongycastleAsn1DvcsDVCSRequestInformation *initialInfo);

FOUNDATION_EXPORT OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder *new_OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder_initWithOrgSpongycastleAsn1DvcsDVCSRequestInformation_(OrgSpongycastleAsn1DvcsDVCSRequestInformation *initialInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder *create_OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder_initWithOrgSpongycastleAsn1DvcsDVCSRequestInformation_(OrgSpongycastleAsn1DvcsDVCSRequestInformation *initialInfo);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1DvcsDVCSRequestInformationBuilder")
