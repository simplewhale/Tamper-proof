//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/Store.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleUtilStore")
#ifdef RESTRICT_OrgSpongycastleUtilStore
#define INCLUDE_ALL_OrgSpongycastleUtilStore 0
#else
#define INCLUDE_ALL_OrgSpongycastleUtilStore 1
#endif
#undef RESTRICT_OrgSpongycastleUtilStore

#if !defined (OrgSpongycastleUtilStore_) && (INCLUDE_ALL_OrgSpongycastleUtilStore || defined(INCLUDE_OrgSpongycastleUtilStore))
#define OrgSpongycastleUtilStore_

@protocol JavaUtilCollection;
@protocol OrgSpongycastleUtilSelector;

@protocol OrgSpongycastleUtilStore < JavaObject >

- (id<JavaUtilCollection>)getMatchesWithOrgSpongycastleUtilSelector:(id<OrgSpongycastleUtilSelector>)selector;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleUtilStore)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleUtilStore)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleUtilStore")
