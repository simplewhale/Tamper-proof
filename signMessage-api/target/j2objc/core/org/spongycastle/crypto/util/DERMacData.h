//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/util/DERMacData.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoUtilDERMacData")
#ifdef RESTRICT_OrgSpongycastleCryptoUtilDERMacData
#define INCLUDE_ALL_OrgSpongycastleCryptoUtilDERMacData 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoUtilDERMacData 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoUtilDERMacData

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#if !defined (OrgSpongycastleCryptoUtilDERMacData_) && (INCLUDE_ALL_OrgSpongycastleCryptoUtilDERMacData || defined(INCLUDE_OrgSpongycastleCryptoUtilDERMacData))
#define OrgSpongycastleCryptoUtilDERMacData_

@class IOSByteArray;

@interface OrgSpongycastleCryptoUtilDERMacData : NSObject

#pragma mark Public

- (IOSByteArray *)getMacData;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoUtilDERMacData)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoUtilDERMacData)

#endif

#if !defined (OrgSpongycastleCryptoUtilDERMacData_Type_) && (INCLUDE_ALL_OrgSpongycastleCryptoUtilDERMacData || defined(INCLUDE_OrgSpongycastleCryptoUtilDERMacData_Type))
#define OrgSpongycastleCryptoUtilDERMacData_Type_

#define RESTRICT_JavaLangEnum 1
#define INCLUDE_JavaLangEnum 1
#include "java/lang/Enum.h"

@class IOSByteArray;
@class IOSObjectArray;

typedef NS_ENUM(NSUInteger, OrgSpongycastleCryptoUtilDERMacData_Type_Enum) {
  OrgSpongycastleCryptoUtilDERMacData_Type_Enum_UNILATERALU = 0,
  OrgSpongycastleCryptoUtilDERMacData_Type_Enum_UNILATERALV = 1,
  OrgSpongycastleCryptoUtilDERMacData_Type_Enum_BILATERALU = 2,
  OrgSpongycastleCryptoUtilDERMacData_Type_Enum_BILATERALV = 3,
};

@interface OrgSpongycastleCryptoUtilDERMacData_Type : JavaLangEnum

#pragma mark Public

- (IOSByteArray *)getHeader;

+ (OrgSpongycastleCryptoUtilDERMacData_Type *)valueOfWithNSString:(NSString *)name;

+ (IOSObjectArray *)values;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoUtilDERMacData_Type)

/*! INTERNAL ONLY - Use enum accessors declared below. */
FOUNDATION_EXPORT OrgSpongycastleCryptoUtilDERMacData_Type *OrgSpongycastleCryptoUtilDERMacData_Type_values_[];

inline OrgSpongycastleCryptoUtilDERMacData_Type *OrgSpongycastleCryptoUtilDERMacData_Type_get_UNILATERALU(void);
J2OBJC_ENUM_CONSTANT(OrgSpongycastleCryptoUtilDERMacData_Type, UNILATERALU)

inline OrgSpongycastleCryptoUtilDERMacData_Type *OrgSpongycastleCryptoUtilDERMacData_Type_get_UNILATERALV(void);
J2OBJC_ENUM_CONSTANT(OrgSpongycastleCryptoUtilDERMacData_Type, UNILATERALV)

inline OrgSpongycastleCryptoUtilDERMacData_Type *OrgSpongycastleCryptoUtilDERMacData_Type_get_BILATERALU(void);
J2OBJC_ENUM_CONSTANT(OrgSpongycastleCryptoUtilDERMacData_Type, BILATERALU)

inline OrgSpongycastleCryptoUtilDERMacData_Type *OrgSpongycastleCryptoUtilDERMacData_Type_get_BILATERALV(void);
J2OBJC_ENUM_CONSTANT(OrgSpongycastleCryptoUtilDERMacData_Type, BILATERALV)

FOUNDATION_EXPORT IOSObjectArray *OrgSpongycastleCryptoUtilDERMacData_Type_values(void);

FOUNDATION_EXPORT OrgSpongycastleCryptoUtilDERMacData_Type *OrgSpongycastleCryptoUtilDERMacData_Type_valueOfWithNSString_(NSString *name);

FOUNDATION_EXPORT OrgSpongycastleCryptoUtilDERMacData_Type *OrgSpongycastleCryptoUtilDERMacData_Type_fromOrdinal(NSUInteger ordinal);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoUtilDERMacData_Type)

#endif

#if !defined (OrgSpongycastleCryptoUtilDERMacData_Builder_) && (INCLUDE_ALL_OrgSpongycastleCryptoUtilDERMacData || defined(INCLUDE_OrgSpongycastleCryptoUtilDERMacData_Builder))
#define OrgSpongycastleCryptoUtilDERMacData_Builder_

@class IOSByteArray;
@class OrgSpongycastleCryptoUtilDERMacData;
@class OrgSpongycastleCryptoUtilDERMacData_Type;

@interface OrgSpongycastleCryptoUtilDERMacData_Builder : NSObject

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoUtilDERMacData_Type:(OrgSpongycastleCryptoUtilDERMacData_Type *)type
                                                   withByteArray:(IOSByteArray *)idU
                                                   withByteArray:(IOSByteArray *)idV
                                                   withByteArray:(IOSByteArray *)ephemDataU
                                                   withByteArray:(IOSByteArray *)ephemDataV;

- (OrgSpongycastleCryptoUtilDERMacData *)build;

- (OrgSpongycastleCryptoUtilDERMacData_Builder *)withTextWithByteArray:(IOSByteArray *)text;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoUtilDERMacData_Builder)

FOUNDATION_EXPORT void OrgSpongycastleCryptoUtilDERMacData_Builder_initWithOrgSpongycastleCryptoUtilDERMacData_Type_withByteArray_withByteArray_withByteArray_withByteArray_(OrgSpongycastleCryptoUtilDERMacData_Builder *self, OrgSpongycastleCryptoUtilDERMacData_Type *type, IOSByteArray *idU, IOSByteArray *idV, IOSByteArray *ephemDataU, IOSByteArray *ephemDataV);

FOUNDATION_EXPORT OrgSpongycastleCryptoUtilDERMacData_Builder *new_OrgSpongycastleCryptoUtilDERMacData_Builder_initWithOrgSpongycastleCryptoUtilDERMacData_Type_withByteArray_withByteArray_withByteArray_withByteArray_(OrgSpongycastleCryptoUtilDERMacData_Type *type, IOSByteArray *idU, IOSByteArray *idV, IOSByteArray *ephemDataU, IOSByteArray *ephemDataV) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoUtilDERMacData_Builder *create_OrgSpongycastleCryptoUtilDERMacData_Builder_initWithOrgSpongycastleCryptoUtilDERMacData_Type_withByteArray_withByteArray_withByteArray_withByteArray_(OrgSpongycastleCryptoUtilDERMacData_Type *type, IOSByteArray *idU, IOSByteArray *idV, IOSByteArray *ephemDataU, IOSByteArray *ephemDataV);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoUtilDERMacData_Builder)

#endif


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoUtilDERMacData")
