//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/ServerName.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsServerName")
#ifdef RESTRICT_OrgSpongycastleCryptoTlsServerName
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsServerName 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsServerName 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoTlsServerName

#if !defined (OrgSpongycastleCryptoTlsServerName_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsServerName || defined(INCLUDE_OrgSpongycastleCryptoTlsServerName))
#define OrgSpongycastleCryptoTlsServerName_

@class JavaIoInputStream;
@class JavaIoOutputStream;

@interface OrgSpongycastleCryptoTlsServerName : NSObject {
 @public
  jshort nameType_;
  id name_;
}

#pragma mark Public

- (instancetype)initWithShort:(jshort)nameType
                       withId:(id)name;

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)output;

- (NSString *)getHostName;

- (id)getName;

- (jshort)getNameType;

+ (OrgSpongycastleCryptoTlsServerName *)parseWithJavaIoInputStream:(JavaIoInputStream *)input;

#pragma mark Protected

+ (jboolean)isCorrectTypeWithShort:(jshort)nameType
                            withId:(id)name;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoTlsServerName)

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsServerName, name_, id)

FOUNDATION_EXPORT void OrgSpongycastleCryptoTlsServerName_initWithShort_withId_(OrgSpongycastleCryptoTlsServerName *self, jshort nameType, id name);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsServerName *new_OrgSpongycastleCryptoTlsServerName_initWithShort_withId_(jshort nameType, id name) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsServerName *create_OrgSpongycastleCryptoTlsServerName_initWithShort_withId_(jshort nameType, id name);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsServerName *OrgSpongycastleCryptoTlsServerName_parseWithJavaIoInputStream_(JavaIoInputStream *input);

FOUNDATION_EXPORT jboolean OrgSpongycastleCryptoTlsServerName_isCorrectTypeWithShort_withId_(jshort nameType, id name);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsServerName)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsServerName")