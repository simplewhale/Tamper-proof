//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/config/ProviderConfigurationPermission.java
//

#include "J2ObjC_source.h"
#include "com/youzh/lingtu/sign/crypto/config/ProviderConfigurationPermission.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/security/BasicPermission.h"
#include "java/security/Permission.h"
#include "java/util/StringTokenizer.h"
#include "org/spongycastle/util/Strings.h"

@interface ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission () {
 @public
  NSString *actions_;
  jint permissionMask_;
}

- (jint)calculateMaskWithNSString:(NSString *)actions;

@end

J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission, actions_, NSString *)

inline jint ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_get_THREAD_LOCAL_EC_IMPLICITLY_CA(void);
#define ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_THREAD_LOCAL_EC_IMPLICITLY_CA 1
J2OBJC_STATIC_FIELD_CONSTANT(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission, THREAD_LOCAL_EC_IMPLICITLY_CA, jint)

inline jint ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_get_EC_IMPLICITLY_CA(void);
#define ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_EC_IMPLICITLY_CA 2
J2OBJC_STATIC_FIELD_CONSTANT(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission, EC_IMPLICITLY_CA, jint)

inline jint ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_get_THREAD_LOCAL_DH_DEFAULT_PARAMS(void);
#define ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_THREAD_LOCAL_DH_DEFAULT_PARAMS 4
J2OBJC_STATIC_FIELD_CONSTANT(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission, THREAD_LOCAL_DH_DEFAULT_PARAMS, jint)

inline jint ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_get_DH_DEFAULT_PARAMS(void);
#define ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_DH_DEFAULT_PARAMS 8
J2OBJC_STATIC_FIELD_CONSTANT(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission, DH_DEFAULT_PARAMS, jint)

inline jint ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_get_ALL(void);
#define ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_ALL 15
J2OBJC_STATIC_FIELD_CONSTANT(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission, ALL, jint)

inline NSString *ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_get_THREAD_LOCAL_EC_IMPLICITLY_CA_STR(void);
static NSString *ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_THREAD_LOCAL_EC_IMPLICITLY_CA_STR = @"threadlocalecimplicitlyca";
J2OBJC_STATIC_FIELD_OBJ_FINAL(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission, THREAD_LOCAL_EC_IMPLICITLY_CA_STR, NSString *)

inline NSString *ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_get_EC_IMPLICITLY_CA_STR(void);
static NSString *ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_EC_IMPLICITLY_CA_STR = @"ecimplicitlyca";
J2OBJC_STATIC_FIELD_OBJ_FINAL(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission, EC_IMPLICITLY_CA_STR, NSString *)

inline NSString *ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_get_THREAD_LOCAL_DH_DEFAULT_PARAMS_STR(void);
static NSString *ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_THREAD_LOCAL_DH_DEFAULT_PARAMS_STR = @"threadlocaldhdefaultparams";
J2OBJC_STATIC_FIELD_OBJ_FINAL(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission, THREAD_LOCAL_DH_DEFAULT_PARAMS_STR, NSString *)

inline NSString *ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_get_DH_DEFAULT_PARAMS_STR(void);
static NSString *ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_DH_DEFAULT_PARAMS_STR = @"dhdefaultparams";
J2OBJC_STATIC_FIELD_OBJ_FINAL(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission, DH_DEFAULT_PARAMS_STR, NSString *)

inline NSString *ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_get_ALL_STR(void);
static NSString *ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_ALL_STR = @"all";
J2OBJC_STATIC_FIELD_OBJ_FINAL(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission, ALL_STR, NSString *)

__attribute__((unused)) static jint ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_calculateMaskWithNSString_(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission *self, NSString *actions);

@implementation ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission

- (instancetype)initWithNSString:(NSString *)name {
  ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_initWithNSString_(self, name);
  return self;
}

- (instancetype)initWithNSString:(NSString *)name
                    withNSString:(NSString *)actions {
  ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_initWithNSString_withNSString_(self, name, actions);
  return self;
}

- (jint)calculateMaskWithNSString:(NSString *)actions {
  return ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_calculateMaskWithNSString_(self, actions);
}

- (NSString *)getActions {
  return actions_;
}

- (jboolean)impliesWithJavaSecurityPermission:(JavaSecurityPermission *)permission {
  if (!([permission isKindOfClass:[ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission class]])) {
    return false;
  }
  if (![((NSString *) nil_chk([self getName])) isEqual:[((JavaSecurityPermission *) nil_chk(permission)) getName]]) {
    return false;
  }
  ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission *other = (ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission *) cast_chk(permission, [ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission class]);
  return (self->permissionMask_ & other->permissionMask_) == other->permissionMask_;
}

- (jboolean)isEqual:(id)obj {
  if (obj == self) {
    return true;
  }
  if ([obj isKindOfClass:[ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission class]]) {
    ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission *other = (ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission *) obj;
    return self->permissionMask_ == ((ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission *) nil_chk(other))->permissionMask_ && [((NSString *) nil_chk([self getName])) isEqual:[other getName]];
  }
  return false;
}

- (NSUInteger)hash {
  return ((jint) [((NSString *) nil_chk([self getName])) hash]) + self->permissionMask_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 2, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 7, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  methods[1].selector = @selector(initWithNSString:withNSString:);
  methods[2].selector = @selector(calculateMaskWithNSString:);
  methods[3].selector = @selector(getActions);
  methods[4].selector = @selector(impliesWithJavaSecurityPermission:);
  methods[5].selector = @selector(isEqual:);
  methods[6].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "THREAD_LOCAL_EC_IMPLICITLY_CA", "I", .constantValue.asInt = ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_THREAD_LOCAL_EC_IMPLICITLY_CA, 0x1a, -1, -1, -1, -1 },
    { "EC_IMPLICITLY_CA", "I", .constantValue.asInt = ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_EC_IMPLICITLY_CA, 0x1a, -1, -1, -1, -1 },
    { "THREAD_LOCAL_DH_DEFAULT_PARAMS", "I", .constantValue.asInt = ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_THREAD_LOCAL_DH_DEFAULT_PARAMS, 0x1a, -1, -1, -1, -1 },
    { "DH_DEFAULT_PARAMS", "I", .constantValue.asInt = ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_DH_DEFAULT_PARAMS, 0x1a, -1, -1, -1, -1 },
    { "ALL", "I", .constantValue.asInt = ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_ALL, 0x1a, -1, -1, -1, -1 },
    { "THREAD_LOCAL_EC_IMPLICITLY_CA_STR", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 8, -1, -1 },
    { "EC_IMPLICITLY_CA_STR", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 9, -1, -1 },
    { "THREAD_LOCAL_DH_DEFAULT_PARAMS_STR", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 10, -1, -1 },
    { "DH_DEFAULT_PARAMS_STR", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 11, -1, -1 },
    { "ALL_STR", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 12, -1, -1 },
    { "actions_", "LNSString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "permissionMask_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;", "LNSString;LNSString;", "calculateMask", "implies", "LJavaSecurityPermission;", "equals", "LNSObject;", "hashCode", &ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_THREAD_LOCAL_EC_IMPLICITLY_CA_STR, &ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_EC_IMPLICITLY_CA_STR, &ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_THREAD_LOCAL_DH_DEFAULT_PARAMS_STR, &ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_DH_DEFAULT_PARAMS_STR, &ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_ALL_STR };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission = { "ProviderConfigurationPermission", "com.youzh.lingtu.sign.crypto.config", ptrTable, methods, fields, 7, 0x1, 7, 12, -1, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission;
}

@end

void ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_initWithNSString_(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission *self, NSString *name) {
  JavaSecurityBasicPermission_initWithNSString_(self, name);
  self->actions_ = @"all";
  self->permissionMask_ = ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_ALL;
}

ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission *new_ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_initWithNSString_(NSString *name) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission, initWithNSString_, name)
}

ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission *create_ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_initWithNSString_(NSString *name) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission, initWithNSString_, name)
}

void ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_initWithNSString_withNSString_(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission *self, NSString *name, NSString *actions) {
  JavaSecurityBasicPermission_initWithNSString_withNSString_(self, name, actions);
  self->actions_ = actions;
  self->permissionMask_ = ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_calculateMaskWithNSString_(self, actions);
}

ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission *new_ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_initWithNSString_withNSString_(NSString *name, NSString *actions) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission, initWithNSString_withNSString_, name, actions)
}

ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission *create_ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_initWithNSString_withNSString_(NSString *name, NSString *actions) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission, initWithNSString_withNSString_, name, actions)
}

jint ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_calculateMaskWithNSString_(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission *self, NSString *actions) {
  JavaUtilStringTokenizer *tok = new_JavaUtilStringTokenizer_initWithNSString_withNSString_(OrgSpongycastleUtilStrings_toLowerCaseWithNSString_(actions), @" ,");
  jint mask = 0;
  while ([tok hasMoreTokens]) {
    NSString *s = [tok nextToken];
    if ([((NSString *) nil_chk(s)) isEqual:ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_THREAD_LOCAL_EC_IMPLICITLY_CA_STR]) {
      mask |= ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_THREAD_LOCAL_EC_IMPLICITLY_CA;
    }
    else if ([s isEqual:ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_EC_IMPLICITLY_CA_STR]) {
      mask |= ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_EC_IMPLICITLY_CA;
    }
    else if ([s isEqual:ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_THREAD_LOCAL_DH_DEFAULT_PARAMS_STR]) {
      mask |= ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_THREAD_LOCAL_DH_DEFAULT_PARAMS;
    }
    else if ([s isEqual:ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_DH_DEFAULT_PARAMS_STR]) {
      mask |= ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_DH_DEFAULT_PARAMS;
    }
    else if ([s isEqual:ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_ALL_STR]) {
      mask |= ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission_ALL;
    }
  }
  if (mask == 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unknown permissions passed to mask");
  }
  return mask;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoConfigProviderConfigurationPermission)
