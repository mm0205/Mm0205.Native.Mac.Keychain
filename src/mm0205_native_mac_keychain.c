#include "mm0205_native_mac_keychain.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

static CFMutableDictionaryRef mm_convert_edit_generic_password_t_to_dictionary(
    const mm_save_generic_password_t* source
);

static CFMutableDictionaryRef mm_convert_reference_generic_password_t_to_dictionary(
    const mm_reference_generic_password_t* source
);


int mm_save_generic_password(
    const mm_save_generic_password_t* parameter,
    int* api_status
) {
    CFMutableDictionaryRef item_dictionary;
    OSStatus status;

    if (parameter == NULL) {
        return MM_NMK_ERROR_ARGUMENT_IS_NULL;
    }

    if (parameter->account == NULL) {
        return MM_NMK_ERROR_ARGUMENT_ACCOUNT_IS_NULL;
    }

    if (parameter->password == NULL) {
        return MM_NMK_ERROR_ARGUMENT_PASSWORD_IS_NULL;
    }

    item_dictionary = mm_convert_edit_generic_password_t_to_dictionary(parameter);

    status = SecItemAdd(item_dictionary, NULL);
    if (api_status) {
        *api_status = status;
    }
    CFRelease(item_dictionary);

    if (status != errSecSuccess) {
        return MM_NMK_ERROR_API_RETURNS_ERROR;
    }

    return MM_NMK_ERROR_SUCCESS;
}

int mm_load_generic_password(
    const mm_reference_generic_password_t* parameter,
    char* password,
    int password_capacity,
    int* api_status
) {
    CFMutableDictionaryRef query;
    CFStringRef password_text;
    OSStatus status;
    CFDataRef result = NULL;
    Boolean password_conversion_is_ok;

    if (parameter == NULL) {
        return MM_NMK_ERROR_ARGUMENT_IS_NULL;
    }
    if (password == NULL) {
        return MM_NMK_ERROR_ARGUMENT_PASSWORD_IS_NULL;
    }
    if (password_capacity < 1) {
        return MM_NMK_ERROR_ARGUMENT_PASSWORD_CAPACITY_LESS_THAN_1;
    }

    query = mm_convert_reference_generic_password_t_to_dictionary(parameter);
    CFDictionaryAddValue(query, kSecReturnData, kCFBooleanTrue);

    status = SecItemCopyMatching(query, (CFTypeRef*) &result);
    if (api_status) {
        *api_status = status;
    }
    CFRelease(query);

    if (status != errSecSuccess) {
        return MM_NMK_ERROR_API_RETURNS_ERROR;
    }

    password_text = CFStringCreateFromExternalRepresentation(NULL, result, kCFStringEncodingUTF8);
    password_conversion_is_ok = CFStringGetCString(password_text, password, password_capacity, kCFStringEncodingUTF8);
    CFRelease(result);

    if (!password_conversion_is_ok) {
        return MM_NMK_ERROR_FAILED_TO_CONVERT_PASSWORD_TO_C_STRING;
    }

    return MM_NMK_ERROR_SUCCESS;
}

int mm_load_generic_password_attributes(
    const mm_reference_generic_password_t* parameter,
    mm_dictionary_t* result,
    int* api_status
) {
    CFMutableDictionaryRef query;
    OSStatus status;
    CFDictionaryRef attributes;
    CFIndex attribute_count;
    CFStringRef* keys;
    CFTypeRef* values;

    if (parameter == NULL) {
        return MM_NMK_ERROR_ARGUMENT_IS_NULL;
    }
    if (result == NULL) {
        return MM_NMK_ERROR_ARGUMENT_RESULT_IS_NULL;
    }

    query = mm_convert_reference_generic_password_t_to_dictionary(parameter);
    CFDictionaryAddValue(query, kSecReturnAttributes, kCFBooleanTrue);

    status = SecItemCopyMatching(query, (CFTypeRef*) &attributes);
    if (api_status) {
        *api_status = status;
    }
    CFRelease(query);

    if (status != errSecSuccess) {
        return MM_NMK_ERROR_API_RETURNS_ERROR;
    }

    attribute_count = CFDictionaryGetCount(attributes);
    keys = (CFStringRef*) malloc(attribute_count * sizeof(CFTypeRef));
    values = (CFTypeRef*) malloc(attribute_count * sizeof(CFTypeRef));

    result->count = attribute_count;
    result->keys = malloc(attribute_count * sizeof(char*));
    result->values = malloc(attribute_count * sizeof(char*));

    CFDictionaryGetKeysAndValues(attributes, (const void**) keys, (const void**) values);


    for (int i = 0; i < attribute_count; i++) {
        int length = CFStringGetLength(keys[i]);
        long utf8Length = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
        result->keys[i] = malloc(utf8Length);
        CFStringGetCString(keys[i], result->keys[i], utf8Length, kCFStringEncodingUTF8);

        if (strcmp(result->keys[i], "mdat") == 0 || strcmp(result->keys[i], "cdat") == 0) {
            CFLocaleRef current_locale = CFLocaleCopyCurrent();
            CFDateFormatterRef formatter = CFDateFormatterCreate(
                NULL,
                current_locale,
                kCFDateFormatterFullStyle,
                kCFDateFormatterFullStyle
            );

            CFStringRef date = CFDateFormatterCreateStringWithDate(NULL, formatter, values[i]);

            length = CFStringGetLength(date);
            utf8Length = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
            result->values[i] = malloc(utf8Length);
            CFStringGetCString(date, result->values[i], utf8Length, kCFStringEncodingUTF8);

            CFRelease(date);
            CFRelease(formatter);
            CFRelease(current_locale);
        } else if (values[0]) {
            length = CFStringGetLength(values[i]);
            utf8Length = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
            result->values[i] = malloc(utf8Length);
            CFStringGetCString(values[i], result->values[i], utf8Length, kCFStringEncodingUTF8);
        }
    }
    free(keys);
    free(values);
    CFRelease(attributes);

    return MM_NMK_ERROR_SUCCESS;
}

int mm_delete_generic_password(
    const mm_reference_generic_password_t* parameter,
    int* api_status
) {
    CFMutableDictionaryRef query;
    OSStatus status;

    if (parameter == NULL) {
        return MM_NMK_ERROR_ARGUMENT_IS_NULL;
    }

    query = mm_convert_reference_generic_password_t_to_dictionary(parameter);
    status = SecItemDelete(query);
    if (api_status) {
        *api_status = status;
    }
    CFRelease(query);

    if (status != errSecSuccess) {
        return MM_NMK_ERROR_API_RETURNS_ERROR;
    }

    return MM_NMK_ERROR_SUCCESS;
}

int mm_update_generic_password(
    const mm_reference_generic_password_t* query_parameter,
    const mm_save_generic_password_t* edit_parameter,
    int* api_status
) {
    CFMutableDictionaryRef search_query;
    CFMutableDictionaryRef edit_query;
    OSStatus status;

    if (query_parameter == NULL) {
        return MM_NMK_ERROR_ARGUMENT_IS_NULL;
    }
    if (edit_parameter == NULL) {
        return MM_NMK_ERROR_ARGUMENT_IS_NULL;
    }

    search_query = mm_convert_reference_generic_password_t_to_dictionary(query_parameter);
    edit_query = mm_convert_edit_generic_password_t_to_dictionary(edit_parameter);
    SecItemUpdate(search_query, edit_query);

    status = SecItemDelete(search_query);
    if (api_status) {
        *api_status = status;
    }
    CFRelease(search_query);

    if (status != errSecSuccess) {
        return MM_NMK_ERROR_API_RETURNS_ERROR;
    }

    return MM_NMK_ERROR_SUCCESS;
}

void mm_free_dictionary(mm_dictionary_t* dictionary) {
    mm_dictionary_t* p;

    if (dictionary == NULL) {
        return;
    }

    p = dictionary;

    for (int i = 0; i < p->count; i++) {
        if (p->keys[i]) {
            free(p->keys[i]);
            p->keys[i] = NULL;
        }
        if (p->values[i]) {
            free(p->values[i]);
            p->values[i] = NULL;
        }
    }
    free(p->keys);
    free(p->values);
}


CFMutableDictionaryRef mm_convert_edit_generic_password_t_to_dictionary(const mm_save_generic_password_t* source) {
    CFMutableDictionaryRef item_dictionary;
    CFStringRef account;
    CFStringRef password_text;
    CFDataRef password;
    CFStringRef service;
    CFStringRef comment;
    CFStringRef description;
    CFStringRef label;
    OSStatus status;

    item_dictionary = CFDictionaryCreateMutable(
        NULL,
        0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionaryAddValue(item_dictionary, kSecClass, kSecClassGenericPassword);

    if (source->account) {
        account = CFStringCreateWithCString(NULL, source->account, kCFStringEncodingUTF8);
        CFDictionaryAddValue(item_dictionary, kSecAttrAccount, account);
    }

    if (source->password) {
        password_text = CFStringCreateWithCString(NULL, source->password, kCFStringEncodingUTF8);
        password = CFStringCreateExternalRepresentation(NULL, password_text, kCFStringEncodingUTF8, 0);
        CFRelease(password_text);
        CFDictionaryAddValue(item_dictionary, kSecValueData, password);
    }

    if (source->service) {
        service = CFStringCreateWithCString(NULL, source->service, kCFStringEncodingUTF8);
        CFDictionaryAddValue(item_dictionary, kSecAttrService, service);
    }
    if (source->comment) {
        comment = CFStringCreateWithCString(NULL, source->comment, kCFStringEncodingUTF8);
        CFDictionaryAddValue(item_dictionary, kSecAttrComment, comment);
    }
    if (source->description) {
        description = CFStringCreateWithCString(NULL, source->description, kCFStringEncodingUTF8);
        CFDictionaryAddValue(item_dictionary, kSecAttrDescription, description);
    }
    if (source->label) {
        label = CFStringCreateWithCString(NULL, source->label, kCFStringEncodingUTF8);
        CFDictionaryAddValue(item_dictionary, kSecAttrLabel, label);
    }
    return item_dictionary;
}

static CFMutableDictionaryRef mm_convert_reference_generic_password_t_to_dictionary(
    const mm_reference_generic_password_t* source
) {
    CFMutableDictionaryRef item_dictionary;
    CFStringRef account;
    CFStringRef service;
    CFStringRef comment;
    CFStringRef description;
    CFStringRef label;

    item_dictionary = CFDictionaryCreateMutable(
        NULL,
        0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionaryAddValue(item_dictionary, kSecClass, kSecClassGenericPassword);

    account = CFStringCreateWithCString(NULL, source->account, kCFStringEncodingUTF8);
    CFDictionaryAddValue(item_dictionary, kSecAttrAccount, account);

    if (source->service) {
        service = CFStringCreateWithCString(NULL, source->service, kCFStringEncodingUTF8);
        CFDictionaryAddValue(item_dictionary, kSecAttrService, service);
    }
    if (source->comment) {
        comment = CFStringCreateWithCString(NULL, source->comment, kCFStringEncodingUTF8);
        CFDictionaryAddValue(item_dictionary, kSecAttrComment, comment);
    }
    if (source->description) {
        description = CFStringCreateWithCString(NULL, source->description, kCFStringEncodingUTF8);
        CFDictionaryAddValue(item_dictionary, kSecAttrDescription, description);
    }
    if (source->label) {
        label = CFStringCreateWithCString(NULL, source->label, kCFStringEncodingUTF8);
        CFDictionaryAddValue(item_dictionary, kSecAttrLabel, label);
    }

    return item_dictionary;
}


