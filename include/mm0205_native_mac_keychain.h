#ifndef MM0205_NATIVE_MAC_KEYCHAIN_MM0205_NATIVE_MAC_KEYCHAIN_H
#define MM0205_NATIVE_MAC_KEYCHAIN_MM0205_NATIVE_MAC_KEYCHAIN_H

#ifdef __cplusplus
extern "C" {

#endif

/**
 * Indicates the operation succeeded.
 */
#define MM_NMK_ERROR_SUCCESS 0

/**
 * Indicates any required arguments of function are NULL.
 */
#define MM_NMK_ERROR_ARGUMENT_IS_NULL 1

/**
 * Indicates the `account` of the parameter is NULL.
 */
#define MM_NMK_ERROR_ARGUMENT_ACCOUNT_IS_NULL 2

/**
 * Indicates the `password`  is NULL.
 */
#define MM_NMK_ERROR_ARGUMENT_PASSWORD_IS_NULL 3

/**
 * Indicates the `password_capacity` is LESS THAN 1.
 */
#define MM_NMK_ERROR_ARGUMENT_PASSWORD_CAPACITY_LESS_THAN_1 4

/**
 * Indicates the `result` is NULL.
 */
#define MM_NMK_ERROR_ARGUMENT_RESULT_IS_NULL 5

/**
 * Indicates the conversion failed.
 * If the function returns this value,
 * probably the buffer is too small or the password is invalid utf-8 sequence.
 */
#define MM_NMK_ERROR_FAILED_TO_CONVERT_PASSWORD_TO_C_STRING 5

/**
 * Indicates an API used in the function returns error status. \n
 * When the function returns this error code,
 * The `apiStatus` parameter of the function has a value that is described at
 * https://developer.apple.com/documentation/security/1542001-security_framework_result_codes
 */
#define MM_NMK_ERROR_API_RETURNS_ERROR 1000

/**
 * Dictionary type.
 */
typedef struct _mm_dictionary_t {
    /**
     * Indicates the number of elements of keys and values.
     */
    int count;

    /**
     * array of keys.
     * Each element of keys is null terminated.
     */
    char** keys;

    /**
     * array of values.
     * Each element of values is null terminated.
     */
    char** values;
} mm_dictionary_t;

/**
 * This struct is used for the argument of `mm_save_generic_password`.
 */
typedef struct _mm_save_generic_password_t {
    /**
     * @brief [required] The account corresponds to the password.
     * @see https://developer.apple.com/documentation/security/ksecattraccount
     */
    char* account;

    /**
     * @brief [required] The password to be stored.
     * @see https://developer.apple.com/documentation/security/ksecattrgeneric
     */
    char* password;

    /**
     * @brief The description of the password.
     * This is visible to users.
     * @see https://developer.apple.com/documentation/security/ksecattrdescription
     */
    char* description;

    /**
     * @brief The comment of the password.
     * This is editable by users.
     * @see https://developer.apple.com/documentation/security/ksecattrcomment
     */
    char* comment;

    /**
     * @brief The label of the password.
     * @see https://developer.apple.com/documentation/security/ksecattrlabel
     */
    char* label;

    /**
     * @brief The service associated with the password.
     * @see https://developer.apple.com/documentation/security/ksecattrservice
     */
    char* service;
} mm_save_generic_password_t;

/**
 * This struct is used for `mm_load_generic_password`.
 * The fields in this struct is used as a parameter of the query
 * to retrieve Keychain item.
 */
typedef struct _mm_reference_generic_password_t {
    /**
     * @brief The account corresponds to the password.
     * @see https://developer.apple.com/documentation/security/ksecattraccount
     */
    char* account;

    /**
     * @brief The description of the password.
     * This is visible to users.
     * @see https://developer.apple.com/documentation/security/ksecattrdescription
     */
    char* description;

    /**
     * @brief The comment of the password.
     * This is editable by users.
     * @see https://developer.apple.com/documentation/security/ksecattrcomment
     */
    char* comment;

    /**
     * @brief The label of the password.
     * @see https://developer.apple.com/documentation/security/ksecattrlabel
     */
    char* label;

    /**
     * @brief The service associated with the password.
     * @see https://developer.apple.com/documentation/security/ksecattrservice
     */
    char* service;
} mm_reference_generic_password_t;

/**
 * Saves a given generic password.
 *
 * @param parameter parameter for generic password.
 * @param api_status status code returned by the OS API.
 *
 * @return zero if succeeded otherwise non-zero.
 */
int mm_save_generic_password(
    const mm_save_generic_password_t* parameter,
    int* api_status
);

/**
 * Loads a generic password specified by the parameter.
 *
 * @param parameter parameter for query to find a password.
 * @param password output buffer for password.
 * @param password_capacity capacity of the `password` in bytes.
 * @param api_status status returned by the OS API.
 *
 * @return zero if succeeded otherwise non-zero
 */
int mm_load_generic_password(
    const mm_reference_generic_password_t* parameter,
    char* password,
    int password_capacity,
    int* api_status
);

int mm_load_generic_password_attributes(
    const mm_reference_generic_password_t* parameter,
    mm_dictionary_t* result,
    int* api_status
);

int mm_update_generic_password(
    const mm_reference_generic_password_t* query_parameter,
    const mm_save_generic_password_t* edit_parameter,
    int* api_status
);

int mm_delete_generic_password(
    const mm_reference_generic_password_t* parameter,
    int* api_status
);

/**
 * @brief releases the dictionary contents.
 * @param dictionary a dictionary whose items to be released.
 */
void mm_free_dictionary(mm_dictionary_t* dictionary);

#ifdef __cplusplus
}
#endif

#endif //MM0205_NATIVE_MAC_KEYCHAIN_MM0205_NATIVE_MAC_KEYCHAIN_H
