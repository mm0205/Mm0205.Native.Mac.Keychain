//
// Created by munenaga on 2020/01/13.
//

#include "mm0205_native_mac_keychain.h"
#include <memory.h>

static int test_add_generic_password();

static int test_load_generic_password();

static int test_load_generic_password_attributes();

static int test_update_generic_password();

static int test_delete_generic_password();


int main() {
    test_add_generic_password();
    test_load_generic_password();
    test_load_generic_password_attributes();
//    test_update_generic_password();
    test_delete_generic_password();
}


static int test_add_generic_password() {
    int api_status;
    int error;

    mm_save_generic_password_t parameter;
    memset(&parameter, 0, sizeof(mm_save_generic_password_t));
    parameter.account = "mm0205-keychain-test-account";
    parameter.password = "mm0205-keychain-test-password";
    parameter.service = "mm0205-keychain-test-service";
    parameter.description = "mm0205-keychain-test-description";
    parameter.comment = "mm0205-keychain-test-comment";
    parameter.label = "mm0205-keychain-test-label";

    error = mm_save_generic_password(
        &parameter,
        &api_status
    );

    if (error) {
        return 1;
    }

    return 0;
}


static int test_load_generic_password() {
    int api_status;
    int error;
    const int BUFFER_SIZE = 255;
    char password_buffer[BUFFER_SIZE];

    mm_reference_generic_password_t parameter;
    memset(&parameter, 0, sizeof(mm_reference_generic_password_t));

    parameter.account = "mm0205-keychain-test-account";
    parameter.service = "mm0205-keychain-test-service";
    parameter.description = "mm0205-keychain-test-description";
    parameter.comment = "mm0205-keychain-test-comment";
    parameter.label = "mm0205-keychain-test-label";

    error = mm_load_generic_password(
        &parameter,
        password_buffer,
        BUFFER_SIZE,
        &api_status
    );

    if (error) {
        return 1;
    }

    return 0;
}

static int test_load_generic_password_attributes() {
    int api_status;
    int error;
    mm_dictionary_t attributes;

    mm_reference_generic_password_t parameter;
    memset(&parameter, 0, sizeof(mm_reference_generic_password_t));

    parameter.account = "mm0205-keychain-test-account";
    parameter.service = "mm0205-keychain-test-service";
    parameter.description = "mm0205-keychain-test-description";
    parameter.comment = "mm0205-keychain-test-comment";
    parameter.label = "mm0205-keychain-test-label";

    error = mm_load_generic_password_attributes(
        &parameter,
        &attributes,
        &api_status
    );

    if (error) {
        return 1;
    }

    mm_free_dictionary(&attributes);

    return 0;
}

int test_update_generic_password() {
    int api_status;
    int error;
    mm_save_generic_password_t edit_param;
    mm_reference_generic_password_t query_param;

    memset(&query_param, 0, sizeof(mm_reference_generic_password_t));
    query_param.account = "mm0205-keychain-test-account";
    query_param.service = "mm0205-keychain-test-service";
    query_param.description = "mm0205-keychain-test-description";
    query_param.comment = "mm0205-keychain-test-comment";
    query_param.label = "mm0205-keychain-test-label";

    memset(&edit_param, 0, sizeof(mm_save_generic_password_t));
    edit_param.account = "mm0205-keychain-test-account2";
    edit_param.password = "mm0205-keychain-test-password2";
    edit_param.service = "mm0205-keychain-test-service2";
    edit_param.description = "mm0205-keychain-test-description2";
    edit_param.comment = "mm0205-keychain-test-comment2";
    edit_param.label = "mm0205-keychain-test-label2";

    error = mm_update_generic_password(
        &query_param,
        &edit_param,
        &api_status
    );

    if (error) {
        return 1;
    }

    return 0;
}

int test_delete_generic_password() {
    int api_status;
    int error;

    mm_reference_generic_password_t parameter;
    memset(&parameter, 0, sizeof(mm_reference_generic_password_t));

    parameter.account = "mm0205-keychain-test-account";
    parameter.service = "mm0205-keychain-test-service";
    parameter.description = "mm0205-keychain-test-description";
    parameter.comment = "mm0205-keychain-test-comment";
    parameter.label = "mm0205-keychain-test-label";

    error = mm_delete_generic_password(
        &parameter,
        &api_status
    );

    if (error) {
        return 1;
    }

    return 0;
}


