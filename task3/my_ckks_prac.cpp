// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void my_ckks_prac()
{
    print_example_banner("THIS IS MY CKKS PRACTICE");

    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 50, 50, 50, 50, 60 }));

    double scale = pow(2.0, 50);    // 델타 Δ

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++)
    {
        input.push_back(curr_point);
        curr_point += step_size;
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);  // 3부터 7개의 요소 출력. 즉 input[3], input[4], ... input[9]

    cout << "Evaluating polynomial (x+1)^2 * (x^2+2) ..." << endl;

    Plaintext plain_con1, plain_con2;   // 상수 1, 2
    encoder.encode(1.0, scale, plain_con1);
    encoder.encode(2.0, scale, plain_con2);

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, scale, x_plain);
    Ciphertext x_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);   // 암호화된 x = x_encrypted -> lv4

    Ciphertext xplus1;
    evaluator.add_plain(x_encrypted, plain_con1, xplus1);   // xplus1 = (x+1) -> lv4

    Ciphertext xplus1_square;
    print_line(__LINE__);
    cout << "Compute (x+1)^2 and relinearize:" << endl;
    evaluator.square(xplus1, xplus1_square);                // (x+1)^2
    evaluator.relinearize_inplace(xplus1_square, relin_keys);   // relinearize
    cout << "    + Scale of (x+1)^2 before rescale: " << log2(xplus1_square.scale()) << " bits" << endl;

    print_line(__LINE__);
    cout << "Rescale (x+1)^2." << endl;
    evaluator.rescale_to_next_inplace(xplus1_square);   // (x+1)^2 rescale -> lv3
    cout << "    + Scale of (x+1)^2 after rescale: " << log2(xplus1_square.scale()) << " bits" << endl;

    print_line(__LINE__);
    cout << "Compute, relinearize and rescale x * x." << endl;
    Ciphertext x_square;
    evaluator.square(x_encrypted, x_square);    // x^2
    evaluator.relinearize_inplace(x_square, relin_keys);    // relinearize

    print_line(__LINE__);
    cout << "    + Scale of x^2 before rescale: " << log2(x_square.scale()) << " bits" << endl;

    print_line(__LINE__);
    evaluator.rescale_to_next_inplace(x_square);    // x^2 rescale -> lv3
    cout << "    + Scale of x^2 after rescale: " << log2(x_square.scale()) << " bits" << endl;

    // print_line(__LINE__);
    // parms_id_type last_parms_id = x_square.parms_id();
    // evaluator.mod_switch_to_inplace(plain_con2, last_parms_id); // x^2 + 2를 위해 2를 lv3으로 내림

    print_line(__LINE__);
    cout << "Parameters used by x^2 and 2 are different. \n\tLevel of '2' should be down!!!" << endl;
    cout << "    + Modulus chain index for (x+1)^2: "
         << context.get_context_data(xplus1_square.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for (x^2): "
         << context.get_context_data(x_square.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for (2): "
         << context.get_context_data(plain_con2.parms_id())->chain_index() << endl;

    x_square.scale() = pow(2.0, 50);
    parms_id_type last_parms_id = x_square.parms_id();
    evaluator.mod_switch_to_inplace(plain_con2, last_parms_id);

    Ciphertext x_square_plus2;
    evaluator.add_plain(x_square, plain_con2, x_square_plus2);  // (x^2 + 2) -> lv3

    cout << "    + Modulus chain index for (x^2 + 2): "
    << context.get_context_data(x_square_plus2.parms_id())->chain_index() << endl;
    
    Ciphertext encrypted_result;
    print_line(__LINE__);
    cout << "Compute (x+1)^2 * (x^2+2), relinearize, rescale: " << endl;
    evaluator.multiply(xplus1_square, x_square_plus2, encrypted_result);
    evaluator.relinearize_inplace(encrypted_result, relin_keys);    // relinearize

    print_line(__LINE__);
    cout << "    + Scale of (x+1)^2 * (x^2+2) before rescale: " << log2(encrypted_result.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(encrypted_result);    // rescale

    print_line(__LINE__);
    cout << "    + Scale of (x+1)^2 * (x^2+2) after rescale: " << log2(encrypted_result.scale()) << " bits" << endl;

    print_line(__LINE__);
    cout << "    + Modulus chain index for encrypted_result: "
         << context.get_context_data(encrypted_result.parms_id())->chain_index() << endl;
    cout << endl;

    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode (x+1)^2 * (x^2+2)." << endl;
    cout << "   + Expected result: " << endl;
    vector<double> true_result;
    for (size_t i = 0; i < input.size(); i++)
    {
        double x = input[i];
        true_result.push_back((x+1) * (x+1) * (x * x + 2));
    }
    print_vector(true_result, 3, 7);

    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "    + Computed result ...... Correct." << endl;
    print_vector(result, 3, 7);

    Ciphertext rotated; // rotation 시작!
    print_line(__LINE__);
    cout << "Rotate 2 steps left." << endl;
    evaluator.rotate_vector(encrypted_result, 2, gal_keys, rotated);
    cout << "    + Decrypt and decode ...... Correct." << endl;
    decryptor.decrypt(rotated, plain_result);
    encoder.decode(plain_result, result);
    print_vector(result, 3, 7);

}
