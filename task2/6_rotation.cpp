#include "examples.h"

using namespace std;
using namespace seal;

void example_rotation_bfv() // 행렬의 행을 왼쪽으로 3번 회전시킨 후, 열을 회전시키는 과정
{
    print_example_banner("Example: Rotation / Rotation in BFV");

    EncryptionParameters parms(scheme_type::bfv);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key(); // 비밀키
    PublicKey public_key;
    keygen.create_public_key(public_key); // 공개키
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys); // 재선형화 키
    Encryptor encryptor(context, public_key); // 공개키로 암호화
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key); // 비밀키로 복호화

    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2; // 행의 크기는 슬롯 크기의 1/2
    cout << "Plaintext matrix row size: " << row_size << endl;

    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);
    
     // BatchEncoder를 이용하여 행렬을 평문으로 만듦.

    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode and encrypt." << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    cout << "    + Noise budget in fresh encryption: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
         << endl;
    cout << endl;

    GaloisKeys galois_keys; 
    keygen.create_galois_keys(galois_keys); // 회전 연산에 필요한 Galois 키를 생성

    // 암호화된 행렬의 행을 왼쪽으로 세번 회전, 복호화, 디코딩, 출력하는 과정
    
    print_line(__LINE__);
    cout << "Rotate rows 3 steps left." << endl;
    evaluator.rotate_rows_inplace(encrypted_matrix, 3, galois_keys); // 행을 왼쪽으로 3번 회전시킵니다.
    Plaintext plain_result;
    cout << "    + Noise budget after rotation: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
         << endl;
    cout << "    + Decrypt and decode ...... Correct." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result); // 평문 형태로 복호화
    batch_encoder.decode(plain_result, pod_matrix); // 평문 행렬을 배치 디코더를 사용하여 원래의 형태로 디코딩
    print_matrix(pod_matrix, row_size);

    /*
    열 또한 회전시킬 수 있음
    */
    print_line(__LINE__);
    cout << "Rotate columns." << endl;
    evaluator.rotate_columns_inplace(encrypted_matrix, galois_keys); // 열 회전
    cout << "    + Noise budget after rotation: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
         << endl;
    cout << "    + Decrypt and decode ...... Correct." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result); // 복호화
    batch_encoder.decode(plain_result, pod_matrix); // 디코딩
    print_matrix(pod_matrix, row_size);

     //행을 오른쪽으로 4번 회전시키고, 복호화, 디코딩, 출력하는 과정
    
    print_line(__LINE__);
    cout << "Rotate rows 4 steps right." << endl;
    evaluator.rotate_rows_inplace(encrypted_matrix, -4, galois_keys); // 오른쪽으로 4번 회전
    cout << "    + Noise budget after rotation: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
         << endl;
    cout << "    + Decrypt and decode ...... Correct." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result); // 복호화
    batch_encoder.decode(plain_result, pod_matrix); // 디코딩
    print_matrix(pod_matrix, row_size);

     // 회전 연산은 노이즈 버젯을 사용하지 않음. 그러나 이것은 특수 소수가 적어도 다른 소수들 만큼 큰 경우에만 해당.
}

void example_rotation_ckks() // ckks는 bfv와 매우 유사한 방식으로 회전 연산을 수행
{
    print_example_banner("Example: Rotation / Rotation in CKKS");

    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40 }));
     // 40비트 크기의 5개의 소수(prime)를 사용하여 계수 모듈러스를 생성

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key(); // 비밀키
    PublicKey public_key;
    keygen.create_public_key(public_key); // 공개키
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys); // 재선형화 키
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys); // 갈로아 키
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder ckks_encoder(context);

    size_t slot_count = ckks_encoder.slot_count(); // 슬롯 개수 할당
    cout << "Number of slots: " << slot_count << endl;
    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector:" << endl;
    print_vector(input, 3, 7);

    auto scale = pow(2.0, 50); // 스케일을 2^50으로 설정

    print_line(__LINE__);
    cout << "Encode and encrypt." << endl;
    Plaintext plain;
    ckks_encoder.encode(input, scale, plain); // 평문 형태로 인코딩
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted); // 평문을 암호화

    Ciphertext rotated;
    print_line(__LINE__);
    cout << "Rotate 2 steps left." << endl;
    evaluator.rotate_vector(encrypted, 2, galois_keys, rotated); // 암호화된 매트릭스를 2칸 왼쪽으로 회전
    cout << "    + Decrypt and decode ...... Correct." << endl;
    decryptor.decrypt(rotated, plain); // 복호화
    vector<double> result;
    ckks_encoder.decode(plain, result); // 디코딩
    print_vector(result, 3, 7);
}

void example_rotation()
{
    print_example_banner("Example: Rotation");

    example_rotation_bfv();
    example_rotation_ckks();
}