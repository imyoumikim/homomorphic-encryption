#include "examples.h"

using namespace std;
using namespace seal;

void example_ckks_basics()
{
    print_example_banner("Example: CKKS Basics");

    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    /*
    초기 스케일을 2^40으로 설정.
    마지막 레벨에서는 소수점 앞쪽에 60-40=20비트의 정밀도와 소수점 뒤쪽에 충분한 (대략 10-20비트) 정밀도를 남김. 
    중간 소수들은 40비트(실제로 2^40에 매우 가까움).
    -> 위에서 말한 스케일 안정화를 달성할 수 있음. (=초기 스케일 S와 계수 모듈러스의 소수 P_i를 서로 매우 가깝게 설정)
    */

    double scale = pow(2.0, 40);

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key(); // 비밀키
    PublicKey public_key;
    keygen.create_public_key(public_key); // 공개키
	  RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys); // 평문 재선형화 키
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys); // 갈루아 키
    Encryptor encryptor(context, public_key); // 암호화 객체
    Evaluator evaluator(context); // 계산 객체
    Decryptor decryptor(context, secret_key); // 복호화 객체

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count(); // 슬롯 개수
    cout << "Number of slots: " << slot_count << endl;

    /*
    슬롯: 일종의 배열 요소. 
    다항식의 계수(coefficients)를 나타냄. 즉, 다항식은 슬롯에 저장된 계수들의 조합으로 표현됨.
    ex) f(x) = 3x^2 + 2x - 1은 슬롯 0에는 -1이 저장되고, 슬롯 1에는 2가 저장
    보다 많은 슬롯을 사용하면 다항식 계산의 정확도가 높아지지만, 암호문의 크기가 커지고 처리 속도가 감소할 수 있음.
    */

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1); // 슬롯 간 간격
    for (size_t i = 0; i < slot_count; i++)
    {
        input.push_back(curr_point); // input 벡터에 curr_point 추가
        curr_point += step_size;
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7); // 3부터 7개의 요소 출력. 즉 input[3], input[4], ... input[9]

    cout << "Evaluating polynomial PI*x^3 + 0.4x + 1 ..." << endl;

    Plaintext plain_coeff3, plain_coeff1, plain_coeff0; // 다항식의 계수를 평문 형태로 저장
    encoder.encode(3.14159265, scale, plain_coeff3); // x^3의 계수 PI를 scale로 인코딩
    encoder.encode(0.4, scale, plain_coeff1);
    encoder.encode(1.0, scale, plain_coeff0);

    Plaintext x_plain; // 평문 형태로 입력 벡터 저장 예정
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, scale, x_plain); // 입력 벡터를 scale로 인코딩하여 x_plain에 저장
    Ciphertext x1_encrypted;  // x
    encryptor.encrypt(x_plain, x1_encrypted); // x_plain을 암호문 형태로 x1_encrypted = x에 저장

    // 재선형화(암호문의 크기를 최소화하고 연산 성능을 향상시키는 역할) 과정 시작
    // x^3를 계산하기 전에 x^2를 먼저 계산하고 재선형화.

    Ciphertext x3_encrypted; // x^2
    print_line(__LINE__);
    cout << "Compute x^2 and relinearize:" << endl;
    evaluator.square(x1_encrypted, x3_encrypted); // x1_encrypted를 제곱하여 x3_encrypted에 저장
    evaluator.relinearize_inplace(x3_encrypted, relin_keys); // x3_encrypted를 재선형화.
    cout << "    + Scale of x^2 before rescale: " << log2(x3_encrypted.scale()) << " bits" << endl; // x^2의 스케일 값을 출력

    print_line(__LINE__);
    cout << "Rescale x^2." << endl;
    evaluator.rescale_to_next_inplace(x3_encrypted); // Rescaling(암호문의 스케일을 줄이는 과정, 수행될 때 암호문의 스케일이 감소)
    cout << "    + Scale of x^2 after rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

    // PI * x를 먼저 계산하고, 그것을 x^2와 곱해서 PI * x^3을 구함.
    // 그러기 위해서 먼저 Pi * x를 2^80 -> 2^40으로 rescale back

    print_line(__LINE__);
    cout << "Compute and rescale PI*x." << endl;
    Ciphertext x1_encrypted_coeff3;   // PI * x
    evaluator.multiply_plain(x1_encrypted, plain_coeff3, x1_encrypted_coeff3); // x1_encrypted * plain_coeff3를 x1_encrypted_coeff3(PI * x)에 저장
    cout << "    + Scale of PI*x before rescale: " << log2(x1_encrypted_coeff3.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted_coeff3);
    cout << "    + Scale of PI*x after rescale: " << log2(x1_encrypted_coeff3.scale()) << " bits" << endl;

		print_line(__LINE__);
    cout << "Compute, relinearize, and rescale (PI*x)*x^2." << endl;
    evaluator.multiply_inplace(x3_encrypted, x1_encrypted_coeff3); //x^2 * (PI * x)를 x3_encrypted에 저장 
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "    + Scale of PI*x^3 before rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(x3_encrypted);   // PIx^3(lv0)
    cout << "    + Scale of PI*x^3 after rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

	// 0.4 * x를 계산하고 rescaling하는 과정

	print_line(__LINE__);
    cout << "Compute and rescale 0.4*x." << endl;
    evaluator.multiply_plain_inplace(x1_encrypted, plain_coeff1); // x1_enrypted = x1_enrypted * plain_coeff1(0.4)
    cout << "    + Scale of 0.4*x before rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted);
    cout << "    + Scale of 0.4*x after rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;
	
	// 세 개의 항을 더하는 계산을 하고자 함.
	// 그러나 암호화 매개변수가 모두 다름(rescaling에서 모듈러스 스위칭 때문)

	cout << endl;
    print_line(__LINE__);
    cout << "Parameters used by all three terms are different." << endl;
    cout << "    + Modulus chain index for x3_encrypted: "
         << context.get_context_data(x3_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for x1_encrypted: "
         << context.get_context_data(x1_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for plain_coeff0: "
         << context.get_context_data(plain_coeff0.parms_id())->chain_index() << endl;
    cout << endl;
    
    print_line(__LINE__);
    cout << "The exact scales of all three terms are different:" << endl;
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10); // cout의 출력 형식을 고정 소수점으로 설정하고 소수점 이하 10자리로 설정
    cout << "    + Exact scale in PI*x^3: " << x3_encrypted.scale() << endl;
    cout << "    + Exact scale in  0.4*x: " << x1_encrypted.scale() << endl;
    cout << "    + Exact scale in      1: " << plain_coeff0.scale() << endl;
    cout << endl;
    cout.copyfmt(old_fmt);

	// 스케일을 2^40로 정규화하는 과정

    print_line(__LINE__);
    cout << "Normalize scales to 2^40." << endl;
    x3_encrypted.scale() = pow(2.0, 40); // x3_enrypted의 스케일을 2^40으로 설정
    x1_encrypted.scale() = pow(2.0, 40); // x1_enrypted의 스케일을 2^40으로 설정
		
	// 여전히 암호화 매개변수가 일치하지 않는다는 문제점 O
		
    print_line(__LINE__);
    cout << "Normalize encryption parameters to the lowest level." << endl;
    parms_id_type last_parms_id = x3_encrypted.parms_id(); // x3_encrypted의 매개변수 ID를 last_parms_id에 저장
    evaluator.mod_switch_to_inplace(x1_encrypted, last_parms_id); // x1_encrypted를 last_parms_id의 매개변수로 모듈러스 스위칭
    evaluator.mod_switch_to_inplace(plain_coeff0, last_parms_id); // plain_coeff0를 last_parms_id의 매개변수로 모듈러스 스위칭
	
	// 세 암호문은 이제 계산 가능함
		
    print_line(__LINE__);
    cout << "Compute PI*x^3 + 0.4*x + 1." << endl;
    Ciphertext encrypted_result;
    evaluator.add(x3_encrypted, x1_encrypted, encrypted_result); // x3_encrypted + x1_encrypted
    evaluator.add_plain_inplace(encrypted_result, plain_coeff0); // + 1(plain_coeff0)

	// 실제 결과 출력

    Plaintext plain_result; // 복호화 결과 저장 변수
    print_line(__LINE__);
    cout << "Decrypt and decode PI*x^3 + 0.4x + 1." << endl;
    cout << "    + Expected result:" << endl;
    vector<double> true_result;
    for (size_t i = 0; i < input.size(); i++)
    {
        double x = input[i];
        true_result.push_back((3.14159265 * x * x + 0.4) * x + 1);
    }
    print_vector(true_result, 3, 7);

	// 복호화 결과 출력

    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "    + Computed result ...... Correct." << endl;
    print_vector(result, 3, 7);

}