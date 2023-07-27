//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Advanced examples CKKS
 */

// Define PROFILE to enable TIC-TOC timing measurements
#define PROFILE

#include "openfhe.h"

using namespace lbcrypto;

void AutomaticRescaleDemo(ScalingTechnique scalTech);
void ManualRescaleDemo(ScalingTechnique scalTech);

int main(int argc, char* argv[]) {

    AutomaticRescaleDemo(FLEXIBLEAUTO);

    AutomaticRescaleDemo(FIXEDAUTO);

    ManualRescaleDemo(FIXEDMANUAL);

    return 0;
}

void AutomaticRescaleDemo(ScalingTechnique scalTech) {

    if (scalTech == FLEXIBLEAUTO) {
        std::cout << std::endl << std::endl << std::endl << " ===== FlexibleAutoDemo ============= " << std::endl;
    }
    else {
        std::cout << std::endl << std::endl << std::endl << " ===== FixedAutoDemo ============= " << std::endl;
    }

    uint32_t batchSize = 8;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(5);
    parameters.SetScalingModSize(50);
    parameters.SetScalingTechnique(scalTech);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Input
    std::vector<double> x = {1.0, 1.01, 1.02, 1.03, 1.04, 1.05, 1.06, 1.07};
    Plaintext ptxt        = cc->MakeCKKSPackedPlaintext(x);

    std::cout << "Input x: " << ptxt << std::endl;

    auto c = cc->Encrypt(ptxt, keys.publicKey);
    auto cplus1 = cc->EvalAdd(c, 1);                     // x+1
    auto cplus1_2 = cc->EvalMult(cplus1, cplus1);        // (x+1)^2
    auto c2   = cc->EvalMult(c, c);                      // x^2
    auto c2plus2 = cc->EvalAdd(c2, 2);                   // (x^2+2)

    auto cRes = cc->EvalMult(cplus1_2, c2plus2);  // Final result

    Plaintext result;
    std::cout.precision(8);

    cc->Decrypt(cRes, keys.secretKey, &result);
    result->SetLength(batchSize);
    std::cout << "(x+1)^2 * (x^2+2) = " << result << std::endl;

    // Rotation - HybridKeySwitchingDemo1
    parameters.SetNumLargeDigits(2);
    std::cout << "- Using HYBRID key switching with " << 2 << " digits" << std::endl;
    cc->EvalRotateKeyGen(keys.secretKey, {2});

    TimeVar t;
    TIC(t);
    auto cRot2         = cc->EvalRotate(cRes, 2);
    double time2digits = TOC(t);

    cc->Decrypt(keys.secretKey, cRot2, &result);
    result->SetLength(batchSize);
    std::cout << "x left rotate 2 = " << result << std::endl;
    std::cout << "---------- rotations with HYBRID (2 digits) took " << time2digits << "ms" << std::endl << std::endl;;

    // Rotation - HybridKeySwitchingDemo2
    parameters.SetNumLargeDigits(3);
    std::cout << "- Using HYBRID key switching with " << 3 << " digits" << std::endl;

    TIC(t);
    auto cRot2_2 = cc->EvalRotate(cRes, 2);
    double time3digits = TOC(t);    // The runtime here is smaller than in the previous demo.

    cc->Decrypt(keys.secretKey, cRot2_2, &result);
    result->SetLength(batchSize);
    std::cout << "x left rotate 2 = " << result << std::endl;
    std::cout << "---------- rotations with HYBRID (3 digits) took " << time3digits << "ms" << std::endl;
}

void ManualRescaleDemo(ScalingTechnique scalTech) {

    std::cout << "\n\n\n ===== FixedManualDemo ============= " << std::endl;

    uint32_t batchSize = 8;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(5);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Input
    std::vector<double> x = {1.0, 1.01, 1.02, 1.03, 1.04, 1.05, 1.06, 1.07};
    Plaintext ptxt        = cc->MakeCKKSPackedPlaintext(x);

    std::cout << "Input x: " << ptxt << std::endl;

    auto c = cc->Encrypt(keys.publicKey, ptxt);

    // Computing f(x) = (x+1)^2(x^2+2)

    // (x+1)^2
    auto cplus1 = cc->EvalAdd(c, 1);
    auto cplus1sqr_depth2 = cc->EvalMult(cplus1, cplus1);
    auto cplus1sqr_depth1 = cc->Rescale(cplus1sqr_depth2);

    // x^2
    auto c2_depth2 = cc->EvalMult(c, c);
    auto c2_depth1 = cc->Rescale(c2_depth2);

    // (x^2+2)
    auto c2plus2_depth1 = cc->EvalAdd(c2_depth1, 2);

    // Final result
    auto cRes_depth2 = cc->EvalMult(cplus1sqr_depth1, c2plus2_depth1);
    auto cRes_depth1 = cc->Rescale(cRes_depth2);

    Plaintext result;
    std::cout.precision(8);

    cc->Decrypt(keys.secretKey, cRes_depth1, &result);
    result->SetLength(batchSize);
    std::cout << "(x+1)^2 * (x^2+2) = " << result << std::endl;

    // Rotation - HybridKeySwitchingDemo1
    parameters.SetNumLargeDigits(2);
    std::cout << "- Using HYBRID key switching with " << 2 << " digits" << std::endl;
    cc->EvalRotateKeyGen(keys.secretKey, {2});

    auto cRot2         = cc->EvalRotate(cRes_depth1, 2);

    cc->Decrypt(keys.secretKey, cRot2, &result);
    result->SetLength(batchSize);
    std::cout << "x left rotate 2 = " << result << std::endl;

}