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
  Operations for the representation of ciphertext in OpenFHE
 */

#ifndef LBCRYPTO_CRYPTO_CIPHERTEXT_H
#define LBCRYPTO_CRYPTO_CIPHERTEXT_H

#include "ciphertext-fwd.h"
#include "cryptoobject.h"

#include "metadata.h"
#include "key/key.h"
#include "key/privatekey-fwd.h"

#include <memory>             
#include <string>
#include <utility>
#include <vector>
#include <map>

namespace lbcrypto {

// ------------------------------- TraceableCiphertext
template <typename Element>
class TraceableCiphertext {
private:
    std::vector<std::complex<double>> originalVector;
    Ciphertext<Element> ciphertext;
    const PrivateKey<Element>& privateKey; 
    const CryptoContext<Element>& cryptoContext;

public:
    TraceableCiphertext(std::vector<std::complex<double>> data,
                        Ciphertext<Element> ct,
                        const PrivateKey<Element>& pk,
                        const CryptoContext<Element>& cc)
        : originalVector(data), ciphertext(ct), privateKey(pk), cryptoContext(cc) {
    }

    std::vector<std::complex<double>> getOriginalVector() {
        return originalVector;
    }

    Ciphertext<Element> getCiphertext() {
        return ciphertext;
    }

    TraceableCiphertext cipherAdd(double constant) { // 암호문 + 상수
        Ciphertext<Element> result = cryptoContext->EvalAdd(this->getCiphertext(), constant);
        std::vector<std::complex<double>> vec = originalAdd(constant);
        TraceableCiphertext tc(vec, result, privateKey, cryptoContext);
        tc.showDetail();
        return tc;
    }

    TraceableCiphertext cipherAdd(TraceableCiphertext<Element> cipher) {    // 암호문 + 암호문
        Ciphertext<Element> result = cryptoContext->EvalAdd(this->getCiphertext(), cipher.getCiphertext());
        std::vector<std::complex<double>> vec = originalAdd(cipher.getOriginalVector());
        TraceableCiphertext tc(vec, result, privateKey, cryptoContext);
        tc.showDetail();
        return tc;
    }

    std::vector<std::complex<double>> originalAdd(double constant) {    // 암호문 + 상수 시 original vector 값 계산
        std::vector<std::complex<double>> vec = this->getOriginalVector();

        for (size_t i = 0; i < vec.size(); ++i) {
            vec[i] += constant;
        }
        return vec;
    }

    std::vector<std::complex<double>> originalAdd(std::vector<std::complex<double>> vector) {   // 암호문 + 암호문 시 original vector 값 계산
        std::vector<std::complex<double>> vec = this->getOriginalVector();

        for (size_t i = 0; i < vec.size(); ++i) {
            vec[i] += vector[i];
        }
        return vec;
    }

    TraceableCiphertext cipherMult(TraceableCiphertext<Element> cipher) { // 암호문 * 암호문
        Ciphertext<Element> result = cryptoContext->EvalMult(this->getCiphertext(), cipher.getCiphertext());
        std::vector<std::complex<double>> vec = originalMult(cipher.getOriginalVector());
        TraceableCiphertext tc(vec, result, privateKey, cryptoContext);
        tc.showDetail();
        return tc;
    }

    TraceableCiphertext cipherMult(double constant) { // 암호문 * 상수
        Ciphertext<Element> result = cryptoContext->EvalMult(this->getCiphertext(), constant);
        std::vector<std::complex<double>> vec = originalMult(constant);
        TraceableCiphertext tc(vec, result, privateKey, cryptoContext);
        tc.showDetail();
        return tc;
    }
    
    std::vector<std::complex<double>> originalMult(std::vector<std::complex<double>> vec) { // 암호문 * 암호문 시 original vector 계산
        std::vector<std::complex<double>> result = this->getOriginalVector();

        for (size_t i = 0; i < vec.size(); ++i) {
            result[i] *= vec[i];
        }   
        return result;
    }

    std::vector<std::complex<double>> originalMult(double constant) { // 암호문 * 상수 시 original vector 계산
        std::vector<std::complex<double>> result = this->getOriginalVector();

        for (size_t i = 0; i < result.size(); ++i) {
            result[i] *= constant;
        }   
        return result;
    }

    Plaintext getDecrypted() {
        Plaintext result;
        cryptoContext->Decrypt(this->getCiphertext(), privateKey, &result);
        result->SetLength(8);
        return result;
    }


    void showDetail() {
        std::cout << "Original Vector<Complex>: " << this->getOriginalVector() << std::endl;
        std::cout << "Decrypted Vector<Complex>: " << this->getDecrypted();
        std::cout << "\tScaling Factor: " << this->ciphertext->GetScalingFactor() << std::endl;
        std::cout << "\tScaling Factor Degree: " << this->ciphertext->GetNoiseScaleDeg() << std::endl << std::endl;
    }
    
};

}  // namespace lbcrypto

#endif
