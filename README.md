## [2023 Summer] CAU PAIC LAB 학부연구생

### Goal
동형 암호(Homomorphic Encryption) 연구 보조를 위한 디버깅 환경 구축

-----
* week1: Microsoft SEAL 라이브러리 설치
* week2: Microsoft SEAL 라이브러리 일부 코드 분석
  * 5_ckks_basics.cpp, 6_rotation.cpp
* week3: 주어진 상황에 맞게 위의 두 코드 수정
* week4: week3의 과제를 OpenFHE의 코드로 수정
* week5, 6: Debugging을 용이하게 하는 새로운 클래스 TraceableCiphertext 생성
  *  Scale 확인, Original vector 값 - Decryption vector 값 비교
-----
### Reference
Microsoft SEAL: https://github.com/microsoft/SEAL <br>
OpenFHE: https://github.com/openfheorg/openfhe-development
