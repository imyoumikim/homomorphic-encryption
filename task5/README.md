## Task5: 디버깅용 TraceableCiphertext 클래스 만들기

### 요구사항
* Original vector & Decryption vector 값 비교
* Scale 확인

### 필드
- originalVector : 평문 or 원래 가져야 하는 값
- ciphertext : 암호문
- privateKey
- cryptoContext : 암호문 덧셈, 곱셈 등의 연산에 필요한 CryptoContext 객체

### 메소드
- getOriginalVector() : 원래 가져야 하는 값의 getter
- getCiphertext() : 현 암호문의 getter
- showDetail() : 원래 벡터값, 계산한 암호문을 복호화한 값, scaling factor 확인
- cipherAdd() : 암호문 + 암호문, 암호문 + 상수로 나누어 오버로딩
- originalAdd() : 덧셈의 결과로 생기는 originalVector값을 계산. cipherAdd() 안에서 호출됨.
- cipherMult() : 암호문 \* 암호문, 암호문 \* 상수로 나누어 오버로딩
- originalMult() : 곱셈의 결과로 생기는 originalVector값을 계산. cipherMult() 안에서 호출됨.

### 실행 결과
![image](https://github.com/imyoumikim/homomorphic-encryption/assets/99166914/8f3b88e2-0cbd-47d6-b82a-2805fe065573)
