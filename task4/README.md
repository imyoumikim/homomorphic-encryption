## Task4: task3를 openFHE의 코드로 수정

#### 1. simple-real-numbers.cpp, advanced-real-numbers.cpp를 분석
#### 2. 두 코드를 참고하여 다음의 조건을 수행하는 프로그램 작성

* $주어진 \ 식: (x+1)^2(x^2+2)$
* Left Rotation 2

|구분|값|
|------|------|
|$$N$$|$$2^{14}$$|
|$$Coefficient \ Modulus$$|{60,50,50,50,50,60}|
|$$\triangle$$|$$2^{50}$$|

* AutomaticRescaleDemo() 메소드에서만 HybridKeySwitchingDemo1(), HybridKeySwitchingDemo2()의 코드를 삽입하여 실행 시간을 비교함

### 수행 결과
<img src="https://github.com/imyoumikim/homomorphic-encryption/assets/99166914/2235cdff-c1ce-4805-b6aa-b369cb83d206">
