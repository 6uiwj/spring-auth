package com.sparta.springauth;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest
public class PasswordEncoderTest {

    @Autowired
    PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("수동 등록한 passwordEncoder를 주입 받아와 문자열 암호화")
    void test1() {
        String password = "Robbie's password"; //설정한 비밀번호

        // 암호화
        String encodePassword = passwordEncoder.encode(password);
        System.out.println("encodePassword = " + encodePassword);

        String inputPassword = "Robbie"; //현재 로그인 시 입력한 비밀번호

        // 해시된 비밀번호와 사용자가 입력한 비밀번호를 해싱한 값을 비교 (입력받은 문자열을 자동으로 암호화해서 암호화된 비밀번호와 비교)
        boolean matches = passwordEncoder.matches(inputPassword, encodePassword); //(입력받은 문자열, 암호화한 비밀번호)
        System.out.println("matches = " + matches); // 암호화할 때 사용된 값과 다른 문자열과 비교했기 때문에 false
    }
}