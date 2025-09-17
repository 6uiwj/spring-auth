package com.sparta.springauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration //
public class PasswordConfig {

    @Bean //Bean으로 등록하고자 하는 객체를 반환하는 메서드 선언
    public PasswordEncoder passwordEncoder() {
        //BCrypt : 비밀번호를 암호호해주는 해시함수
        return new BCryptPasswordEncoder(); //passwordEncoder 인터페이스의 구현체
    }
}