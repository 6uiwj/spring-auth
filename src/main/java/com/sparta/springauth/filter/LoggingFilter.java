package com.sparta.springauth.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j(topic = "LoggingFilter") //로깅 찍힐 때 이름
//@Component //컴포넌트로 로깅 등록
@Order(1) //필터 순서 지정
public class LoggingFilter implements Filter { //인증 및 인가 처리 필터
    @Override //파라미터 - FilterChain : 필터를 이동할 때 사용
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        // 전처리
        //request 에서 url 정보를 가져올 것임
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String url = httpServletRequest.getRequestURI();
        log.info(url); //어떤 요청인지 로그를 찍음

        chain.doFilter(request, response); // 다음 Filter 로 이동

        // 후처리
        log.info("비즈니스 로직 완료");
    }
}