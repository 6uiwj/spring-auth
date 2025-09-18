package com.sparta.springauth.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sparta.springauth.dto.LoginRequestDto;
import com.sparta.springauth.entity.UserRoleEnum;
import com.sparta.springauth.security.UserDetailsImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Slf4j(topic = "로그인 및 JWT 생성")
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final JwtUtil jwtUtil; //JWT 생성하기 위해 UTIL 필요

    public JwtAuthenticationFilter(JwtUtil jwtUtil) { //생성자 주입으로 JwtUtil받아오기
        this.jwtUtil = jwtUtil;
        setFilterProcessesUrl("/api/user/login");
    }

    //로그인을 시도하는 메서드
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("로그인 시도");
        try {                               //json 형태 -> Object로 변환
            //getInputStream:  요청 바디에 useranme과 password가 json형식으로 넘어옴
            //LoginRequestDto : 변환할 오브젝트 타입
            LoginRequestDto requestDto = new ObjectMapper().readValue(request.getInputStream(), LoginRequestDto.class);

            return getAuthenticationManager().authenticate( //인증처리 메서드
                    new UsernamePasswordAuthenticationToken( //인증토큰
                            requestDto.getUsername(),
                            requestDto.getPassword(),
                            null
                    )
            );
        } catch (IOException e) {
            log.error(e.getMessage());
            throw new RuntimeException(e.getMessage());
        }
    }

    //성공했을 때 수행 메서드
    //로그인이 성공했으니 JWT 생성해야 함
    //성공을 했으니 Authentication 객체를 가져올 수 있다 가져와서 그 안에서 UserDetails 를 가져옴
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.info("로그인 성공 및 JWT 생성");
        //실제로 UserDetailsImple 객체가 담겨있지만, Spring이 Object로 반환하기 때문에 캐스팅 필요
        String username = ((UserDetailsImpl) authResult.getPrincipal()).getUsername(); //Authentication에서 이름 가져오기
        UserRoleEnum role = ((UserDetailsImpl) authResult.getPrincipal()).getUser().getRole(); //역할 가져오기

        String token = jwtUtil.createToken(username, role); //토큰생성
        jwtUtil.addJwtToCookie(token, response); //쿠키 생성해서 Response객체에 넣어줌
    }

    //로그인이 실패했을 때 수행 메서드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        log.info("로그인 실패");
        response.setStatus(401); //상태코드 반환
    }
}