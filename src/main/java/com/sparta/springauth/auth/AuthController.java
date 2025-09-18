package com.sparta.springauth.auth;

import com.sparta.springauth.entity.UserRoleEnum;
import com.sparta.springauth.jwt.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

@RestController
@RequestMapping("/api")
public class AuthController {


    public static final String AUTHORIZATION_HEADER = "Authorization"; //쿠키 키 이름

    private final JwtUtil jwtUtil;

    //의존성 생성자로 주입
    public AuthController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    //쿠키 생성
    //저장할 쿠키를 이름으로 받아옴
    @GetMapping("/create-cookie")
    public String createCookie(HttpServletResponse res) {
        addCookie("Robbie Auth", res); //쿠키를 생성하는 메서드 실행

        return "createCookie";
    }

    /**
     * 쿠키 가져오기
     * @param value
     * @return
     */
    @GetMapping("/get-cookie")
    //@CookieValue(쿠키이름) String value : HttpServletRequest에 담겨 있는 쿠키 중에서
    // "Authorization"이라는 이름의 쿠키를 가져와 그 쿠키의 값이 변수(value)에 담김
    public String getCookie(@CookieValue(AUTHORIZATION_HEADER) String value) {
        System.out.println("value = " + value);

        return "getCookie : " + value;
    }

    //세션 생성하기
    //사용자가 요청을 보내면 Servlet컨테이너에서 HttpServletRequest, Response객체가 생성되므로 우리가 파라미터에 선언해서 불러올 수 있다.
    @GetMapping("/create-session")
    public String createSession(HttpServletRequest req) {
        // 세션이 존재할 경우 세션 반환, 없을 경우 새로운 세션을 생성한 후 반환
        //새로 세션이 생성되면 컨테이너가 Set-Cookie : JSESSIONID = ... 응답헤더를 내려줌(브라우저는 이 쿠키를 저장)
        HttpSession session = req.getSession(true);

        // 세션에 저장될 정보 "키/값"을 추가합니다.
        session.setAttribute(AUTHORIZATION_HEADER, "Robbie Auth");
        return "createSession";
    }

    //세션 가져오기
    @GetMapping("/get-session")
    public String getSession(HttpServletRequest req) {
        // 세션이 존재할 경우 세션 반환, 없을 경우 null 반환
        HttpSession session = req.getSession(false);

        String value = (String) session.getAttribute(AUTHORIZATION_HEADER); // 가져온 세션에 저장된 Value 를 Name 을 사용하여 가져옵니다.
        System.out.println("value = " + value);

        return "getSession : " + value;
    }

    //쿠키 생성-저장 메서드 (쿠키엔 공백이 있으면 안된다! -> URLEncoder로 변환 )
    public static void addCookie(String cookieValue, HttpServletResponse res) {
        try {
            // Cookie Value 에는 공백이 불가능해서 encoding 진행 ->
            cookieValue = URLEncoder.encode(cookieValue, "utf-8").replaceAll("\\+", "%20");

            //쿠키만들기
            Cookie cookie = new Cookie(AUTHORIZATION_HEADER, cookieValue); //쿠키생성 -> 생성자(쿠키 Name, 쿠키 Value)
            cookie.setPath("/"); //패스 설정(모든 경로에 쿠키 전송)
            cookie.setMaxAge(30 * 60); //만료기한 설정

            // Response 객체에 생성한 Cookie 추가(HttpServletResponse)
            res.addCookie(cookie); //Set-Cookie 헤더를 응답에 추가 (쿠키를 만들라고 지시하는 헤더)
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    @GetMapping("/create-jwt")
    public String createJwt(HttpServletResponse res) {
        // Jwt 생성
        String token = jwtUtil.createToken("Robbie", UserRoleEnum.USER);

        // Jwt 쿠키 저장
        jwtUtil.addJwtToCookie(token, res);

        return "createJwt : " + token;
    }

    @GetMapping("/get-jwt")
    public String getJwt(@CookieValue(JwtUtil.AUTHORIZATION_HEADER) String tokenValue) {
        // JWT 토큰 substring
        String token = jwtUtil.substringToken(tokenValue); //prefix 짜르고 순수한 토큰만 남기기

        // 토큰 검증
        if(!jwtUtil.validateToken(token)){
            throw new IllegalArgumentException("Token Error");
        }

        // 토큰에서 사용자 정보 가져오기
        Claims info = jwtUtil.getUserInfoFromToken(token); //토큰에서 getBody로 Claims 받아옴
        // 사용자 username
        String username = info.getSubject();
        System.out.println("username = " + username);
        // 사용자 권한
        String authority = (String) info.get(JwtUtil.AUTHORIZATION_KEY);
        System.out.println("authority = " + authority);

        return "getJwt : " + username + ", " + authority;
    }
}