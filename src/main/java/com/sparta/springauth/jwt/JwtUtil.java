package com.sparta.springauth.jwt;

import com.sparta.springauth.entity.UserRoleEnum;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtil {

    //1. JWT 생성
    //반환방법: 1. response Header에 직접 담기
    //        2. 쿠키객체를 만들어서 쿠키객체에 토큰을 담은 다음 쿠키를 Response Header에 담기 (쿠키 자체의 만료기간과 다른 옵션을 줄 수 있다)
    //              Set-Cookie에 담으면 알아서 cookie 저장소에 담김

    //2. 생성된 JWT를 Cookie에 저장
    //3. Cookie에 들어있던 JWT 토큰을 Substring
    //4. JWT 검증
    //5. JWT에서 사용자 정보 가져오기
    // ///////////////////////////////////////////////////////////////////

    // Header KEY 값 (= 쿠키의 name 값)
    public static final String AUTHORIZATION_HEADER = "Authorization";
    // 사용자 권한 값의 KEY
    public static final String AUTHORIZATION_KEY = "auth";
    // Token 식별자 (우리가 만들 토큰의 앞에 붙일 용어(접두사 같은?)
    public static final String BEARER_PREFIX = "Bearer ";
    // 토큰 만료시간 (기준 ms)
    private final long TOKEN_TIME = 60 * 60 * 1000L; // 60분

    //application.proerties에 저장한 secret key를 가져옴 -> 이 값을 SecretKey 변수에 넣음
    @Value("${jwt.secret.key}") // Base64 Encode 한 SecretKey
    private String secretKey;
    private Key key; //SecretKey를 담을 객체 -> 담아서 암호화,복호화, 검증 진행
    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256; //사용할 알고리즘

    // 로그 설정 (로깅: 애플리케이션이 동작하는 동안 프로젝트의 상태나 동작 정보를 시간순으로 기록하는 것) ( slf4j - 롬복에서 지원)
    public static final Logger logger = LoggerFactory.getLogger("JWT 관련 로그");

    @PostConstruct //딱 한번만 받아오는 값을 받아올 때마다 요청을 새로하는 실수 방지
    public void init() {
        byte[] bytes = Base64.getDecoder().decode(secretKey); //인코딩한 키를 Base64로 디코딩
        key = Keys.hmacShaKeyFor(bytes);
    }

    // 1. JWT 토큰 생성
    public String createToken(String username, UserRoleEnum role) {
        Date date = new Date();

        return BEARER_PREFIX +
                Jwts.builder()
                        .setSubject(username) // 사용자 식별자값(ID)
                        .claim(AUTHORIZATION_KEY, role) // 사용자 권한 (키, 값(여기서는 우리가 설정한 권한값))
                        .setExpiration(new Date(date.getTime() + TOKEN_TIME)) // 만료 시간
                        .setIssuedAt(date) // 발급일
                        .signWith(key, signatureAlgorithm) // **암호화 알고리즘** (시크릿 키, 암호화 알고리즘)
                        .compact();
    }

    //2. 생성된 JWT를 Cookie에 저장
    public void addJwtToCookie(String token, HttpServletResponse res) {
        try {
            // Cookie Value 에는 공백이 불가능해서 encoding 진행
            token = URLEncoder.encode(token, "utf-8").replaceAll("\\+", "%20");
            Cookie cookie = new Cookie(AUTHORIZATION_HEADER, token); // Name-Value
            cookie.setPath("/");

            // Response 객체에 Cookie 추가
            res.addCookie(cookie);
        } catch (UnsupportedEncodingException e) {
            logger.error(e.getMessage());
        }
    }

   // 3. Cookie에 들어있던 JWT 토큰을 Substring (Prefix로 붙은 Bearer을 떼어내기 위해)
   // JWT 토큰 substring
   public String substringToken(String tokenValue) {
       //공백&null인지, 토큰이 bearer로 시작하는 지 확인(우리 토큰이 맞는지)
       if (StringUtils.hasText(tokenValue) && tokenValue.startsWith(BEARER_PREFIX)) {
           return tokenValue.substring(7); //"bearer "이 7자이기 때문에 잘라서 순수한 토큰값만 남김
       }
       logger.error("Not Found Token");
       throw new NullPointerException("Not Found Token");
   }

   //4. JWT 검증
   // 토큰 검증(위변조, 파괴, 만료 등)
   public boolean validateToken(String token) {
       try {
           Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token); //암호화할때 사용한 키로 검증
           return true; //문제 없을 경우
       } catch (SecurityException | MalformedJwtException | SignatureException e) {
           logger.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.");
       } catch (ExpiredJwtException e) {
           logger.error("Expired JWT token, 만료된 JWT token 입니다.");
       } catch (UnsupportedJwtException e) {
           logger.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.");
       } catch (IllegalArgumentException e) {
           logger.error("JWT claims is empty, 잘못된 JWT 토큰 입니다.");
       }
       return false; //문제 있을 경우
   }

   //5. JWT에서 사용자 정보 가져오기
   // 토큰에서 사용자 정보 가져오기
    //Body 부분에 있는 Claims(데이터들의 집합)를 가져와 반환
   public Claims getUserInfoFromToken(String token) {
       return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
   }
}