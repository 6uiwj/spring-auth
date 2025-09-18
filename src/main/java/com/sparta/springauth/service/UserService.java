package com.sparta.springauth.service;

import com.sparta.springauth.dto.LoginRequestDto;
import com.sparta.springauth.dto.SignupRequestDto;
import com.sparta.springauth.entity.User;
import com.sparta.springauth.entity.UserRoleEnum;
import com.sparta.springauth.jwt.JwtUtil;
import com.sparta.springauth.repository.UserRepository;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;


    // ADMIN_TOKEN (관리자권한 부여)
    private final String ADMIN_TOKEN = "AAABnvxRVklrnYxKZ0aHgTBcXukeZygoC";

//    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
//        this.userRepository = userRepository;
//        this.passwordEncoder = passwordEncoder;
//        this.jwtUtil = jwtUtil;
//    }

    public void signup(SignupRequestDto requestDto) { //회원가입할 데이터를 requestDto로 받아옴
        String username = requestDto.getUsername();
        String password = passwordEncoder.encode(requestDto.getPassword()); //비밀번호 암호화

        // 회원 중복 확인
        Optional<User> checkUsername = userRepository.findByUsername(username);
        if (checkUsername.isPresent()) {
            throw new IllegalArgumentException("중복된 사용자가 존재합니다.");
        }

        // email 중복확인
        String email = requestDto.getEmail();
        Optional<User> checkEmail = userRepository.findByEmail(email);
        if (checkEmail.isPresent()) {
            throw new IllegalArgumentException("중복된 Email 입니다.");
        }

        // 사용자 ROLE 확인
        UserRoleEnum role = UserRoleEnum.USER; //일단 일반 사용자권한을 넣어놓음
        if (requestDto.isAdmin()) { //관리자인지 확인
            if (!ADMIN_TOKEN.equals(requestDto.getAdminToken())) { //관리자 아님
                throw new IllegalArgumentException("관리자 암호가 틀려 등록이 불가능합니다.");
            }
            role = UserRoleEnum.ADMIN; //관리자임
        }

        // 사용자 등록
        User user = new User(username, password, email, role);
        userRepository.save(user);
    }

    public void login(LoginRequestDto requestDto, HttpServletResponse res) {
            String username = requestDto.getUsername();
            String password = requestDto.getPassword();

            //사용자 확인
            //Optional을 바로 User로 받기 위해 orElseThrow로 optional 처리
            User user = userRepository.findByUsername(username).orElseThrow(
                    () -> new IllegalArgumentException("등록된 사용자가 없습니다.")
            );

            //비밀번호 확인
            if(!passwordEncoder.matches(password, user.getPassword())) { //비밀번호가 일치하지 않은 경우
                throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
            }

            //인증이 완료되었으니
            //JWT 생성 및 쿠키에 저장 후 Response 객체에 추가

        //토큰 만들기
            String token = jwtUtil.createToken(user.getUsername(),user.getRole());
            jwtUtil.addJwtToCookie(token, res);
    }
}