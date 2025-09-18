package com.sparta.springauth.controller;

import com.sparta.springauth.dto.LoginRequestDto;
import com.sparta.springauth.dto.SignupRequestDto;
import com.sparta.springauth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/api")
public class UserController {

    public UserController(UserService userService) {
        this.userService = userService;
    }

    private final UserService userService;

    @GetMapping("/user/login-page")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/user/signup")
    public String signupPage() {
        return "signup";
    }

    @PostMapping("/user/signup")
    public String signup(SignupRequestDto requestDto) {
        userService.signup(requestDto);

        return "redirect:/api/user/login-page";
    }

    //이제 필터에서 처리할 것이므로 삭제
//    @PostMapping("/user/login")
//    public String login(LoginRequestDto requestDto, HttpServletResponse res) {
//        try {
//            userService.login(requestDto, res);
//        } catch (Exception e) { //로그인 실패시 서버가 error페이지로 이동하라는 리다이렉트를 보내고, 클라이언트가 아래의 주소로 요청을 보냄
//            return "redirect:/api/user/login-page?error";
//        }
//
//        return "redirect:/";
//    }
}