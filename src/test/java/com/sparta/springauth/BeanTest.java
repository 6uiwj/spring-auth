package com.sparta.springauth;

import com.sparta.springauth.food.Food;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class BeanTest {

    @Autowired //타입 기반주입을 함 ( Food 타입을 만족하는 구현체를 찾음)
                // food 인터페이스이므로 객체를 만들 수없고,
    @Qualifier("pizza")

    Food food; //pizza, chicken중 어디에 주입해야하는지 알 수 없어서 NoUniqueBeanDefinitionException이 뜸

//    @Autowired
//    Food chicken;
//
//    @Autowired
//    Food pizza;

    @Test
    @DisplayName("Primary와 Qualifier 우선순위 확인")
    void test1() {
//        pizza.eat(); // 실행해보면 어떤 구현체가 주입됐는지 확인 가능
//        chicken.eat();
        food.eat();
    }

}

