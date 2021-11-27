package tw.com.rex.casproxypractice.app.web.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/tester")
public class TestController {

    @PostMapping("/test")
    public ResponseEntity<Boolean> test() {
        return ResponseEntity.ok(Boolean.TRUE);
    }

}
