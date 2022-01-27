package com.eCommerceProject.api.controller;

import com.eCommerceProject.business.abstracts.UserService;
import com.eCommerceProject.entities.concretes.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/api/users/")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("add")
    public void add(@RequestBody @Valid User user) {
        this.userService.add(user);
    }

    @GetMapping("getAll")
    public ResponseEntity<List<User>> getAll() {
       List<User> users = this.userService.getAll();
       return ResponseEntity.ok(users);
    }

    @GetMapping("getById/{id}")
    public User getByid(@PathVariable int id) {
        return this.userService.getByid(id);
    }

}
