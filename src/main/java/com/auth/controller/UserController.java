package com.auth.controller;

import com.auth.dto.AuthUserRequestDTO;
import com.auth.dto.UpdateUserDTO;
import com.auth.entity.UserEntity;
import com.auth.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/create")
    private ResponseEntity<Object> create(@Valid @RequestBody UserEntity userEntity) {

        try {
            return ResponseEntity.ok().body(this.userService.createUser(userEntity));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/auth")
    private ResponseEntity<Object> auth(@RequestBody AuthUserRequestDTO authUserRequestDTO) {

        try {
            return ResponseEntity.ok().body(this.userService.authenticationUser(authUserRequestDTO));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

    @PutMapping("/update")
    private ResponseEntity<Object> update(@RequestHeader("Authorization") String authorizationHeader,
                                          @RequestBody UpdateUserDTO updateUserDTO) {

        try {
            String token = authorizationHeader.replace("Bearer ", "");
            return ResponseEntity.ok().body(userService.updateUser(token, updateUserDTO));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

    @DeleteMapping("/delete")
    private  ResponseEntity<Object> delete(@RequestHeader("Authorization") String authorizationHeader) {

        try {
            String token = authorizationHeader.replace("Bearer ", "");
            return ResponseEntity.ok().body(userService.deleteUser(token));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }
}
