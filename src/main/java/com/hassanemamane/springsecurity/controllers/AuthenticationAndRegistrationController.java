package com.hassanemamane.springsecurity.controllers;

import com.hassanemamane.springsecurity.entities.AuthRequest;
import com.hassanemamane.springsecurity.entities.UserInfo;
import com.hassanemamane.springsecurity.services.JwtService;
import com.hassanemamane.springsecurity.services.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/auth")
public class AuthenticationAndRegistrationController {
    private final UserInfoService userInfoService;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    public AuthenticationAndRegistrationController(UserInfoService userInfoService) {
        this.userInfoService = userInfoService;
    }
    @PostMapping("/user")
    public String authenticateAndGetToken(@RequestBody AuthRequest authRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        if (authentication.isAuthenticated()) {
            return jwtService.generateToken(authRequest.getUsername());
        } else {
            throw new UsernameNotFoundException("invalid user request !");
        }
    }

    @PostMapping("/users/register")
    public String addNewCustomer(@RequestBody UserInfo userInfo) {
        return userInfoService.addUser(userInfo);
    }
    @GetMapping("/welcome")
    public String welcome() {
        return "Welcome this endpoint is not secure";
    }

    @PreAuthorize("hasAuthority('USER')")
    @GetMapping("/testusers")
    public String testUser() {
        return "Welcome this endpoint is for user";
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("/testadmins")
    public String testAdmin() {
        return "Welcome this endpoint is for admin";
    }
}
