package com.sqllib.controllers;

import java.sql.SQLException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.sqllib.services.UserSecureService;

@RestController
@RequestMapping("/api/users/secure")
public class UserSecureController {

    @Autowired
    private UserSecureService userSecureService;

    @GetMapping("/{id}")
    public String getUserByIdSecure(@PathVariable String id) throws SQLException {
        // Versione SICURA usando PreparedStatement
        return userSecureService.getUserById(id);
    }

    @PostMapping("/")
    public String createUserSecure(@RequestParam String username, @RequestParam String password, @RequestParam String email) throws SQLException {
        // SECURE version using PreparedStatement
        int userId = userSecureService.createUser(username, password, email);
        return "User created securely with ID: " + userId;
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) throws SQLException {
        // SECURE version using PreparedStatement
        boolean authenticated = userSecureService.authenticate(username, password);
        return authenticated ? "Login successful" : "Login failed";
    }

    @GetMapping("/profile/{userId}")
    public String getUserProfile(@PathVariable String userId) throws SQLException {
        // SECURE against Second Order SQL Injection
        return userSecureService.getUserProfile(userId);
    }

    @GetMapping("/exists/{username}")
    public String checkUserExists(@PathVariable String username) throws SQLException {
        // SECURE against Boolean-based Blind SQL Injection
        boolean exists = userSecureService.checkUserExists(username);
        return exists ? "User exists" : "User not found";
    }

    @GetMapping("/email/{userId}")
    public String getUserEmail(@PathVariable String userId) throws SQLException {
        // SECURE against Time-based Blind SQL Injection
        return userSecureService.getUserEmail(userId);
    }

    @GetMapping("/search")
    public String searchUserByName(@RequestParam String username) throws SQLException {
        // SECURE against UNION-based SQL Injection
        return userSecureService.searchUserByName(username);
    }

    @GetMapping("/password/{userId}")
    public String getUserPassword(@PathVariable String userId) throws SQLException {
        // SECURE against Error-Based SQL Injection
        return userSecureService.getUserPassword(userId);
    }
}