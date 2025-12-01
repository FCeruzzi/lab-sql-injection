package com.sqllib.services;

import java.sql.SQLException;

import org.springframework.stereotype.Service;

import com.sqllib.repositories.UserSecureRepository;

@Service
public class UserSecureService {
    private final UserSecureRepository userSecureRepository;

    public UserSecureService() {
        this.userSecureRepository = new UserSecureRepository();
    }

    // SECURE methods using PreparedStatement

    public String getUserById(String id) throws SQLException {
        return userSecureRepository.getUserById(id);
    }

    public int createUser(String username, String password, String email) throws SQLException {
        return userSecureRepository.createUser(username, password, email);
    }

    public boolean authenticate(String username, String password) throws SQLException {
        return userSecureRepository.authenticate(username, password);
    }

    public String getUserProfile(String userId) throws SQLException {
        return userSecureRepository.getUserProfile(userId);
    }

    public boolean checkUserExists(String username) throws SQLException {
        return userSecureRepository.checkUserExists(username);
    }

    public String getUserEmail(String userId) throws SQLException {
        return userSecureRepository.getUserEmail(userId);
    }

    public String searchUserByName(String username) throws SQLException {
        return userSecureRepository.searchUserByName(username);
    }

    public String getUserPassword(String userId) throws SQLException {
        return userSecureRepository.getUserPassword(userId);
    }
}