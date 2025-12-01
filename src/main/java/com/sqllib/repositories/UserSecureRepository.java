package com.sqllib.repositories;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import com.sqllib.utils.DatabaseConnection;

public class UserSecureRepository {

    /**
     * SECURE: Using PreparedStatement
     */
    public String getUserById(String id) throws SQLException {
        String query = "SELECT username FROM users WHERE id = ?";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, id);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("username");
                }
            }
        }
        return null;
    }

    /**
     * SECURE: Using PreparedStatement
     * Returns the generated user ID
     */
    public int createUser(String username, String password, String email) throws SQLException {
        String query = "INSERT INTO users (username, password, email) VALUES (?, ?, ?)";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, username);
            pstmt.setString(2, password);
            pstmt.setString(3, email);
            pstmt.executeUpdate();

            // Retrieve and return generated ID
            try (ResultSet rs = pstmt.getGeneratedKeys()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
            throw new SQLException("Creating user failed, no ID obtained.");
        }
    }

    /**
     * SECURE: Authentication with PreparedStatement
     */
    public boolean authenticate(String username, String password) throws SQLException {
        String query = "SELECT * FROM users WHERE username = ? AND password = ?";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, username);
            pstmt.setString(2, password);
            try (ResultSet rs = pstmt.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * SECURE: Second Order SQL Injection Prevention - Step 2
     * Uses PreparedStatement even with stored data
     * Takes userId instead of username to demonstrate proper prevention
     */
    public String getUserProfile(String userId) throws SQLException {
        // Step 1: Retrieve username by ID using PreparedStatement
        String getUserQuery = "SELECT username FROM users WHERE id = ?";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt1 = conn.prepareStatement(getUserQuery)) {
            pstmt1.setInt(1, Integer.parseInt(userId));

            try (ResultSet rs = pstmt1.executeQuery()) {
                if (rs.next()) {
                    String storedUsername = rs.getString("username");

                    // Step 2: IMPORTANT: Even though data comes from DB, still use PreparedStatement!
                    String profileQuery = "SELECT email FROM users WHERE username = ?";
                    try (PreparedStatement pstmt2 = conn.prepareStatement(profileQuery)) {
                        pstmt2.setString(1, storedUsername);
                        try (ResultSet rs2 = pstmt2.executeQuery()) {
                            if (rs2.next()) {
                                return rs2.getString("email");
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * SECURE: Boolean-based Blind SQL Injection Prevention
     * Uses PreparedStatement to prevent condition injection
     */
    public boolean checkUserExists(String username) throws SQLException {
        String query = "SELECT COUNT(*) as count FROM users WHERE username = ?";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, username);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt("count") > 0;
                }
            }
        }
        return false;
    }

    /**
     * SECURE: Time-based Blind SQL Injection Prevention
     * Uses PreparedStatement to prevent time delay injection
     */
    public String getUserEmail(String userId) throws SQLException {
        String query = "SELECT email FROM users WHERE id = ?";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, userId);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("email");
                }
            }
        }
        return "User not found";
    }

    /**
     * SECURE: UNION-based SQL Injection Prevention
     * Uses PreparedStatement to prevent UNION query injection
     * Input is treated as data, not SQL code
     */
    public String searchUserByName(String username) throws SQLException {
        String query = "SELECT username FROM users WHERE username LIKE ?";

        StringBuilder results = new StringBuilder();
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, "%" + username + "%");

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    if (results.length() > 0) {
                        results.append(", ");
                    }
                    results.append(rs.getString("username")); // Safe: using column name
                }
            }
        }
        return results.length() > 0 ? results.toString() : "No users found";
    }

    /**
     * SECURE: Error-Based SQL Injection Prevention
     * Uses PreparedStatement and proper error handling
     */
    public String getUserPassword(String userId) throws SQLException {
        String query = "SELECT password FROM users WHERE id = ?";

        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, userId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("password");
                }
            }
        }
        return null;
    }
}