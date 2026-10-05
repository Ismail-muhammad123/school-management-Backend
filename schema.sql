-- Database Schema for School Management System
-- Database: school_management

CREATE DATABASE IF NOT EXISTS `school_management` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `school_management`;

-- Single table for both staff and students with role: 'admin' or 'student'
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(100) NOT NULL UNIQUE,
    `password` VARCHAR(255) NOT NULL,
    `role` ENUM('admin', 'student') NOT NULL DEFAULT 'student',
    `phone` VARCHAR(30) NULL,
    `address` TEXT NULL,
    `department` VARCHAR(100) NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Applications table for student admissions/applications
CREATE TABLE IF NOT EXISTS `applications` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `qualification` VARCHAR(255) NOT NULL,
    `level` VARCHAR(100) NOT NULL,
    `profile_pic` VARCHAR(255) NULL,
    `certificate` VARCHAR(255) NULL,
    `status` ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
    `admin_comment` TEXT NULL,
    `reviewed_by` INT NULL,
    `reviewed_at` TIMESTAMP NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`reviewed_by`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Password resets table for token storage & expiration
CREATE TABLE IF NOT EXISTS `password_resets` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `email` VARCHAR(100) NOT NULL,
    `token` VARCHAR(255) NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `expires_at` DATETIME NOT NULL,
    `used` TINYINT(1) DEFAULT 0,
    INDEX (`email`),
    INDEX (`token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed default administrator account (Password: admin123)
-- Password hash generated using password_hash('admin123', PASSWORD_BCRYPT)
INSERT INTO `users` (`name`, `email`, `password`, `role`, `phone`, `department`)
SELECT 'System Administrator', 'admin@school.com', '$2y$10$w8T.tKkHfZiQ/8Yt9Vf3d.7i1mNn92Gq7K8jZ5YQ0u1Fq7gR9b5C2', 'admin', '123-456-7890', 'Administration'
WHERE NOT EXISTS (SELECT 1 FROM `users` WHERE `role` = 'admin');
