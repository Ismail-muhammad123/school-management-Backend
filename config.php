<?php
// config.php - Database connection & System Configuration

if (!defined('JWT_SECRET')) {
    define('JWT_SECRET', 'school_mgmt_secret_key_jwt_2026_xyz');
}
if (!defined('JWT_EXPIRATION')) {
    define('JWT_EXPIRATION', 86400); // 24 hours in seconds
}

class Connection {
    private $host = "localhost";
    private $user = "root";
    private $password = "";
    private $database = "school_management";
    private $pdo = null;

    public function connect() {
        if ($this->pdo === null) {
            try {
                // First ensure database exists
                $dsnWithoutDb = "mysql:host=" . $this->host . ";charset=utf8mb4";
                $tempPdo = new PDO($dsnWithoutDb, $this->user, $this->password, [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
                ]);
                $tempPdo->exec("CREATE DATABASE IF NOT EXISTS `" . $this->database . "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");

                // Connect to the specific database
                $dsn = "mysql:host=" . $this->host . ";dbname=" . $this->database . ";charset=utf8mb4";
                $this->pdo = new PDO($dsn, $this->user, $this->password, [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                ]);

                // Auto initialize users table if it doesn't exist
                $this->initializeSchema();

            } catch (PDOException $e) {
                http_response_code(500);
                header('Content-Type: application/json');
                echo json_encode([
                    'status' => 'error',
                    'message' => 'Database connection failed: ' . $e->getMessage()
                ]);
                exit;
            }
        }
        return $this->pdo;
    }

    private function initializeSchema() {
        $tableSql = "CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            role ENUM('admin', 'student') NOT NULL DEFAULT 'student',
            phone VARCHAR(30) NULL,
            address TEXT NULL,
            department VARCHAR(100) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

        $this->pdo->exec($tableSql);

        $appTableSql = "CREATE TABLE IF NOT EXISTS applications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            qualification VARCHAR(255) NOT NULL,
            level VARCHAR(100) NOT NULL,
            profile_pic VARCHAR(255) NULL,
            certificate VARCHAR(255) NULL,
            status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
            admin_comment TEXT NULL,
            reviewed_by INT NULL,
            reviewed_at TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

        $this->pdo->exec($appTableSql);

        $resetTableSql = "CREATE TABLE IF NOT EXISTS password_resets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(100) NOT NULL,
            token VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            used TINYINT(1) DEFAULT 0,
            INDEX (email),
            INDEX (token)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

        $this->pdo->exec($resetTableSql);

        // Ensure upload directories exist
        $uploadDirs = [
            __DIR__ . '/uploads',
            __DIR__ . '/uploads/profile_pics',
            __DIR__ . '/uploads/certificates'
        ];
        foreach ($uploadDirs as $dir) {
            if (!is_dir($dir)) {
                @mkdir($dir, 0777, true);
            }
        }

        // Check if admin user exists; if not, seed a default admin
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM users WHERE role = 'admin'");
        $stmt->execute();
        $adminCount = $stmt->fetchColumn();

        if ($adminCount == 0) {
            $defaultPassword = password_hash('admin123', PASSWORD_BCRYPT);
            $seedSql = "INSERT INTO users (name, email, password, role, phone, department) 
                        VALUES ('System Administrator', 'admin@school.com', :password, 'admin', '123-456-7890', 'Administration')";
            $seedStmt = $this->pdo->prepare($seedSql);
            $seedStmt->execute([':password' => $defaultPassword]);
        }
    }
}

// Global connection instance helper
$db = new Connection();
$conn = $db->connect();