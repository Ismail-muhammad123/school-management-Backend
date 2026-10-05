<?php
// User.php - Classes for Staff and Students operating on single 'users' table

require_once __DIR__ . '/config.php';

/**
 * Base User class for database interaction with the 'users' table
 */
class User {
    protected $conn;
    protected $table = 'users';

    public function __construct(?PDO $pdo = null) {
        if ($pdo !== null) {
            $this->conn = $pdo;
        } else {
            $connection = new Connection();
            $this->conn = $connection->connect();
        }
    }

    /**
     * Find user by ID (regardless of role)
     */
    public function findById(int $id): ?array {
        $stmt = $this->conn->prepare("SELECT id, name, email, role, phone, address, department, created_at, updated_at FROM {$this->table} WHERE id = :id");
        $stmt->execute([':id' => $id]);
        $user = $stmt->fetch();
        return $user ?: null;
    }

    /**
     * Find user by Email (includes password hash for auth)
     */
    public function findByEmail(string $email): ?array {
        $stmt = $this->conn->prepare("SELECT * FROM {$this->table} WHERE email = :email");
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch();
        return $user ?: null;
    }

    /**
     * Verify user credentials for login
     */
    public function authenticate(string $email, string $password): ?array {
        $user = $this->findByEmail($email);
        if (!$user) {
            return null;
        }

        if (password_verify($password, $user['password'])) {
            unset($user['password']); // Never leak password hash
            return $user;
        }

        return null;
    }

    /**
     * Common update profile method
     */
    public function updateProfile(int $id, array $data): array {
        $fields = [];
        $params = [':id' => $id];

        $allowedFields = ['name', 'phone', 'address', 'department'];
        foreach ($allowedFields as $field) {
            if (array_key_exists($field, $data)) {
                $fields[] = "$field = :$field";
                $params[":$field"] = $data[$field];
            }
        }

        if (!empty($data['email'])) {
            // Check if email is already taken by another user
            $checkStmt = $this->conn->prepare("SELECT id FROM {$this->table} WHERE email = :email AND id != :id");
            $checkStmt->execute([':email' => $data['email'], ':id' => $id]);
            if ($checkStmt->fetch()) {
                throw new InvalidArgumentException("Email is already registered by another user");
            }
            $fields[] = "email = :email";
            $params[':email'] = $data['email'];
        }

        if (!empty($data['password'])) {
            if (strlen($data['password']) < 6) {
                throw new InvalidArgumentException("Password must be at least 6 characters long");
            }
            $fields[] = "password = :password";
            $params[':password'] = password_hash($data['password'], PASSWORD_BCRYPT);
        }

        if (empty($fields)) {
            return $this->findById($id);
        }

        $sql = "UPDATE {$this->table} SET " . implode(', ', $fields) . " WHERE id = :id";
        $stmt = $this->conn->prepare($sql);
        $stmt->execute($params);

        return $this->findById($id);
    }
}

/**
 * Staff Class (Role: admin)
 * Fetches, adds, deletes, and updates staff profiles
 */
class Staff extends User {
    private $role = 'admin';

    /**
     * Fetch all staff members
     */
    public function getAll(): array {
        $stmt = $this->conn->prepare(
            "SELECT id, name, email, role, phone, address, department, created_at, updated_at 
             FROM {$this->table} 
             WHERE role = :role 
             ORDER BY id DESC"
        );
        $stmt->execute([':role' => $this->role]);
        return $stmt->fetchAll();
    }

    /**
     * Fetch a single staff profile by ID
     */
    public function getById(int $id): ?array {
        $stmt = $this->conn->prepare(
            "SELECT id, name, email, role, phone, address, department, created_at, updated_at 
             FROM {$this->table} 
             WHERE id = :id AND role = :role"
        );
        $stmt->execute([':id' => $id, ':role' => $this->role]);
        $staff = $stmt->fetch();
        return $staff ?: null;
    }

    /**
     * Fetch staff profile (alias for getById)
     */
    public function getProfile(int $id): ?array {
        return $this->getById($id);
    }

    /**
     * Add a new staff member (Role: admin)
     */
    public function add(array $data): array {
        // Validation
        if (empty($data['name']) || empty($data['email']) || empty($data['password'])) {
            throw new InvalidArgumentException("Name, email, and password are required for staff");
        }

        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            throw new InvalidArgumentException("Invalid email format");
        }

        if ($this->findByEmail($data['email'])) {
            throw new InvalidArgumentException("Email already exists");
        }

        if (strlen($data['password']) < 6) {
            throw new InvalidArgumentException("Password must be at least 6 characters");
        }

        $hashedPassword = password_hash($data['password'], PASSWORD_BCRYPT);
        $phone = $data['phone'] ?? null;
        $address = $data['address'] ?? null;
        $department = $data['department'] ?? 'General Staff';

        $stmt = $this->conn->prepare(
            "INSERT INTO {$this->table} (name, email, password, role, phone, address, department) 
             VALUES (:name, :email, :password, :role, :phone, :address, :department)"
        );

        $stmt->execute([
            ':name' => trim($data['name']),
            ':email' => trim($data['email']),
            ':password' => $hashedPassword,
            ':role' => $this->role,
            ':phone' => $phone,
            ':address' => $address,
            ':department' => $department
        ]);

        $newId = (int)$this->conn->lastInsertId();
        return $this->getById($newId);
    }

    /**
     * Update staff profile
     */
    public function update(int $id, array $data): array {
        $existing = $this->getById($id);
        if (!$existing) {
            throw new RuntimeException("Staff member not found");
        }

        $this->updateProfile($id, $data);
        return $this->getById($id);
    }

    /**
     * Delete staff member
     */
    public function delete(int $id): bool {
        $existing = $this->getById($id);
        if (!$existing) {
            throw new RuntimeException("Staff member not found");
        }

        $stmt = $this->conn->prepare("DELETE FROM {$this->table} WHERE id = :id AND role = :role");
        return $stmt->execute([':id' => $id, ':role' => $this->role]);
    }
}

/**
 * Student Class (Role: student)
 * Fetches, adds, deletes, and updates student profiles
 */
class Student extends User {
    private $role = 'student';

    /**
     * Fetch all students
     */
    public function getAll(): array {
        $stmt = $this->conn->prepare(
            "SELECT id, name, email, role, phone, address, department, created_at, updated_at 
             FROM {$this->table} 
             WHERE role = :role 
             ORDER BY id DESC"
        );
        $stmt->execute([':role' => $this->role]);
        return $stmt->fetchAll();
    }

    /**
     * Fetch a single student profile by ID
     */
    public function getById(int $id): ?array {
        $stmt = $this->conn->prepare(
            "SELECT id, name, email, role, phone, address, department, created_at, updated_at 
             FROM {$this->table} 
             WHERE id = :id AND role = :role"
        );
        $stmt->execute([':id' => $id, ':role' => $this->role]);
        $student = $stmt->fetch();
        return $student ?: null;
    }

    /**
     * Fetch student profile (alias for getById)
     */
    public function getProfile(int $id): ?array {
        return $this->getById($id);
    }

    /**
     * Add / Register a new student (Role: student)
     */
    public function add(array $data): array {
        // Validation
        if (empty($data['name']) || empty($data['email']) || empty($data['password'])) {
            throw new InvalidArgumentException("Name, email, and password are required for student registration");
        }

        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            throw new InvalidArgumentException("Invalid email format");
        }

        if ($this->findByEmail($data['email'])) {
            throw new InvalidArgumentException("Email already registered");
        }

        if (strlen($data['password']) < 6) {
            throw new InvalidArgumentException("Password must be at least 6 characters");
        }

        $hashedPassword = password_hash($data['password'], PASSWORD_BCRYPT);
        $phone = $data['phone'] ?? null;
        $address = $data['address'] ?? null;
        $department = $data['department'] ?? 'General Studies';

        $stmt = $this->conn->prepare(
            "INSERT INTO {$this->table} (name, email, password, role, phone, address, department) 
             VALUES (:name, :email, :password, :role, :phone, :address, :department)"
        );

        $stmt->execute([
            ':name' => trim($data['name']),
            ':email' => trim($data['email']),
            ':password' => $hashedPassword,
            ':role' => $this->role,
            ':phone' => $phone,
            ':address' => $address,
            ':department' => $department
        ]);

        $newId = (int)$this->conn->lastInsertId();
        return $this->getById($newId);
    }

    /**
     * Update student profile
     */
    public function update(int $id, array $data): array {
        $existing = $this->getById($id);
        if (!$existing) {
            throw new RuntimeException("Student not found");
        }

        $this->updateProfile($id, $data);
        return $this->getById($id);
    }

    /**
     * Delete student
     */
    public function delete(int $id): bool {
        $existing = $this->getById($id);
        if (!$existing) {
            throw new RuntimeException("Student not found");
        }

        $stmt = $this->conn->prepare("DELETE FROM {$this->table} WHERE id = :id AND role = :role");
        return $stmt->execute([':id' => $id, ':role' => $this->role]);
    }
}
