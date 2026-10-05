<?php
// Application.php - Application model for student applications and admin review

require_once __DIR__ . '/config.php';

class Application {
    private $conn;
    private $table = 'applications';

    public function __construct(?PDO $pdo = null) {
        if ($pdo !== null) {
            $this->conn = $pdo;
        } else {
            $connection = new Connection();
            $this->conn = $connection->connect();
        }
    }

    /**
     * Handle file uploads securely
     */
    public function handleFileUpload(array $file, string $subfolder, array $allowedExtensions = ['jpg', 'jpeg', 'png', 'webp', 'pdf']): ?string {
        if (!isset($file['error']) || is_array($file['error'])) {
            return null;
        }

        if ($file['error'] !== UPLOAD_ERR_OK) {
            return null;
        }

        // Limit size: 10MB
        if ($file['size'] > 10 * 1024 * 1024) {
            throw new InvalidArgumentException("File size exceeds 10MB limit");
        }

        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($extension, $allowedExtensions)) {
            throw new InvalidArgumentException("Invalid file extension: .$extension. Allowed: " . implode(', ', $allowedExtensions));
        }

        $targetDir = __DIR__ . '/uploads/' . trim($subfolder, '/');
        if (!is_dir($targetDir)) {
            @mkdir($targetDir, 0777, true);
        }

        $filename = uniqid('app_', true) . '.' . $extension;
        $targetPath = $targetDir . '/' . $filename;

        if (!move_uploaded_file($file['tmp_name'], $targetPath)) {
            // Fallback for CLI/testing environments where move_uploaded_file might not be from POST
            if (copy($file['tmp_name'], $targetPath)) {
                @unlink($file['tmp_name']);
            } else {
                throw new RuntimeException("Failed to save uploaded file");
            }
        }

        return 'uploads/' . trim($subfolder, '/') . '/' . $filename;
    }

    /**
     * Submit a new student application
     */
    public function create(int $userId, array $data, array $files = []): array {
        if (empty($data['qualification'])) {
            throw new InvalidArgumentException("Qualification is required");
        }
        if (empty($data['level'])) {
            throw new InvalidArgumentException("Academic level is required");
        }

        // Handle file uploads
        $profilePicPath = null;
        $certificatePath = null;

        if (isset($files['profile_pic']) && $files['profile_pic']['error'] === UPLOAD_ERR_OK) {
            $profilePicPath = $this->handleFileUpload($files['profile_pic'], 'profile_pics', ['jpg', 'jpeg', 'png', 'webp']);
        } elseif (!empty($data['profile_pic'])) {
            $profilePicPath = trim($data['profile_pic']);
        }

        if (isset($files['certificate']) && $files['certificate']['error'] === UPLOAD_ERR_OK) {
            $certificatePath = $this->handleFileUpload($files['certificate'], 'certificates', ['jpg', 'jpeg', 'png', 'webp', 'pdf']);
        } elseif (!empty($data['certificate'])) {
            $certificatePath = trim($data['certificate']);
        }

        $stmt = $this->conn->prepare(
            "INSERT INTO {$this->table} (user_id, qualification, level, profile_pic, certificate, status) 
             VALUES (:user_id, :qualification, :level, :profile_pic, :certificate, 'pending')"
        );

        $stmt->execute([
            ':user_id' => $userId,
            ':qualification' => trim($data['qualification']),
            ':level' => trim($data['level']),
            ':profile_pic' => $profilePicPath,
            ':certificate' => $certificatePath
        ]);

        $newId = (int)$this->conn->lastInsertId();
        return $this->getById($newId);
    }

    /**
     * Fetch application by ID with student and reviewer metadata
     */
    public function getById(int $id): ?array {
        $stmt = $this->conn->prepare(
            "SELECT 
                a.id, a.user_id, a.qualification, a.level, a.profile_pic, a.certificate, 
                a.status, a.admin_comment, a.reviewed_by, a.reviewed_at, a.created_at, a.updated_at,
                u.name AS student_name, u.email AS student_email, u.phone AS student_phone, u.department AS student_department,
                r.name AS reviewer_name, r.email AS reviewer_email
             FROM {$this->table} a
             JOIN users u ON a.user_id = u.id
             LEFT JOIN users r ON a.reviewed_by = r.id
             WHERE a.id = :id"
        );
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /**
     * Fetch all applications submitted by a specific student
     */
    public function getByUserId(int $userId): array {
        $stmt = $this->conn->prepare(
            "SELECT 
                a.id, a.user_id, a.qualification, a.level, a.profile_pic, a.certificate, 
                a.status, a.admin_comment, a.reviewed_by, a.reviewed_at, a.created_at, a.updated_at,
                r.name AS reviewer_name
             FROM {$this->table} a
             LEFT JOIN users r ON a.reviewed_by = r.id
             WHERE a.user_id = :user_id
             ORDER BY a.created_at DESC"
        );
        $stmt->execute([':user_id' => $userId]);
        return $stmt->fetchAll();
    }

    /**
     * Fetch all applications (for Admin), optionally filtered by status
     */
    public function getAll(?string $status = null): array {
        $sql = "SELECT 
                    a.id, a.user_id, a.qualification, a.level, a.profile_pic, a.certificate, 
                    a.status, a.admin_comment, a.reviewed_by, a.reviewed_at, a.created_at, a.updated_at,
                    u.name AS student_name, u.email AS student_email, u.phone AS student_phone, u.department AS student_department,
                    r.name AS reviewer_name
                FROM {$this->table} a
                JOIN users u ON a.user_id = u.id
                LEFT JOIN users r ON a.reviewed_by = r.id";

        $params = [];
        if ($status !== null && in_array(strtolower($status), ['pending', 'approved', 'rejected'])) {
            $sql .= " WHERE a.status = :status";
            $params[':status'] = strtolower($status);
        }

        $sql .= " ORDER BY a.created_at DESC";

        $stmt = $this->conn->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    /**
     * Admin review: accept or reject application with optional comment
     */
    public function updateStatus(int $id, string $status, ?string $comment = null, int $adminId): array {
        $status = strtolower(trim($status));
        if (!in_array($status, ['approved', 'rejected', 'pending'])) {
            throw new InvalidArgumentException("Status must be 'approved', 'rejected', or 'pending'");
        }

        $existing = $this->getById($id);
        if (!$existing) {
            throw new RuntimeException("Application not found");
        }

        $stmt = $this->conn->prepare(
            "UPDATE {$this->table} 
             SET status = :status, admin_comment = :comment, reviewed_by = :reviewed_by, reviewed_at = NOW() 
             WHERE id = :id"
        );

        $stmt->execute([
            ':status' => $status,
            ':comment' => $comment !== null ? trim($comment) : $existing['admin_comment'],
            ':reviewed_by' => $adminId,
            ':id' => $id
        ]);

        return $this->getById($id);
    }

    /**
     * Delete application
     */
    public function delete(int $id): bool {
        $existing = $this->getById($id);
        if (!$existing) {
            throw new RuntimeException("Application not found");
        }

        // Clean up files if they exist on disk
        if (!empty($existing['profile_pic']) && file_exists(__DIR__ . '/' . $existing['profile_pic'])) {
            @unlink(__DIR__ . '/' . $existing['profile_pic']);
        }
        if (!empty($existing['certificate']) && file_exists(__DIR__ . '/' . $existing['certificate'])) {
            @unlink(__DIR__ . '/' . $existing['certificate']);
        }

        $stmt = $this->conn->prepare("DELETE FROM {$this->table} WHERE id = :id");
        return $stmt->execute([':id' => $id]);
    }
}
