<?php
// password_reset.php - Password reset request, email sending, and reset confirmation

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/jwt.php';
require_once __DIR__ . '/User.php';

class PasswordResetService {
    private $pdo;

    public function __construct() {
        $connection = new Connection();
        $this->pdo = $connection->connect();
    }

    /**
     * Send password reset email with token
     */
    public function requestReset(string $email): array {
        $email = trim(strtolower($email));

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new InvalidArgumentException("Invalid email format");
        }

        // Verify user exists in single users table
        $userModel = new User($this->pdo);
        $user = $userModel->findByEmail($email);
        if (!$user) {
            throw new RuntimeException("No user found with email: $email");
        }

        // Invalidate any previous unused tokens for this email
        $invalidateStmt = $this->pdo->prepare("UPDATE password_resets SET used = 1 WHERE email = :email AND used = 0");
        $invalidateStmt->execute([':email' => $email]);

        // Generate cryptographically secure 64-character token
        $token = bin2hex(random_bytes(32));
        // Expiration: 1 hour (3600 seconds)
        $expiresAt = date('Y-m-d H:i:s', time() + 3600);

        // Store reset record
        $stmt = $this->pdo->prepare("INSERT INTO password_resets (email, token, expires_at, used) VALUES (:email, :token, :expires_at, 0)");
        $stmt->execute([
            ':email' => $email,
            ':token' => $token,
            ':expires_at' => $expiresAt
        ]);

        // Construct reset link
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https" : "http";
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $resetUrl = "$protocol://$host/school/password_reset.php?token=$token";

        // Send Email
        $userName = $user['name'] ?? 'User';
        $emailSent = $this->sendResetEmail($email, $userName, $token, $resetUrl);

        return [
            'status' => 'success',
            'message' => 'Password reset instructions have been sent to your email address.',
            'email' => $email,
            'token' => $token, // Included for easy API / local XAMPP testing
            'expires_at' => $expiresAt,
            'reset_link' => $resetUrl,
            'email_sent' => $emailSent
        ];
    }

    /**
     * Verify token validity
     */
    public function verifyToken(string $token): ?array {
        $token = trim($token);
        if (empty($token)) {
            return null;
        }

        $stmt = $this->pdo->prepare(
            "SELECT * FROM password_resets 
             WHERE token = :token AND used = 0 AND expires_at > NOW() 
             ORDER BY id DESC LIMIT 1"
        );
        $stmt->execute([':token' => $token]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /**
     * Confirm password reset and update password
     */
    public function confirmReset(string $token, string $newPassword): array {
        $token = trim($token);
        $record = $this->verifyToken($token);

        if (!$record) {
            throw new InvalidArgumentException("Password reset token is invalid, has expired, or was already used");
        }

        if (strlen($newPassword) < 6) {
            throw new InvalidArgumentException("New password must be at least 6 characters long");
        }

        $email = $record['email'];
        $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);

        // Update password in users table
        $updateStmt = $this->pdo->prepare("UPDATE users SET password = :password WHERE email = :email");
        $updateStmt->execute([
            ':password' => $hashedPassword,
            ':email' => $email
        ]);

        // Mark token as used
        $markStmt = $this->pdo->prepare("UPDATE password_resets SET used = 1 WHERE id = :id");
        $markStmt->execute([':id' => $record['id']]);

        // Optionally send confirmation email
        $this->sendConfirmationEmail($email);

        return [
            'status' => 'success',
            'message' => 'Password has been successfully updated! You can now log in with your new password.',
            'email' => $email
        ];
    }

    /**
     * Send email via PHP mail()
     */
    private function sendResetEmail(string $to, string $name, string $token, string $resetUrl): bool {
        $subject = "Password Reset Request - School Management System";
        $message = "Hello $name,\r\n\r\n"
                 . "We received a request to reset your password for the School Management System.\r\n\r\n"
                 . "Your password reset token is:\r\n"
                 . "$token\r\n\r\n"
                 . "You can also reset your password directly using this link:\r\n"
                 . "$resetUrl\r\n\r\n"
                 . "This token will expire in 1 hour.\r\n\r\n"
                 . "If you did not make this request, you can safely ignore this email.\r\n\r\n"
                 . "Regards,\r\nSchool Management Administration";

        $headers = "From: School Management <noreply@school.com>\r\n"
                 . "Reply-To: noreply@school.com\r\n"
                 . "X-Mailer: PHP/" . phpversion();

        // Attempt PHP mail; suppress warning in local development if sendmail is not configured
        return (bool)@mail($to, $subject, $message, $headers);
    }

    /**
     * Send confirmation email that password was changed
     */
    private function sendConfirmationEmail(string $to): bool {
        $subject = "Password Successfully Reset - School Management System";
        $message = "Hello,\r\n\r\n"
                 . "Your account password for the School Management System was successfully changed.\r\n\r\n"
                 . "If you did not perform this action, please contact your administrator immediately.\r\n\r\n"
                 . "Regards,\r\nSchool Management Administration";

        $headers = "From: School Management <noreply@school.com>\r\n"
                 . "Reply-To: noreply@school.com\r\n"
                 . "X-Mailer: PHP/" . phpversion();

        return (bool)@mail($to, $subject, $message, $headers);
    }
}

// -------------------------------------------------------------
// Request Handler
// -------------------------------------------------------------

$resetService = new PasswordResetService();
$method = $_SERVER['REQUEST_METHOD'];
$body = Auth::getRequestBody();
$action = $_GET['action'] ?? $body['action'] ?? null;

// Determine if client expects HTML or JSON
$acceptHeader = $_SERVER['HTTP_ACCEPT'] ?? '';
$isHtmlRequest = (strpos($acceptHeader, 'text/html') !== false) && empty($body);

// 1. GET Request: Verify token status or render HTML password reset form
if ($method === 'GET') {
    $token = $_GET['token'] ?? null;

    if ($token) {
        $record = $resetService->verifyToken($token);

        // If accessed directly from browser as HTML page, show user-friendly form
        if ($isHtmlRequest) {
            renderHtmlResetForm($token, $record ? $record['email'] : null, (bool)$record);
            exit;
        }

        if (!$record) {
            Auth::respondJson(400, [
                'status' => 'error',
                'valid' => false,
                'message' => 'Password reset token is invalid, expired, or already used'
            ]);
        }

        Auth::respondJson(200, [
            'status' => 'success',
            'valid' => true,
            'message' => 'Token is valid',
            'email' => $record['email'],
            'expires_at' => $record['expires_at']
        ]);
    }

    // GET without token: if browser, render Request Reset Form
    if ($isHtmlRequest) {
        renderHtmlRequestForm();
        exit;
    }

    Auth::respondJson(400, [
        'status' => 'error',
        'message' => 'Please provide ?token={token} to verify or send a POST request with your email to request a reset'
    ]);
}

// 2. POST Request: Either Request Token OR Confirm Reset
if ($method === 'POST') {
    // Check if this is a Confirm Reset request (token + password provided, or action=confirm)
    $token = $body['token'] ?? $_GET['token'] ?? null;
    $password = $body['password'] ?? $body['new_password'] ?? null;

    if ($action === 'confirm' || ($token && $password)) {
        if (empty($token)) {
            Auth::respondJson(400, [
                'status' => 'error',
                'message' => 'Reset token is required'
            ]);
        }
        if (empty($password)) {
            Auth::respondJson(400, [
                'status' => 'error',
                'message' => 'New password is required'
            ]);
        }

        // Optional confirm_password validation
        if (isset($body['confirm_password']) && $password !== $body['confirm_password']) {
            Auth::respondJson(400, [
                'status' => 'error',
                'message' => 'Passwords do not match'
            ]);
        }

        try {
            $result = $resetService->confirmReset($token, $password);
            Auth::respondJson(200, $result);
        } catch (InvalidArgumentException $e) {
            Auth::respondJson(400, [
                'status' => 'error',
                'message' => $e->getMessage()
            ]);
        } catch (Exception $e) {
            Auth::respondJson(500, [
                'status' => 'error',
                'message' => 'Password reset failed: ' . $e->getMessage()
            ]);
        }
    }

    // Otherwise, treat as Request Reset (send email with token)
    $email = $body['email'] ?? null;
    if (empty($email)) {
        Auth::respondJson(400, [
            'status' => 'error',
            'message' => 'Email address is required to request a password reset'
        ]);
    }

    try {
        $result = $resetService->requestReset($email);
        Auth::respondJson(200, $result);
    } catch (InvalidArgumentException $e) {
        Auth::respondJson(400, [
            'status' => 'error',
            'message' => $e->getMessage()
        ]);
    } catch (RuntimeException $e) {
        Auth::respondJson(404, [
            'status' => 'error',
            'message' => $e->getMessage()
        ]);
    } catch (Exception $e) {
        Auth::respondJson(500, [
            'status' => 'error',
            'message' => 'Error processing reset: ' . $e->getMessage()
        ]);
    }
}

Auth::respondJson(405, ['status' => 'error', 'message' => 'Method not allowed']);


// -------------------------------------------------------------
// Clean HTML Fallback Forms for browser access
// -------------------------------------------------------------

function renderHtmlRequestForm(): void {
    header('Content-Type: text/html; charset=utf-8');
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Request Password Reset</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; padding: 2rem; display: flex; justify-content: center; }
            .card { background: white; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); width: 100%; max-width: 420px; }
            h2 { margin-bottom: 0.5rem; color: #1e293b; }
            p { font-size: 0.875rem; color: #64748b; margin-bottom: 1.5rem; }
            label { display: block; font-size: 0.8rem; font-weight: 600; color: #475569; margin-bottom: 0.4rem; text-transform: uppercase; }
            input { width: 100%; padding: 0.65rem; border: 1px solid #cbd5e1; border-radius: 8px; box-sizing: border-box; font-size: 0.95rem; margin-bottom: 1.25rem; }
            button { width: 100%; padding: 0.75rem; background: #4f46e5; color: white; border: none; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; }
            button:hover { background: #4338ca; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>Reset Password</h2>
            <p>Enter your account email address to receive a secure reset token.</p>
            <form method="POST" action="password_reset.php">
                <label>Email Address</label>
                <input type="email" name="email" required placeholder="user@school.com">
                <button type="submit">Send Reset Token</button>
            </form>
        </div>
    </body>
    </html>
    <?php
}

function renderHtmlResetForm(string $token, ?string $email, bool $isValid): void {
    header('Content-Type: text/html; charset=utf-8');
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Confirm Password Reset</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; padding: 2rem; display: flex; justify-content: center; }
            .card { background: white; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); width: 100%; max-width: 420px; }
            h2 { margin-bottom: 0.5rem; color: #1e293b; }
            p { font-size: 0.875rem; color: #64748b; margin-bottom: 1.5rem; }
            label { display: block; font-size: 0.8rem; font-weight: 600; color: #475569; margin-bottom: 0.4rem; text-transform: uppercase; }
            input { width: 100%; padding: 0.65rem; border: 1px solid #cbd5e1; border-radius: 8px; box-sizing: border-box; font-size: 0.95rem; margin-bottom: 1.25rem; }
            button { width: 100%; padding: 0.75rem; background: #4f46e5; color: white; border: none; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; }
            button:hover { background: #4338ca; }
            .error { background: #fee2e2; color: #991b1b; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; font-size: 0.875rem; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>Set New Password</h2>
            <?php if (!$isValid): ?>
                <div class="error">This password reset link is invalid or has expired. Please request a new token.</div>
                <a href="password_reset.php" style="display:block; text-align:center; color:#4f46e5; text-decoration:none;">Request new token</a>
            <?php else: ?>
                <p>Enter a new password for <strong><?= htmlspecialchars($email ?? '') ?></strong>.</p>
                <form method="POST" action="password_reset.php">
                    <input type="hidden" name="token" value="<?= htmlspecialchars($token) ?>">
                    <input type="hidden" name="action" value="confirm">
                    <label>New Password</label>
                    <input type="password" name="password" required minlength="6" placeholder="Minimum 6 characters">
                    <label>Confirm Password</label>
                    <input type="password" name="confirm_password" required minlength="6" placeholder="Repeat new password">
                    <button type="submit">Update Password</button>
                </form>
            <?php endif; ?>
        </div>
    </body>
    </html>
    <?php
}
