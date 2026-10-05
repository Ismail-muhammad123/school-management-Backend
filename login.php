<?php
// login.php - Authenticate user & return JWT

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Methods: POST, OPTIONS");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/jwt.php';
require_once __DIR__ . '/User.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    Auth::respondJson(405, [
        'status' => 'error',
        'message' => 'Method not allowed. Use POST to login.'
    ]);
}

$body = Auth::getRequestBody();
$email = trim($body['email'] ?? $body['username'] ?? '');
$password = trim($body['password'] ?? '');

if (empty($email) || empty($password)) {
    Auth::respondJson(400, [
        'status' => 'error',
        'message' => 'Email/Username and password are required'
    ]);
}

$userModel = new User();
$user = $userModel->authenticate($email, $password);

if (!$user) {
    Auth::respondJson(401, [
        'status' => 'error',
        'message' => 'Invalid email or password'
    ]);
}

// Generate JWT token with user claims
$token = JWT::encode([
    'user' => [
        'id' => (int)$user['id'],
        'name' => $user['name'],
        'email' => $user['email'],
        'role' => $user['role']
    ]
]);

Auth::respondJson(200, [
    'status' => 'success',
    'message' => 'Login successful',
    'token' => $token,
    'user' => [
        'id' => (int)$user['id'],
        'name' => $user['name'],
        'email' => $user['email'],
        'role' => $user['role'],
        'phone' => $user['phone'],
        'department' => $user['department']
    ]
]);
