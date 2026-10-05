<?php
// register.php - Public registration endpoint for students

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
        'message' => 'Method not allowed. Use POST to register.'
    ]);
}

$body = Auth::getRequestBody();

try {
    $studentModel = new Student();
    $newStudent = $studentModel->add([
        'name' => $body['name'] ?? '',
        'email' => $body['email'] ?? '',
        'password' => $body['password'] ?? '',
        'phone' => $body['phone'] ?? null,
        'address' => $body['address'] ?? null,
        'department' => $body['department'] ?? 'General Studies'
    ]);

    // Automatically issue a JWT upon successful registration
    $token = JWT::encode([
        'user' => [
            'id' => (int)$newStudent['id'],
            'name' => $newStudent['name'],
            'email' => $newStudent['email'],
            'role' => $newStudent['role']
        ]
    ]);

    Auth::respondJson(201, [
        'status' => 'success',
        'message' => 'Student registered successfully',
        'token' => $token,
        'user' => $newStudent
    ]);

} catch (InvalidArgumentException $e) {
    Auth::respondJson(400, [
        'status' => 'error',
        'message' => $e->getMessage()
    ]);
} catch (Exception $e) {
    Auth::respondJson(500, [
        'status' => 'error',
        'message' => 'Registration error: ' . $e->getMessage()
    ]);
}
