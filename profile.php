<?php
// profile.php - View and Update User Profile (Students have owned access; Admins have full access)

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/jwt.php';
require_once __DIR__ . '/User.php';

// Require valid JWT authentication
$currentUser = Auth::requireAuth();

$method = $_SERVER['REQUEST_METHOD'];
// Support method spoofing for HTML forms
if ($method === 'POST') {
    $rawBody = Auth::getRequestBody();
    if (isset($rawBody['_method']) && strtoupper($rawBody['_method']) === 'PUT') {
        $method = 'PUT';
    }
}

$userModel = new User();

// GET - View Profile
if ($method === 'GET') {
    $targetId = (int)$currentUser['id'];

    if (isset($_GET['id']) && is_numeric($_GET['id'])) {
        $requestedId = (int)$_GET['id'];
        // Enforce ownership: students can ONLY view their own profile
        if ($currentUser['role'] !== 'admin' && $requestedId !== (int)$currentUser['id']) {
            Auth::respondJson(403, [
                'status' => 'error',
                'message' => 'Forbidden: Students are only allowed to view their own profile'
            ]);
        }
        $targetId = $requestedId;
    }

    $profile = $userModel->findById($targetId);
    if (!$profile) {
        Auth::respondJson(404, [
            'status' => 'error',
            'message' => 'Profile not found'
        ]);
    }

    Auth::respondJson(200, [
        'status' => 'success',
        'data' => $profile
    ]);
}

// PUT / POST - Update Profile
if ($method === 'PUT' || $method === 'POST') {
    $body = Auth::getRequestBody();

    $targetId = (int)$currentUser['id'];
    $requestedId = null;

    if (isset($_GET['id']) && is_numeric($_GET['id'])) {
        $requestedId = (int)$_GET['id'];
    } elseif (isset($body['id']) && is_numeric($body['id'])) {
        $requestedId = (int)$body['id'];
    }

    if ($requestedId !== null) {
        if ($currentUser['role'] !== 'admin' && $requestedId !== (int)$currentUser['id']) {
            Auth::respondJson(403, [
                'status' => 'error',
                'message' => 'Forbidden: Students are only allowed to update their own profile'
            ]);
        }
        $targetId = $requestedId;
    }

    try {
        $updated = $userModel->updateProfile($targetId, $body);
        Auth::respondJson(200, [
            'status' => 'success',
            'message' => 'Profile updated successfully',
            'data' => $updated
        ]);
    } catch (InvalidArgumentException $e) {
        Auth::respondJson(400, [
            'status' => 'error',
            'message' => $e->getMessage()
        ]);
    } catch (Exception $e) {
        Auth::respondJson(500, [
            'status' => 'error',
            'message' => 'Update failed: ' . $e->getMessage()
        ]);
    }
}

Auth::respondJson(405, [
    'status' => 'error',
    'message' => 'Method not allowed'
]);
