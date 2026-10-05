<?php
// students.php - CRUD endpoint for Students
// Full access for Admin; Owned access for Students (view own profile and register)

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/jwt.php';
require_once __DIR__ . '/User.php';

$method = $_SERVER['REQUEST_METHOD'];
$body = Auth::getRequestBody();

// Method spoofing for forms and HTTP clients
if ($method === 'POST') {
    if (isset($body['_method'])) {
        $method = strtoupper($body['_method']);
    } elseif (isset($_GET['_method'])) {
        $method = strtoupper($_GET['_method']);
    }
}

$studentModel = new Student();

// 1. CREATE (POST) - Register or Admin Add
if ($method === 'POST') {
    // Check if user is authenticated
    $currentUser = Auth::user();

    // Either unauthenticated user registering as student, or Admin adding a student
    try {
        $newStudent = $studentModel->add([
            'name' => $body['name'] ?? '',
            'email' => $body['email'] ?? '',
            'password' => $body['password'] ?? '',
            'phone' => $body['phone'] ?? null,
            'address' => $body['address'] ?? null,
            'department' => $body['department'] ?? 'General Studies'
        ]);

        // If unauthenticated registration, issue JWT right away
        $token = null;
        if (!$currentUser || $currentUser['role'] === 'student') {
            $token = JWT::encode([
                'user' => [
                    'id' => (int)$newStudent['id'],
                    'name' => $newStudent['name'],
                    'email' => $newStudent['email'],
                    'role' => $newStudent['role']
                ]
            ]);
        }

        Auth::respondJson(201, [
            'status' => 'success',
            'message' => 'Student registered successfully',
            'token' => $token,
            'data' => $newStudent
        ]);
    } catch (InvalidArgumentException $e) {
        Auth::respondJson(400, [
            'status' => 'error',
            'message' => $e->getMessage()
        ]);
    } catch (Exception $e) {
        Auth::respondJson(500, [
            'status' => 'error',
            'message' => 'Failed to create student: ' . $e->getMessage()
        ]);
    }
}

// All subsequent operations (GET, PUT, DELETE) require a valid JWT token
$currentUser = Auth::requireAuth();

// 2. READ (GET) - Fetch students (Admin: all or by ID; Student: owned profile only)
if ($method === 'GET') {
    $targetId = null;
    if (isset($_GET['id']) && is_numeric($_GET['id'])) {
        $targetId = (int)$_GET['id'];
    }

    // STUDENT: Only allowed to view their own profile
    if ($currentUser['role'] === 'student') {
        if ($targetId !== null && $targetId !== (int)$currentUser['id']) {
            Auth::respondJson(403, [
                'status' => 'error',
                'message' => 'Forbidden: Students are only permitted to view their own profile'
            ]);
        }

        // Return the student's own profile
        $profile = $studentModel->getById((int)$currentUser['id']);
        Auth::respondJson(200, [
            'status' => 'success',
            'data' => $profile
        ]);
    }

    // ADMIN: Full access to view any student or all students
    if ($targetId !== null) {
        $student = $studentModel->getById($targetId);
        if (!$student) {
            Auth::respondJson(404, [
                'status' => 'error',
                'message' => "Student with ID $targetId not found"
            ]);
        }
        Auth::respondJson(200, [
            'status' => 'success',
            'data' => $student
        ]);
    }

    $allStudents = $studentModel->getAll();
    Auth::respondJson(200, [
        'status' => 'success',
        'count' => count($allStudents),
        'data' => $allStudents
    ]);
}

// 3. UPDATE (PUT) - Update student profile (Admin: any student; Student: own profile only)
if ($method === 'PUT') {
    $targetId = null;
    if (isset($_GET['id']) && is_numeric($_GET['id'])) {
        $targetId = (int)$_GET['id'];
    } elseif (isset($body['id']) && is_numeric($body['id'])) {
        $targetId = (int)$body['id'];
    }

    if (!$targetId) {
        // If not specified, default to own id for student
        if ($currentUser['role'] === 'student') {
            $targetId = (int)$currentUser['id'];
        } else {
            Auth::respondJson(400, [
                'status' => 'error',
                'message' => 'Student ID is required for update'
            ]);
        }
    }

    // Check ownership: Student can only update their own profile
    if ($currentUser['role'] === 'student' && $targetId !== (int)$currentUser['id']) {
        Auth::respondJson(403, [
            'status' => 'error',
            'message' => 'Forbidden: You can only update your own profile'
        ]);
    }

    try {
        $updatedStudent = $studentModel->update($targetId, $body);
        Auth::respondJson(200, [
            'status' => 'success',
            'message' => 'Student profile updated successfully',
            'data' => $updatedStudent
        ]);
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
            'message' => 'Update failed: ' . $e->getMessage()
        ]);
    }
}

// 4. DELETE (DELETE) - Full access for Admin only; Students forbidden
if ($method === 'DELETE') {
    // Enforce Admin only
    if ($currentUser['role'] !== 'admin') {
        Auth::respondJson(403, [
            'status' => 'error',
            'message' => 'Forbidden: Only administrators have permission to delete student accounts'
        ]);
    }

    $targetId = null;
    if (isset($_GET['id']) && is_numeric($_GET['id'])) {
        $targetId = (int)$_GET['id'];
    } elseif (isset($body['id']) && is_numeric($body['id'])) {
        $targetId = (int)$body['id'];
    }

    if (!$targetId) {
        Auth::respondJson(400, [
            'status' => 'error',
            'message' => 'Student ID is required for deletion'
        ]);
    }

    try {
        $studentModel->delete($targetId);
        Auth::respondJson(200, [
            'status' => 'success',
            'message' => "Student with ID $targetId deleted successfully"
        ]);
    } catch (RuntimeException $e) {
        Auth::respondJson(404, [
            'status' => 'error',
            'message' => $e->getMessage()
        ]);
    } catch (Exception $e) {
        Auth::respondJson(500, [
            'status' => 'error',
            'message' => 'Delete failed: ' . $e->getMessage()
        ]);
    }
}

Auth::respondJson(405, [
    'status' => 'error',
    'message' => 'Method not allowed'
]);
