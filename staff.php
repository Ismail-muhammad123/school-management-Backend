<?php
// staff.php - CRUD endpoint for Staff (Full access for Admin only; Forbidden for students)

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

// Strictly require Admin role for Staff CRUD
$adminUser = Auth::requireAdmin();

$method = $_SERVER['REQUEST_METHOD'];
$body = Auth::getRequestBody();

// Support method spoofing for forms and clients without native PUT/DELETE
if ($method === 'POST') {
    if (isset($body['_method'])) {
        $method = strtoupper($body['_method']);
    } elseif (isset($_GET['_method'])) {
        $method = strtoupper($_GET['_method']);
    }
}

$staffModel = new Staff();

// 1. READ (GET) - Fetch all staff or single staff by ID
if ($method === 'GET') {
    if (isset($_GET['id']) && is_numeric($_GET['id'])) {
        $staffId = (int)$_GET['id'];
        $staff = $staffModel->getById($staffId);
        if (!$staff) {
            Auth::respondJson(404, [
                'status' => 'error',
                'message' => "Staff member with ID $staffId not found"
            ]);
        }
        Auth::respondJson(200, [
            'status' => 'success',
            'data' => $staff
        ]);
    }

    $allStaff = $staffModel->getAll();
    Auth::respondJson(200, [
        'status' => 'success',
        'count' => count($allStaff),
        'data' => $allStaff
    ]);
}

// 2. CREATE (POST) - Add new staff member
if ($method === 'POST') {
    try {
        $newStaff = $staffModel->add([
            'name' => $body['name'] ?? '',
            'email' => $body['email'] ?? '',
            'password' => $body['password'] ?? '',
            'phone' => $body['phone'] ?? null,
            'address' => $body['address'] ?? null,
            'department' => $body['department'] ?? 'Staff'
        ]);

        Auth::respondJson(201, [
            'status' => 'success',
            'message' => 'Staff member created successfully',
            'data' => $newStaff
        ]);
    } catch (InvalidArgumentException $e) {
        Auth::respondJson(400, [
            'status' => 'error',
            'message' => $e->getMessage()
        ]);
    } catch (Exception $e) {
        Auth::respondJson(500, [
            'status' => 'error',
            'message' => 'Could not create staff: ' . $e->getMessage()
        ]);
    }
}

// 3. UPDATE (PUT) - Update staff profile
if ($method === 'PUT') {
    $staffId = null;
    if (isset($_GET['id']) && is_numeric($_GET['id'])) {
        $staffId = (int)$_GET['id'];
    } elseif (isset($body['id']) && is_numeric($body['id'])) {
        $staffId = (int)$body['id'];
    }

    if (!$staffId) {
        Auth::respondJson(400, [
            'status' => 'error',
            'message' => 'Staff ID is required for update'
        ]);
    }

    try {
        $updatedStaff = $staffModel->update($staffId, $body);
        Auth::respondJson(200, [
            'status' => 'success',
            'message' => 'Staff profile updated successfully',
            'data' => $updatedStaff
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
            'message' => 'Could not update staff: ' . $e->getMessage()
        ]);
    }
}

// 4. DELETE (DELETE) - Delete staff member
if ($method === 'DELETE') {
    $staffId = null;
    if (isset($_GET['id']) && is_numeric($_GET['id'])) {
        $staffId = (int)$_GET['id'];
    } elseif (isset($body['id']) && is_numeric($body['id'])) {
        $staffId = (int)$body['id'];
    }

    if (!$staffId) {
        Auth::respondJson(400, [
            'status' => 'error',
            'message' => 'Staff ID is required for deletion'
        ]);
    }

    // Prevent admin from deleting their own currently logged-in account
    if ($staffId === (int)$adminUser['id']) {
        Auth::respondJson(400, [
            'status' => 'error',
            'message' => 'Cannot delete your own active administrator account'
        ]);
    }

    try {
        $staffModel->delete($staffId);
        Auth::respondJson(200, [
            'status' => 'success',
            'message' => "Staff member with ID $staffId deleted successfully"
        ]);
    } catch (RuntimeException $e) {
        Auth::respondJson(404, [
            'status' => 'error',
            'message' => $e->getMessage()
        ]);
    } catch (Exception $e) {
        Auth::respondJson(500, [
            'status' => 'error',
            'message' => 'Could not delete staff: ' . $e->getMessage()
        ]);
    }
}

Auth::respondJson(405, [
    'status' => 'error',
    'message' => 'Method not allowed'
]);