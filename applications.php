<?php
// applications.php - Endpoints for Student Applications & Admin Review

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
require_once __DIR__ . '/Application.php';

// All operations on applications require authentication
$currentUser = Auth::requireAuth();

$method = $_SERVER['REQUEST_METHOD'];
$body = Auth::getRequestBody();

// Support method spoofing
if ($method === 'POST') {
    if (isset($body['_method'])) {
        $method = strtoupper($body['_method']);
    } elseif (isset($_GET['_method'])) {
        $method = strtoupper($_GET['_method']);
    }
}

$appModel = new Application();

// 1. READ (GET) - View application(s)
if ($method === 'GET') {
    // Single application lookup by ID
    if (isset($_GET['id']) && is_numeric($_GET['id'])) {
        $appId = (int)$_GET['id'];
        $application = $appModel->getById($appId);

        if (!$application) {
            Auth::respondJson(404, [
                'status' => 'error',
                'message' => "Application with ID $appId not found"
            ]);
        }

        // Access Control: Students can ONLY view their own application
        if ($currentUser['role'] !== 'admin' && (int)$application['user_id'] !== (int)$currentUser['id']) {
            Auth::respondJson(403, [
                'status' => 'error',
                'message' => 'Forbidden: You can only view the status of your own application'
            ]);
        }

        Auth::respondJson(200, [
            'status' => 'success',
            'data' => $application
        ]);
    }

    // List applications:
    // If Admin: returns all applications (supports ?status=pending|approved|rejected)
    // If Student: returns only applications submitted by current student
    if ($currentUser['role'] === 'admin') {
        $statusFilter = isset($_GET['status']) ? trim($_GET['status']) : null;
        $applications = $appModel->getAll($statusFilter);

        Auth::respondJson(200, [
            'status' => 'success',
            'count' => count($applications),
            'filter' => $statusFilter ?: 'all',
            'data' => $applications
        ]);
    } else {
        // Student view: their own applications and statuses
        $applications = $appModel->getByUserId((int)$currentUser['id']);
        Auth::respondJson(200, [
            'status' => 'success',
            'count' => count($applications),
            'data' => $applications
        ]);
    }
}

// 2. CREATE (POST) - Submit application
if ($method === 'POST') {
    $targetUserId = (int)$currentUser['id'];

    // If Admin is submitting on behalf of a student, they can supply user_id
    if ($currentUser['role'] === 'admin' && isset($body['user_id']) && is_numeric($body['user_id'])) {
        $targetUserId = (int)$body['user_id'];
    }

    // Check if files were uploaded via multipart/form-data
    $files = $_FILES ?? [];

    try {
        $newApp = $appModel->create($targetUserId, $body, $files);

        Auth::respondJson(201, [
            'status' => 'success',
            'message' => 'Application submitted successfully. Status is pending review.',
            'data' => $newApp
        ]);
    } catch (InvalidArgumentException $e) {
        Auth::respondJson(400, [
            'status' => 'error',
            'message' => $e->getMessage()
        ]);
    } catch (Exception $e) {
        Auth::respondJson(500, [
            'status' => 'error',
            'message' => 'Could not submit application: ' . $e->getMessage()
        ]);
    }
}

// 3. UPDATE (PUT) - Admin Accept/Reject or Student Update
if ($method === 'PUT') {
    $appId = null;
    if (isset($_GET['id']) && is_numeric($_GET['id'])) {
        $appId = (int)$_GET['id'];
    } elseif (isset($body['id']) && is_numeric($body['id'])) {
        $appId = (int)$body['id'];
    }

    if (!$appId) {
        Auth::respondJson(400, [
            'status' => 'error',
            'message' => 'Application ID is required'
        ]);
    }

    $existing = $appModel->getById($appId);
    if (!$existing) {
        Auth::respondJson(404, [
            'status' => 'error',
            'message' => "Application with ID $appId not found"
        ]);
    }

    // A. ADMIN WORKFLOW: Accept or Reject application
    if ($currentUser['role'] === 'admin') {
        $newStatus = $body['status'] ?? $_GET['status'] ?? null;
        $adminComment = $body['admin_comment'] ?? $body['comment'] ?? null;

        if (!$newStatus) {
            Auth::respondJson(400, [
                'status' => 'error',
                'message' => "Status is required (e.g. 'approved' or 'rejected')"
            ]);
        }

        try {
            $updated = $appModel->updateStatus($appId, $newStatus, $adminComment, (int)$currentUser['id']);
            Auth::respondJson(200, [
                'status' => 'success',
                'message' => "Application status updated to '$newStatus'",
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
                'message' => 'Error updating status: ' . $e->getMessage()
            ]);
        }
    }

    // B. STUDENT WORKFLOW: Can only view or cannot change status
    if ($currentUser['role'] !== 'admin') {
        if ((int)$existing['user_id'] !== (int)$currentUser['id']) {
            Auth::respondJson(403, [
                'status' => 'error',
                'message' => 'Forbidden: You do not own this application'
            ]);
        }

        // If student tries to approve/reject
        if (isset($body['status'])) {
            Auth::respondJson(403, [
                'status' => 'error',
                'message' => 'Forbidden: Only administrators can approve or reject applications'
            ]);
        }

        Auth::respondJson(400, [
            'status' => 'error',
            'message' => 'Only administrators can update application review status'
        ]);
    }
}

// 4. DELETE (DELETE) - Remove application
if ($method === 'DELETE') {
    $appId = null;
    if (isset($_GET['id']) && is_numeric($_GET['id'])) {
        $appId = (int)$_GET['id'];
    } elseif (isset($body['id']) && is_numeric($body['id'])) {
        $appId = (int)$body['id'];
    }

    if (!$appId) {
        Auth::respondJson(400, [
            'status' => 'error',
            'message' => 'Application ID is required'
        ]);
    }

    $existing = $appModel->getById($appId);
    if (!$existing) {
        Auth::respondJson(404, [
            'status' => 'error',
            'message' => "Application with ID $appId not found"
        ]);
    }

    // Admins can delete any application; Students can only delete their own if still pending
    if ($currentUser['role'] !== 'admin') {
        if ((int)$existing['user_id'] !== (int)$currentUser['id']) {
            Auth::respondJson(403, [
                'status' => 'error',
                'message' => 'Forbidden: You do not own this application'
            ]);
        }
        if ($existing['status'] !== 'pending') {
            Auth::respondJson(403, [
                'status' => 'error',
                'message' => 'Forbidden: Cannot delete an application that has already been ' . $existing['status']
            ]);
        }
    }

    try {
        $appModel->delete($appId);
        Auth::respondJson(200, [
            'status' => 'success',
            'message' => "Application with ID $appId deleted successfully"
        ]);
    } catch (Exception $e) {
        Auth::respondJson(500, [
            'status' => 'error',
            'message' => 'Could not delete application: ' . $e->getMessage()
        ]);
    }
}

Auth::respondJson(405, [
    'status' => 'error',
    'message' => 'Method not allowed'
]);
