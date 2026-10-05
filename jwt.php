<?php
// jwt.php - Pure PHP JWT Implementation & Authentication Middleware

require_once __DIR__ . '/config.php';

class JWT {
    private static function base64UrlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode($data) {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $padLen = 4 - $remainder;
            $data .= str_repeat('=', $padLen);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * Generate a JWT token
     */
    public static function encode(array $payload, string $secret = JWT_SECRET, int $expiry = JWT_EXPIRATION): string {
        $header = [
            'alg' => 'HS256',
            'typ' => 'JWT'
        ];

        $now = time();
        $payload['iat'] = $payload['iat'] ?? $now;
        $payload['exp'] = $payload['exp'] ?? ($now + $expiry);
        $payload['iss'] = $payload['iss'] ?? 'school_management_system';

        $headerEncoded = self::base64UrlEncode(json_encode($header));
        $payloadEncoded = self::base64UrlEncode(json_encode($payload));

        $signature = hash_hmac('sha256', "$headerEncoded.$payloadEncoded", $secret, true);
        $signatureEncoded = self::base64UrlEncode($signature);

        return "$headerEncoded.$payloadEncoded.$signatureEncoded";
    }

    /**
     * Decode and validate a JWT token
     */
    public static function decode(string $token, string $secret = JWT_SECRET): array {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new Exception("Invalid token structure");
        }

        list($headerEncoded, $payloadEncoded, $signatureEncoded) = $parts;

        $header = json_decode(self::base64UrlDecode($headerEncoded), true);
        if (!$header || ($header['alg'] ?? '') !== 'HS256') {
            throw new Exception("Unsupported algorithm or invalid header");
        }

        $expectedSig = hash_hmac('sha256', "$headerEncoded.$payloadEncoded", $secret, true);
        $actualSig = self::base64UrlDecode($signatureEncoded);

        if (!hash_equals($expectedSig, $actualSig)) {
            throw new Exception("Invalid token signature");
        }

        $payload = json_decode(self::base64UrlDecode($payloadEncoded), true);
        if (!$payload) {
            throw new Exception("Invalid token payload");
        }

        if (isset($payload['exp']) && $payload['exp'] < time()) {
            throw new Exception("Token has expired");
        }

        return $payload;
    }
}

class Auth {
    /**
     * Extract token from Authorization header or parameters
     */
    public static function getBearerToken(): ?string {
        $headers = null;

        if (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            $requestHeaders = array_change_key_case($requestHeaders, CASE_LOWER);
            if (isset($requestHeaders['authorization'])) {
                $headers = trim($requestHeaders['authorization']);
            }
        }

        if (!$headers) {
            if (isset($_SERVER['Authorization'])) {
                $headers = trim($_SERVER['Authorization']);
            } elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) {
                $headers = trim($_SERVER['HTTP_AUTHORIZATION']);
            } elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
                $headers = trim($_SERVER['REDIRECT_HTTP_AUTHORIZATION']);
            }
        }

        // Check Header: Bearer <token>
        if (!empty($headers)) {
            if (preg_match('/Bearer\s(\S+)/i', $headers, $matches)) {
                return $matches[1];
            }
        }

        // Fallback: Check query string or body parameter
        if (isset($_GET['token']) && !empty($_GET['token'])) {
            return trim($_GET['token']);
        }
        if (isset($_POST['token']) && !empty($_POST['token'])) {
            return trim($_POST['token']);
        }

        return null;
    }

    /**
     * Get the authenticated user payload, or null if unauthenticated
     */
    public static function user(): ?array {
        $token = self::getBearerToken();
        if (!$token) {
            return null;
        }

        try {
            $decoded = JWT::decode($token);
            return $decoded['user'] ?? null;
        } catch (Exception $e) {
            return null;
        }
    }

    /**
     * Require authentication; send 401 response and exit if invalid
     */
    public static function requireAuth(): array {
        $token = self::getBearerToken();
        if (!$token) {
            self::respondJson(401, [
                'status' => 'error',
                'message' => 'Unauthorized: Missing Bearer token'
            ]);
        }

        try {
            $decoded = JWT::decode($token);
            if (!isset($decoded['user'])) {
                throw new Exception("Missing user information in token");
            }
            return $decoded['user'];
        } catch (Exception $e) {
            self::respondJson(401, [
                'status' => 'error',
                'message' => 'Unauthorized: ' . $e->getMessage()
            ]);
        }
    }

    /**
     * Require admin access; sends 403 response if user role is not admin
     */
    public static function requireAdmin(): array {
        $user = self::requireAuth();
        if (($user['role'] ?? '') !== 'admin') {
            self::respondJson(403, [
                'status' => 'error',
                'message' => 'Forbidden: Full access requires admin role'
            ]);
        }
        return $user;
    }

    /**
     * Require either admin role OR that the authenticated user owns this resource
     */
    public static function requireOwnedOrAdmin(int $targetUserId): array {
        $user = self::requireAuth();
        if ($user['role'] === 'admin') {
            return $user; // Admin has full access
        }

        if ((int)$user['id'] === (int)$targetUserId) {
            return $user; // User owns their resource
        }

        self::respondJson(403, [
            'status' => 'error',
            'message' => 'Forbidden: You only have access to your own profile'
        ]);
    }

    /**
     * Standard JSON response helper
     */
    public static function respondJson(int $statusCode, array $data): void {
        http_response_code($statusCode);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }

    /**
     * Parse incoming JSON or Form request body
     */
    public static function getRequestBody(): array {
        $raw = file_get_contents('php://input');
        if (!empty($raw)) {
            $json = json_decode($raw, true);
            if (is_array($json)) {
                return $json;
            }
        }
        return $_POST ?? [];
    }
}
