<?php
define('DB_FILE', __DIR__ . '/passwords.json');

// AES-256-CBC Encryption
function encrypt($data, $key) {
    $iv = random_bytes(16);
    $cipher = openssl_encrypt($data, 'aes-256-cbc', hash('sha256', $key), 0, $iv);
    return base64_encode($iv . $cipher);
}

function decrypt($data, $key) {
    $raw = base64_decode($data);
    $iv = substr($raw, 0, 16);
    $cipher = substr($raw, 16);
    return openssl_decrypt($cipher, 'aes-256-cbc', hash('sha256', $key), 0, $iv);
}

// Generate Salt
function generateSalt($length = 16) {
    return bin2hex(random_bytes($length));
}

// Hash password with salt
function hashPassword($password, $salt) {
    return hash('sha256', $salt . $password);
}

// Load existing entries
$entries = [];
if(file_exists(DB_FILE)){
    $entries = json_decode(file_get_contents(DB_FILE), true);
}

$response = [];

if($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    $master = $data['master'] ?? '';
    $action = $data['action'] ?? '';

    if($action === 'save' && isset($data['site'], $data['password']) && $master){
        $site = trim($data['site']);
        $password = trim($data['password']);
        $salt = generateSalt();
        $hash = hashPassword($password, $salt);
        $encrypted = encrypt($password, $master);

        $entries[$site] = [
            'salt' => $salt,
            'hash' => $hash,
            'encrypted' => $encrypted
        ];
        file_put_contents(DB_FILE, json_encode($entries, JSON_PRETTY_PRINT));
        $response = ['status'=>'ok','message'=>"Password saved"];
    }

    if($action === 'view' && $master){
        $view = [];
        foreach($entries as $site => $data){
            $decrypted = decrypt($data['encrypted'], $master);
            $view[$site] = [
                'hash' => $data['hash'] . ' (salt: '.$data['salt'].')',
                'password' => $decrypted ?: '❌ Wrong master password'
            ];
        }
        $response = ['status'=>'ok','entries'=>$view];
    }

    header('Content-Type: application/json');
    echo json_encode($response);
    exit;
}
