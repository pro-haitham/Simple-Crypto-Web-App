<?php
// file_crypto.php - fixed header length bug, improved checks
// WARNING: demo code. For production use authenticated encryption, proper KDF and key management.

if($_SERVER['REQUEST_METHOD'] !== 'POST'){
  http_response_code(405);
  echo "Only POST allowed.";
  exit;
}
if(!isset($_FILES['userfile']) || !isset($_POST['passphrase']) || !isset($_POST['mode'])){
  echo "Missing inputs.";
  exit;
}
if(!extension_loaded('openssl')){
  echo "OpenSSL PHP extension is not loaded.";
  exit;
}

$mode = $_POST['mode']; // 'encrypt' or 'decrypt'
$pass = $_POST['passphrase'];
$tmpPath = $_FILES['userfile']['tmp_name'];
$origName = basename($_FILES['userfile']['name']);

define('HEADER', "SIMPLEAES\n"); // must match exactly both when encrypting and stripping

// derive key and iv from passphrase (simple): use sha256 for key, sha256(pass+'iv') for iv
$key = hash('sha256', $pass, true); // 32 bytes
$iv = substr(hash('sha256', $pass . 'iv', true), 0, 16); // 16 bytes

$data = file_get_contents($tmpPath);
if($data === false){
  echo "Failed to read uploaded file.";
  exit;
}

$cipher = "AES-256-CBC";

if($mode === 'encrypt'){
  $encrypted = openssl_encrypt($data, $cipher, $key, OPENSSL_RAW_DATA, $iv);
  if($encrypted === false){
    echo "Encryption failed: " . openssl_error_string();
    exit;
  }
  $outData = HEADER . $encrypted;
  header('Content-Description: File Transfer');
  header('Content-Type: application/octet-stream');
  header('Content-Disposition: attachment; filename="' . $origName . '.enc"');
  header('Content-Length: ' . strlen($outData));
  echo $outData;
  exit;
} elseif($mode === 'decrypt'){
  // strip header if present - use exact HEADER length
  if(substr($data, 0, strlen(HEADER)) === HEADER){
    $data = substr($data, strlen(HEADER));
  }
  $decrypted = openssl_decrypt($data, $cipher, $key, OPENSSL_RAW_DATA, $iv);
  if($decrypted === false){
    echo "Decryption failed. Wrong password or corrupt file. OpenSSL error: " . openssl_error_string();
    exit;
  }
  header('Content-Description: File Transfer');
  header('Content-Type: application/octet-stream');
  $downloadName = preg_replace('/\.enc$/', '', $origName);
  header('Content-Disposition: attachment; filename="' . $downloadName . '"');
  header('Content-Length: ' . strlen($decrypted));
  echo $decrypted;
  exit;
} else {
  echo "Unknown mode.";
  exit;
}
?>
<?php
// file_crypto_secure.php
// Improved demo: PBKDF2 (hash_pbkdf2) key derivation with random salt and random IV stored in header.
// Header layout: "SIMPLEAESv2" (11 bytes) + 16-byte salt + 16-byte iv + ciphertext
// WARNING: still a simple demo. For production prefer libsodium or OpenSSL AEAD (e.g., AES-GCM) + HMAC or use sodium_crypto_secretbox.

if($_SERVER['REQUEST_METHOD'] !== 'POST'){
  http_response_code(405);
  echo "Only POST allowed.";
  exit;
}
if(!isset($_FILES['userfile']) || !isset($_POST['passphrase']) || !isset($_POST['mode'])){
  echo "Missing inputs.";
  exit;
}
if(!extension_loaded('openssl')){
  echo "OpenSSL PHP extension is not loaded.";
  exit;
}

$mode = $_POST['mode']; // 'encrypt' or 'decrypt'
$pass = $_POST['passphrase'];
$tmpPath = $_FILES['userfile']['tmp_name'];
$origName = basename($_FILES['userfile']['name']);

define('HDRV2', "SIMPLEAESv2"); // versioned header
$cipher = "AES-256-CBC";
$kdfIterations = 100000; // PBKDF2 iterations (adjust as needed)

// Helper to derive key using PBKDF2
function derive_key($pass, $salt, $length = 32, $iterations = 100000){
  if(!function_exists('hash_pbkdf2')){
    // fallback (less secure) - not recommended
    return substr(hash('sha256', $pass . $salt, true), 0, $length);
  }
  return hash_pbkdf2('sha256', $pass, $salt, $iterations, $length, true);
}

$data = file_get_contents($tmpPath);
if($data === false){
  echo "Failed to read uploaded file.";
  exit;
}

if($mode === 'encrypt'){
  $salt = random_bytes(16);
  $iv = random_bytes(16);
  $key = derive_key($pass, $salt, 32, $kdfIterations);
  $encrypted = openssl_encrypt($data, $cipher, $key, OPENSSL_RAW_DATA, $iv);
  if($encrypted === false){
    echo "Encryption failed: " . openssl_error_string();
    exit;
  }
  // Output: header + salt + iv + ciphertext
  $outData = HDRV2 . $salt . $iv . $encrypted;
  header('Content-Description: File Transfer');
  header('Content-Type: application/octet-stream');
  header('Content-Disposition: attachment; filename="' . $origName . '.enc"');
  header('Content-Length: ' . strlen($outData));
  echo $outData;
  exit;
} elseif($mode === 'decrypt'){
  // check header
  if(substr($data, 0, strlen(HDRV2)) !== HDRV2){
    echo "Unknown file format or header missing.";
    exit;
  }
  $offset = strlen(HDRV2);
  $salt = substr($data, $offset, 16);
  $iv = substr($data, $offset + 16, 16);
  $ciphertext = substr($data, $offset + 32);
  if($salt === false || $iv === false || $ciphertext === false){
    echo "File appears truncated or corrupt.";
    exit;
  }
  $key = derive_key($pass, $salt, 32, $kdfIterations);
  $decrypted = openssl_decrypt($ciphertext, $cipher, $key, OPENSSL_RAW_DATA, $iv);
  if($decrypted === false){
    echo "Decryption failed. Wrong password or corrupt file. OpenSSL error: " . openssl_error_string();
    exit;
  }
  header('Content-Description: File Transfer');
  header('Content-Type: application/octet-stream');
  $downloadName = preg_replace('/\.enc$/', '', $origName);
  header('Content-Disposition: attachment; filename="' . $downloadName . '"');
  header('Content-Length: ' . strlen($decrypted));
  echo $decrypted;
  exit;
} else {
  echo "Unknown mode.";
  exit;
}
?>
