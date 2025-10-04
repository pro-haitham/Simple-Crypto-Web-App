<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Hash Generator
    if (isset($_POST['hashText'])) {
        $text = $_POST['hashText'];
        $algo = $_POST['algorithm'] ?? 'sha256';
        $hashResult = hash($algo, $text);

        echo "<h2>Hash Result</h2>";
        echo "<p><b>Algorithm:</b> $algo</p>";
        echo "<p><b>Text:</b> " . htmlspecialchars($text) . "</p>";
        echo "<p><b>Hash:</b> $hashResult</p>";
        echo "<a href='index.html'>⬅ Back</a>";
    }

    // Hash Verifier
    if (isset($_POST['verifyText']) && isset($_POST['verifyHash'])) {
        $text = $_POST['verifyText'];
        $algo = $_POST['verifyAlgorithm'] ?? 'sha256';
        $hash = $_POST['verifyHash'];

        echo "<h2>Hash Verification</h2>";
        echo "<p><b>Algorithm:</b> $algo</p>";
        echo "<p><b>Text:</b> " . htmlspecialchars($text) . "</p>";
        echo "<p><b>Expected Hash:</b> " . htmlspecialchars($hash) . "</p>";

        if (hash($algo, $text) === $hash) {
            echo "<p style='color:green'><b>✅ Hash matches!</b></p>";
        } else {
            echo "<p style='color:red'><b>❌ Hash does not match!</b></p>";
        }

        echo "<a href='index.html'>⬅ Back</a>";
    }
}
?>
