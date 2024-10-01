<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TUGAS 1 KRIPTOGRAFI K5</title>
    <link rel="stylesheet" href="assets/style.css">
    <link rel="icon" type="image/png" href="assets/logo.png">
</head>
<body>
    <div class="container">
        <h1>TUGAS 1 KRIPTOGRAFI KELOMPOK 5</h1>
        <form action="index.php" method="POST" enctype="multipart/form-data">
            <div>
                <label for="cipher">Metode Cipher yang di pilih :</label>
                <select name="cipher" id="cipher">
                    <option value="">-- Pilih Metode --</option>
                    <option value="vigenere">Vigenere Cipher</option>
                    <option value="autokey_vigenere">Auto-Key Vigenere Cipher</option>
                    <option value="playfair">Playfair Cipher</option>
                    <option value="hill">Hill Cipher</option>
                    <option value="super_encryption">Super Encryption</option>
                </select>
            </div>
            <div>
                <label for="key">Masukkan Kunci:</label>
                <input type="text" name="kunci" required placeholder="Kunci Harus Menggunakan Huruf">
            </div>
            <div>
                <label for="plaintext">Masukkan Kalimat:</label>
                <textarea name="plaintext" id="plaintext" rows="5" placeholder="Masukkan Teks Disini"></textarea>
            </div>
            <div>
                <label for="file">Atau Upload File:</label>
                <input type="file" name="file">
            </div>
            <div>
                <button type="submit" name="encrypt">Enkripsi</button>
                <button type="submit" name="decrypt">Dekripsi</button>
            </div>
        </form>

        <?php
        require_once 'proses.php';

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $cipher = $_POST['cipher'];
            $kunci = $_POST['kunci'];
            $plaintext = $_POST['plaintext'] ?? '';
            $file = $_FILES['file']['tmp_name'] ?? null;
        
            if ($file) {
                // Code untuk File Encrypt dan Decrypt
                $fileContent = file_get_contents($file);
                $filename = $_FILES['file']['name'];
                if (isset($_POST['encrypt'])) {
                    $ciphertext = encrypt_file($fileContent, $kunci, $cipher);
                    file_put_contents("ciphered_$filename.dat", $ciphertext);
                    echo "<h3>File encrypted successfully. Download cipher file: <a href='ciphered_$filename.dat'>Download</a></h3>";
                } else if (isset($_POST['decrypt'])) {
                    $decryptedFile = decrypt_file($fileContent, $kunci, $cipher);
                    file_put_contents("decrypted_$filename", $decryptedFile);
                    echo "<h3>File decrypted successfully. Download decrypted file: <a href='decrypted_$filename'>Download</a></h3>";
                }
            } else {
                // Code untuk Kalimat Encrypt dan Decrypt
                if (isset($_POST['encrypt'])) {
                    $ciphertext = encrypt_text($plaintext, $kunci, $cipher);
                    $base64Ciphertext = base64_encode($ciphertext);
                    echo "<h3>Encrypted Text (Base64):</h3>";
                    echo "<textarea readonly>$base64Ciphertext</textarea>";
                } else if (isset($_POST['decrypt'])) {
                    // Pastikan mendekode base64 sebelum dekripsi
                    $ciphertext = base64_decode($plaintext);
                    $decryptedText = decrypt_text($ciphertext, $kunci, $cipher);
                    echo "<h3>Decrypted Text:</h3>";
                    echo "<textarea readonly>$decryptedText</textarea>";
                }
            }
        }
        ?>
    </div>
</body>
</html>
