<?php

// Proses Enkripsi dan Dekripsi Vigenere Cipher
function vigenere_cipher($kalimat, $kunci, $decrypt = false) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $kalimat = strtoupper(preg_replace('/[^A-Z]/i', '', $kalimat));
    $kunci = strtoupper(preg_replace('/[^A-Z]/i', '', $kunci));
    
    // Pastikan kunci tidak kosong
    if (empty($kunci)) {
        throw new Exception('Kunci tidak boleh kosong');
    }

    $kunci = str_repeat($kunci, ceil(strlen($kalimat) / strlen($kunci)));
    $result = '';

    for ($i = 0, $len = strlen($kalimat); $i < $len; $i++) {
        $charKalimat = strpos($alphabet, $kalimat[$i]);
        $chatKunci = strpos($alphabet, $kunci[$i]);
        if ($decrypt) {
            $charKalimat = ($charKalimat - $chatKunci + 26) % 26;
        } else {
            $charKalimat = ($charKalimat + $chatKunci) % 26;
        }
        $result .= $alphabet[$charKalimat];
    }
    return $result;
}

// Playfair Cipher
function playfair_encrypt($plaintext, $key) {
    $plaintext = strtoupper(preg_replace('/[^A-Z]/i', '', $plaintext));
    $key = strtoupper(preg_replace('/[^A-Z]/i', '', $key));
    $key = str_replace('J', 'I', $key);
    // Generate Playfair key matrix
    $matrix = generate_playfair_key_table($key);
    
    // Prepare plaintext pairs
    $pairs = prepare_playfair_pairs($plaintext);

    $ciphertext = '';
    foreach ($pairs as $pair) {
        list($a, $b) = $pair;
        list($rowA, $colA) = find_position_in_matrix($a, $matrix);
        list($rowB, $colB) = find_position_in_matrix($b, $matrix);
        
        if ($rowA == $rowB) {
            $ciphertext .= $matrix[$rowA][($colA + 1) % 5];
            $ciphertext .= $matrix[$rowB][($colB + 1) % 5];
        } elseif ($colA == $colB) {
            $ciphertext .= $matrix[($rowA + 1) % 5][$colA];
            $ciphertext .= $matrix[($rowB + 1) % 5][$colB];
        } else {
            $ciphertext .= $matrix[$rowA][$colB];
            $ciphertext .= $matrix[$rowB][$colA];
        }
    }

    return $ciphertext;
}

function generate_playfair_key_table($key) {
    $key = strtoupper(preg_replace('/[^A-Z]/i', '', $key));
    $key = str_replace('J', 'I', $key);
    $alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
    $table = [];
    $usedChars = [];

    foreach (str_split($key) as $char) {
        if (!in_array($char, $usedChars)) {
            $usedChars[] = $char;
            $table[] = $char;
        }
    }

    foreach (str_split($alphabet) as $char) {
        if (!in_array($char, $usedChars)) {
            $usedChars[] = $char;
            $table[] = $char;
        }
    }

    return array_chunk($table, 5);
}

function prepare_playfair_pairs($plaintext) {
    $pairs = [];
    for ($i = 0; $i < strlen($plaintext); $i += 2) {
        $a = $plaintext[$i];
        $b = ($i + 1 < strlen($plaintext)) ? $plaintext[$i + 1] : 'X';
        if ($a == $b) {
            $pairs[] = [$a, 'X'];
            $i--; // go back to treat this character again
        } else {
            $pairs[] = [$a, $b];
        }
    }
    return $pairs;
}

function find_position_in_matrix($char, $matrix) {
    for ($row = 0; $row < 5; $row++) {
        for ($col = 0; $col < 5; $col++) {
            if ($matrix[$row][$col] === $char) {
                return [$row, $col];
            }
        }
    }
    return null; // If character not found
}

function playfair_decrypt($ciphertext, $key) {
    $matrix = generate_playfair_key_table($key);
    
    $plaintext = '';
    $pairs = prepare_playfair_pairs($ciphertext);
    
    foreach ($pairs as $pair) {
        list($a, $b) = $pair;
        list($rowA, $colA) = find_position_in_matrix($a, $matrix);
        list($rowB, $colB) = find_position_in_matrix($b, $matrix);
        
        if ($rowA == $rowB) {
            $plaintext .= $matrix[$rowA][($colA - 1 + 5) % 5];
            $plaintext .= $matrix[$rowB][($colB - 1 + 5) % 5];
        } elseif ($colA == $colB) {
            $plaintext .= $matrix[($rowA - 1 + 5) % 5][$colA];
            $plaintext .= $matrix[($rowB - 1 + 5) % 5][$colB];
        } else {
            $plaintext .= $matrix[$rowA][$colB];
            $plaintext .= $matrix[$rowB][$colA];
        }
    }

    return $plaintext;
}

// Hill Cipher
function hill_encrypt($text, $kunci) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $kunci = strtoupper(preg_replace('/[^A-Z]/i', '', $kunci)); // Hanya huruf

    if (strlen($kunci) !== 4) {
        throw new Exception('Kunci untuk Hill Cipher harus 4 huruf (2x2 matriks)');
    }

    // Buat matriks kunci 2x2
    $keyMatrix = [
        [strpos($alphabet, $kunci[0]), strpos($alphabet, $kunci[1])],
        [strpos($alphabet, $kunci[2]), strpos($alphabet, $kunci[3])]
    ];

    // Bersihkan teks, hanya huruf, dan ubah ke uppercase
    $text = strtoupper(preg_replace('/[^A-Z]/i', '', $text));

    // Tambahkan padding 'X' jika panjang ganjil
    if (strlen($text) % 2 !== 0) {
        $text .= 'X';
    }

    $result = '';

    // Proses enkripsi, memproses dua huruf setiap iterasi
    for ($i = 0; $i < strlen($text); $i += 2) {
        $pair = [$text[$i], $text[$i + 1]];
        $vector = [strpos($alphabet, $pair[0]), strpos($alphabet, $pair[1])];

        // Operasi matriks (vektor * keyMatrix)
        $newVector = [
            ($keyMatrix[0][0] * $vector[0] + $keyMatrix[0][1] * $vector[1]) % 26,
            ($keyMatrix[1][0] * $vector[0] + $keyMatrix[1][1] * $vector[1]) % 26
        ];

        // Ambil huruf dari alfabet berdasarkan hasil enkripsi
        $result .= $alphabet[$newVector[0]] . $alphabet[$newVector[1]];
    }

    return $result;
}


function mod_inverse($a, $m) {
    $m0 = $m;
    $x0 = 0;
    $x1 = 1;

    if ($m == 1) {
        return false;
    }

    while ($a > 1) {
        $q = intdiv($a, $m);
        $t = $m;
        $m = $a % $m;
        $a = $t;
        $t = $x0;
        $x0 = $x1 - $q * $x0;
        $x1 = $t;
    }

    if ($x1 < 0) {
        $x1 += $m0;
    }

    return $x1;
}

function inverse_key_matrix($matrix) {
    $det = ($matrix[0][0] * $matrix[1][1] - $matrix[0][1] * $matrix[1][0]) % 26;
    $detInverse = mod_inverse($det, 26);

    if ($detInverse === false) {
        throw new Exception('Determinan tidak memiliki invers modulus, dekripsi tidak memungkinkan.');
    }

    // Matriks invers dari matriks 2x2
    return [
        [($matrix[1][1] * $detInverse) % 26, (-$matrix[0][1] * $detInverse + 26) % 26],
        [(-$matrix[1][0] * $detInverse + 26) % 26, ($matrix[0][0] * $detInverse) % 26]
    ];
}

function hill_decrypt($text, $kunci) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $kunci = strtoupper(preg_replace('/[^A-Z]/i', '', $kunci)); // Hanya huruf
    
    if (strlen($kunci) !== 4) {
        throw new Exception('Kunci untuk Hill Cipher harus 4 huruf (2x2 matriks)');
    }

    // Buat matriks kunci 2x2
    $keyMatrix = [
        [strpos($alphabet, $kunci[0]), strpos($alphabet, $kunci[1])],
        [strpos($alphabet, $kunci[2]), strpos($alphabet, $kunci[3])]
    ];

    // Hitung invers matriks kunci terlebih dahulu
    $keyMatrix = inverse_key_matrix($keyMatrix);

    // Bersihkan teks, hanya huruf, dan ubah ke uppercase
    $text = strtoupper(preg_replace('/[^A-Z]/i', '', $text));

    $result = '';

    // Proses dekripsi, memproses dua huruf setiap iterasi
    for ($i = 0; $i < strlen($text); $i += 2) {
        $pair = [$text[$i], $text[$i + 1]];
        $vector = [strpos($alphabet, $pair[0]), strpos($alphabet, $pair[1])];

        // Operasi matriks (vektor * keyMatrix)
        $newVector = [
            ($keyMatrix[0][0] * $vector[0] + $keyMatrix[0][1] * $vector[1]) % 26,
            ($keyMatrix[1][0] * $vector[0] + $keyMatrix[1][1] * $vector[1]) % 26
        ];

        // Ambil huruf dari alfabet berdasarkan hasil dekripsi
        $result .= $alphabet[$newVector[0]] . $alphabet[$newVector[1]];
    }

    // Menghapus padding
    return rtrim($result, 'X');
}




// Super Enkripsi (Kombinasi Vigenere dan Transposisi)
function super_encryption($kalimat, $kunci) {
    // Pertama, menggunakan Vigenere cipher
    $ciphertext = vigenere_cipher($kalimat, $kunci);
    // Kemudian menggunakan cipher transposisi
    $ciphertext = column_transposition($ciphertext, $kunci);
    return $ciphertext;
}

function super_decryption($ciphertext, $kunci) {
    // Pertama, membalikkan cipher transposisi
    $plaintext = column_transposition_decrypt($ciphertext, $kunci);
    // Kemudian menggunakan dekripsi Vigenere
    $plaintext = vigenere_cipher($plaintext, $kunci, true); // true untuk dekripsi
    return $plaintext;
}

// Kolom Transposisi
function column_transposition($kalimat, $kunci) {
    // Membuat kolom berdasarkan panjang kunci
    $kolom = array_fill(0, strlen($kunci), '');
    for ($i = 0, $len = strlen($kalimat); $i < $len; $i++) {
        $kolom[$i % strlen($kunci)] .= $kalimat[$i];
    }
    // Mengurutkan kunci untuk kolom
    $sortedKey = str_split($kunci);
    sort($sortedKey);
    
    // Membuat peta indeks
    $keyMap = [];
    foreach ($sortedKey as $key) {
        $keyMap[] = array_search($key, $sortedKey);
    }
    
    // Menggabungkan kolom berdasarkan urutan kunci
    $ciphertext = '';
    foreach ($keyMap as $index) {
        $ciphertext .= $kolom[$index];
    }

    return $ciphertext;
}

function column_transposition_decrypt($ciphertext, $kunci) {
    $numCols = strlen($kunci);
    $numRows = ceil(strlen($ciphertext) / $numCols);

    // Membuat array untuk kolom
    $columns = array_fill(0, $numCols, '');
    $kunciArr = str_split($kunci);
    $sortedKey = $kunciArr;
    sort($sortedKey);
    
    // Peta indeks
    $keyMap = [];
    foreach ($sortedKey as $key) {
        $keyMap[] = array_search($key, $kunciArr);
    }

    // Mengisi kolom
    for ($i = 0; $i < $numCols; $i++) {
        $colIndex = $keyMap[$i];
        $columns[$colIndex] = substr($ciphertext, $i * $numRows, $numRows);
    }

    // Menggabungkan kembali ke plaintext
    $plaintext = '';
    for ($r = 0; $r < $numRows; $r++) {
        for ($c = 0; $c < $numCols; $c++) {
            if ($r < strlen($columns[$c])) {
                $plaintext .= $columns[$c][$r];
            }
        }
    }
    return $plaintext;
}


// Enkripsi Plaintext
function encrypt_text($plaintext, $kunci, $cipher) {
    if (empty($plaintext) || empty($kunci)) {
        return 'Plaintext dan kunci tidak boleh kosong.';
    }

    switch ($cipher) {
        case 'vigenere':
            return vigenere_cipher($plaintext, $kunci);
        case 'super_encryption':
            return super_encryption($plaintext, $kunci);
        case 'playfair':
            return playfair_encrypt($plaintext, $kunci);
        case 'hill':
            return hill_encrypt($plaintext, $kunci);
        default:
            return $plaintext; // Placeholder for other ciphers
    }
}

// Decrypt ciphertext (text mode)
function decrypt_text($ciphertext, $kunci, $cipher) {
    switch ($cipher) {
        case 'vigenere':
            return vigenere_cipher($ciphertext, $kunci, true);
            case 'playfair':
                return playfair_decrypt($ciphertext, $kunci);
        case 'super_encryption':
            return super_decryption($ciphertext, $kunci);
        case 'hill' :
            return hill_decrypt($ciphertext, $kunci);
        default:
            return $ciphertext; // Placeholder for other ciphers
    }
}

// Encrypt file content
function encrypt_file($fileContent, $kunci, $cipher) {
    return encrypt_text($fileContent, $kunci, $cipher);
}

// Decrypt file content
function decrypt_file($ciphertext, $kunci, $cipher) {
    return decrypt_text($ciphertext, $kunci, $cipher);
}

