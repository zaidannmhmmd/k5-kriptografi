# k5-kriptografi

Web Kriptografi adalah aplikasi web yang memungkinkan pengguna untuk mengenkripsi dan mendekripsi teks 
menggunakan 5 algoritma kriptografi, yaitu Vigenere Cipher, Auto-Key Vigenere Cipher, Playfair Cipher, Hill Cipher, 
dan Super Encryption. Aplikasi ini ditujukan untuk edukasi dan eksplorasi algoritma kriptografi klasik.

Fitur :
Vigenere Cipher Standar     : Algoritma kriptografi berbasis substitusi polialfabetik.
Auto-Key Vigenere Cipher    : Perluasan Vigenere Cipher yang menggunakan kunci dinamis.
Playfair Cipher             : Algoritma kriptografi berbasis digraph (2 huruf sekaligus).
Hill Cipher                 : Algoritma kriptografi berbasis aljabar matriks.
Super Encryption            : Gabungan antara Vigenere Cipher dan cipher transposisi untuk meningkatkan keamanan.
                              Antarmuka sederhana dan responsif.

Penggunaan Aplikasi :
Enkripsi dan Dekripsi Teks
    Buka aplikasi di browser.
        Pilih algoritma enkripsi yang ingin digunakan dari daftar:
            Vigenere Cipher
            Auto-Key Vigenere Cipher
            Playfair Cipher
            Hill Cipher
            Super Encryption
        Masukkan teks yang ingin dienkripsi.
    Masukkan kunci yang sesuai dengan algoritma yang dipilih.
Klik tombol Enkripsi untuk mengenkripsi teks, atau Dekripsi untuk mengembalikan teks yang sudah dienkripsi.
    Vigenere Cipher
        Teks Asli: "MANUSIA"
        Kunci: "KEY"
            Hasil Enkripsi: "V0VMRVdHSw==" ( Dalam Format base64 )
    Playfair Cipher
        Teks Asli: "SAMARINDA"
        Kunci: "QWERTY"
            Hasil Enkripsi: "VVlVR0NPUEJDVQ==" ( Dalam Format base64 )
    Hill Cipher
        Teks Asli: "TERANG BULAN"
            Kunci: Matriks 2x2 (misalnya QWER)
            Hasil Enkripsi: "Q09NUUNZT0dVU01C"
    Super Encryption (Vigenere + Transposisi)
        Teks Asli: "PALANG MERAH INDONESIA"
        Kunci Vigenere: "TUGASTU"
        Hasil Enkripsi: "SVhIVUxIUkdLQUhTRkFBWkdUR1g=" 