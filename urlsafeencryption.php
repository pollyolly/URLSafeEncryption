<?php

$id = 67;
function decTicketid($encId){
        $id = base64_decode(urldecode($encId));
        $iv_length = openssl_cipher_iv_length('AES-128-CBC');
        $dec_key = openssl_digest(php_uname(), 'MD5', TRUE);
        $options = 0;
        $dec_iv = 'ieksleksldjflskj';
        $decryption = openssl_decrypt($id, 'AES-128-CBC', $dec_key, $options, $dec_iv);
       return $decryption;
}

function encTicketid($id){
            $iv_length = openssl_cipher_iv_length('AES-128-CBC');
            $enc_key = openssl_digest(php_uname(), 'MD5', TRUE);
            $options = 0;
            $enc_iv = 'ieksleksldjflskj';
            $encryption = openssl_encrypt($id, 'AES-128-CBC', $enc_key, $options, $enc_iv);
            return urlencode(base64_encode($encryption));
 }
$encId = encTicketid($id);
echo 'Encrypted for URL:'.encTicketid($id);
echo 'Decrypted from URL:'.decTicketid($encId);
