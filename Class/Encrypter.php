<?php

namespace xPasswords;

class Encrypter {
    
    function __construct($options) {
        
        if (isset($options)) {
            $this->options = $options;
            return true;
        }
        
        throw new \Exception('Unable to set AES Options');
        return false;
    }
    
    public function encrypt($datas = false) {
        
        if(!isset($this->options['encryptionKey'])) {
            throw new \Exception('No encryption key specified.');
            return false;
        }
        if(empty($datas)) {
            throw new \Exception('No data to be encrypted specified.');
            return false;
        }
        
        return trim(base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $this->options['encryptionKey'], $datas, MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND))));
    }

    public function decrypt($datas = false) {
        
        if(!isset($this->options['encryptionKey'])) {
            throw new \Exception('No encryption key specified.');
            return false;
        }
        if(empty($datas)) {
            throw new \Exception('No data to be decrypted specified.');
            return false;
        }
        if(!Core::isBASE64($datas)) {
            throw new \Exception('Fatal error while decrypting');
            return false;
        }
        
        return trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $this->options['encryptionKey'], base64_decode($datas), MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND)));
    }
};