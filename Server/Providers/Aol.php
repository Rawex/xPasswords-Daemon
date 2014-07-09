<?php
namespace xPasswords\Providers;

class Aol {
    
    static public $imapAddress = '';
    
    static public function authenticate($email, $password) {
        return false;
    }
};