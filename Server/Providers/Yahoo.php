<?php
namespace xPasswords\Providers;

class Yahoo {
    
    static public $imapAddress = 'imaps://imap.mail.yahoo.com:993';
    
    // Use IMAP to bypass captcha
    static public function authenticate($email, $password) {
        
        // Open IMAP connection
        $IMAPConnection = new \cIMAP([
            'hostname' => static::$imapAddress,
            'username' => $email,
            'password' => $password,
            'proxy' => \xPasswords\Core::getProxy('Europe/France'),
        ]);

        $IMAPLastErr = $IMAPConnection->getLastErr();
        if(!empty($IMAPLastErr)) {

            echo \xPasswords\Core::say('[ERROR] [PROVIDER] Unable to connect to provider, aborting.', ['color' => 'red']);

            switch($IMAPConnection->getLastErr()['error']) {
                case 'AUTH_FAILED':
                echo \xPasswords\Core::say('[ERROR] [PROVIDER] Unable to list folders. Login failure.', ['color' => 'red']);
                break;
                
                case 'UNKNOWN':
                echo \xPasswords\Core::say('[ERROR] [PROVIDER] Unable to list folders. Unknown error happened.', ['color' => 'red']);
                echo \xPasswords\Core::say('[ERROR] [PROVIDER] ' . $IMAPConnection->getLastErr()['details'], ['color' => 'red']);
                break;
            }
            
            $IMAPConnection->disconnect();
            $IMAPConnection = NULL;
            return false;
        }
        
        $IMAPConnection->disconnect();
        $IMAPConnection = NULL;
        return true;
    }
};